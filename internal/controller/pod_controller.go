/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/sebrandon1/imagecertinfo-operator/api/v1alpha1"
	"github.com/sebrandon1/imagecertinfo-operator/internal/metrics"
	"github.com/sebrandon1/imagecertinfo-operator/internal/version"
	"github.com/sebrandon1/imagecertinfo-operator/pkg/dockerhub"
	"github.com/sebrandon1/imagecertinfo-operator/pkg/image"
	"github.com/sebrandon1/imagecertinfo-operator/pkg/pyxis"

	quaylib "github.com/sebrandon1/go-quay/lib"
)

// Event reasons for Kubernetes events
const (
	EventReasonImageDiscovered      = "ImageDiscovered"
	EventReasonCertificationChanged = "CertificationChanged"
	EventReasonVulnerabilitiesFound = "VulnerabilitiesFound"
	EventReasonEOLApproaching       = "EOLApproaching"
	EventReasonHealthDegraded       = "HealthDegraded"
)

// Registry constants
const (
	RegistryDockerHub = "docker.io"
	RegistryQuayIO    = "quay.io"
)

// Annotation keys
const (
	AnnotationCVEs = "security.telco.openshift.io/cves"
)

// Label keys stamped on ImageCertificationInfo CRs for external operator lookup
const (
	LabelDigest          = "imagecertinfo.security.telco.openshift.io/digest"
	LabelOperatorVersion = "imagecertinfo.security.telco.openshift.io/operator-version"
)

// DefaultEnrichmentWorkers is the default number of concurrent enrichment
// workers draining the queue.
const DefaultEnrichmentWorkers = 4

// maxEnrichmentRetries bounds how often a failed enrichment is retried before
// it is dropped. Without a cap a permanently broken image (for example an
// unknown repository) would retry forever.
const maxEnrichmentRetries = 5

// gradeOrder maps health grades to numeric values for comparison
var gradeOrder = map[string]int{"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}

// lastSeenRefreshWindow is the minimum interval between LastSeenAt rewrites for
// an already-tracked pod reference. Kubelet updates pod status frequently, so
// writing on every event is pure write amplification.
var lastSeenRefreshWindow = 5 * time.Minute

// digestLabel builds the value for LabelDigest from a full sha256 digest string.
// The colon in "sha256:" is not valid in label values, so we use "sha256-" instead.
// We use the first 16 hex characters to keep the label short and unique enough.
func digestLabel(digest string) string {
	hex := strings.TrimPrefix(digest, "sha256:")
	if len(hex) > 16 {
		hex = hex[:16]
	}
	return "sha256-" + hex
}

// PodReconciler reconciles a Pod object and creates/updates ImageCertificationInfo resources
type PodReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	PyxisClient     pyxis.Client
	DockerHubClient dockerhub.Client
	QuayClient      quaylib.RepositoryReader
	Recorder        record.EventRecorder

	// EnrichQueue feeds the bounded enrichment workers. It is nil when the
	// reconciler is used outside a manager (for example in tests), in which
	// case enrichment is skipped.
	EnrichQueue workqueue.TypedRateLimitingInterface[enrichRequest]
}

// enrichRequest asks a worker to enrich one ImageCertificationInfo. It holds
// the image reference so the worker does not have to parse it again. Requests
// are keyed by CR name, so several pods sharing an image collapse into one.
type enrichRequest struct {
	crName string
	ref    image.Reference
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods/status,verbs=get
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=imagecertificationinfoes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=imagecertificationinfoes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.telco.openshift.io,resources=imagecertificationinfoes/finalizers,verbs=update

// Reconcile watches Pods and creates/updates ImageCertificationInfo resources for each unique image
func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	logger := log.FromContext(ctx)

	// Fetch the Pod
	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			// Pod was deleted - we handle cleanup via owner references or periodic reconciliation
			metrics.RecordReconcile("success", time.Since(start).Seconds(), "pod")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to fetch Pod")
		metrics.RecordReconcile("error", time.Since(start).Seconds(), "pod")
		return ctrl.Result{}, err
	}

	// Skip pods that are not running or pending
	if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodPending {
		metrics.RecordReconcile("success", time.Since(start).Seconds(), "pod")
		return ctrl.Result{}, nil
	}

	// Process all container statuses (including init containers)
	allStatuses := make([]corev1.ContainerStatus, 0, len(pod.Status.ContainerStatuses)+len(pod.Status.InitContainerStatuses))
	allStatuses = append(allStatuses, pod.Status.ContainerStatuses...)
	allStatuses = append(allStatuses, pod.Status.InitContainerStatuses...)

	var errs []error

	for _, containerStatus := range allStatuses {
		if containerStatus.ImageID == "" {
			continue
		}

		// Parse the image ID
		ref, err := image.ParseImageID(containerStatus.ImageID)
		if err != nil {
			logger.V(1).Info("failed to parse imageID", "imageID", containerStatus.ImageID, "error", err)
			continue
		}

		// Generate CR name from image reference (human-readable)
		crName := image.ReferenceToCRName(ref)

		// Create pod reference
		podRef := securityv1alpha1.PodReference{
			Namespace: pod.Namespace,
			Name:      pod.Name,
			Container: containerStatus.Name,
		}

		// Try to get existing ImageCertificationInfo
		var existingCR securityv1alpha1.ImageCertificationInfo
		err = r.Get(ctx, client.ObjectKey{Name: crName}, &existingCR)

		if apierrors.IsNotFound(err) {
			// Create new ImageCertificationInfo
			if err := r.createImageCertificationInfo(ctx, ref, crName, podRef); err != nil {
				logger.Error(err, "failed to create ImageCertificationInfo", "name", crName)
				errs = append(errs, fmt.Errorf("create %s: %w", crName, err))
				continue
			}
			logger.Info("created ImageCertificationInfo", "name", crName, "registry", ref.Registry)
		} else if err != nil {
			logger.Error(err, "failed to get ImageCertificationInfo", "name", crName)
			errs = append(errs, fmt.Errorf("get %s: %w", crName, err))
			continue
		} else {
			// Update existing CR with new pod reference
			if err := r.updatePodReferences(ctx, &existingCR, podRef); err != nil {
				logger.Error(err, "failed to update ImageCertificationInfo", "name", crName)
				errs = append(errs, fmt.Errorf("update %s: %w", crName, err))
				continue
			}
		}
	}

	// Returning the error makes controller-runtime requeue with backoff, so a
	// failed write is retried instead of being lost until the pod changes again.
	if len(errs) > 0 {
		metrics.RecordReconcile("error", time.Since(start).Seconds(), "pod")
		return ctrl.Result{}, errors.Join(errs...)
	}

	metrics.RecordReconcile("success", time.Since(start).Seconds(), "pod")
	return ctrl.Result{}, nil
}

// createImageCertificationInfo creates a new ImageCertificationInfo resource
func (r *PodReconciler) createImageCertificationInfo(ctx context.Context, ref *image.Reference, crName string, podRef securityv1alpha1.PodReference) error {
	now := metav1.Now()
	registryType := image.ClassifyRegistry(ref.Registry)

	cr := &securityv1alpha1.ImageCertificationInfo{
		Name: crName,
		Labels: map[string]string{
			LabelDigest:          digestLabel(ref.Digest),
			LabelOperatorVersion: version.Version,
		},
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        ref.Digest,
			FullImageReference: ref.FullReference,
			Registry:           ref.Registry,
			Repository:         ref.Repository,
			Tag:                ref.Tag,
		},
	}

	// Create the resource
	if err := r.Create(ctx, cr); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		// Another pod carrying the same image won the race. Treat it as the
		// update path so its reference is not dropped.
		var existing securityv1alpha1.ImageCertificationInfo
		if getErr := r.Get(ctx, client.ObjectKey{Name: crName}, &existing); getErr != nil {
			return getErr
		}
		return r.updatePodReferences(ctx, &existing, podRef)
	}

	// Update status
	cr.Status = securityv1alpha1.ImageCertificationInfoStatus{
		RegistryType:        registryType,
		CertificationStatus: securityv1alpha1.CertificationStatusUnknown,
		PodReferences:       []securityv1alpha1.PodReference{podRef},
		FirstSeenAt:         &now,
		LastSeenAt:          &now,
	}

	// Set initial conditions
	cr.Status.Conditions = []metav1.Condition{
		{
			Type:               "Available",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: now,
			Reason:             "ImageDiscovered",
			Message:            "Image has been discovered in the cluster",
		},
	}

	// Write the status on the object returned by Create: it carries the
	// server-assigned resourceVersion, so no read is needed. Re-fetching here
	// would go through the informer cache, which has not observed the create
	// yet and would fail the write with NotFound.
	initialStatus := cr.Status
	if err := r.Status().Update(ctx, cr); err != nil {
		if !apierrors.IsConflict(err) {
			return err
		}
		// Another writer bumped the object; re-apply on the latest version.
		if err := r.updateCRStatus(ctx, cr.Name, func(latest *securityv1alpha1.ImageCertificationInfo) {
			latest.Status = initialStatus
		}); err != nil {
			return err
		}
	}

	// Emit event and record metrics
	metrics.ImagesDiscovered.Inc()
	if r.Recorder != nil {
		r.Recorder.Event(cr, corev1.EventTypeNormal, EventReasonImageDiscovered,
			fmt.Sprintf("Discovered image %s", ref.FullReference))
		metrics.RecordEvent(corev1.EventTypeNormal, EventReasonImageDiscovered)
	}

	// Enrichment runs on the bounded worker pool instead of a goroutine per
	// image: on a large cluster a first start would otherwise spawn hundreds of
	// goroutines that outlive shutdown and are never retried.
	r.enqueueEnrichment(cr.Name, ref)

	return nil
}

// enqueueEnrichment hands an image to the enrichment worker pool. With no queue
// configured (no manager, e.g. a unit test) enrichment is skipped.
func (r *PodReconciler) enqueueEnrichment(crName string, ref *image.Reference) {
	if r.EnrichQueue == nil {
		return
	}

	r.EnrichQueue.Add(enrichRequest{crName: crName, ref: *ref})
}

// updatePodReferences updates the pod references in an existing ImageCertificationInfo.
// It retries on conflict with a freshly fetched copy so a concurrent write for
// another pod sharing the image cannot drop this reference.
func (r *PodReconciler) updatePodReferences(ctx context.Context, cr *securityv1alpha1.ImageCertificationInfo, podRef securityv1alpha1.PodReference) error {
	now := metav1.Now()

	if cr.Labels[LabelOperatorVersion] != version.Version {
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var latest securityv1alpha1.ImageCertificationInfo
			if err := r.Get(ctx, client.ObjectKey{Name: cr.Name}, &latest); err != nil {
				return err
			}
			if latest.Labels == nil {
				latest.Labels = make(map[string]string)
			}
			latest.Labels[LabelOperatorVersion] = version.Version
			return r.Update(ctx, &latest)
		}); err != nil {
			return err
		}
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var latest securityv1alpha1.ImageCertificationInfo
		if err := r.Get(ctx, client.ObjectKey{Name: cr.Name}, &latest); err != nil {
			return err
		}

		// Already tracked: just refresh LastSeenAt.
		for _, existing := range latest.Status.PodReferences {
			if existing.Namespace == podRef.Namespace &&
				existing.Name == podRef.Name &&
				existing.Container == podRef.Container {
				if lastSeenRecently(latest.Status.LastSeenAt) {
					return nil
				}
				latest.Status.LastSeenAt = &now
				return r.Status().Update(ctx, &latest)
			}
		}

		latest.Status.PodReferences = append(latest.Status.PodReferences, podRef)
		latest.Status.LastSeenAt = &now

		return r.Status().Update(ctx, &latest)
	})
}

// lastSeenRecently reports whether a pod reference was refreshed within
// lastSeenRefreshWindow.
func lastSeenRecently(lastSeen *metav1.Time) bool {
	if lastSeen == nil {
		return false
	}
	return time.Since(lastSeen.Time) < lastSeenRefreshWindow
}

// updateCRStatus applies mutate to the latest version of a CR and writes its
// status subresource, retrying on conflict.
func (r *PodReconciler) updateCRStatus(
	ctx context.Context, crName string, mutate func(*securityv1alpha1.ImageCertificationInfo),
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cr securityv1alpha1.ImageCertificationInfo
		if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
			return err
		}
		mutate(&cr)
		return r.Status().Update(ctx, &cr)
	})
}

// checkPyxisCertification queries the Pyxis API for certification data. It
// returns an error when the lookup should be retried.
func (r *PodReconciler) checkPyxisCertification(ctx context.Context, crName string, ref *image.Reference) error {
	logger := log.FromContext(ctx).WithValues("crName", crName)

	if r.PyxisClient == nil {
		return nil
	}

	// Query Pyxis
	certData, err := r.PyxisClient.GetImageCertification(ctx, ref.Registry, ref.Repository, ref.Digest)
	if err != nil {
		logger.Error(err, "failed to query Pyxis API")
		// Still try to update status to reflect the error
		var cr securityv1alpha1.ImageCertificationInfo
		if getErr := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); getErr != nil {
			logger.Error(getErr, "failed to get ImageCertificationInfo for Pyxis error update")
			return errors.Join(err, getErr)
		}
		now := metav1.Now()
		cr.Status.LastPyxisCheckAt = &now
		cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusError
		// A failed lookup leaves the CR describing nothing that Pyxis returned in
		// this cycle. Keeping the previous payload next to an Error status makes
		// consumers report an EOL date and vulnerability counts the API no longer
		// confirms, so clear it for consistency with the NotCertified path.
		clearPyxisStatus(&cr)
		if updateErr := r.Status().Update(ctx, &cr); updateErr != nil {
			logger.Error(updateErr, "failed to update status after Pyxis error")
			return errors.Join(err, updateErr)
		}
		if clearErr := r.clearCVEAnnotation(ctx, crName); clearErr != nil {
			logger.Error(clearErr, "failed to clear CVE annotations after Pyxis error")
		}
		return err
	}

	// Fetch the latest version of the CR
	var cr securityv1alpha1.ImageCertificationInfo
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		logger.Error(err, "failed to get ImageCertificationInfo for Pyxis update")
		return err
	}

	now := metav1.Now()
	cr.Status.LastPyxisCheckAt = &now

	if certData == nil {
		// No certification data found. Reset the payload as well, otherwise the
		// values from the previous refresh survive next to a NotCertified status.
		cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusNotCertified
		clearPyxisStatus(&cr)
	} else {
		// Update with certification data using shared method
		r.updateCRWithPyxisData(&cr, certData)

		// Emit event if EOL approaching (within 90 days)
		if cr.Status.DaysUntilEOL != nil {
			daysUntil := *cr.Status.DaysUntilEOL
			if daysUntil >= 0 && daysUntil <= 90 && r.Recorder != nil {
				msg := fmt.Sprintf("Image reaches EOL in %d days", daysUntil)
				if certData.ReplacedBy != "" {
					msg += fmt.Sprintf(", replacement: %s", certData.ReplacedBy)
				}
				r.Recorder.Event(&cr, corev1.EventTypeWarning, EventReasonEOLApproaching, msg)
				metrics.RecordEvent(corev1.EventTypeWarning, EventReasonEOLApproaching)
			}
		}

		// Emit event if vulnerabilities found
		if certData.Vulnerabilities != nil &&
			(certData.Vulnerabilities.Critical > 0 || certData.Vulnerabilities.Important > 0) &&
			r.Recorder != nil {
			r.Recorder.Event(&cr, corev1.EventTypeWarning, EventReasonVulnerabilitiesFound,
				fmt.Sprintf("Found %d critical, %d important vulnerabilities",
					certData.Vulnerabilities.Critical, certData.Vulnerabilities.Important))
			metrics.RecordEvent(corev1.EventTypeWarning, EventReasonVulnerabilitiesFound)
		}
	}

	// Update status first
	if err := r.Status().Update(ctx, &cr); err != nil {
		logger.Error(err, "failed to update ImageCertificationInfo with Pyxis data")
		return err
	}

	// Update CVE annotations separately (after status update). An empty CVE list
	// means the annotation from an earlier refresh no longer applies.
	if certData == nil || len(certData.CVEs) == 0 {
		if clearErr := r.clearCVEAnnotation(ctx, crName); clearErr != nil {
			logger.Error(clearErr, "failed to clear CVE annotations")
		}
	} else if updateErr := r.updateCVEAnnotations(ctx, crName, certData.CVEs); updateErr != nil {
		logger.Error(updateErr, "failed to update CVE annotations")
	}

	return nil
}

// checkDockerHubData queries the Docker Hub API for repository metadata. It
// returns an error when the enrichment should be retried.
func (r *PodReconciler) checkDockerHubData(ctx context.Context, crName string, ref *image.Reference) error {
	logger := log.FromContext(ctx).WithValues("crName", crName)

	if r.DockerHubClient == nil {
		return nil
	}

	// Parse namespace and repository from the repository path
	// For official images: library/nginx -> namespace=library, repo=nginx
	// For user images: bitnami/redis -> namespace=bitnami, repo=redis
	namespace, repo := parseDockerHubRepo(ref.Repository)

	// Query Docker Hub
	repoInfo, err := r.DockerHubClient.GetRepositoryInfo(ctx, namespace, repo)
	if err != nil {
		logger.Error(err, "failed to query Docker Hub API")
		return err
	}

	// Fetch the latest version of the CR
	var cr securityv1alpha1.ImageCertificationInfo
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		logger.Error(err, "failed to get ImageCertificationInfo for Docker Hub update")
		return err
	}

	if repoInfo == nil {
		// The repository is gone: deleted, renamed, or made private. Drop the
		// payload from the previous cycle, otherwise the CR keeps advertising an
		// Official or Verified badge that Docker Hub no longer confirms.
		clearDockerHubStatus(&cr)
	} else {
		r.updateCRWithDockerHubData(&cr, repoInfo)
	}

	// Update status
	if err := r.Status().Update(ctx, &cr); err != nil {
		logger.Error(err, "failed to update ImageCertificationInfo with Docker Hub data")
		return err
	}

	return nil
}

// parseDockerHubRepo parses a repository path into namespace and repository name
func parseDockerHubRepo(repository string) (namespace, repo string) {
	parts := strings.SplitN(repository, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	// If no slash, it's an official image
	return "library", repository
}

// updateCRWithDockerHubData updates a CR's status with data from Docker Hub
func (r *PodReconciler) updateCRWithDockerHubData(cr *securityv1alpha1.ImageCertificationInfo, repoInfo *dockerhub.RepositoryInfo) {
	daysSinceUpdate := dockerhub.CalculateDaysSince(repoInfo.LastUpdated)

	cr.Status.DockerHubData = &securityv1alpha1.DockerHubData{
		IsOfficialImage:     repoInfo.IsOfficial,
		IsVerifiedPublisher: repoInfo.IsVerifiedPublisher,
		PullCount:           repoInfo.PullCount,
		StarCount:           repoInfo.StarCount,
		LastUpdated:         &metav1.Time{Time: repoInfo.LastUpdated},
		DaysSinceUpdate:     &daysSinceUpdate,
		PullCountFormatted:  dockerhub.FormatPullCount(repoInfo.PullCount),
	}

	// Update certification status based on Docker Hub trust level
	if repoInfo.IsOfficial {
		cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusOfficial
	} else if repoInfo.IsVerifiedPublisher {
		cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusVerified
	} else if cr.Status.CertificationStatus == securityv1alpha1.CertificationStatusUnknown {
		// Only update to NotCertified if currently Unknown
		cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusNotCertified
	}
}

// checkQuayData queries the Quay.io API for repository metadata. It returns an
// error when the enrichment should be retried.
func (r *PodReconciler) checkQuayData(ctx context.Context, crName string, ref *image.Reference) error {
	logger := log.FromContext(ctx).WithValues("crName", crName)

	if r.QuayClient == nil {
		return nil
	}

	namespace, repo := parseQuayRepo(ref.Repository)

	start := time.Now()
	repoInfo, err := r.QuayClient.GetRepository(ctx, namespace, repo)
	duration := time.Since(start).Seconds()

	if err != nil {
		if isQuayDenied(err) {
			// Quay answers 401/403 for repositories the token may not see, which
			// includes repositories that are gone, so this is not proof of a
			// deletion: keep the previous enrichment instead of blanking it.
			metrics.RecordQuayRequest("denied", "repository", duration)
			logger.Info("Quay denied access to the repository; keeping the previous enrichment", "error", err)

			return classifyQuayError(err)
		}
		metrics.RecordQuayRequest("error", "repository", duration)
		logger.Error(err, "failed to query Quay.io API")
		return err
	}

	metrics.RecordQuayRequest("success", "repository", duration)

	var cr securityv1alpha1.ImageCertificationInfo
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		logger.Error(err, "failed to get ImageCertificationInfo for Quay update")
		return err
	}

	r.updateCRWithQuayData(&cr, &repoInfo)

	// Supplementary enrichment is best-effort: a failure here must not discard
	// the repository data above, so the errors are collected and returned only
	// after the status write, which makes the worker retry.
	var (
		cves       []string
		scanOK     bool
		enrichErrs []error
	)
	scanAttempted := ref.Digest != ""
	if scanAttempted {
		var manifestOK, labelsOK bool
		cves, scanOK = r.enrichQuaySecurity(ctx, &cr, namespace, repo, ref.Digest)
		manifestOK = r.enrichQuayManifest(ctx, &cr, namespace, repo, ref.Digest)
		labelsOK = r.enrichQuayLabels(ctx, &cr, namespace, repo, ref.Digest)
		enrichErrs = appendQuayEnrichmentFailures(enrichErrs, crName, scanOK, manifestOK, labelsOK)
	}

	if err := r.Status().Update(ctx, &cr); err != nil {
		logger.Error(err, "failed to update ImageCertificationInfo with Quay data")
		return err
	}

	// Emit vulnerability events and CVE annotations after status update. A
	// failed scan preserved the previous counts, so only a fresh scan may
	// re-emit an event about them.
	if scanOK && cr.Status.QuayData != nil && cr.Status.QuayData.Vulnerabilities != nil {
		vulns := cr.Status.QuayData.Vulnerabilities
		if vulns.Critical > 0 || vulns.Important > 0 {
			if r.Recorder != nil {
				r.Recorder.Event(&cr, corev1.EventTypeWarning, EventReasonVulnerabilitiesFound,
					fmt.Sprintf("Quay security scan found %d critical, %d important vulnerabilities",
						vulns.Critical, vulns.Important))
				metrics.RecordEvent(corev1.EventTypeWarning, EventReasonVulnerabilitiesFound)
			}
		}
	}

	// A successful scan owns the annotation: an empty result removes a stale
	// list. A failed scan leaves the previous one alone, so a transient Clair
	// outage does not erase evidence. Skipping the scan entirely (no digest)
	// also leaves it alone: there is no basis on which to clear it.
	if scanOK {
		if len(cves) > 0 {
			if updateErr := r.updateCVEAnnotations(ctx, crName, cves); updateErr != nil {
				logger.Error(updateErr, "failed to update CVE annotations")
			}
		} else if clearErr := r.clearCVEAnnotation(ctx, crName); clearErr != nil {
			logger.Error(clearErr, "failed to clear CVE annotations")
		}
	}

	return errors.Join(enrichErrs...)
}

// parseQuayRepo parses a repository path into namespace and repository name
func parseQuayRepo(repository string) (namespace, repo string) {
	parts := strings.SplitN(repository, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return repository, repository
}

// updateCRWithQuayData replaces the repository-owned fields of
// status.quayData. The security, manifest, and label enrichment helpers own the
// remaining fields and write them separately, so this must not touch them: a
// failed scan has to leave the previous summary intact.
func (r *PodReconciler) updateCRWithQuayData(cr *securityv1alpha1.ImageCertificationInfo, repo *quaylib.RepositoryWithTags) {
	quayData := ensureQuayData(cr)

	quayData.IsPublic = repo.IsPublic
	quayData.IsOrganization = repo.IsOrganization
	quayData.TrustEnabled = repo.TrustEnabled
	quayData.State = repo.State
	quayData.Description = repo.Description
	quayData.TagCount = len(repo.Tags.Tags)

	// Only a tag timestamp the API still reports may produce these values, so
	// drop them first: a repository whose tags all disappeared must not keep
	// advertising the last tag it once had.
	quayData.LastModified = nil
	quayData.DaysSinceUpdate = nil

	if latest := repo.LatestTagTimestamp(); !latest.IsZero() {
		daysSince := quaylib.CalculateDaysSince(latest)
		quayData.LastModified = &metav1.Time{Time: latest}
		quayData.DaysSinceUpdate = &daysSince
	}
}

// ensureQuayData returns status.quayData, creating it when absent. The
// repository, security, manifest, and label paths each write a disjoint set of
// fields, so they all need somewhere to write.
func ensureQuayData(cr *securityv1alpha1.ImageCertificationInfo) *securityv1alpha1.QuayData {
	if cr.Status.QuayData == nil {
		cr.Status.QuayData = &securityv1alpha1.QuayData{}
	}

	return cr.Status.QuayData
}

// enrichQuaySecurity applies the Clair scan result and returns the CVE IDs it
// reports. ok is false only when the request itself failed: the caller then
// keeps whatever an earlier scan recorded.
func (r *PodReconciler) enrichQuaySecurity(
	ctx context.Context, cr *securityv1alpha1.ImageCertificationInfo, namespace, repo, digest string,
) (cves []string, ok bool) {
	logger := log.FromContext(ctx).WithValues("crName", cr.Name)

	start := time.Now()
	scan, err := r.QuayClient.GetManifestSecurity(ctx, namespace, repo, digest, true)
	duration := time.Since(start).Seconds()

	if err != nil {
		metrics.RecordQuayRequest("error", "security", duration)
		logger.V(1).Info("failed to query Quay security scan", "error", err)
		return nil, false
	}

	metrics.RecordQuayRequest("success", "security", duration)

	quayData := ensureQuayData(cr)

	// The request succeeded, so this helper owns the scan fields from here on:
	// a scan that reports nothing clears whatever an earlier cycle recorded.
	quayData.SecurityScanStatus = ""
	quayData.Vulnerabilities = nil
	quayData.TotalVulnerabilities = 0
	quayData.FixableVulnerabilities = 0

	if scan == nil {
		return nil, true
	}
	quayData.SecurityScanStatus = scan.Status

	if scan.Data == nil || scan.Data.Layer == nil {
		return nil, true
	}

	var critical, important, moderate, low, total, fixable int
	for i := range scan.Data.Layer.Features {
		for j := range scan.Data.Layer.Features[i].Vulnerabilities {
			vuln := &scan.Data.Layer.Features[i].Vulnerabilities[j]
			total++
			if vuln.FixedBy != "" {
				fixable++
			}

			switch vuln.Severity {
			case "Critical":
				critical++
				cves = append(cves, vuln.Name)
			case "High":
				important++
				// High vulnerabilities are named too: the Pyxis path writes every
				// CVE it is given, and an annotation that means different things
				// per registry is worse than no annotation.
				cves = append(cves, vuln.Name)
			case "Medium":
				moderate++
			case "Low":
				low++
			}
		}
	}

	quayData.Vulnerabilities = &securityv1alpha1.VulnerabilitySummary{
		Critical:  critical,
		Important: important,
		Moderate:  moderate,
		Low:       low,
	}
	quayData.TotalVulnerabilities = total
	quayData.FixableVulnerabilities = fixable

	return cves, true
}

// enrichQuayManifest applies the manifest metadata. ok is false only when the
// request itself failed.
func (r *PodReconciler) enrichQuayManifest(
	ctx context.Context, cr *securityv1alpha1.ImageCertificationInfo, namespace, repo, digest string,
) (ok bool) {
	logger := log.FromContext(ctx).WithValues("crName", cr.Name)

	start := time.Now()
	manifest, err := r.QuayClient.GetManifest(ctx, namespace, repo, digest)
	duration := time.Since(start).Seconds()

	if err != nil {
		metrics.RecordQuayRequest("error", "manifest", duration)
		logger.V(1).Info("failed to query Quay manifest", "error", err)
		return false
	}

	metrics.RecordQuayRequest("success", "manifest", duration)

	quayData := ensureQuayData(cr)

	// A successful request that carries no manifest clears the previous values.
	quayData.LayerCount = 0
	quayData.CompressedSizeBytes = 0
	quayData.IsManifestList = false

	if manifest == nil {
		return true
	}

	quayData.LayerCount = len(manifest.Layers)
	quayData.CompressedSizeBytes = manifest.LayersCompressedSize
	quayData.IsManifestList = manifest.IsManifestList

	return true
}

var quayLabelKeys = map[string]func(*securityv1alpha1.QuayData, string){
	"vendor":                   func(q *securityv1alpha1.QuayData, v string) { q.Vendor = v },
	"architecture":             func(q *securityv1alpha1.QuayData, v string) { q.Architecture = v },
	"build-date":               func(q *securityv1alpha1.QuayData, v string) { q.BuildDate = v },
	"com.redhat.license_terms": func(q *securityv1alpha1.QuayData, v string) { q.LicenseURL = v },
	"vcs-ref":                  func(q *securityv1alpha1.QuayData, v string) { q.VCSRef = v },
}

// enrichQuayLabels applies the OCI labels Quay knows about. ok is false only
// when the request itself failed.
func (r *PodReconciler) enrichQuayLabels(
	ctx context.Context, cr *securityv1alpha1.ImageCertificationInfo, namespace, repo, digest string,
) (ok bool) {
	logger := log.FromContext(ctx).WithValues("crName", cr.Name)

	start := time.Now()
	labels, err := r.QuayClient.GetManifestLabels(ctx, namespace, repo, digest)
	duration := time.Since(start).Seconds()

	if err != nil {
		metrics.RecordQuayRequest("error", "labels", duration)
		logger.V(1).Info("failed to query Quay manifest labels", "error", err)
		return false
	}

	metrics.RecordQuayRequest("success", "labels", duration)

	quayData := ensureQuayData(cr)

	// Reset first: a label the manifest no longer carries must not survive.
	quayData.Vendor = ""
	quayData.Architecture = ""
	quayData.BuildDate = ""
	quayData.LicenseURL = ""
	quayData.VCSRef = ""

	if labels == nil {
		return true
	}

	for i := range labels.Labels {
		if setter, ok := quayLabelKeys[labels.Labels[i].Key]; ok {
			setter(quayData, labels.Labels[i].Value)
		}
	}

	return true
}

// appendQuayEnrichmentFailures appends one error per supplementary Quay call
// that failed. The helpers log the cause; this only carries the retry signal
// back to the caller so a successful repository lookup is not thrown away.
func appendQuayEnrichmentFailures(errs []error, crName string, securityOK, manifestOK, labelsOK bool) []error {
	if !securityOK {
		errs = append(errs, fmt.Errorf("quay security enrichment failed for %s", crName))
	}
	if !manifestOK {
		errs = append(errs, fmt.Errorf("quay manifest enrichment failed for %s", crName))
	}
	if !labelsOK {
		errs = append(errs, fmt.Errorf("quay labels enrichment failed for %s", crName))
	}

	return errs
}

// SetupWithManager sets up the controller with the Manager
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Named("pod").
		WithEventFilter(podDiscoveryPredicate()).
		Complete(r)
}

// podDiscoveryPredicate admits only the pod events that can change image
// discovery: creation, deletion, and updates that alter the phase or the set of
// container image IDs. Everything else is routine kubelet status churn.
func podDiscoveryPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return true },
		DeleteFunc:  func(event.DeleteEvent) bool { return true },
		GenericFunc: func(event.GenericEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPod, oldOK := e.ObjectOld.(*corev1.Pod)
			newPod, newOK := e.ObjectNew.(*corev1.Pod)
			if !oldOK || !newOK {
				return true
			}

			return podImageSetChanged(oldPod, newPod)
		},
	}
}

// podImageSetChanged reports whether the pod phase or the set of container
// image IDs differs between two versions of a pod.
func podImageSetChanged(oldPod, newPod *corev1.Pod) bool {
	if oldPod.Status.Phase != newPod.Status.Phase {
		return true
	}

	return !slices.Equal(podImageIDs(oldPod), podImageIDs(newPod))
}

// podImageIDs returns the sorted image IDs reported by the pod's containers.
func podImageIDs(pod *corev1.Pod) []string {
	ids := make([]string, 0, len(pod.Status.ContainerStatuses))
	for _, status := range pod.Status.ContainerStatuses {
		ids = append(ids, status.ImageID)
	}
	slices.Sort(ids)

	return ids
}

// RecomputeInventoryMetrics refreshes the image inventory gauges from the
// current set of ImageCertificationInfo resources. The list is served from the
// informer cache, so calling it on every cleanup and refresh cycle is cheap.
func (r *PodReconciler) RecomputeInventoryMetrics(ctx context.Context) {
	var crList securityv1alpha1.ImageCertificationInfoList
	if err := r.List(ctx, &crList); err != nil {
		log.FromContext(ctx).Error(err, "failed to list ImageCertificationInfo for inventory metrics")
		return
	}

	metrics.UpdateInventory(crList.Items)
}

// CleanupStaleReferences removes pod references for pods that no longer exist
// This should be called periodically
func (r *PodReconciler) CleanupStaleReferences(ctx context.Context) error {
	logger := log.FromContext(ctx)

	// List all ImageCertificationInfo resources
	var crList securityv1alpha1.ImageCertificationInfoList
	if err := r.List(ctx, &crList); err != nil {
		return err
	}

	for i := range crList.Items {
		cr := &crList.Items[i]
		var validRefs []securityv1alpha1.PodReference

		for _, podRef := range cr.Status.PodReferences {
			// Check if pod still exists
			var pod corev1.Pod
			err := r.Get(ctx, client.ObjectKey{
				Namespace: podRef.Namespace,
				Name:      podRef.Name,
			}, &pod)

			if err == nil {
				// Pod exists, keep the reference
				validRefs = append(validRefs, podRef)
			} else if !apierrors.IsNotFound(err) {
				// Error other than not found, keep the reference to be safe
				validRefs = append(validRefs, podRef)
				logger.Error(err, "error checking pod existence", "namespace", podRef.Namespace, "name", podRef.Name)
			}
			// If not found, the reference is stale and won't be kept
		}

		if len(validRefs) != len(cr.Status.PodReferences) {
			if err := r.updateCRStatus(ctx, cr.Name, func(latest *securityv1alpha1.ImageCertificationInfo) {
				latest.Status.PodReferences = validRefs
			}); err != nil {
				logger.Error(err, "failed to update stale references", "name", cr.Name)
			}
		}
	}

	r.RecomputeInventoryMetrics(ctx)

	return nil
}

// StartCleanupLoop runs CleanupStaleReferences every interval until ctx is
// cancelled. It blocks, so it can be registered as a manager Runnable: the
// manager then starts it only on the leader and cancels it on shutdown.
func (r *PodReconciler) StartCleanupLoop(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.CleanupStaleReferences(ctx); err != nil {
				log.FromContext(ctx).Error(err, "failed to cleanup stale references")
			}
		}
	}
}

// StartRefreshLoop runs RefreshAllImages every interval until ctx is cancelled.
// It blocks, so it can be registered as a manager Runnable: the manager then
// starts it only on the leader and cancels it on shutdown.
func (r *PodReconciler) StartRefreshLoop(ctx context.Context, interval time.Duration) error {
	logger := log.FromContext(ctx).WithName("refresh-loop")

	// Random startup delay (0-5 minutes) to avoid thundering herd
	startupDelay := time.Duration(rand.Int63n(int64(5 * time.Minute))) //nolint:gosec
	logger.Info("refresh loop starting with delay", "delay", startupDelay)
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(startupDelay):
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately after startup delay
	if err := r.RefreshAllImages(ctx); err != nil {
		logger.Error(err, "failed to refresh images")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.RefreshAllImages(ctx); err != nil {
				logger.Error(err, "failed to refresh images")
			}
		}
	}
}

// SetupEnrichmentWorkers creates the enrichment queue and registers the worker
// pool with the manager. As a plain Runnable the pool runs only on the leader,
// which matches the controller that feeds it.
func (r *PodReconciler) SetupEnrichmentWorkers(mgr ctrl.Manager, workers int) error {
	if workers <= 0 {
		workers = DefaultEnrichmentWorkers
	}
	r.EnrichQueue = newEnrichQueue()

	return mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		r.runEnrichmentWorkers(ctx, workers)

		return nil
	}))
}

// newEnrichQueue builds the work queue shared by the enrichment workers.
func newEnrichQueue() workqueue.TypedRateLimitingInterface[enrichRequest] {
	return workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[enrichRequest]())
}

// runEnrichmentWorkers drains the enrichment queue with the given number of
// workers until ctx is cancelled. It returns after every worker has exited.
func (r *PodReconciler) runEnrichmentWorkers(ctx context.Context, workers int) {
	var wg sync.WaitGroup

	for range workers {
		wg.Go(func() {
			r.enrichmentWorker(ctx)
		})
	}

	<-ctx.Done()
	// ShutDown wakes blocked workers; without it Get would block forever and
	// the manager would wait out its shutdown timeout.
	r.EnrichQueue.ShutDown()
	wg.Wait()
}

// enrichmentWorker processes requests until the queue is shut down.
func (r *PodReconciler) enrichmentWorker(ctx context.Context) {
	for {
		item, shutdown := r.EnrichQueue.Get()
		if shutdown {
			return
		}

		r.processEnrichRequest(ctx, item)
		r.EnrichQueue.Done(item)
	}
}

// permanentError marks an enrichment failure that retrying cannot fix, such as
// an authorization denial. The worker forgets these instead of spending the
// backoff on them.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// isQuayDenied reports whether err is an authorization answer from Quay.
func isQuayDenied(err error) bool {
	return quaylib.IsUnauthorized(err) || quaylib.IsForbidden(err)
}

// classifyQuayError marks an authorization answer as permanent. Quay returns
// 401/403 for repositories the token may not see, including repositories that
// no longer exist, so backing off and trying again cannot change the answer.
func classifyQuayError(err error) error {
	if isQuayDenied(err) {
		return &permanentError{err: err}
	}

	return err
}

// processEnrichRequest enriches one image once and decides whether to retry it.
// Retries use the queue's exponential backoff so a transient API failure is
// retried within seconds instead of waiting for the 24h refresh cycle.
func (r *PodReconciler) processEnrichRequest(ctx context.Context, item enrichRequest) {
	err := r.enrich(ctx, item)
	if err == nil {
		r.EnrichQueue.Forget(item)

		return
	}

	logger := log.FromContext(ctx).WithValues("crName", item.crName)

	// Do not requeue work the manager cancelled; the queue is shutting down.
	if ctx.Err() != nil {
		r.EnrichQueue.Forget(item)

		return
	}

	if _, ok := errors.AsType[*permanentError](err); ok {
		logger.Info("not retrying image enrichment after a permanent failure", "error", err)
		r.EnrichQueue.Forget(item)

		return
	}

	if requeues := r.EnrichQueue.NumRequeues(item); requeues >= maxEnrichmentRetries {
		logger.Error(err, "giving up on image enrichment after retries", "requeues", requeues)
		r.EnrichQueue.Forget(item)

		return
	}

	logger.Error(err, "image enrichment failed, retrying with backoff")
	r.EnrichQueue.AddRateLimited(item)
}

// enrich dispatches a request to the client that serves the image's registry.
func (r *PodReconciler) enrich(ctx context.Context, item enrichRequest) error {
	switch {
	case r.PyxisClient != nil && image.IsRedHatRegistry(item.ref.Registry):
		return r.checkPyxisCertification(ctx, item.crName, &item.ref)
	case r.DockerHubClient != nil && item.ref.Registry == RegistryDockerHub:
		return r.checkDockerHubData(ctx, item.crName, &item.ref)
	case r.QuayClient != nil && item.ref.Registry == RegistryQuayIO:
		return r.checkQuayData(ctx, item.crName, &item.ref)
	default:
		return nil
	}
}

// RefreshAllImages refreshes certification data for all Red Hat registry images
func (r *PodReconciler) RefreshAllImages(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("refresh")
	start := time.Now()

	// List all ImageCertificationInfo resources
	var crList securityv1alpha1.ImageCertificationInfoList
	if err := r.List(ctx, &crList); err != nil {
		return err
	}

	refreshed := 0
	skipped := 0
	errorCount := 0

	for i := range crList.Items {
		cr := &crList.Items[i]

		// Determine which API to use based on stored registry type
		isRedHatRegistry := cr.Status.RegistryType == securityv1alpha1.RegistryTypeRedHat
		isDockerHub := cr.Spec.Registry == RegistryDockerHub
		isQuayIO := cr.Spec.Registry == RegistryQuayIO

		// Skip if no enrichment is possible
		if !isRedHatRegistry && !isDockerHub && !isQuayIO {
			skipped++
			continue
		}

		// Skip if checked within the last hour (staggering)
		if cr.Status.LastPyxisCheckAt != nil && isRedHatRegistry {
			if time.Since(cr.Status.LastPyxisCheckAt.Time) < time.Hour {
				skipped++
				continue
			}
		}

		// Refresh single image with delay between requests (staggering)
		if err := r.refreshSingleImage(ctx, cr); err != nil {
			logger.Error(err, "failed to refresh image", "name", cr.Name)
			errorCount++
		} else {
			refreshed++
		}

		// 100ms delay between refreshes to avoid API overload
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	duration := time.Since(start)
	metrics.RecordRefreshCycle(duration.Seconds())

	logger.Info("refresh cycle completed",
		"duration", duration,
		"refreshed", refreshed,
		"skipped", skipped,
		"errors", errorCount,
		"total", len(crList.Items))

	r.RecomputeInventoryMetrics(ctx)

	return nil
}

// refreshSingleImage refreshes certification data for a single ImageCertificationInfo
func (r *PodReconciler) refreshSingleImage(ctx context.Context, cr *securityv1alpha1.ImageCertificationInfo) error {
	logger := log.FromContext(ctx).WithValues("crName", cr.Name)

	// Re-fetch CR to get latest version (avoid conflicts)
	var latestCR securityv1alpha1.ImageCertificationInfo
	if err := r.Get(ctx, client.ObjectKey{Name: cr.Name}, &latestCR); err != nil {
		return err
	}

	// Store old values for change detection
	oldSnapshot := snapshotImageState(&latestCR)

	// Track CVEs for annotation updates (only relevant for Pyxis)
	var cves []string
	// clearCVEs marks that the refresh found no CVE data, so an annotation from
	// an earlier cycle has to be removed.
	var clearCVEs bool
	// enrichErrs collects supplementary enrichment failures. They are returned
	// only after the status write so the data that did succeed is persisted.
	var enrichErrs []error

	// Refresh based on registry type
	if image.IsRedHatRegistry(cr.Spec.Registry) && r.PyxisClient != nil {
		// Query Pyxis for Red Hat registry images
		certData, err := r.PyxisClient.GetImageCertification(ctx, cr.Spec.Registry, cr.Spec.Repository, cr.Spec.ImageDigest)
		if err != nil {
			logger.Error(err, "failed to query Pyxis API during refresh")
			return err
		}

		now := metav1.Now()
		latestCR.Status.LastPyxisCheckAt = &now

		if certData == nil {
			// No certification data any more: clear the payload so the CR does not
			// keep advertising an EOL date and vulnerability counts that Pyxis has
			// stopped returning.
			latestCR.Status.CertificationStatus = securityv1alpha1.CertificationStatusNotCertified
			clearPyxisStatus(&latestCR)
			clearCVEs = true
		} else {
			r.updateCRWithPyxisData(&latestCR, certData)
			cves = certData.CVEs
			clearCVEs = len(cves) == 0
		}
	} else if cr.Spec.Registry == RegistryDockerHub && r.DockerHubClient != nil {
		// Query Docker Hub for docker.io images
		namespace, repo := parseDockerHubRepo(cr.Spec.Repository)
		repoInfo, err := r.DockerHubClient.GetRepositoryInfo(ctx, namespace, repo)
		if err != nil {
			logger.Error(err, "failed to query Docker Hub API during refresh")
			return err
		}

		if repoInfo != nil {
			r.updateCRWithDockerHubData(&latestCR, repoInfo)
		} else {
			// Docker Hub answered successfully but no longer knows this
			// repository, so the previous payload is stale.
			clearDockerHubStatus(&latestCR)
		}
	} else if cr.Spec.Registry == RegistryQuayIO && r.QuayClient != nil {
		namespace, repo := parseQuayRepo(cr.Spec.Repository)
		repoInfo, err := r.QuayClient.GetRepository(ctx, namespace, repo)
		if err != nil {
			if isQuayDenied(err) {
				logger.Info("Quay denied access to the repository; keeping the previous enrichment", "error", err)
			} else {
				logger.Error(err, "failed to query Quay.io API during refresh")
			}

			return classifyQuayError(err)
		}

		r.updateCRWithQuayData(&latestCR, &repoInfo)

		if cr.Spec.ImageDigest != "" {
			var scanOK, manifestOK, labelsOK bool
			cves, scanOK = r.enrichQuaySecurity(ctx, &latestCR, namespace, repo, cr.Spec.ImageDigest)
			manifestOK = r.enrichQuayManifest(ctx, &latestCR, namespace, repo, cr.Spec.ImageDigest)
			labelsOK = r.enrichQuayLabels(ctx, &latestCR, namespace, repo, cr.Spec.ImageDigest)
			enrichErrs = appendQuayEnrichmentFailures(enrichErrs, cr.Name, scanOK, manifestOK, labelsOK)
			// Only a successful scan may retire an annotation; a failed one
			// leaves the previous list in place.
			clearCVEs = scanOK && len(cves) == 0
		}
	} else {
		// No client available for this registry
		return nil
	}

	if err := r.Status().Update(ctx, &latestCR); err != nil {
		logger.Error(err, "failed to update ImageCertificationInfo during refresh")
		return err
	}

	// Update or clear CVE annotations
	if clearCVEs {
		if err := r.clearCVEAnnotation(ctx, latestCR.Name); err != nil {
			logger.Error(err, "failed to clear CVE annotations during refresh")
		}
	} else if len(cves) > 0 {
		if err := r.updateCVEAnnotations(ctx, latestCR.Name, cves); err != nil {
			logger.Error(err, "failed to update CVE annotations during refresh")
		}
	}

	metrics.RecordImageRefreshed()

	// Emit change events
	newSnapshot := snapshotImageState(&latestCR)
	r.emitChangeEvents(&latestCR, oldSnapshot, newSnapshot)

	return errors.Join(enrichErrs...)
}

// updateCRWithPyxisData updates a CR's status with data from Pyxis
func (r *PodReconciler) updateCRWithPyxisData(cr *securityv1alpha1.ImageCertificationInfo, certData *pyxis.CertificationData) {
	cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusCertified

	// Drop the derived scalars before recomputing them: they are only assigned
	// when the source timestamp exists, so a value Pyxis stops publishing would
	// otherwise survive forever.
	cr.Status.ImageAge = ""
	cr.Status.DaysUntilEOL = nil

	cr.Status.PyxisData = &securityv1alpha1.PyxisData{
		ProjectID:   certData.ProjectID,
		Publisher:   certData.Publisher,
		HealthIndex: certData.HealthIndex,
		CatalogURL:  certData.CatalogURL,
	}

	// Parse and set PublishedAt timestamp
	if certData.PublishedAt != "" {
		if publishedTime, parseErr := time.Parse(time.RFC3339, certData.PublishedAt); parseErr == nil {
			publishedAt := metav1.NewTime(publishedTime)
			cr.Status.PyxisData.PublishedAt = &publishedAt
		}
	}

	if certData.Vulnerabilities != nil {
		cr.Status.PyxisData.Vulnerabilities = &securityv1alpha1.VulnerabilitySummary{
			Critical:  certData.Vulnerabilities.Critical,
			Important: certData.Vulnerabilities.Important,
			Moderate:  certData.Vulnerabilities.Moderate,
			Low:       certData.Vulnerabilities.Low,
		}
	}

	// Lifecycle fields
	if certData.EOLDate != "" {
		if eolTime, parseErr := time.Parse(time.RFC3339, certData.EOLDate); parseErr == nil {
			eolDate := metav1.NewTime(eolTime)
			cr.Status.PyxisData.EOLDate = &eolDate
		} else if eolTime, parseErr := time.Parse("2006-01-02", certData.EOLDate); parseErr == nil {
			eolDate := metav1.NewTime(eolTime)
			cr.Status.PyxisData.EOLDate = &eolDate
		}
	}
	cr.Status.PyxisData.ReleaseCategory = certData.ReleaseCategory
	cr.Status.PyxisData.ReplacedBy = certData.ReplacedBy

	// Operational fields
	cr.Status.PyxisData.Architectures = certData.Architectures
	cr.Status.PyxisData.CompressedSizeBytes = certData.CompressedSizeBytes

	// Security fields
	cr.Status.PyxisData.AutoRebuildEnabled = certData.AutoRebuildEnabled

	// Enhanced fields for v0.2.0
	cr.Status.PyxisData.ArchitectureHealth = certData.ArchitectureHealth
	cr.Status.PyxisData.UncompressedSizeBytes = certData.UncompressedSizeBytes
	cr.Status.PyxisData.LayerCount = certData.LayerCount
	cr.Status.PyxisData.BuildDate = certData.BuildDate
	cr.Status.PyxisData.AdvisoryIDs = certData.AdvisoryIDs

	// Compute ImageAge if PublishedAt is available
	if cr.Status.PyxisData.PublishedAt != nil {
		age := time.Since(cr.Status.PyxisData.PublishedAt.Time)
		cr.Status.ImageAge = formatDuration(age)
	}

	// Compute DaysUntilEOL if EOLDate is available
	if cr.Status.PyxisData.EOLDate != nil {
		daysUntil := int(time.Until(cr.Status.PyxisData.EOLDate.Time).Hours() / 24)
		cr.Status.DaysUntilEOL = &daysUntil
	}
}

// clearPyxisStatus removes every Pyxis-derived field from a CR's status. A
// refresh that no longer returns certification data must not leave values from
// an earlier response behind, or consumers keep reporting a stale EOL date,
// health grade and vulnerability count.
func clearPyxisStatus(cr *securityv1alpha1.ImageCertificationInfo) {
	cr.Status.PyxisData = nil
	cr.Status.ImageAge = ""
	cr.Status.DaysUntilEOL = nil
}

// clearDockerHubStatus drops the Docker Hub payload when the repository is no
// longer known to Docker Hub. Only the certification states Docker Hub is
// responsible for are reset; a state set by another source is left alone.
func clearDockerHubStatus(cr *securityv1alpha1.ImageCertificationInfo) {
	cr.Status.DockerHubData = nil

	switch cr.Status.CertificationStatus {
	case securityv1alpha1.CertificationStatusOfficial,
		securityv1alpha1.CertificationStatusVerified,
		securityv1alpha1.CertificationStatusNotCertified:
		cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusUnknown
	}
}

// clearCVEAnnotation removes the CVE annotation when a refresh no longer has
// CVE data for the image. It lives in object metadata, so it needs its own
// write: a status subresource update does not touch annotations.
func (r *PodReconciler) clearCVEAnnotation(ctx context.Context, crName string) error {
	var cr securityv1alpha1.ImageCertificationInfo
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		return err
	}
	if _, ok := cr.Annotations[AnnotationCVEs]; !ok {
		return nil
	}

	// A merge patch deletes the key without carrying a resourceVersion, so it
	// cannot lose the race against the status write that precedes it. A cached
	// read keeps returning the pre-write version, which makes an Update conflict
	// on every attempt until the cache catches up.
	patch := client.RawPatch(types.MergePatchType,
		[]byte(fmt.Sprintf(`{"metadata":{"annotations":{%q:null}}}`, AnnotationCVEs)))

	return r.Patch(ctx, &cr, patch)
}

// MaxCVEAnnotationBytes bounds the joined CVE annotation. Kubernetes caps an
// object's whole metadata at 256 KiB, so 64 KiB leaves headroom for the other
// annotations and labels on the CR.
const MaxCVEAnnotationBytes = 64 * 1024

// cveTruncationSentinel prefixes the last element of a truncated CVE list, so a
// consumer can tell the list is incomplete and how many IDs were dropped.
const cveTruncationSentinel = "...truncated:"

// buildCVEAnnotation joins the CVE IDs into a single annotation value that
// stays within MaxCVEAnnotationBytes. It reports whether it had to truncate.
func buildCVEAnnotation(cves []string) (string, bool) {
	var b strings.Builder

	for i, cve := range cves {
		remaining := len(cves) - i
		// Reserve room for the sentinel element plus its separator.
		reserve := len(cveTruncationSentinel) + len(strconv.Itoa(remaining)) + 2
		if b.Len()+len(cve)+1+reserve > MaxCVEAnnotationBytes {
			return strings.TrimSuffix(b.String(), ",") +
				"," + cveTruncationSentinel + strconv.Itoa(remaining), true
		}
		b.WriteString(cve)
		b.WriteString(",")
	}

	return strings.TrimSuffix(b.String(), ","), false
}

// updateCVEAnnotations updates the CVE annotation on a CR
func (r *PodReconciler) updateCVEAnnotations(ctx context.Context, crName string, cves []string) error {
	value, truncated := buildCVEAnnotation(cves)

	var cr securityv1alpha1.ImageCertificationInfo
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		return err
	}
	// Nothing to write when the list has not changed since the last refresh.
	if cr.Annotations[AnnotationCVEs] == value {
		return nil
	}

	log.FromContext(ctx).V(1).Info("updating CVE annotation",
		"crName", crName, "cves", len(cves), "bytes", len(value), "truncated", truncated)

	// A merge patch carries no resourceVersion, so it does not conflict with the
	// status write that precedes it in the same reconcile.
	patch := client.RawPatch(types.MergePatchType,
		[]byte(fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, AnnotationCVEs, value)))

	return r.Patch(ctx, &cr, patch)
}

// imageStateSnapshot captures the state of an image for change detection
type imageStateSnapshot struct {
	CertStatus     securityv1alpha1.CertificationStatus
	HealthGrade    string
	CriticalVulns  int
	ImportantVulns int
}

// snapshotImageState captures the current state of a CR for change comparison
func snapshotImageState(cr *securityv1alpha1.ImageCertificationInfo) imageStateSnapshot {
	s := imageStateSnapshot{CertStatus: cr.Status.CertificationStatus}
	if cr.Status.PyxisData != nil {
		s.HealthGrade = cr.Status.PyxisData.HealthIndex
		if cr.Status.PyxisData.Vulnerabilities != nil {
			s.CriticalVulns = cr.Status.PyxisData.Vulnerabilities.Critical
			s.ImportantVulns = cr.Status.PyxisData.Vulnerabilities.Important
		}
	}
	if cr.Status.QuayData != nil && cr.Status.QuayData.Vulnerabilities != nil {
		s.CriticalVulns += cr.Status.QuayData.Vulnerabilities.Critical
		s.ImportantVulns += cr.Status.QuayData.Vulnerabilities.Important
	}
	return s
}

// emitChangeEvents emits Kubernetes events when certification status, health, or vulnerabilities change
func (r *PodReconciler) emitChangeEvents(cr *securityv1alpha1.ImageCertificationInfo, old, new imageStateSnapshot) {
	if r.Recorder == nil {
		return
	}

	// Certification status changed
	if old.CertStatus != new.CertStatus && old.CertStatus != "" {
		msg := fmt.Sprintf("Certification status changed from %s to %s", old.CertStatus, new.CertStatus)
		r.Recorder.Event(cr, corev1.EventTypeWarning, EventReasonCertificationChanged, msg)
		metrics.RecordEvent(corev1.EventTypeWarning, EventReasonCertificationChanged)
		metrics.RecordCertificationStatusChange(string(old.CertStatus), string(new.CertStatus))
	}

	// Health grade degraded
	if old.HealthGrade != "" && new.HealthGrade != "" && isHealthDegraded(old.HealthGrade, new.HealthGrade) {
		msg := fmt.Sprintf("Health grade degraded from %s to %s", old.HealthGrade, new.HealthGrade)
		r.Recorder.Event(cr, corev1.EventTypeWarning, EventReasonHealthDegraded, msg)
		metrics.RecordEvent(corev1.EventTypeWarning, EventReasonHealthDegraded)
	}

	// New critical/important vulnerabilities
	if new.CriticalVulns > old.CriticalVulns || new.ImportantVulns > old.ImportantVulns {
		msg := fmt.Sprintf("Vulnerabilities increased: critical %d→%d, important %d→%d",
			old.CriticalVulns, new.CriticalVulns, old.ImportantVulns, new.ImportantVulns)
		r.Recorder.Event(cr, corev1.EventTypeWarning, EventReasonVulnerabilitiesFound, msg)
		metrics.RecordEvent(corev1.EventTypeWarning, EventReasonVulnerabilitiesFound)
	}
}

// isHealthDegraded compares health grades and returns true if the new grade is worse
// Health grades are A > B > C > D > F
func isHealthDegraded(oldGrade, newGrade string) bool {
	oldVal, oldOk := gradeOrder[oldGrade]
	newVal, newOk := gradeOrder[newGrade]

	if !oldOk || !newOk {
		return false
	}

	return newVal < oldVal
}

// formatDuration formats a duration into a human-readable string (e.g., "45 days", "3 months")
func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days < 1 {
		return "less than a day"
	}
	if days == 1 {
		return "1 day"
	}
	if days < 30 {
		return fmt.Sprintf("%d days", days)
	}
	months := days / 30
	if months == 1 {
		return "1 month"
	}
	if months < 12 {
		return fmt.Sprintf("%d months", months)
	}
	years := months / 12
	remainingMonths := months % 12
	if years == 1 {
		if remainingMonths == 0 {
			return "1 year"
		}
		return fmt.Sprintf("1 year %d months", remainingMonths)
	}
	if remainingMonths == 0 {
		return fmt.Sprintf("%d years", years)
	}
	return fmt.Sprintf("%d years %d months", years, remainingMonths)
}
