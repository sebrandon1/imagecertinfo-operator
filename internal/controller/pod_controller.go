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
	"fmt"
	"math/rand"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/sebrandon1/imagecertinfo-operator/api/v1alpha1"
	"github.com/sebrandon1/imagecertinfo-operator/internal/metrics"
	"github.com/sebrandon1/imagecertinfo-operator/internal/version"
	"github.com/sebrandon1/imagecertinfo-operator/pkg/dockerhub"
	"github.com/sebrandon1/imagecertinfo-operator/pkg/image"
	"github.com/sebrandon1/imagecertinfo-operator/pkg/pyxis"
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

// gradeOrder maps health grades to numeric values for comparison
var gradeOrder = map[string]int{"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}

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
	Recorder        record.EventRecorder
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
				continue
			}
			logger.Info("created ImageCertificationInfo", "name", crName, "registry", ref.Registry)
		} else if err != nil {
			logger.Error(err, "failed to get ImageCertificationInfo", "name", crName)
			continue
		} else {
			// Update existing CR with new pod reference
			if err := r.updatePodReferences(ctx, &existingCR, podRef); err != nil {
				logger.Error(err, "failed to update ImageCertificationInfo", "name", crName)
				continue
			}
		}
	}

	metrics.RecordReconcile("success", time.Since(start).Seconds(), "pod")
	return ctrl.Result{}, nil
}

// createImageCertificationInfo creates a new ImageCertificationInfo resource
func (r *PodReconciler) createImageCertificationInfo(ctx context.Context, ref *image.Reference, crName string, podRef securityv1alpha1.PodReference) error {
	now := metav1.Now()
	registryType := image.ClassifyRegistry(ref.Registry)

	cr := &securityv1alpha1.ImageCertificationInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crName,
			Labels: map[string]string{
				LabelDigest:          digestLabel(ref.Digest),
				LabelOperatorVersion: version.Version,
			},
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
		return err
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

	if err := r.Status().Update(ctx, cr); err != nil {
		return err
	}

	// Emit event and record metrics
	metrics.ImagesDiscovered.Inc()
	if r.Recorder != nil {
		r.Recorder.Event(cr, corev1.EventTypeNormal, EventReasonImageDiscovered,
			fmt.Sprintf("Discovered image %s", ref.FullReference))
		metrics.RecordEvent(corev1.EventTypeNormal, EventReasonImageDiscovered)
	}

	// If Pyxis client is available and this is a Red Hat registry, check certification
	if r.PyxisClient != nil && image.IsRedHatRegistry(ref.Registry) {
		go r.checkPyxisCertification(context.Background(), cr.Name, ref)
	}

	// If Docker Hub client is available and this is docker.io, enrich with Docker Hub data
	if r.DockerHubClient != nil && ref.Registry == RegistryDockerHub {
		go r.checkDockerHubData(context.Background(), cr.Name, ref)
	}

	return nil
}

// updatePodReferences updates the pod references in an existing ImageCertificationInfo
func (r *PodReconciler) updatePodReferences(ctx context.Context, cr *securityv1alpha1.ImageCertificationInfo, podRef securityv1alpha1.PodReference) error {
	now := metav1.Now()

	if cr.Labels[LabelOperatorVersion] != version.Version {
		if cr.Labels == nil {
			cr.Labels = make(map[string]string)
		}
		cr.Labels[LabelOperatorVersion] = version.Version
		if err := r.Update(ctx, cr); err != nil {
			return err
		}
	}

	// Check if this pod reference already exists
	for _, existing := range cr.Status.PodReferences {
		if existing.Namespace == podRef.Namespace &&
			existing.Name == podRef.Name &&
			existing.Container == podRef.Container {
			// Already tracked, just update LastSeenAt
			cr.Status.LastSeenAt = &now
			return r.Status().Update(ctx, cr)
		}
	}

	// Add new pod reference
	cr.Status.PodReferences = append(cr.Status.PodReferences, podRef)
	cr.Status.LastSeenAt = &now

	return r.Status().Update(ctx, cr)
}

// checkPyxisCertification queries the Pyxis API for certification data
func (r *PodReconciler) checkPyxisCertification(ctx context.Context, crName string, ref *image.Reference) {
	logger := log.FromContext(ctx).WithValues("crName", crName)

	if r.PyxisClient == nil {
		return
	}

	// Query Pyxis
	certData, err := r.PyxisClient.GetImageCertification(ctx, ref.Registry, ref.Repository, ref.Digest)
	if err != nil {
		logger.Error(err, "failed to query Pyxis API")
		// Still try to update status to reflect the error
		var cr securityv1alpha1.ImageCertificationInfo
		if getErr := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); getErr != nil {
			logger.Error(getErr, "failed to get ImageCertificationInfo for Pyxis error update")
			return
		}
		now := metav1.Now()
		cr.Status.LastPyxisCheckAt = &now
		cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusError
		if updateErr := r.Status().Update(ctx, &cr); updateErr != nil {
			logger.Error(updateErr, "failed to update status after Pyxis error")
		}
		return
	}

	// Fetch the latest version of the CR
	var cr securityv1alpha1.ImageCertificationInfo
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		logger.Error(err, "failed to get ImageCertificationInfo for Pyxis update")
		return
	}

	now := metav1.Now()
	cr.Status.LastPyxisCheckAt = &now

	if certData == nil {
		// No certification data found
		cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusNotCertified
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
	}

	// Update CVE annotations separately (after status update)
	if certData != nil && len(certData.CVEs) > 0 {
		if updateErr := r.updateCVEAnnotations(ctx, crName, certData.CVEs); updateErr != nil {
			logger.Error(updateErr, "failed to update CVE annotations")
		}
	}
}

// checkDockerHubData queries the Docker Hub API for repository metadata
func (r *PodReconciler) checkDockerHubData(ctx context.Context, crName string, ref *image.Reference) {
	logger := log.FromContext(ctx).WithValues("crName", crName)

	if r.DockerHubClient == nil {
		return
	}

	// Parse namespace and repository from the repository path
	// For official images: library/nginx -> namespace=library, repo=nginx
	// For user images: bitnami/redis -> namespace=bitnami, repo=redis
	namespace, repo := parseDockerHubRepo(ref.Repository)

	// Query Docker Hub
	repoInfo, err := r.DockerHubClient.GetRepositoryInfo(ctx, namespace, repo)
	if err != nil {
		logger.Error(err, "failed to query Docker Hub API")
		return
	}

	// Fetch the latest version of the CR
	var cr securityv1alpha1.ImageCertificationInfo
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		logger.Error(err, "failed to get ImageCertificationInfo for Docker Hub update")
		return
	}

	if repoInfo == nil {
		// No data found
		return
	}

	// Update CR with Docker Hub data
	r.updateCRWithDockerHubData(&cr, repoInfo)

	// Update status
	if err := r.Status().Update(ctx, &cr); err != nil {
		logger.Error(err, "failed to update ImageCertificationInfo with Docker Hub data")
	}
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

// SetupWithManager sets up the controller with the Manager
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Named("pod").
		Complete(r)
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
			cr.Status.PodReferences = validRefs
			if err := r.Status().Update(ctx, cr); err != nil {
				logger.Error(err, "failed to update stale references", "name", cr.Name)
			}
		}
	}

	return nil
}

// StartCleanupLoop starts a goroutine that periodically cleans up stale pod references
func (r *PodReconciler) StartCleanupLoop(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := r.CleanupStaleReferences(ctx); err != nil {
					log.FromContext(ctx).Error(err, "failed to cleanup stale references")
				}
			}
		}
	}()
}

// StartRefreshLoop starts a goroutine that periodically refreshes all ImageCertificationInfo resources
func (r *PodReconciler) StartRefreshLoop(ctx context.Context, interval time.Duration) {
	go func() {
		logger := log.FromContext(ctx).WithName("refresh-loop")

		// Random startup delay (0-5 minutes) to avoid thundering herd
		startupDelay := time.Duration(rand.Int63n(int64(5 * time.Minute))) //nolint:gosec
		logger.Info("refresh loop starting with delay", "delay", startupDelay)
		select {
		case <-ctx.Done():
			return
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
				return
			case <-ticker.C:
				if err := r.RefreshAllImages(ctx); err != nil {
					logger.Error(err, "failed to refresh images")
				}
			}
		}
	}()
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
	errors := 0

	for i := range crList.Items {
		cr := &crList.Items[i]

		// Determine which API to use based on stored registry type
		isRedHatRegistry := cr.Status.RegistryType == securityv1alpha1.RegistryTypeRedHat
		isDockerHub := cr.Spec.Registry == RegistryDockerHub

		// Skip if no enrichment is possible
		if !isRedHatRegistry && !isDockerHub {
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
			errors++
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
		"errors", errors,
		"total", len(crList.Items))

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
			latestCR.Status.CertificationStatus = securityv1alpha1.CertificationStatusNotCertified
		} else {
			r.updateCRWithPyxisData(&latestCR, certData)
			cves = certData.CVEs
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
		}
	} else {
		// No client available for this registry
		return nil
	}

	if err := r.Status().Update(ctx, &latestCR); err != nil {
		logger.Error(err, "failed to update ImageCertificationInfo during refresh")
		return err
	}

	// Update CVE annotations if available
	if len(cves) > 0 {
		if err := r.updateCVEAnnotations(ctx, latestCR.Name, cves); err != nil {
			logger.Error(err, "failed to update CVE annotations during refresh")
		}
	}

	metrics.RecordImageRefreshed()

	// Emit change events
	newSnapshot := snapshotImageState(&latestCR)
	r.emitChangeEvents(&latestCR, oldSnapshot, newSnapshot)

	return nil
}

// updateCRWithPyxisData updates a CR's status with data from Pyxis
func (r *PodReconciler) updateCRWithPyxisData(cr *securityv1alpha1.ImageCertificationInfo, certData *pyxis.CertificationData) {
	cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusCertified
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

// updateCVEAnnotations updates the CVE annotation on a CR
func (r *PodReconciler) updateCVEAnnotations(ctx context.Context, crName string, cves []string) error {
	var cr securityv1alpha1.ImageCertificationInfo
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		return err
	}
	if cr.Annotations == nil {
		cr.Annotations = make(map[string]string)
	}
	cr.Annotations[AnnotationCVEs] = strings.Join(cves, ",")
	return r.Update(ctx, &cr)
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
