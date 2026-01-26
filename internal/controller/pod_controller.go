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

// PodReconciler reconciles a Pod object and creates/updates ImageCertificationInfo resources
type PodReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	PyxisClient pyxis.Client
	Recorder    record.EventRecorder
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
	allStatuses := append(pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses...)

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

	return nil
}

// updatePodReferences updates the pod references in an existing ImageCertificationInfo
func (r *PodReconciler) updatePodReferences(ctx context.Context, cr *securityv1alpha1.ImageCertificationInfo, podRef securityv1alpha1.PodReference) error {
	now := metav1.Now()

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

	// Fetch the latest version of the CR
	var cr securityv1alpha1.ImageCertificationInfo
	if err := r.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		logger.Error(err, "failed to get ImageCertificationInfo for Pyxis update")
		return
	}

	now := metav1.Now()
	cr.Status.LastPyxisCheckAt = &now

	if err != nil {
		logger.Error(err, "failed to query Pyxis API")
		cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusError
		updateErr := r.Status().Update(ctx, &cr)
		if updateErr != nil {
			logger.Error(updateErr, "failed to update status after Pyxis error")
		}
		return
	}

	if certData == nil {
		// No certification data found
		cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusNotCertified
	} else {
		// Update with certification data
		cr.Status.CertificationStatus = securityv1alpha1.CertificationStatusCertified
		cr.Status.PyxisData = &securityv1alpha1.PyxisData{
			ProjectID:   certData.ProjectID,
			Publisher:   certData.Publisher,
			HealthIndex: certData.HealthIndex,
			CatalogURL:  certData.CatalogURL,
		}

		// Parse and set PublishedAt timestamp
		if certData.PublishedAt != "" {
			// Pyxis returns timestamps in ISO 8601 format
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
			// Parse EOL date (may be in different formats)
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

			// Emit event if EOL approaching (within 90 days)
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
		// Re-fetch CR to get current resourceVersion for object update
		var crForAnnotation securityv1alpha1.ImageCertificationInfo
		if fetchErr := r.Get(ctx, client.ObjectKey{Name: crName}, &crForAnnotation); fetchErr != nil {
			logger.Error(fetchErr, "failed to fetch CR for annotation update")
			return
		}
		if crForAnnotation.Annotations == nil {
			crForAnnotation.Annotations = make(map[string]string)
		}
		// Store CVEs as comma-separated list in annotation
		crForAnnotation.Annotations["security.telco.openshift.io/cves"] = strings.Join(certData.CVEs, ",")
		if updateErr := r.Update(ctx, &crForAnnotation); updateErr != nil {
			logger.Error(updateErr, "failed to update CVE annotations")
		}
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
