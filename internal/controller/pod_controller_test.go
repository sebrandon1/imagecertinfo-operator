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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/sebrandon1/imagecertinfo-operator/api/v1alpha1"
	"github.com/sebrandon1/imagecertinfo-operator/internal/version"
	"github.com/sebrandon1/imagecertinfo-operator/pkg/image"
	"github.com/sebrandon1/imagecertinfo-operator/pkg/pyxis"
)

const (
	testDigest      = "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
	testCRName      = "registry.redhat.io.ubi8.ubi.abc123de"
	testNamespace   = "default"
	testPodName     = "test-pod"
	testContainer   = "test-container"
	testRegistry    = "registry.redhat.io"
	testRepository  = "ubi8/ubi"
	testExistingPod = "existing-pod"
	testPublisher   = "Red Hat, Inc."
)

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = securityv1alpha1.AddToScheme(scheme)
	return scheme
}

func TestPodReconciler_Reconcile(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	// Create a test pod with container status
	testPod := &corev1.Pod{
		Name:      testPodName,
		Namespace: testNamespace,
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  testContainer,
					Image: "registry.redhat.io/ubi8/ubi:latest",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:    testContainer,
					ImageID: "docker-pullable://registry.redhat.io/ubi8/ubi@" + testDigest,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testPod).
		WithStatusSubresource(&securityv1alpha1.ImageCertificationInfo{}).
		Build()

	reconciler := &PodReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	// Reconcile the pod
	req := reconcile.Request{
		Name:      testPodName,
		Namespace: testNamespace,
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("Reconcile() returned RequeueAfter != 0, want 0")
	}

	// Verify ImageCertificationInfo was created
	// Expected name format: registry.redhat.io.ubi8.ubi.abc123de (first 8 chars of digest)
	var cr securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testCRName}, &cr); err != nil {
		t.Fatalf("Failed to get ImageCertificationInfo: %v", err)
	}

	// Verify spec fields
	if cr.Spec.ImageDigest != testDigest {
		t.Errorf("ImageDigest = %v, want %v", cr.Spec.ImageDigest, testDigest)
	}
	if cr.Spec.Registry != testRegistry {
		t.Errorf("Registry = %v, want registry.redhat.io", cr.Spec.Registry)
	}
	if cr.Spec.Repository != testRepository {
		t.Errorf("Repository = %v, want ubi8/ubi", cr.Spec.Repository)
	}

	// Verify status fields
	if cr.Status.RegistryType != securityv1alpha1.RegistryTypeRedHat {
		t.Errorf("RegistryType = %v, want %v", cr.Status.RegistryType, securityv1alpha1.RegistryTypeRedHat)
	}
	if len(cr.Status.PodReferences) != 1 {
		t.Fatalf("PodReferences count = %v, want 1", len(cr.Status.PodReferences))
	}
	if cr.Status.PodReferences[0].Name != testPodName {
		t.Errorf("PodReference.Name = %v, want %s", cr.Status.PodReferences[0].Name, testPodName)
	}
	if cr.Status.PodReferences[0].Namespace != testNamespace {
		t.Errorf("PodReference.Namespace = %v, want %s", cr.Status.PodReferences[0].Namespace, testNamespace)
	}
	if cr.Status.PodReferences[0].Container != testContainer {
		t.Errorf("PodReference.Container = %v, want %s", cr.Status.PodReferences[0].Container, testContainer)
	}

	// Verify digest label is set for external operator lookup
	wantDigestLabel := "sha256-" + strings.TrimPrefix(testDigest, "sha256:")[:16]
	if got := cr.Labels[LabelDigest]; got != wantDigestLabel {
		t.Errorf("Label %q = %q, want %q", LabelDigest, got, wantDigestLabel)
	}

	// Verify operator-version label is set
	if got := cr.Labels[LabelOperatorVersion]; got == "" {
		t.Error("Label LabelOperatorVersion is empty, want non-empty version string")
	}
}

func TestPodReconciler_Reconcile_ExistingCR(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	// Create existing ImageCertificationInfo
	now := metav1.Now()
	existingCR := &securityv1alpha1.ImageCertificationInfo{
		Name: testCRName,
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        testDigest,
			FullImageReference: "registry.redhat.io/ubi8/ubi@" + testDigest,
			Registry:           testRegistry,
			Repository:         testRepository,
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			RegistryType:        securityv1alpha1.RegistryTypeRedHat,
			CertificationStatus: securityv1alpha1.CertificationStatusUnknown,
			PodReferences: []securityv1alpha1.PodReference{
				{
					Namespace: testNamespace,
					Name:      testExistingPod,
					Container: "existing-container",
				},
			},
			FirstSeenAt: &now,
			LastSeenAt:  &now,
		},
	}

	// Create a new pod that uses the same image
	newPod := &corev1.Pod{
		Name:      "new-pod",
		Namespace: testNamespace,
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "new-container",
					Image: "registry.redhat.io/ubi8/ubi:latest",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:    "new-container",
					ImageID: "docker-pullable://registry.redhat.io/ubi8/ubi@" + testDigest,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingCR, newPod).
		WithStatusSubresource(existingCR).
		Build()

	reconciler := &PodReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	// Reconcile the new pod
	req := reconcile.Request{
		Name:      "new-pod",
		Namespace: testNamespace,
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("Reconcile() returned RequeueAfter != 0, want 0")
	}

	// Verify ImageCertificationInfo was updated with new pod reference
	var cr securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testCRName}, &cr); err != nil {
		t.Fatalf("Failed to get ImageCertificationInfo: %v", err)
	}

	// Should now have 2 pod references
	if len(cr.Status.PodReferences) != 2 {
		t.Errorf("PodReferences count = %v, want 2", len(cr.Status.PodReferences))
	}

	// Verify operator-version label was added to the existing CR during update
	if got := cr.Labels[LabelOperatorVersion]; got == "" {
		t.Error("Label LabelOperatorVersion not set on existing CR after reconcile, want non-empty version")
	}
}

func TestPodReconciler_Reconcile_DeletedPod(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := &PodReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	// Reconcile a non-existent pod
	req := reconcile.Request{
		Name:      "deleted-pod",
		Namespace: testNamespace,
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("Reconcile() returned RequeueAfter != 0, want 0")
	}
}

func TestPodReconciler_Reconcile_PodNotRunning(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	// Create a pod that is not running
	completedPod := &corev1.Pod{
		Name:      "completed-pod",
		Namespace: testNamespace,
		Status: corev1.PodStatus{
			Phase: corev1.PodSucceeded,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(completedPod).
		Build()

	reconciler := &PodReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	req := reconcile.Request{
		Name:      "completed-pod",
		Namespace: testNamespace,
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Error("Reconcile() returned RequeueAfter != 0, want 0")
	}

	// Verify no ImageCertificationInfo was created
	var crList securityv1alpha1.ImageCertificationInfoList
	if err := fakeClient.List(ctx, &crList); err != nil {
		t.Fatalf("Failed to list ImageCertificationInfos: %v", err)
	}
	if len(crList.Items) != 0 {
		t.Errorf("ImageCertificationInfo count = %v, want 0", len(crList.Items))
	}
}

// MockPyxisClient implements pyxis.Client for testing
type MockPyxisClient struct {
	CertData *pyxis.CertificationData
	Err      error
	Healthy  bool
}

func (m *MockPyxisClient) GetImageCertification(ctx context.Context, registry, repository, digest string) (*pyxis.CertificationData, error) {
	return m.CertData, m.Err
}

func (m *MockPyxisClient) IsHealthy(ctx context.Context) bool {
	return m.Healthy
}

func TestPodReconciler_SetupWithManager(t *testing.T) {
	// This test requires a real cluster config, so we skip it in unit tests.
	// Integration tests using envtest will cover this functionality.
	t.Skip("Skipping test - requires kubeconfig or envtest setup")
}

func TestPodReconciler_CleanupStaleReferences(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	// Create existing pod
	existingPod := &corev1.Pod{
		Name:      testExistingPod,
		Namespace: testNamespace,
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	// Create ImageCertificationInfo with references to existing and deleted pods
	now := metav1.Now()
	existingCR := &securityv1alpha1.ImageCertificationInfo{
		Name: testCRName,
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        testDigest,
			FullImageReference: "registry.redhat.io/ubi8/ubi@" + testDigest,
			Registry:           testRegistry,
			Repository:         testRepository,
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			RegistryType:        securityv1alpha1.RegistryTypeRedHat,
			CertificationStatus: securityv1alpha1.CertificationStatusUnknown,
			PodReferences: []securityv1alpha1.PodReference{
				{
					Namespace: testNamespace,
					Name:      testExistingPod,
					Container: "container1",
				},
				{
					Namespace: testNamespace,
					Name:      "deleted-pod",
					Container: "container2",
				},
			},
			FirstSeenAt: &now,
			LastSeenAt:  &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingCR, existingPod).
		WithStatusSubresource(existingCR).
		Build()

	reconciler := &PodReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	// Run cleanup
	if err := reconciler.CleanupStaleReferences(ctx); err != nil {
		t.Fatalf("CleanupStaleReferences() error = %v", err)
	}

	// Verify stale reference was removed
	var cr securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testCRName}, &cr); err != nil {
		t.Fatalf("Failed to get ImageCertificationInfo: %v", err)
	}

	if len(cr.Status.PodReferences) != 1 {
		t.Errorf("PodReferences count = %v, want 1", len(cr.Status.PodReferences))
	}
	if cr.Status.PodReferences[0].Name != testExistingPod {
		t.Errorf("Remaining PodReference.Name = %v, want existing-pod", cr.Status.PodReferences[0].Name)
	}
}

func TestPodReconciler_StartCleanupLoop(t *testing.T) {
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := &PodReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start cleanup loop with short interval
	reconciler.StartCleanupLoop(ctx, 100*time.Millisecond)

	// Let it run briefly
	time.Sleep(150 * time.Millisecond)

	// Cancel context to stop the loop
	cancel()

	// Give time for goroutine to exit
	time.Sleep(50 * time.Millisecond)
}

func TestPodReconciler_RefreshAllImages(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	// Create ImageCertificationInfo for a Red Hat image (should be refreshed)
	oldCheckTime := metav1.NewTime(time.Now().Add(-2 * time.Hour)) // Checked 2 hours ago
	redHatCR := &securityv1alpha1.ImageCertificationInfo{
		Name: "registry.redhat.io.ubi9.ubi.abc12345",
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        "sha256:abc12345abc12345abc12345abc12345abc12345abc12345abc12345abc12345",
			FullImageReference: "registry.redhat.io/ubi9/ubi@sha256:abc12345",
			Registry:           testRegistry,
			Repository:         "ubi9/ubi",
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			RegistryType:        securityv1alpha1.RegistryTypeRedHat,
			CertificationStatus: securityv1alpha1.CertificationStatusUnknown,
			LastPyxisCheckAt:    &oldCheckTime,
		},
	}

	// Create ImageCertificationInfo for a non-Red Hat image (should be skipped)
	dockerCR := &securityv1alpha1.ImageCertificationInfo{
		Name: "docker.io.library.nginx.def67890",
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        "sha256:def67890def67890def67890def67890def67890def67890def67890def67890",
			FullImageReference: "docker.io/library/nginx@sha256:def67890",
			Registry:           "docker.io",
			Repository:         "library/nginx",
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			RegistryType:        securityv1alpha1.RegistryTypeCommunity,
			CertificationStatus: securityv1alpha1.CertificationStatusUnknown,
		},
	}

	// Create a Red Hat CR that was recently checked (should be skipped)
	recentCheckTime := metav1.NewTime(time.Now().Add(-30 * time.Minute))
	recentCR := &securityv1alpha1.ImageCertificationInfo{
		Name: "registry.redhat.io.ubi8.ubi.recent123",
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        "sha256:recent123recent123recent123recent123recent123recent123recent123re",
			FullImageReference: "registry.redhat.io/ubi8/ubi@sha256:recent123",
			Registry:           testRegistry,
			Repository:         testRepository,
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			RegistryType:        securityv1alpha1.RegistryTypeRedHat,
			CertificationStatus: securityv1alpha1.CertificationStatusCertified,
			LastPyxisCheckAt:    &recentCheckTime,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(redHatCR, dockerCR, recentCR).
		WithStatusSubresource(redHatCR, dockerCR, recentCR).
		Build()

	mockPyxis := &MockPyxisClient{
		CertData: &pyxis.CertificationData{
			ProjectID:   "ubi9-ubi",
			Publisher:   testPublisher,
			HealthIndex: "A",
		},
		Healthy: true,
	}

	reconciler := &PodReconciler{
		Client:      fakeClient,
		Scheme:      scheme,
		PyxisClient: mockPyxis,
	}

	// Run refresh
	err := reconciler.RefreshAllImages(ctx)
	if err != nil {
		t.Fatalf("RefreshAllImages() error = %v", err)
	}

	// Verify the Red Hat CR that needed refresh was updated
	var updatedRedHatCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "registry.redhat.io.ubi9.ubi.abc12345"}, &updatedRedHatCR); err != nil {
		t.Fatalf("Failed to get refreshed ImageCertificationInfo: %v", err)
	}

	// Should be certified now
	if updatedRedHatCR.Status.CertificationStatus != securityv1alpha1.CertificationStatusCertified {
		t.Errorf("CertificationStatus = %v, want Certified", updatedRedHatCR.Status.CertificationStatus)
	}

	// LastPyxisCheckAt should be updated (more recent than the old check time)
	if updatedRedHatCR.Status.LastPyxisCheckAt == nil ||
		!updatedRedHatCR.Status.LastPyxisCheckAt.After(oldCheckTime.Time) {
		t.Error("LastPyxisCheckAt should be updated after refresh")
	}

	// Docker CR should be unchanged (not a Red Hat registry)
	var unchangedDockerCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "docker.io.library.nginx.def67890"}, &unchangedDockerCR); err != nil {
		t.Fatalf("Failed to get Docker ImageCertificationInfo: %v", err)
	}
	if unchangedDockerCR.Status.CertificationStatus != securityv1alpha1.CertificationStatusUnknown {
		t.Errorf("Docker CR should remain Unknown, got %v", unchangedDockerCR.Status.CertificationStatus)
	}

	// Recently checked CR should not have been updated (staggering)
	var unchangedRecentCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "registry.redhat.io.ubi8.ubi.recent123"}, &unchangedRecentCR); err != nil {
		t.Fatalf("Failed to get recent ImageCertificationInfo: %v", err)
	}
	// LastPyxisCheckAt should still be approximately the original time (within a second)
	if unchangedRecentCR.Status.LastPyxisCheckAt == nil {
		t.Error("LastPyxisCheckAt should not be nil")
	} else {
		timeDiff := unchangedRecentCR.Status.LastPyxisCheckAt.Sub(recentCheckTime.Time)
		if timeDiff < 0 {
			timeDiff = -timeDiff
		}
		if timeDiff > time.Second {
			t.Errorf("Recently checked CR should not be refreshed within the hour, time diff: %v", timeDiff)
		}
	}
}

func TestPodReconciler_RefreshSingleImage(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	cr := &securityv1alpha1.ImageCertificationInfo{
		Name: testCRName,
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        testDigest,
			FullImageReference: "registry.redhat.io/ubi8/ubi@" + testDigest,
			Registry:           testRegistry,
			Repository:         testRepository,
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			RegistryType:        securityv1alpha1.RegistryTypeRedHat,
			CertificationStatus: securityv1alpha1.CertificationStatusUnknown,
			FirstSeenAt:         &now,
			LastSeenAt:          &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	mockPyxis := &MockPyxisClient{
		CertData: &pyxis.CertificationData{
			ProjectID:   "ubi8-container",
			Publisher:   testPublisher,
			HealthIndex: "B",
			Vulnerabilities: &pyxis.VulnerabilitySummary{
				Critical:  1,
				Important: 3,
				Moderate:  5,
				Low:       10,
			},
		},
		Healthy: true,
	}

	reconciler := &PodReconciler{
		Client:      fakeClient,
		Scheme:      scheme,
		PyxisClient: mockPyxis,
	}

	// Refresh the image
	err := reconciler.refreshSingleImage(ctx, cr)
	if err != nil {
		t.Fatalf("refreshSingleImage() error = %v", err)
	}

	// Verify the CR was updated
	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testCRName}, &updatedCR); err != nil {
		t.Fatalf("Failed to get refreshed ImageCertificationInfo: %v", err)
	}

	if updatedCR.Status.CertificationStatus != securityv1alpha1.CertificationStatusCertified {
		t.Errorf("CertificationStatus = %v, want Certified", updatedCR.Status.CertificationStatus)
	}

	if updatedCR.Status.PyxisData == nil {
		t.Fatal("PyxisData should not be nil")
	}

	if updatedCR.Status.PyxisData.Publisher != testPublisher {
		t.Errorf("Publisher = %v, want Red Hat, Inc.", updatedCR.Status.PyxisData.Publisher)
	}

	if updatedCR.Status.PyxisData.HealthIndex != "B" {
		t.Errorf("HealthIndex = %v, want B", updatedCR.Status.PyxisData.HealthIndex)
	}

	if updatedCR.Status.PyxisData.Vulnerabilities == nil {
		t.Fatal("Vulnerabilities should not be nil")
	}

	if updatedCR.Status.PyxisData.Vulnerabilities.Critical != 1 {
		t.Errorf("Critical vulnerabilities = %v, want 1", updatedCR.Status.PyxisData.Vulnerabilities.Critical)
	}
}

func TestPodReconciler_RefreshSingleImage_NotCertified(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	cr := &securityv1alpha1.ImageCertificationInfo{
		Name: testCRName,
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        testDigest,
			FullImageReference: "registry.redhat.io/ubi8/ubi@" + testDigest,
			Registry:           testRegistry,
			Repository:         testRepository,
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			RegistryType:        securityv1alpha1.RegistryTypeRedHat,
			CertificationStatus: securityv1alpha1.CertificationStatusCertified,
			FirstSeenAt:         &now,
			LastSeenAt:          &now,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	// Mock Pyxis returns nil (not certified)
	mockPyxis := &MockPyxisClient{
		CertData: nil,
		Healthy:  true,
	}

	reconciler := &PodReconciler{
		Client:      fakeClient,
		Scheme:      scheme,
		PyxisClient: mockPyxis,
	}

	// Refresh the image
	err := reconciler.refreshSingleImage(ctx, cr)
	if err != nil {
		t.Fatalf("refreshSingleImage() error = %v", err)
	}

	// Verify the CR status changed to NotCertified
	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testCRName}, &updatedCR); err != nil {
		t.Fatalf("Failed to get refreshed ImageCertificationInfo: %v", err)
	}

	if updatedCR.Status.CertificationStatus != securityv1alpha1.CertificationStatusNotCertified {
		t.Errorf("CertificationStatus = %v, want NotCertified", updatedCR.Status.CertificationStatus)
	}
}

const testCVE = "CVE-2026-0001"

func TestBuildCVEAnnotation(t *testing.T) {
	cves := make([]string, 10000)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-2026-%05d", i)
	}

	got, truncated := buildCVEAnnotation(cves)

	if !truncated {
		t.Fatal("expected a truncated annotation for 10000 CVEs")
	}
	if len(got) > MaxCVEAnnotationBytes {
		t.Errorf("annotation length = %d, want <= %d", len(got), MaxCVEAnnotationBytes)
	}
	if !strings.HasSuffix(got, cveTruncationSentinel+"1") && !strings.Contains(got, cveTruncationSentinel) {
		t.Errorf("annotation does not carry the truncation sentinel: %.80s", got)
	}

	// A short list is written verbatim with no sentinel.
	small := []string{testCVE, "CVE-2026-0002"}
	value, truncated := buildCVEAnnotation(small)
	if truncated {
		t.Error("short list must not be truncated")
	}
	if value != testCVE+",CVE-2026-0002" {
		t.Errorf("value = %q, want the joined list", value)
	}
}

func TestUpdateCVEAnnotations_SkipsUnchangedValue(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	name := testCRName
	cr := &securityv1alpha1.ImageCertificationInfo{}
	cr.Name = name
	cr.Annotations = map[string]string{AnnotationCVEs: testCVE}

	patches := 0
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object,
				patch client.Patch, opts ...client.PatchOption) error {
				patches++
				return c.Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	reconciler := &PodReconciler{Client: fakeClient, Scheme: scheme}

	if err := reconciler.updateCVEAnnotations(ctx, name, []string{testCVE}); err != nil {
		t.Fatalf("updateCVEAnnotations() error = %v", err)
	}
	if patches != 0 {
		t.Errorf("patches = %d, want 0 for an unchanged list", patches)
	}

	if err := reconciler.updateCVEAnnotations(ctx, name, []string{"CVE-2026-0002"}); err != nil {
		t.Fatalf("updateCVEAnnotations() error = %v", err)
	}
	if patches != 1 {
		t.Errorf("patches = %d, want 1 after the list changed", patches)
	}
}

func TestIsHealthDegraded(t *testing.T) {
	tests := []struct {
		name     string
		oldGrade string
		newGrade string
		want     bool
	}{
		{"A to B is degraded", "A", "B", true},
		{"A to C is degraded", "A", "C", true},
		{"A to F is degraded", "A", "F", true},
		{"B to A is not degraded", "B", "A", false},
		{"B to B is not degraded", "B", "B", false},
		{"C to D is degraded", "C", "D", true},
		{"F to A is not degraded", "F", "A", false},
		{"empty old grade is not degraded", "", "B", false},
		{"empty new grade is not degraded", "A", "", false},
		{"invalid grades are not degraded", "X", "Y", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHealthDegraded(tt.oldGrade, tt.newGrade)
			if got != tt.want {
				t.Errorf("isHealthDegraded(%q, %q) = %v, want %v", tt.oldGrade, tt.newGrade, got, tt.want)
			}
		})
	}
}

func TestPodReconciler_StartRefreshLoop(t *testing.T) {
	scheme := newTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := &PodReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start refresh loop - note: it has a random startup delay (0-5 min)
	// so we can't easily test the actual refresh, just that it starts and stops
	reconciler.StartRefreshLoop(ctx, 1*time.Hour)

	// Give some time for the goroutine to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context to stop the loop
	cancel()

	// Give time for goroutine to exit
	time.Sleep(50 * time.Millisecond)
}

func TestDigestLabel(t *testing.T) {
	tests := []struct {
		name   string
		digest string
		want   string
	}{
		{
			name:   "empty digest",
			digest: "",
			want:   "sha256-",
		},
		{
			name:   "full sha256 digest truncated to 16",
			digest: "sha256:abcdef1234567890abcdef1234567890",
			want:   "sha256-abcdef1234567890",
		},
		{
			name:   "exactly 16 hex chars",
			digest: "sha256:1234567890abcdef",
			want:   "sha256-1234567890abcdef",
		},
		{
			name:   "shorter than 16 hex chars kept as-is",
			digest: "sha256:abc123",
			want:   "sha256-abc123",
		},
		{
			name:   "no sha256 prefix passes through",
			digest: "abc123",
			want:   "sha256-abc123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := digestLabel(tt.digest)
			if got != tt.want {
				t.Errorf("digestLabel(%q) = %q, want %q", tt.digest, got, tt.want)
			}
		})
	}
}

func TestPodReconciler_UpdateCRWithPyxisData_ClearsDroppedFields(t *testing.T) {
	reconciler := &PodReconciler{}
	cr := &securityv1alpha1.ImageCertificationInfo{}
	cr.Name = testCRName

	// First refresh: Pyxis publishes a build date and an EOL date.
	reconciler.updateCRWithPyxisData(cr, &pyxis.CertificationData{
		HealthIndex: "A",
		PublishedAt: time.Now().Add(-48 * time.Hour).Format(time.RFC3339),
		EOLDate:     time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
	})
	if cr.Status.PyxisData == nil || cr.Status.PyxisData.EOLDate == nil {
		t.Fatal("expected EOLDate to be set by the first refresh")
	}
	if cr.Status.ImageAge == "" {
		t.Fatal("expected ImageAge to be set by the first refresh")
	}
	if cr.Status.DaysUntilEOL == nil {
		t.Fatal("expected DaysUntilEOL to be set by the first refresh")
	}

	// Second refresh: Pyxis no longer returns either timestamp.
	reconciler.updateCRWithPyxisData(cr, &pyxis.CertificationData{HealthIndex: "A"})

	if cr.Status.PyxisData.EOLDate != nil {
		t.Errorf("EOLDate = %v, want nil", cr.Status.PyxisData.EOLDate)
	}
	if cr.Status.DaysUntilEOL != nil {
		t.Errorf("DaysUntilEOL = %d, want nil", *cr.Status.DaysUntilEOL)
	}
	if cr.Status.ImageAge != "" {
		t.Errorf("ImageAge = %q, want empty", cr.Status.ImageAge)
	}
}

// staleCertifiedCR returns a CR that still carries the payload of an earlier,
// successful refresh.
func staleCertifiedCR() *securityv1alpha1.ImageCertificationInfo {
	now := metav1.Now()
	eol := metav1.NewTime(time.Now().Add(30 * 24 * time.Hour))
	days := 30
	meta := metav1.ObjectMeta{
		Name:        testCRName,
		Annotations: map[string]string{AnnotationCVEs: "CVE-2026-0001,CVE-2026-0002"},
	}
	return &securityv1alpha1.ImageCertificationInfo{
		ObjectMeta: meta,
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        testDigest,
			FullImageReference: "registry.redhat.io/ubi8/ubi@" + testDigest,
			Registry:           testRegistry,
			Repository:         testRepository,
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			RegistryType:        securityv1alpha1.RegistryTypeRedHat,
			CertificationStatus: securityv1alpha1.CertificationStatusCertified,
			FirstSeenAt:         &now,
			LastSeenAt:          &now,
			ImageAge:            "45 days",
			DaysUntilEOL:        &days,
			PyxisData: &securityv1alpha1.PyxisData{
				HealthIndex: "A",
				EOLDate:     &eol,
				Vulnerabilities: &securityv1alpha1.VulnerabilitySummary{
					Critical: 99,
				},
			},
		},
	}
}

// assertStalePayloadCleared checks that no Pyxis-derived value survived.
func assertStalePayloadCleared(t *testing.T, cr *securityv1alpha1.ImageCertificationInfo) {
	t.Helper()
	if cr.Status.CertificationStatus != securityv1alpha1.CertificationStatusNotCertified {
		t.Errorf("CertificationStatus = %v, want NotCertified", cr.Status.CertificationStatus)
	}
	if cr.Status.PyxisData != nil {
		t.Errorf("PyxisData = %+v, want nil", cr.Status.PyxisData)
	}
	if cr.Status.ImageAge != "" {
		t.Errorf("ImageAge = %q, want empty", cr.Status.ImageAge)
	}
	if cr.Status.DaysUntilEOL != nil {
		t.Errorf("DaysUntilEOL = %d, want nil", *cr.Status.DaysUntilEOL)
	}
	if _, ok := cr.Annotations[AnnotationCVEs]; ok {
		t.Errorf("annotation %s still present, want removed", AnnotationCVEs)
	}
}

func TestPodReconciler_CheckPyxisCertification_NotCertifiedClearsPayload(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleCertifiedCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{
		Client:      fakeClient,
		Scheme:      scheme,
		PyxisClient: &MockPyxisClient{CertData: nil, Healthy: true},
	}

	ref := &image.Reference{
		Registry:   testRegistry,
		Repository: testRepository,
		Digest:     testDigest,
	}
	reconciler.checkPyxisCertification(ctx, testCRName, ref)

	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testCRName}, &updatedCR); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo: %v", err)
	}
	assertStalePayloadCleared(t, &updatedCR)
}

func TestPodReconciler_RefreshSingleImage_NotCertifiedClearsPayload(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleCertifiedCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{
		Client:      fakeClient,
		Scheme:      scheme,
		PyxisClient: &MockPyxisClient{CertData: nil, Healthy: true},
	}

	if err := reconciler.refreshSingleImage(ctx, cr); err != nil {
		t.Fatalf("refreshSingleImage() error = %v", err)
	}

	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testCRName}, &updatedCR); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo: %v", err)
	}
	assertStalePayloadCleared(t, &updatedCR)
}

func TestPodReconciler_Reconcile_ReturnsErrorOnWriteFailure(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	meta := metav1.ObjectMeta{Name: testPodName, Namespace: testNamespace}
	pod := &corev1.Pod{
		ObjectMeta: meta,
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: testContainer, ImageID: testRegistry + "/" + testRepository + "@" + testDigest},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod).
		WithStatusSubresource(&securityv1alpha1.ImageCertificationInfo{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object,
				opts ...client.CreateOption) error {
				if _, ok := obj.(*securityv1alpha1.ImageCertificationInfo); ok {
					return errors.New("simulated write failure")
				}
				return c.Create(ctx, obj, opts...)
			},
		}).
		Build()

	reconciler := &PodReconciler{Client: fakeClient, Scheme: scheme}

	key := types.NamespacedName{Name: testPodName, Namespace: testNamespace}
	req := reconcile.Request{NamespacedName: key}
	_, err := reconciler.Reconcile(ctx, req)
	if err == nil {
		t.Fatal("Reconcile() error = nil, want an error so the request is requeued")
	}
}

func TestPodReconciler_UpdatePodReferences_RetriesOnConflict(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	meta := metav1.ObjectMeta{
		Name:   testCRName,
		Labels: map[string]string{LabelOperatorVersion: version.Version},
	}
	cr := &securityv1alpha1.ImageCertificationInfo{
		ObjectMeta: meta,
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			FirstSeenAt: &now,
			LastSeenAt:  &now,
			PodReferences: []securityv1alpha1.PodReference{
				{Namespace: testNamespace, Name: testExistingPod, Container: testContainer},
			},
		},
	}

	conflicts := 0
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, subResource string,
				obj client.Object, opts ...client.SubResourceUpdateOption) error {
				if subResource == "status" && conflicts == 0 {
					conflicts++
					return apierrors.NewConflict(
						schema.GroupResource{
							Group:    "security.telco.openshift.io",
							Resource: "imagecertificationinfoes",
						},
						obj.GetName(),
						errors.New("simulated conflict"),
					)
				}
				return c.SubResource(subResource).Update(ctx, obj, opts...)
			},
		}).
		Build()

	reconciler := &PodReconciler{Client: fakeClient, Scheme: scheme}
	podRef := securityv1alpha1.PodReference{
		Namespace: testNamespace,
		Name:      testPodName,
		Container: testContainer,
	}

	if err := reconciler.updatePodReferences(ctx, cr, podRef); err != nil {
		t.Fatalf("updatePodReferences() error = %v", err)
	}
	if conflicts != 1 {
		t.Errorf("conflicts = %d, want 1 injected conflict", conflicts)
	}

	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testCRName}, &updatedCR); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo: %v", err)
	}
	found := false
	for _, ref := range updatedCR.Status.PodReferences {
		if ref.Name == testPodName {
			found = true
		}
	}
	if !found {
		t.Error("pod reference was not persisted after the conflict retry")
	}
}
