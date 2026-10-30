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
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	quaylib "github.com/sebrandon1/go-quay/lib"
	securityv1alpha1 "github.com/sebrandon1/imagecertinfo-operator/api/v1alpha1"
	"github.com/sebrandon1/imagecertinfo-operator/internal/version"
	"github.com/sebrandon1/imagecertinfo-operator/pkg/dockerhub"
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
	if envtestConfig == nil {
		t.Skip("envtest is not available; set KUBEBUILDER_ASSETS to run this test")
	}

	mgr, err := ctrl.NewManager(envtestConfig, ctrl.Options{
		Scheme:                 newTestScheme(),
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	reconciler := &PodReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager() error = %v", err)
	}
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
	done := make(chan error, 1)

	// The loop blocks until the context is cancelled so the manager can own
	// its lifecycle.
	go func() { done <- reconciler.StartCleanupLoop(ctx, 10*time.Millisecond) }()

	// Let it run through a few ticks.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("StartCleanupLoop() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("StartCleanupLoop() did not return after the context was cancelled")
	}
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
			Repository:         testDockerHubRepository,
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
	small := []string{testCVE, testCVEHigh}
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

	if err := reconciler.updateCVEAnnotations(ctx, name, []string{testCVEHigh}); err != nil {
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
	done := make(chan error, 1)

	// Start refresh loop - note: it has a random startup delay (0-5 min)
	// so we can't easily test the actual refresh, just that it starts and stops
	// on shutdown.
	go func() { done <- reconciler.StartRefreshLoop(ctx, 1*time.Hour) }()

	// Give some time for the goroutine to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context to stop the loop
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("StartRefreshLoop() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("StartRefreshLoop() did not return after the context was cancelled")
	}
}

// flakyPyxisClient fails the first `failures` lookups, then succeeds with no
// certification data.
type flakyPyxisClient struct {
	mu       sync.Mutex
	failures int
	calls    int
}

func (f *flakyPyxisClient) GetImageCertification(
	ctx context.Context, registry, repository, digest string,
) (*pyxis.CertificationData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls++
	if f.calls <= f.failures {
		return nil, errors.New("pyxis temporarily unavailable")
	}

	return nil, nil
}

func (f *flakyPyxisClient) IsHealthy(ctx context.Context) bool { return true }

func (f *flakyPyxisClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.calls
}

func newEnrichmentTestReconciler(t *testing.T, pyxisClient pyxis.Client) *PodReconciler {
	t.Helper()

	scheme := newTestScheme()
	now := metav1.Now()
	cr := &securityv1alpha1.ImageCertificationInfo{
		Name: testCRName,
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        testDigest,
			FullImageReference: testRegistry + "/" + testRepository + "@" + testDigest,
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

	return &PodReconciler{
		Client:      fakeClient,
		Scheme:      scheme,
		PyxisClient: pyxisClient,
		EnrichQueue: newEnrichQueue(),
	}
}

func TestPodReconciler_EnqueuesEnrichment(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	pod := &corev1.Pod{
		Name:      testPodName,
		Namespace: testNamespace,
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:    testContainer,
					ImageID: "docker-pullable://" + testRegistry + "/" + testRepository + "@" + testDigest,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod).
		WithStatusSubresource(&securityv1alpha1.ImageCertificationInfo{}).
		Build()

	reconciler := &PodReconciler{
		Client:      fakeClient,
		Scheme:      scheme,
		EnrichQueue: newEnrichQueue(),
	}
	defer reconciler.EnrichQueue.ShutDown()

	if _, err := reconciler.Reconcile(ctx, reconcile.Request{
		//nolint:modernize // a struct field value cannot elide its literal type
		NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testPodName},
	}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	item, shutdown := reconciler.EnrichQueue.Get()
	if shutdown {
		t.Fatal("enrichment queue was shut down, want one request")
	}
	reconciler.EnrichQueue.Done(item)
	reconciler.EnrichQueue.Forget(item)

	if item.crName != testCRName {
		t.Errorf("enqueued crName = %q, want %q", item.crName, testCRName)
	}
	if item.ref.Digest != testDigest {
		t.Errorf("enqueued digest = %q, want %q", item.ref.Digest, testDigest)
	}
}

func TestProcessEnrichRequest(t *testing.T) {
	item := enrichRequest{
		crName: testCRName,
		ref: image.Reference{
			Registry:   testRegistry,
			Repository: testRepository,
			Digest:     testDigest,
		},
	}

	t.Run("success forgets the request", func(t *testing.T) {
		reconciler := newEnrichmentTestReconciler(t, &MockPyxisClient{
			CertData: &pyxis.CertificationData{ImageID: "img-1"},
		})
		defer reconciler.EnrichQueue.ShutDown()

		reconciler.processEnrichRequest(context.Background(), item)

		if got := reconciler.EnrichQueue.NumRequeues(item); got != 0 {
			t.Errorf("NumRequeues() = %d, want 0 after a successful enrichment", got)
		}
	})

	t.Run("failure requeues with backoff", func(t *testing.T) {
		reconciler := newEnrichmentTestReconciler(t, &MockPyxisClient{
			Err: errors.New("pyxis unavailable"),
		})
		defer reconciler.EnrichQueue.ShutDown()

		reconciler.processEnrichRequest(context.Background(), item)

		if got := reconciler.EnrichQueue.NumRequeues(item); got != 1 {
			t.Errorf("NumRequeues() = %d, want 1 so the request is retried", got)
		}
	})

	t.Run("gives up after the retry cap", func(t *testing.T) {
		reconciler := newEnrichmentTestReconciler(t, &MockPyxisClient{
			Err: errors.New("pyxis unavailable"),
		})
		defer reconciler.EnrichQueue.ShutDown()

		for range maxEnrichmentRetries + 1 {
			reconciler.processEnrichRequest(context.Background(), item)
		}

		if got := reconciler.EnrichQueue.NumRequeues(item); got != 0 {
			t.Errorf("NumRequeues() = %d, want 0 after the retry cap dropped the request", got)
		}
	})

	t.Run("does not requeue on shutdown", func(t *testing.T) {
		reconciler := newEnrichmentTestReconciler(t, &MockPyxisClient{
			Err: errors.New("pyxis unavailable"),
		})
		defer reconciler.EnrichQueue.ShutDown()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		reconciler.processEnrichRequest(ctx, item)

		if got := reconciler.EnrichQueue.NumRequeues(item); got != 0 {
			t.Errorf("NumRequeues() = %d, want 0 when the manager is shutting down", got)
		}
	})
}

func TestRunEnrichmentWorkers_RetriesFailingClient(t *testing.T) {
	pyxisClient := &flakyPyxisClient{failures: 1}
	reconciler := newEnrichmentTestReconciler(t, pyxisClient)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		reconciler.runEnrichmentWorkers(ctx, 1)
	}()

	reconciler.EnrichQueue.Add(enrichRequest{
		crName: testCRName,
		ref:    image.Reference{Registry: testRegistry, Repository: testRepository, Digest: testDigest},
	})

	deadline := time.Now().Add(2 * time.Second)
	for pyxisClient.callCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("enrichment called %d times, want at least 2 (one retry)", pyxisClient.callCount())
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runEnrichmentWorkers() did not return after the context was cancelled")
	}
}

// stubDockerHubClient implements dockerhub.Client for dispatch tests.
type stubDockerHubClient struct {
	info   *dockerhub.RepositoryInfo
	err    error
	called bool
}

func (s *stubDockerHubClient) GetRepositoryInfo(
	ctx context.Context, namespace, repository string,
) (*dockerhub.RepositoryInfo, error) {
	s.called = true

	return s.info, s.err
}

func (s *stubDockerHubClient) IsHealthy(ctx context.Context) bool { return true }

// stubQuayClient implements quaylib.RepositoryReader for dispatch and
// enrichment tests. Each call can be given its own result or error.
type stubQuayClient struct {
	repo        quaylib.RepositoryWithTags
	err         error
	scan        *quaylib.SecurityScan
	scanErr     error
	manifest    *quaylib.Manifest
	manifestErr error
	labels      *quaylib.ManifestLabels
	labelsErr   error
	called      bool
	scanCalled  bool
}

func (s *stubQuayClient) GetRepository(
	ctx context.Context, namespace, repository string,
) (quaylib.RepositoryWithTags, error) {
	s.called = true

	return s.repo, s.err
}

func (s *stubQuayClient) ListTags(
	ctx context.Context, namespace, repository string, limit int, onlyActive bool,
) (*quaylib.RepositoryTags, error) {
	return nil, nil
}

func (s *stubQuayClient) ListAllTags(
	ctx context.Context, namespace, repository string, onlyActive bool,
) ([]quaylib.Tag, error) {
	return nil, nil
}

func (s *stubQuayClient) GetManifestSecurity(
	ctx context.Context, namespace, repository, manifestRef string, vulnerabilities bool,
) (*quaylib.SecurityScan, error) {
	s.scanCalled = true

	return s.scan, s.scanErr
}

func (s *stubQuayClient) GetManifest(
	ctx context.Context, namespace, repository, manifestRef string,
) (*quaylib.Manifest, error) {
	return s.manifest, s.manifestErr
}

func (s *stubQuayClient) GetManifestLabels(
	ctx context.Context, namespace, repository, manifestRef string,
) (*quaylib.ManifestLabels, error) {
	return s.labels, s.labelsErr
}

// newDispatchTestClient returns a fake client holding one CR for the given
// registry and repository.
func newDispatchTestClient(t *testing.T, name, registry, repository string) client.Client {
	t.Helper()

	cr := &securityv1alpha1.ImageCertificationInfo{
		Name: name,
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        testDigest,
			FullImageReference: registry + "/" + repository + "@" + testDigest,
			Registry:           registry,
			Repository:         repository,
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			CertificationStatus: securityv1alpha1.CertificationStatusUnknown,
		},
	}

	return fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()
}

func TestPodReconciler_EnrichDispatchesByRegistry(t *testing.T) {
	ctx := context.Background()

	t.Run("docker.io uses the Docker Hub client", func(t *testing.T) {
		dockerHub := &stubDockerHubClient{info: &dockerhub.RepositoryInfo{IsOfficial: true}}
		reconciler := &PodReconciler{
			Client:          newDispatchTestClient(t, "docker.io.library.nginx", RegistryDockerHub, testDockerHubRepository),
			DockerHubClient: dockerHub,
		}

		item := enrichRequest{
			crName: "docker.io.library.nginx",
			ref:    image.Reference{Registry: RegistryDockerHub, Repository: testDockerHubRepository, Digest: testDigest},
		}
		if err := reconciler.enrich(ctx, item); err != nil {
			t.Fatalf("enrich() error = %v", err)
		}
		if !dockerHub.called {
			t.Error("Docker Hub client was not called for a docker.io image")
		}
	})

	t.Run("quay.io uses the Quay client", func(t *testing.T) {
		quayClient := &stubQuayClient{}
		reconciler := &PodReconciler{
			Client:     newDispatchTestClient(t, "quay.io.ns.repo", RegistryQuayIO, "ns/repo"),
			QuayClient: quayClient,
		}

		item := enrichRequest{
			crName: "quay.io.ns.repo",
			ref:    image.Reference{Registry: RegistryQuayIO, Repository: "ns/repo", Digest: testDigest},
		}
		if err := reconciler.enrich(ctx, item); err != nil {
			t.Fatalf("enrich() error = %v", err)
		}
		if !quayClient.called {
			t.Error("Quay client was not called for a quay.io image")
		}
	})

	t.Run("unknown registry with no client is a no-op", func(t *testing.T) {
		reconciler := &PodReconciler{}

		item := enrichRequest{
			crName: "example.com.ns.repo",
			ref:    image.Reference{Registry: "example.com", Repository: "ns/repo", Digest: testDigest},
		}
		if err := reconciler.enrich(ctx, item); err != nil {
			t.Errorf("enrich() error = %v, want nil for a registry without a client", err)
		}
	})
}

func TestPodReconciler_EnqueueEnrichment_NoQueue(t *testing.T) {
	// A reconciler without a manager (as in these tests) must not panic.
	reconciler := &PodReconciler{}
	reconciler.enqueueEnrichment(testCRName, &image.Reference{Registry: testRegistry})
}

func TestPodReconciler_SetupEnrichmentWorkers(t *testing.T) {
	if envtestConfig == nil {
		t.Skip("envtest is not available; set KUBEBUILDER_ASSETS to run this test")
	}

	mgr, err := ctrl.NewManager(envtestConfig, ctrl.Options{
		Scheme:                 newTestScheme(),
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	reconciler := &PodReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}
	if err := reconciler.SetupEnrichmentWorkers(mgr, 0); err != nil {
		t.Fatalf("SetupEnrichmentWorkers() error = %v", err)
	}
	if reconciler.EnrichQueue == nil {
		t.Error("EnrichQueue is nil after SetupEnrichmentWorkers()")
	}
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
		Annotations: map[string]string{AnnotationCVEs: testCVEAnnotationValue},
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
	_ = reconciler.checkPyxisCertification(ctx, testCRName, ref)

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

func TestPodReconciler_UpdatePodReferences_ThrottlesLastSeenAt(t *testing.T) {
	scheme := newTestScheme()
	ctx := context.Background()

	podRef := securityv1alpha1.PodReference{
		Namespace: testNamespace,
		Name:      testExistingPod,
		Container: testContainer,
	}

	newCR := func(lastSeen metav1.Time) *securityv1alpha1.ImageCertificationInfo {
		cr := &securityv1alpha1.ImageCertificationInfo{}
		cr.Name = testCRName
		cr.Labels = map[string]string{LabelOperatorVersion: version.Version}
		cr.Status.LastSeenAt = &lastSeen
		cr.Status.PodReferences = []securityv1alpha1.PodReference{podRef}
		return cr
	}

	tests := []struct {
		name        string
		lastSeen    metav1.Time
		wantUpdates int
	}{
		{
			name:        "recent reference is not rewritten",
			lastSeen:    metav1.Now(),
			wantUpdates: 0,
		},
		{
			name:        "stale reference is refreshed",
			lastSeen:    metav1.NewTime(time.Now().Add(-2 * lastSeenRefreshWindow)),
			wantUpdates: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updates := 0
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(newCR(tt.lastSeen)).
				WithStatusSubresource(newCR(tt.lastSeen)).
				WithInterceptorFuncs(interceptor.Funcs{
					SubResourceUpdate: func(ctx context.Context, c client.Client, _ string,
						obj client.Object, opts ...client.SubResourceUpdateOption) error {
						updates++
						return c.SubResource("status").Update(ctx, obj, opts...)
					},
				}).
				Build()

			reconciler := &PodReconciler{Client: fakeClient, Scheme: scheme}

			if err := reconciler.updatePodReferences(ctx, newCR(tt.lastSeen), podRef); err != nil {
				t.Fatalf("updatePodReferences() error = %v", err)
			}
			if updates != tt.wantUpdates {
				t.Errorf("status updates = %d, want %d", updates, tt.wantUpdates)
			}
		})
	}
}

func TestPodReconciler_UpdatePodReferences_WritesNewReference(t *testing.T) {
	scheme := newTestScheme()
	ctx := context.Background()

	cr := &securityv1alpha1.ImageCertificationInfo{}
	cr.Name = testCRName
	cr.Labels = map[string]string{LabelOperatorVersion: version.Version}
	cr.Status.LastSeenAt = &metav1.Time{Time: time.Now()}

	updates := 0
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, _ string,
				obj client.Object, opts ...client.SubResourceUpdateOption) error {
				updates++
				return c.SubResource("status").Update(ctx, obj, opts...)
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
	if updates != 1 {
		t.Fatalf("status updates = %d, want 1", updates)
	}

	updated := &securityv1alpha1.ImageCertificationInfo{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testCRName}, updated); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if len(updated.Status.PodReferences) != 1 {
		t.Errorf("PodReferences = %d, want 1", len(updated.Status.PodReferences))
	}
}

func TestPodDiscoveryPredicate(t *testing.T) {
	newPod := func(phase corev1.PodPhase, imageIDs ...string) *corev1.Pod {
		pod := &corev1.Pod{}
		pod.Status.Phase = phase
		for i, id := range imageIDs {
			pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
				Name:    fmt.Sprintf("c%d", i),
				ImageID: id,
			})
		}
		return pod
	}

	p := podDiscoveryPredicate()

	if !p.Create(event.CreateEvent{Object: newPod(corev1.PodPending)}) {
		t.Error("Create() = false, want true")
	}
	if !p.Delete(event.DeleteEvent{Object: newPod(corev1.PodPending)}) {
		t.Error("Delete() = false, want true")
	}
	if p.Generic(event.GenericEvent{Object: newPod(corev1.PodPending)}) {
		t.Error("Generic() = true, want false")
	}

	tests := []struct {
		name string
		old  *corev1.Pod
		new  *corev1.Pod
		want bool
	}{
		{
			name: "unchanged pod is ignored",
			old:  newPod(corev1.PodRunning, "img-a"),
			new:  newPod(corev1.PodRunning, "img-a"),
			want: false,
		},
		{
			name: "phase change is admitted",
			old:  newPod(corev1.PodPending, "img-a"),
			new:  newPod(corev1.PodRunning, "img-a"),
			want: true,
		},
		{
			name: "image ID change is admitted",
			old:  newPod(corev1.PodRunning, "img-a"),
			new:  newPod(corev1.PodRunning, "img-b"),
			want: true,
		},
		{
			name: "new container is admitted",
			old:  newPod(corev1.PodRunning, "img-a"),
			new:  newPod(corev1.PodRunning, "img-a", "img-b"),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.Update(event.UpdateEvent{ObjectOld: tt.old, ObjectNew: tt.new})
			if got != tt.want {
				t.Errorf("Update() = %v, want %v", got, tt.want)
			}
		})
	}
}

// envtestReconcileNamespace is the namespace used by the envtest reconcile test.
const envtestReconcileNamespace = "envtest-reconcile"

func TestPodReconciler_Reconcile_WithEnvtest(t *testing.T) {
	if envtestClient == nil {
		t.Skip("envtest is not available; set KUBEBUILDER_ASSETS to run this test")
	}

	ctx := context.Background()

	ns := &corev1.Namespace{}
	ns.Name = envtestReconcileNamespace
	if err := envtestClient.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create namespace: %v", err)
	}

	imageID := testRegistry + "/ubi9/ubi-minimal@" + testDigest
	pod := &corev1.Pod{}
	pod.Name = "envtest-pod"
	pod.Namespace = envtestReconcileNamespace
	pod.Spec.Containers = []corev1.Container{{
		Name:  testContainer,
		Image: testRegistry + "/ubi9/ubi-minimal:9.5",
	}}
	if err := envtestClient.Create(ctx, pod); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create pod: %v", err)
	}

	// Pod status must be written through the status subresource: the API
	// server, not the client, owns it.
	pod.Status.Phase = corev1.PodRunning
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:    testContainer,
		Image:   testRegistry + "/ubi9/ubi-minimal:9.5",
		ImageID: imageID,
		Ready:   true,
	}}
	if err := envtestClient.Status().Update(ctx, pod); err != nil {
		t.Fatalf("failed to update pod status: %v", err)
	}

	reconciler := &PodReconciler{
		Client:      envtestClient,
		Scheme:      newTestScheme(),
		PyxisClient: &MockPyxisClient{Healthy: true},
		Recorder:    record.NewFakeRecorder(100),
	}

	req := reconcile.Request{
		//nolint:modernize // the field type cannot be elided in a keyed struct literal
		NamespacedName: types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name},
	}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	// The CRD name comes from the parsed image reference.
	ref, err := image.ParseImageID(imageID)
	if err != nil {
		t.Fatalf("ParseImageID() error = %v", err)
	}
	crName := image.ReferenceToCRName(ref)

	cr := &securityv1alpha1.ImageCertificationInfo{}
	if err := envtestClient.Get(ctx, client.ObjectKey{Name: crName}, cr); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo %q: %v", crName, err)
	}

	if len(cr.Status.PodReferences) != 1 {
		t.Fatalf("PodReferences = %d, want 1", len(cr.Status.PodReferences))
	}
	if cr.Status.PodReferences[0].Name != pod.Name {
		t.Errorf("PodReferences[0].Name = %q, want %q", cr.Status.PodReferences[0].Name, pod.Name)
	}
	if cr.Status.LastSeenAt == nil {
		t.Error("LastSeenAt = nil, want the status written by Reconcile")
	}
}

// testDockerHubRepository is the docker.io repository path used by the fixtures
// below.
const testDockerHubRepository = "library/nginx"

// testDockerHubCRName is the CR name for the docker.io fixture below.
const testDockerHubCRName = "docker.io.library.nginx.abc123de"

// staleDockerHubCR returns a docker.io CR carrying a Docker Hub payload and an
// Official certification status left over from an earlier cycle.
func staleDockerHubCR() *securityv1alpha1.ImageCertificationInfo {
	now := metav1.Now()
	days := 12
	meta := metav1.ObjectMeta{Name: testDockerHubCRName}

	return &securityv1alpha1.ImageCertificationInfo{
		ObjectMeta: meta,
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        testDigest,
			FullImageReference: "docker.io/library/nginx@" + testDigest,
			Registry:           RegistryDockerHub,
			Repository:         testDockerHubRepository,
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			RegistryType:        securityv1alpha1.RegistryTypeCommunity,
			CertificationStatus: securityv1alpha1.CertificationStatusOfficial,
			DockerHubData: &securityv1alpha1.DockerHubData{
				IsOfficialImage:    true,
				PullCount:          1_000_000,
				LastUpdated:        &now,
				DaysSinceUpdate:    &days,
				PullCountFormatted: "1M",
			},
		},
	}
}

func TestClearDockerHubStatus(t *testing.T) {
	tests := []struct {
		name string
		in   securityv1alpha1.CertificationStatus
		want securityv1alpha1.CertificationStatus
	}{
		{"official", securityv1alpha1.CertificationStatusOfficial, securityv1alpha1.CertificationStatusUnknown},
		{"verified", securityv1alpha1.CertificationStatusVerified, securityv1alpha1.CertificationStatusUnknown},
		{"not certified", securityv1alpha1.CertificationStatusNotCertified, securityv1alpha1.CertificationStatusUnknown},
		{"certified untouched", securityv1alpha1.CertificationStatusCertified, securityv1alpha1.CertificationStatusCertified},
		{"error untouched", securityv1alpha1.CertificationStatusError, securityv1alpha1.CertificationStatusError},
		{"unknown untouched", securityv1alpha1.CertificationStatusUnknown, securityv1alpha1.CertificationStatusUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := staleDockerHubCR()
			cr.Status.CertificationStatus = tt.in

			clearDockerHubStatus(cr)

			if cr.Status.DockerHubData != nil {
				t.Errorf("DockerHubData = %+v, want nil", cr.Status.DockerHubData)
			}
			if cr.Status.CertificationStatus != tt.want {
				t.Errorf("CertificationStatus = %v, want %v", cr.Status.CertificationStatus, tt.want)
			}
		})
	}
}

func TestPodReconciler_CheckDockerHubData_NotFoundClearsStatus(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleDockerHubCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{
		Client:          fakeClient,
		Scheme:          scheme,
		DockerHubClient: &stubDockerHubClient{info: nil},
	}

	ref := &image.Reference{Registry: RegistryDockerHub, Repository: testDockerHubRepository, Digest: testDigest}
	if err := reconciler.checkDockerHubData(ctx, testDockerHubCRName, ref); err != nil {
		t.Fatalf("checkDockerHubData() error = %v, want nil for a missing repository", err)
	}

	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testDockerHubCRName}, &updatedCR); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo: %v", err)
	}

	if updatedCR.Status.DockerHubData != nil {
		t.Errorf("DockerHubData = %+v, want nil", updatedCR.Status.DockerHubData)
	}
	if updatedCR.Status.CertificationStatus != securityv1alpha1.CertificationStatusUnknown {
		t.Errorf("CertificationStatus = %v, want Unknown", updatedCR.Status.CertificationStatus)
	}
}

func TestPodReconciler_CheckDockerHubData_ErrorPreservesStatus(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleDockerHubCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	apiErr := errors.New("docker hub unavailable")
	reconciler := &PodReconciler{
		Client:          fakeClient,
		Scheme:          scheme,
		DockerHubClient: &stubDockerHubClient{err: apiErr},
	}

	ref := &image.Reference{Registry: RegistryDockerHub, Repository: testDockerHubRepository, Digest: testDigest}
	if err := reconciler.checkDockerHubData(ctx, testDockerHubCRName, ref); !errors.Is(err, apiErr) {
		t.Fatalf("checkDockerHubData() error = %v, want %v", err, apiErr)
	}

	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testDockerHubCRName}, &updatedCR); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo: %v", err)
	}

	// A transient failure must not blank good data: the enrichment worker retries.
	if updatedCR.Status.DockerHubData == nil {
		t.Fatal("DockerHubData = nil, want the previous payload preserved")
	}
	if updatedCR.Status.CertificationStatus != securityv1alpha1.CertificationStatusOfficial {
		t.Errorf("CertificationStatus = %v, want Official", updatedCR.Status.CertificationStatus)
	}
}

func TestPodReconciler_RefreshSingleImage_DockerHubNotFoundClearsStatus(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleDockerHubCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{
		Client:          fakeClient,
		Scheme:          scheme,
		DockerHubClient: &stubDockerHubClient{info: nil},
	}

	if err := reconciler.refreshSingleImage(ctx, cr); err != nil {
		t.Fatalf("refreshSingleImage() error = %v", err)
	}

	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testDockerHubCRName}, &updatedCR); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo: %v", err)
	}

	if updatedCR.Status.DockerHubData != nil {
		t.Errorf("DockerHubData = %+v, want nil", updatedCR.Status.DockerHubData)
	}
	if updatedCR.Status.CertificationStatus != securityv1alpha1.CertificationStatusUnknown {
		t.Errorf("CertificationStatus = %v, want Unknown", updatedCR.Status.CertificationStatus)
	}
}

const (
	testQuayCRName     = "quay.io.redhat.ubi9.abc123de"
	testQuayRepository = "redhat/ubi9"
	testQuayScanStatus = "scanned"
	testQuayVendor     = "Red Hat"

	// testCVEAnnotationValue is the CVE list the fixtures carry in the
	// security.telco.openshift.io/cves annotation.
	testCVEAnnotationValue = "CVE-2026-0001,CVE-2026-0002"
	// testCVEHigh is a High-severity CVE used by the Quay scan fixtures.
	testCVEHigh = "CVE-2026-0002"
)

// staleQuayCR returns a quay.io CR whose status carries enrichment data from an
// earlier cycle, including an annotation that a clean scan should remove.
func staleQuayCR() *securityv1alpha1.ImageCertificationInfo {
	now := metav1.Now()
	days := 40
	meta := metav1.ObjectMeta{
		Name:        testQuayCRName,
		Annotations: map[string]string{AnnotationCVEs: testCVEAnnotationValue},
	}

	return &securityv1alpha1.ImageCertificationInfo{
		ObjectMeta: meta,
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        testDigest,
			FullImageReference: "quay.io/" + testQuayRepository + "@" + testDigest,
			Registry:           RegistryQuayIO,
			Repository:         testQuayRepository,
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			RegistryType:        securityv1alpha1.RegistryTypeCommunity,
			CertificationStatus: securityv1alpha1.CertificationStatusUnknown,
			QuayData: &securityv1alpha1.QuayData{
				IsPublic:               true,
				State:                  "NORMAL",
				Description:            "old description",
				TagCount:               3,
				LastModified:           &now,
				DaysSinceUpdate:        &days,
				SecurityScanStatus:     testQuayScanStatus,
				Vulnerabilities:        &securityv1alpha1.VulnerabilitySummary{Critical: 2, Important: 3},
				TotalVulnerabilities:   5,
				FixableVulnerabilities: 4,
				Vendor:                 testQuayVendor,
				Architecture:           "amd64",
				BuildDate:              "2026-01-01",
				LicenseURL:             "https://example.com/license",
				VCSRef:                 "abcdef",
				LayerCount:             7,
				CompressedSizeBytes:    1234,
				IsManifestList:         true,
			},
		},
	}
}

// assertQuayStaleFieldsCleared checks that no Quay-derived value survived a
// successful enrichment that carried no data.
func assertQuayStaleFieldsCleared(t *testing.T, quayData *securityv1alpha1.QuayData) {
	t.Helper()

	if quayData == nil {
		t.Fatal("QuayData = nil, want it present")
	}
	if quayData.LastModified != nil {
		t.Errorf("LastModified = %v, want nil", quayData.LastModified)
	}
	if quayData.DaysSinceUpdate != nil {
		t.Errorf("DaysSinceUpdate = %d, want nil", *quayData.DaysSinceUpdate)
	}
	if quayData.TagCount != 0 {
		t.Errorf("TagCount = %d, want 0", quayData.TagCount)
	}
	if quayData.State != "" {
		t.Errorf("State = %q, want empty", quayData.State)
	}
	if quayData.Description != "" {
		t.Errorf("Description = %q, want empty", quayData.Description)
	}
	if quayData.SecurityScanStatus != "" {
		t.Errorf("SecurityScanStatus = %q, want empty", quayData.SecurityScanStatus)
	}
	if quayData.Vulnerabilities != nil {
		t.Errorf("Vulnerabilities = %+v, want nil", quayData.Vulnerabilities)
	}
	if quayData.TotalVulnerabilities != 0 {
		t.Errorf("TotalVulnerabilities = %d, want 0", quayData.TotalVulnerabilities)
	}
	if quayData.FixableVulnerabilities != 0 {
		t.Errorf("FixableVulnerabilities = %d, want 0", quayData.FixableVulnerabilities)
	}
	if quayData.LayerCount != 0 {
		t.Errorf("LayerCount = %d, want 0", quayData.LayerCount)
	}
	if quayData.CompressedSizeBytes != 0 {
		t.Errorf("CompressedSizeBytes = %d, want 0", quayData.CompressedSizeBytes)
	}
	if quayData.IsManifestList {
		t.Error("IsManifestList = true, want false")
	}

	labels := map[string]string{
		"Vendor":       quayData.Vendor,
		"Architecture": quayData.Architecture,
		"BuildDate":    quayData.BuildDate,
		"LicenseURL":   quayData.LicenseURL,
		"VCSRef":       quayData.VCSRef,
	}
	for name, value := range labels {
		if value != "" {
			t.Errorf("%s = %q, want empty", name, value)
		}
	}
}

func TestPodReconciler_UpdateCRWithQuayData_ClearsTimestampsWhenAbsent(t *testing.T) {
	cr := staleQuayCR()
	reconciler := &PodReconciler{}

	reconciler.updateCRWithQuayData(cr, &quaylib.RepositoryWithTags{})

	quayData := cr.Status.QuayData
	if quayData.LastModified != nil {
		t.Errorf("LastModified = %v, want nil when the API reports no tag", quayData.LastModified)
	}
	if quayData.DaysSinceUpdate != nil {
		t.Errorf("DaysSinceUpdate = %d, want nil when the API reports no tag", *quayData.DaysSinceUpdate)
	}
	if quayData.TagCount != 0 {
		t.Errorf("TagCount = %d, want 0", quayData.TagCount)
	}
	if quayData.State != "" || quayData.Description != "" {
		t.Errorf("State/Description = %q/%q, want empty", quayData.State, quayData.Description)
	}
}

func TestPodReconciler_UpdateCRWithQuayData_PreservesEnrichmentFields(t *testing.T) {
	cr := staleQuayCR()
	reconciler := &PodReconciler{}

	reconciler.updateCRWithQuayData(cr, &quaylib.RepositoryWithTags{})

	// The helpers own these fields; this function must not blank them, or a
	// failed scan would erase a good summary.
	quayData := cr.Status.QuayData
	if quayData.SecurityScanStatus != testQuayScanStatus {
		t.Errorf("SecurityScanStatus = %q, want scanned", quayData.SecurityScanStatus)
	}
	if quayData.Vulnerabilities == nil || quayData.Vulnerabilities.Critical != 2 {
		t.Errorf("Vulnerabilities = %+v, want Critical 2 preserved", quayData.Vulnerabilities)
	}
	if quayData.LayerCount != 7 {
		t.Errorf("LayerCount = %d, want 7 preserved", quayData.LayerCount)
	}
	if quayData.Vendor != testQuayVendor {
		t.Errorf("Vendor = %q, want preserved", quayData.Vendor)
	}
}

func TestPodReconciler_EnrichQuaySecurity_SuccessNoDataClearsCounts(t *testing.T) {
	ctx := context.Background()
	cr := staleQuayCR()
	reconciler := &PodReconciler{QuayClient: &stubQuayClient{scan: &quaylib.SecurityScan{Status: "queued"}}}

	cves, ok := reconciler.enrichQuaySecurity(ctx, cr, "redhat", "ubi9", testDigest)

	if !ok {
		t.Fatal("ok = false, want true for a successful request")
	}
	if len(cves) != 0 {
		t.Errorf("cves = %v, want empty", cves)
	}

	quayData := cr.Status.QuayData
	if quayData.SecurityScanStatus != "queued" {
		t.Errorf("SecurityScanStatus = %q, want queued", quayData.SecurityScanStatus)
	}
	if quayData.Vulnerabilities != nil {
		t.Errorf("Vulnerabilities = %+v, want nil", quayData.Vulnerabilities)
	}
	if quayData.TotalVulnerabilities != 0 || quayData.FixableVulnerabilities != 0 {
		t.Errorf("Total/Fixable = %d/%d, want 0/0",
			quayData.TotalVulnerabilities, quayData.FixableVulnerabilities)
	}
}

func TestPodReconciler_EnrichQuaySecurity_ErrorPreservesCounts(t *testing.T) {
	ctx := context.Background()
	cr := staleQuayCR()
	reconciler := &PodReconciler{QuayClient: &stubQuayClient{scanErr: errors.New("clair unavailable")}}

	_, ok := reconciler.enrichQuaySecurity(ctx, cr, "redhat", "ubi9", testDigest)

	if ok {
		t.Fatal("ok = true, want false for a failed request")
	}

	quayData := cr.Status.QuayData
	if quayData.Vulnerabilities == nil || quayData.Vulnerabilities.Critical != 2 {
		t.Errorf("Vulnerabilities = %+v, want the previous summary preserved", quayData.Vulnerabilities)
	}
	if quayData.SecurityScanStatus != testQuayScanStatus {
		t.Errorf("SecurityScanStatus = %q, want scanned preserved", quayData.SecurityScanStatus)
	}
}

func TestPodReconciler_EnrichQuayManifest_SuccessNilClearsFields(t *testing.T) {
	ctx := context.Background()
	cr := staleQuayCR()
	reconciler := &PodReconciler{QuayClient: &stubQuayClient{}}

	if ok := reconciler.enrichQuayManifest(ctx, cr, "redhat", "ubi9", testDigest); !ok {
		t.Fatal("ok = false, want true")
	}

	quayData := cr.Status.QuayData
	if quayData.LayerCount != 0 || quayData.CompressedSizeBytes != 0 || quayData.IsManifestList {
		t.Errorf("manifest fields = %d/%d/%v, want zeroed",
			quayData.LayerCount, quayData.CompressedSizeBytes, quayData.IsManifestList)
	}
}

func TestPodReconciler_EnrichQuayManifest_ErrorPreservesFields(t *testing.T) {
	ctx := context.Background()
	cr := staleQuayCR()
	reconciler := &PodReconciler{QuayClient: &stubQuayClient{manifestErr: errors.New("boom")}}

	if ok := reconciler.enrichQuayManifest(ctx, cr, "redhat", "ubi9", testDigest); ok {
		t.Fatal("ok = true, want false")
	}
	if cr.Status.QuayData.LayerCount != 7 {
		t.Errorf("LayerCount = %d, want 7 preserved", cr.Status.QuayData.LayerCount)
	}
}

func TestPodReconciler_EnrichQuayLabels_SuccessResetsDroppedLabels(t *testing.T) {
	ctx := context.Background()
	cr := staleQuayCR()
	reconciler := &PodReconciler{QuayClient: &stubQuayClient{
		labels: &quaylib.ManifestLabels{
			Labels: []quaylib.ManifestLabel{{Key: "vendor", Value: "Red Hat, Inc."}},
		},
	}}

	if ok := reconciler.enrichQuayLabels(ctx, cr, "redhat", "ubi9", testDigest); !ok {
		t.Fatal("ok = false, want true")
	}

	quayData := cr.Status.QuayData
	if quayData.Vendor != "Red Hat, Inc." {
		t.Errorf("Vendor = %q, want the label value", quayData.Vendor)
	}
	if quayData.Architecture != "" || quayData.BuildDate != "" || quayData.LicenseURL != "" || quayData.VCSRef != "" {
		t.Errorf("dropped labels survived: %q/%q/%q/%q",
			quayData.Architecture, quayData.BuildDate, quayData.LicenseURL, quayData.VCSRef)
	}
}

func TestPodReconciler_EnrichQuayLabels_ErrorPreservesLabels(t *testing.T) {
	ctx := context.Background()
	cr := staleQuayCR()
	reconciler := &PodReconciler{QuayClient: &stubQuayClient{labelsErr: errors.New("boom")}}

	if ok := reconciler.enrichQuayLabels(ctx, cr, "redhat", "ubi9", testDigest); ok {
		t.Fatal("ok = true, want false")
	}
	if cr.Status.QuayData.Vendor != testQuayVendor {
		t.Errorf("Vendor = %q, want Red Hat preserved", cr.Status.QuayData.Vendor)
	}
}

func TestPodReconciler_CheckQuayData_EmptyRepositoryResponseClearsRepoFields(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleQuayCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{Client: fakeClient, Scheme: scheme, QuayClient: &stubQuayClient{}}

	ref := &image.Reference{Registry: RegistryQuayIO, Repository: testQuayRepository, Digest: testDigest}
	if err := reconciler.checkQuayData(ctx, testQuayCRName, ref); err != nil {
		t.Fatalf("checkQuayData() error = %v", err)
	}

	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testQuayCRName}, &updatedCR); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo: %v", err)
	}

	assertQuayStaleFieldsCleared(t, updatedCR.Status.QuayData)
}

func TestPodReconciler_RefreshSingleImage_QuayEmptyRepositoryResponseClearsRepoFields(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleQuayCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{Client: fakeClient, Scheme: scheme, QuayClient: &stubQuayClient{}}

	if err := reconciler.refreshSingleImage(ctx, cr); err != nil {
		t.Fatalf("refreshSingleImage() error = %v", err)
	}

	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testQuayCRName}, &updatedCR); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo: %v", err)
	}

	assertQuayStaleFieldsCleared(t, updatedCR.Status.QuayData)
}

func TestPodReconciler_CheckQuayData_SecurityErrorPreservesPreviousSummary(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleQuayCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		QuayClient: &stubQuayClient{scanErr: errors.New("clair unavailable")},
	}

	ref := &image.Reference{Registry: RegistryQuayIO, Repository: testQuayRepository, Digest: testDigest}
	if err := reconciler.checkQuayData(ctx, testQuayCRName, ref); err == nil {
		t.Fatal("checkQuayData() error = nil, want a retryable error")
	}

	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testQuayCRName}, &updatedCR); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo: %v", err)
	}

	quayData := updatedCR.Status.QuayData
	if quayData == nil || quayData.Vulnerabilities == nil {
		t.Fatal("Vulnerabilities = nil, want the previous summary preserved")
	}
	if quayData.Vulnerabilities.Critical != 2 || quayData.TotalVulnerabilities != 5 {
		t.Errorf("Vulnerabilities = %+v total %d, want Critical 2 total 5",
			quayData.Vulnerabilities, quayData.TotalVulnerabilities)
	}
}

// quayScanWith builds a successful Clair scan result carrying the given
// severities, in order.
func quayScanWith(vulns ...quaylib.SecurityVulnerability) *quaylib.SecurityScan {
	return &quaylib.SecurityScan{
		Status: testQuayScanStatus,
		Data: &quaylib.SecurityData{
			Layer: &quaylib.SecurityLayer{
				Features: []quaylib.SecurityFeature{{Vulnerabilities: vulns}},
			},
		},
	}
}

// cveAnnotation returns the stored CVE annotation and whether it is present.
func cveAnnotation(t *testing.T, c client.Client) (string, bool) {
	t.Helper()

	var cr securityv1alpha1.ImageCertificationInfo
	if err := c.Get(context.Background(), client.ObjectKey{Name: testQuayCRName}, &cr); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo: %v", err)
	}

	value, ok := cr.Annotations[AnnotationCVEs]

	return value, ok
}

func TestPodReconciler_EnrichQuaySecurity_IncludesHighCVEs(t *testing.T) {
	ctx := context.Background()
	cr := staleQuayCR()
	reconciler := &PodReconciler{QuayClient: &stubQuayClient{scan: quayScanWith(
		quaylib.SecurityVulnerability{Name: "CVE-2026-0001", Severity: "Critical"},
		quaylib.SecurityVulnerability{Name: testCVEHigh, Severity: "High"},
	)}}

	cves, ok := reconciler.enrichQuaySecurity(ctx, cr, "redhat", "ubi9", testDigest)

	if !ok {
		t.Fatal("ok = false, want true")
	}
	if len(cves) != 2 || cves[0] != "CVE-2026-0001" || cves[1] != testCVEHigh {
		t.Errorf("cves = %v, want both the Critical and the High CVE", cves)
	}

	vulns := cr.Status.QuayData.Vulnerabilities
	if vulns == nil || vulns.Critical != 1 || vulns.Important != 1 {
		t.Errorf("Vulnerabilities = %+v, want Critical 1 Important 1", vulns)
	}
}

func TestPodReconciler_CheckQuayData_CleanScanClearsCVEAnnotation(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleQuayCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	// A successful scan that reports no vulnerabilities at all.
	reconciler := &PodReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		QuayClient: &stubQuayClient{scan: &quaylib.SecurityScan{Status: testQuayScanStatus}},
	}

	ref := &image.Reference{Registry: RegistryQuayIO, Repository: testQuayRepository, Digest: testDigest}
	if err := reconciler.checkQuayData(ctx, testQuayCRName, ref); err != nil {
		t.Fatalf("checkQuayData() error = %v", err)
	}

	if value, ok := cveAnnotation(t, fakeClient); ok {
		t.Errorf("annotation %s = %q, want removed", AnnotationCVEs, value)
	}
}

func TestPodReconciler_RefreshSingleImage_QuayCleanScanClearsCVEAnnotation(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleQuayCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		QuayClient: &stubQuayClient{scan: &quaylib.SecurityScan{Status: testQuayScanStatus}},
	}

	if err := reconciler.refreshSingleImage(ctx, cr); err != nil {
		t.Fatalf("refreshSingleImage() error = %v", err)
	}

	if value, ok := cveAnnotation(t, fakeClient); ok {
		t.Errorf("annotation %s = %q, want removed", AnnotationCVEs, value)
	}
}

func TestPodReconciler_CheckQuayData_HighCVEsWrittenToAnnotation(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleQuayCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{
		Client: fakeClient,
		Scheme: scheme,
		QuayClient: &stubQuayClient{scan: quayScanWith(
			quaylib.SecurityVulnerability{Name: testCVEHigh, Severity: "High"},
		)},
	}

	ref := &image.Reference{Registry: RegistryQuayIO, Repository: testQuayRepository, Digest: testDigest}
	if err := reconciler.checkQuayData(ctx, testQuayCRName, ref); err != nil {
		t.Fatalf("checkQuayData() error = %v", err)
	}

	value, ok := cveAnnotation(t, fakeClient)
	if !ok {
		t.Fatalf("annotation %s missing, want it to name the High CVE", AnnotationCVEs)
	}
	if value != testCVEHigh {
		t.Errorf("annotation = %q, want CVE-2026-0002", value)
	}
}

func TestPodReconciler_CheckQuayData_ScanErrorLeavesAnnotation(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleQuayCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		QuayClient: &stubQuayClient{scanErr: errors.New("clair unavailable")},
	}

	ref := &image.Reference{Registry: RegistryQuayIO, Repository: testQuayRepository, Digest: testDigest}
	if err := reconciler.checkQuayData(ctx, testQuayCRName, ref); err == nil {
		t.Fatal("checkQuayData() error = nil, want a retryable error")
	}

	value, ok := cveAnnotation(t, fakeClient)
	if !ok {
		t.Fatal("annotation removed, want it preserved across a failed scan")
	}
	if value != testCVEAnnotationValue {
		t.Errorf("annotation = %q, want the previous list", value)
	}
}

func TestPodReconciler_RefreshSingleImage_QuayScanErrorLeavesAnnotation(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleQuayCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		QuayClient: &stubQuayClient{scanErr: errors.New("clair unavailable")},
	}

	if err := reconciler.refreshSingleImage(ctx, cr); err == nil {
		t.Fatal("refreshSingleImage() error = nil, want the enrichment failure reported")
	}

	value, ok := cveAnnotation(t, fakeClient)
	if !ok {
		t.Fatal("annotation removed, want it preserved across a failed scan")
	}
	if value != testCVEAnnotationValue {
		t.Errorf("annotation = %q, want the previous list", value)
	}
}

func TestPodReconciler_CheckQuayData_EmptyDigestLeavesAnnotation(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleQuayCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	quayClient := &stubQuayClient{scan: &quaylib.SecurityScan{Status: testQuayScanStatus}}
	reconciler := &PodReconciler{Client: fakeClient, Scheme: scheme, QuayClient: quayClient}

	ref := &image.Reference{Registry: RegistryQuayIO, Repository: testQuayRepository}
	if err := reconciler.checkQuayData(ctx, testQuayCRName, ref); err != nil {
		t.Fatalf("checkQuayData() error = %v", err)
	}

	if quayClient.scanCalled {
		t.Error("GetManifestSecurity was called without a digest")
	}
	if value, ok := cveAnnotation(t, fakeClient); !ok {
		t.Error("annotation removed, want it left alone when no scan is attempted")
	} else if value != testCVEAnnotationValue {
		t.Errorf("annotation = %q, want the previous list", value)
	}
}

func TestPodReconciler_RefreshSingleImage_QuayEmptyDigestLeavesAnnotation(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleQuayCR()
	cr.Spec.ImageDigest = ""

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	quayClient := &stubQuayClient{scan: &quaylib.SecurityScan{Status: testQuayScanStatus}}
	reconciler := &PodReconciler{Client: fakeClient, Scheme: scheme, QuayClient: quayClient}

	if err := reconciler.refreshSingleImage(ctx, cr); err != nil {
		t.Fatalf("refreshSingleImage() error = %v", err)
	}

	if quayClient.scanCalled {
		t.Error("GetManifestSecurity was called without a digest")
	}
	if value, ok := cveAnnotation(t, fakeClient); !ok {
		t.Error("annotation removed, want it left alone when no scan is attempted")
	} else if value != testCVEAnnotationValue {
		t.Errorf("annotation = %q, want the previous list", value)
	}
}

// quayDeniedError builds the authorization error Quay returns for repositories
// the token may not see.
func quayDeniedError() error {
	return &quaylib.QuayError{Status: http.StatusUnauthorized, Message: "Requires authentication"}
}

func TestPodReconciler_CheckQuayData_UnauthorizedKeepsPreviousEnrichment(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleQuayCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		QuayClient: &stubQuayClient{err: quayDeniedError()},
	}

	ref := &image.Reference{Registry: RegistryQuayIO, Repository: testQuayRepository, Digest: testDigest}
	err := reconciler.checkQuayData(ctx, testQuayCRName, ref)
	if err == nil {
		t.Fatal("checkQuayData() error = nil, want the authorization failure reported")
	}

	if _, ok := errors.AsType[*permanentError](err); !ok {
		t.Errorf("error = %T, want a permanent failure so the worker stops retrying", err)
	}
	if !isQuayDenied(err) {
		t.Errorf("isQuayDenied() = false for %v", err)
	}

	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testQuayCRName}, &updatedCR); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo: %v", err)
	}

	// A 401 is not proof of a deleted repository, so nothing may be cleared.
	quayData := updatedCR.Status.QuayData
	if quayData == nil || quayData.Vulnerabilities == nil || quayData.Vulnerabilities.Critical != 2 {
		t.Errorf("Vulnerabilities = %+v, want the previous summary preserved", quayData)
	}
	if quayData.LastModified == nil {
		t.Error("LastModified = nil, want the previous value preserved")
	}
	if value, ok := cveAnnotation(t, fakeClient); !ok || value != testCVEAnnotationValue {
		t.Errorf("annotation = %q/%v, want %q preserved", value, ok, testCVEAnnotationValue)
	}
}

func TestPodReconciler_RefreshSingleImage_QuayUnauthorizedKeepsPreviousEnrichment(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()
	cr := staleQuayCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{
		Client:     fakeClient,
		Scheme:     scheme,
		QuayClient: &stubQuayClient{err: quayDeniedError()},
	}

	err := reconciler.refreshSingleImage(ctx, cr)

	if _, ok := errors.AsType[*permanentError](err); !ok {
		t.Fatalf("refreshSingleImage() error = %v, want a permanent failure", err)
	}

	var updatedCR securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: testQuayCRName}, &updatedCR); err != nil {
		t.Fatalf("failed to get ImageCertificationInfo: %v", err)
	}

	if updatedCR.Status.QuayData == nil || updatedCR.Status.QuayData.Vulnerabilities == nil {
		t.Fatal("Vulnerabilities = nil, want the previous summary preserved")
	}
	if updatedCR.Status.QuayData.Vulnerabilities.Critical != 2 {
		t.Errorf("Critical = %d, want 2 preserved", updatedCR.Status.QuayData.Vulnerabilities.Critical)
	}
}

// newQuayEnrichmentReconciler returns a reconciler whose queue feeds a single
// quay.io CR.
func newQuayEnrichmentReconciler(t *testing.T, quayClient quaylib.RepositoryReader) *PodReconciler {
	t.Helper()

	scheme := newTestScheme()
	cr := staleQuayCR()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	reconciler := &PodReconciler{Client: fakeClient, Scheme: scheme, QuayClient: quayClient}
	reconciler.EnrichQueue = newEnrichQueue()

	return reconciler
}

func TestProcessEnrichRequest_PermanentFailureIsNotRequeued(t *testing.T) {
	item := enrichRequest{
		crName: testQuayCRName,
		ref: image.Reference{
			Registry:   RegistryQuayIO,
			Repository: testQuayRepository,
			Digest:     testDigest,
		},
	}

	tests := []struct {
		name         string
		err          error
		wantRequeues int
	}{
		{"authorization denial is not retried", quayDeniedError(), 0},
		{"transient failure is retried", errors.New("quay unavailable"), 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler := newQuayEnrichmentReconciler(t, &stubQuayClient{err: tt.err})
			defer reconciler.EnrichQueue.ShutDown()

			reconciler.processEnrichRequest(context.Background(), item)

			if got := reconciler.EnrichQueue.NumRequeues(item); got != tt.wantRequeues {
				t.Errorf("NumRequeues() = %d, want %d", got, tt.wantRequeues)
			}
		})
	}
}
