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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/sebrandon1/imagecertinfo-operator/api/v1alpha1"
	"github.com/sebrandon1/imagecertinfo-operator/pkg/pyxis"
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
	testDigest := "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "test-container",
					Image: "registry.redhat.io/ubi8/ubi:latest",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:    "test-container",
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
		NamespacedName: types.NamespacedName{
			Name:      "test-pod",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.Requeue {
		t.Error("Reconcile() returned Requeue = true, want false")
	}

	// Verify ImageCertificationInfo was created
	// Expected name format: registry.redhat.io.ubi8.ubi.abc123de (first 8 chars of digest)
	expectedCRName := "registry.redhat.io.ubi8.ubi.abc123de"
	var cr securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: expectedCRName}, &cr); err != nil {
		t.Fatalf("Failed to get ImageCertificationInfo: %v", err)
	}

	// Verify spec fields
	if cr.Spec.ImageDigest != testDigest {
		t.Errorf("ImageDigest = %v, want %v", cr.Spec.ImageDigest, testDigest)
	}
	if cr.Spec.Registry != "registry.redhat.io" {
		t.Errorf("Registry = %v, want registry.redhat.io", cr.Spec.Registry)
	}
	if cr.Spec.Repository != "ubi8/ubi" {
		t.Errorf("Repository = %v, want ubi8/ubi", cr.Spec.Repository)
	}

	// Verify status fields
	if cr.Status.RegistryType != securityv1alpha1.RegistryTypeRedHat {
		t.Errorf("RegistryType = %v, want %v", cr.Status.RegistryType, securityv1alpha1.RegistryTypeRedHat)
	}
	if len(cr.Status.PodReferences) != 1 {
		t.Fatalf("PodReferences count = %v, want 1", len(cr.Status.PodReferences))
	}
	if cr.Status.PodReferences[0].Name != "test-pod" {
		t.Errorf("PodReference.Name = %v, want test-pod", cr.Status.PodReferences[0].Name)
	}
	if cr.Status.PodReferences[0].Namespace != "default" {
		t.Errorf("PodReference.Namespace = %v, want default", cr.Status.PodReferences[0].Namespace)
	}
	if cr.Status.PodReferences[0].Container != "test-container" {
		t.Errorf("PodReference.Container = %v, want test-container", cr.Status.PodReferences[0].Container)
	}
}

func TestPodReconciler_Reconcile_ExistingCR(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	testDigest := "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
	// Use the new human-readable CR name format
	crName := "registry.redhat.io.ubi8.ubi.abc123de"

	// Create existing ImageCertificationInfo
	now := metav1.Now()
	existingCR := &securityv1alpha1.ImageCertificationInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crName,
		},
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        testDigest,
			FullImageReference: "registry.redhat.io/ubi8/ubi@" + testDigest,
			Registry:           "registry.redhat.io",
			Repository:         "ubi8/ubi",
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			RegistryType:        securityv1alpha1.RegistryTypeRedHat,
			CertificationStatus: securityv1alpha1.CertificationStatusUnknown,
			PodReferences: []securityv1alpha1.PodReference{
				{
					Namespace: "default",
					Name:      "existing-pod",
					Container: "existing-container",
				},
			},
			FirstSeenAt: &now,
			LastSeenAt:  &now,
		},
	}

	// Create a new pod that uses the same image
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-pod",
			Namespace: "default",
		},
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
		WithObjects(existingCR, testPod).
		WithStatusSubresource(existingCR).
		Build()

	reconciler := &PodReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	// Reconcile the new pod
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "new-pod",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.Requeue {
		t.Error("Reconcile() returned Requeue = true, want false")
	}

	// Verify ImageCertificationInfo was updated with new pod reference
	var cr securityv1alpha1.ImageCertificationInfo
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		t.Fatalf("Failed to get ImageCertificationInfo: %v", err)
	}

	// Should now have 2 pod references
	if len(cr.Status.PodReferences) != 2 {
		t.Errorf("PodReferences count = %v, want 2", len(cr.Status.PodReferences))
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
		NamespacedName: types.NamespacedName{
			Name:      "deleted-pod",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.Requeue {
		t.Error("Reconcile() returned Requeue = true, want false")
	}
}

func TestPodReconciler_Reconcile_PodNotRunning(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	// Create a pod that is not running
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "completed-pod",
			Namespace: "default",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodSucceeded,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testPod).
		Build()

	reconciler := &PodReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "completed-pod",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.Requeue {
		t.Error("Reconcile() returned Requeue = true, want false")
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

	testDigest := "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
	// Use the new human-readable CR name format
	crName := "registry.redhat.io.ubi8.ubi.abc123de"

	// Create existing pod
	existingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-pod",
			Namespace: "default",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	// Create ImageCertificationInfo with references to existing and deleted pods
	now := metav1.Now()
	existingCR := &securityv1alpha1.ImageCertificationInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crName,
		},
		Spec: securityv1alpha1.ImageCertificationInfoSpec{
			ImageDigest:        testDigest,
			FullImageReference: "registry.redhat.io/ubi8/ubi@" + testDigest,
			Registry:           "registry.redhat.io",
			Repository:         "ubi8/ubi",
		},
		Status: securityv1alpha1.ImageCertificationInfoStatus{
			RegistryType:        securityv1alpha1.RegistryTypeRedHat,
			CertificationStatus: securityv1alpha1.CertificationStatusUnknown,
			PodReferences: []securityv1alpha1.PodReference{
				{
					Namespace: "default",
					Name:      "existing-pod",
					Container: "container1",
				},
				{
					Namespace: "default",
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
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: crName}, &cr); err != nil {
		t.Fatalf("Failed to get ImageCertificationInfo: %v", err)
	}

	if len(cr.Status.PodReferences) != 1 {
		t.Errorf("PodReferences count = %v, want 1", len(cr.Status.PodReferences))
	}
	if cr.Status.PodReferences[0].Name != "existing-pod" {
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
