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

package secrets

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	rotationNamespace = "imagecertinfo-operator-system"
	rotationSecret    = "pyxis-api-key"
	rotationKey       = "api-key"
)

// rotationReader builds a SecretReader over a fake client seeded with one
// Secret holding value under rotationKey.
func rotationReader(value string) (*SecretReader, client.Client) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		panic(err)
	}

	secret := &corev1.Secret{Data: map[string][]byte{rotationKey: []byte(value)}}
	secret.Name = rotationSecret
	secret.Namespace = rotationNamespace

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	return NewSecretReader(fakeClient), fakeClient
}

func rotationConfig(onRotate func(string)) KeyRotation {
	return KeyRotation{
		Namespace:  rotationNamespace,
		SecretName: rotationSecret,
		SecretKey:  rotationKey,
		Interval:   5 * time.Millisecond,
		OnRotate:   onRotate,
	}
}

func TestStartRotationLoop(t *testing.T) {
	t.Run("reports a changed key", func(t *testing.T) {
		reader, fakeClient := rotationReader("old")

		rotated := make(chan string, 1)
		config := rotationConfig(func(key string) { rotated <- key })
		config.Initial = "old"

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan error, 1)
		go func() { done <- reader.StartRotationLoop(ctx, config) }()

		updated := &corev1.Secret{Data: map[string][]byte{rotationKey: []byte("new")}}
		updated.Name = rotationSecret
		updated.Namespace = rotationNamespace
		if err := fakeClient.Update(context.Background(), updated); err != nil {
			t.Fatalf("update secret: %v", err)
		}

		select {
		case got := <-rotated:
			if got != "new" {
				t.Errorf("OnRotate(%q), want new", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("OnRotate was not called after the Secret changed")
		}

		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("StartRotationLoop() error = %v, want nil", err)
			}
		case <-time.After(time.Second):
			t.Fatal("StartRotationLoop() did not return after the context was cancelled")
		}
	})

	t.Run("does not report an unchanged key", func(t *testing.T) {
		reader, _ := rotationReader("same")

		calls := make(chan string, 4)
		config := rotationConfig(func(key string) { calls <- key })
		config.Initial = "same"

		ctx := t.Context()

		go func() { _ = reader.StartRotationLoop(ctx, config) }()

		select {
		case got := <-calls:
			t.Errorf("OnRotate(%q) called for an unchanged key", got)
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("keeps the previous key when the read fails", func(t *testing.T) {
		reader, fakeClient := rotationReader("previous")

		// Remove the Secret so every read fails.
		secret := &corev1.Secret{}
		secret.Name = rotationSecret
		secret.Namespace = rotationNamespace
		if err := fakeClient.Delete(context.Background(), secret); err != nil {
			t.Fatalf("delete secret: %v", err)
		}

		calls := make(chan string, 4)
		config := rotationConfig(func(key string) { calls <- key })
		config.Initial = "previous"

		ctx := t.Context()

		go func() { _ = reader.StartRotationLoop(ctx, config) }()

		select {
		case got := <-calls:
			t.Errorf("OnRotate(%q) called after a failed read, want the previous key kept", got)
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("non-positive interval returns immediately", func(t *testing.T) {
		reader, _ := rotationReader("value")

		config := rotationConfig(func(string) {})
		config.Interval = 0

		done := make(chan error, 1)
		go func() { done <- reader.StartRotationLoop(context.Background(), config) }()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("StartRotationLoop() error = %v, want nil", err)
			}
		case <-time.After(time.Second):
			t.Fatal("StartRotationLoop() blocked with a non-positive interval")
		}
	})

	t.Run("nil callback returns immediately", func(t *testing.T) {
		reader, _ := rotationReader("value")

		config := rotationConfig(nil)
		config.Interval = time.Minute

		done := make(chan error, 1)
		go func() { done <- reader.StartRotationLoop(context.Background(), config) }()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("StartRotationLoop() error = %v, want nil", err)
			}
		case <-time.After(time.Second):
			t.Fatal("StartRotationLoop() blocked without a callback")
		}
	})
}
