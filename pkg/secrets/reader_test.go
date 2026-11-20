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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace = "imagecertinfo-operator-system"
	testSecret    = "pyxis-api-key"
	testKey       = "api-key"
)

func newTestReader(objects ...*corev1.Secret) *SecretReader {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		panic(err)
	}

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, obj := range objects {
		builder = builder.WithObjects(obj)
	}

	return NewSecretReader(builder.Build())
}

func secretWith(data map[string][]byte) *corev1.Secret {
	secret := &corev1.Secret{Data: data}
	secret.Name = testSecret
	secret.Namespace = testNamespace

	return secret
}
func TestReadAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		reader  *SecretReader
		key     string
		want    string
		wantErr string
	}{
		{
			name:   "returns the key when the secret and key exist",
			reader: newTestReader(secretWith(map[string][]byte{testKey: []byte("s3cret")})),
			key:    testKey,
			want:   "s3cret",
		},
		{
			name:   "returns an empty key when the value is empty",
			reader: newTestReader(secretWith(map[string][]byte{testKey: {}})),
			key:    testKey,
			want:   "",
		},
		{
			name:    "reports a missing secret",
			reader:  newTestReader(),
			key:     testKey,
			wantErr: "failed to get secret",
		},
		{
			name:    "reports a missing key",
			reader:  newTestReader(secretWith(map[string][]byte{"other": []byte("value")})),
			key:     testKey,
			wantErr: `key "api-key" not found`,
		},
		{
			name:    "reports a key the secret does not have",
			reader:  newTestReader(secretWith(map[string][]byte{testKey: []byte("value")})),
			key:     "missing",
			wantErr: `key "missing" not found`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.reader.ReadAPIKey(context.Background(), testNamespace, testSecret, tt.key)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ReadAPIKey() error = nil, want an error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ReadAPIKey() error = %q, want it to contain %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ReadAPIKey() error = %v, want nil", err)
			}
			if got != tt.want {
				t.Errorf("ReadAPIKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadAPIKey_MissingSecretIsNotFound(t *testing.T) {
	reader := newTestReader()

	_, err := reader.ReadAPIKey(context.Background(), testNamespace, testSecret, testKey)
	if !apierrors.IsNotFound(err) {
		// The wrapped error must stay inspectable: main.go branches on IsForbidden
		// and callers may branch on IsNotFound.
		t.Errorf("ReadAPIKey() error = %v, want it to satisfy apierrors.IsNotFound", err)
	}
}

func TestReadAPIKey_RequiresAllArguments(t *testing.T) {
	reader := newTestReader(secretWith(map[string][]byte{testKey: []byte("s3cret")}))

	tests := []struct {
		name      string
		namespace string
		secret    string
		key       string
	}{
		{name: "empty namespace", namespace: "", secret: testSecret, key: testKey},
		{name: "empty secret name", namespace: testNamespace, secret: "", key: testKey},
		{name: "empty key", namespace: testNamespace, secret: testSecret, key: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := reader.ReadAPIKey(context.Background(), tt.namespace, tt.secret, tt.key)
			if err == nil {
				t.Fatal("ReadAPIKey() error = nil, want a validation error")
			}
			if !strings.Contains(err.Error(), "must all be specified") {
				t.Errorf("ReadAPIKey() error = %q, want it to mention the required arguments", err)
			}
		})
	}
}
