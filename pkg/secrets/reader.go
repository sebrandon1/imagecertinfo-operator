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
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SecretReader provides methods to read secrets from Kubernetes.
type SecretReader struct {
	client client.Client
}

// NewSecretReader creates a new SecretReader with the given client.
func NewSecretReader(c client.Client) *SecretReader {
	return &SecretReader{client: c}
}

// ReadAPIKey reads an API key from a Kubernetes Secret.
// Returns the API key value or an error if the secret or key is not found.
func (r *SecretReader) ReadAPIKey(ctx context.Context, namespace, secretName, secretKey string) (string, error) {
	if namespace == "" || secretName == "" || secretKey == "" {
		return "", fmt.Errorf("namespace, secret name, and secret key must all be specified")
	}

	secret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      secretName,
	}, secret); err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", namespace, secretName, err)
	}

	data, ok := secret.Data[secretKey]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", secretKey, namespace, secretName)
	}

	return string(data), nil
}

// KeyRotation configures periodic re-reading of a Secret-backed API key.
type KeyRotation struct {
	Namespace  string
	SecretName string
	SecretKey  string
	// Interval is how often the Secret is re-read. A non-positive value
	// disables rotation.
	Interval time.Duration
	// Initial is the value read at startup, so the loop reports actual changes
	// rather than the initial read.
	Initial string
	// OnRotate receives the new key when it differs from the previous value.
	OnRotate func(key string)
}

// StartRotationLoop re-reads the API key Secret every Interval until ctx is
// cancelled, calling OnRotate when the value changes. It blocks, so it can be
// registered as a manager Runnable.
//
// A failed read keeps the previous key: a transient API error must not drop
// authentication. Rotation is polled rather than watched because the shipped
// RBAC grants get on a single Secret by name, and list/watch cannot be
// restricted with resourceNames - a watch would need read access to every
// Secret in the namespace.
func (r *SecretReader) StartRotationLoop(ctx context.Context, cfg KeyRotation) error {
	if cfg.Interval <= 0 || cfg.OnRotate == nil {
		return nil
	}

	current := cfg.Initial

	reload := func() {
		apiKey, err := r.ReadAPIKey(ctx, cfg.Namespace, cfg.SecretName, cfg.SecretKey)
		if err != nil {
			return
		}

		if apiKey == current {
			return
		}

		current = apiKey
		cfg.OnRotate(apiKey)
	}

	// Read once immediately so a replica that has just become leader picks up a
	// rotation that happened while it was idle.
	reload()

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			reload()
		}
	}
}
