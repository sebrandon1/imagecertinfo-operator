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
