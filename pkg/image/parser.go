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

package image

import (
	"fmt"
	"slices"
	"strings"

	securityv1alpha1 "github.com/sebrandon1/imagecertinfo-operator/api/v1alpha1"
)

// Reference contains parsed image reference components
type Reference struct {
	// Registry is the container registry hostname
	Registry string
	// Repository is the image repository path
	Repository string
	// Tag is the image tag (if available)
	Tag string
	// Digest is the image digest (sha256:...)
	Digest string
	// FullReference is the complete image reference
	FullReference string
}

// ParseImageID parses a container status imageID into its components.
// imageID format is typically: registry/repo@sha256:digest or docker-pullable://registry/repo@sha256:digest
func ParseImageID(imageID string) (*Reference, error) {
	if imageID == "" {
		return nil, fmt.Errorf("empty imageID")
	}

	// Remove docker-pullable:// or docker:// prefix if present
	imageID = strings.TrimPrefix(imageID, "docker-pullable://")
	imageID = strings.TrimPrefix(imageID, "docker://")

	ref := &Reference{
		FullReference: imageID,
	}

	// Split by @ to separate the digest
	parts := strings.Split(imageID, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("imageID does not contain digest: %s", imageID)
	}

	ref.Digest = parts[1]
	imageWithoutDigest := parts[0]

	// Check for tag in the image reference
	if colonIdx := strings.LastIndex(imageWithoutDigest, ":"); colonIdx != -1 {
		// Make sure the colon is not part of a port number
		afterColon := imageWithoutDigest[colonIdx+1:]
		if !strings.Contains(afterColon, "/") {
			ref.Tag = afterColon
			imageWithoutDigest = imageWithoutDigest[:colonIdx]
		}
	}

	// Parse registry and repository
	// First slash typically separates registry from repository
	before, after, ok := strings.Cut(imageWithoutDigest, "/")
	if !ok {
		// No slash means it's a docker.io library image
		ref.Registry = "docker.io"
		ref.Repository = "library/" + imageWithoutDigest
	} else {
		possibleRegistry := before
		// Check if the first part is a registry (contains . or : or is localhost)
		if strings.Contains(possibleRegistry, ".") ||
			strings.Contains(possibleRegistry, ":") ||
			possibleRegistry == "localhost" {
			ref.Registry = possibleRegistry
			ref.Repository = after
		} else {
			// No registry specified, assume docker.io
			ref.Registry = "docker.io"
			ref.Repository = imageWithoutDigest
		}
	}

	return ref, nil
}

// ReferenceToCRName generates a human-readable CR name from an image reference.
// Format: {registry}.{repo}.{short-digest}
// Example: registry.redhat.io.ubi8.ubi.abc123de
func ReferenceToCRName(ref *Reference) string {
	// Start with registry and repository
	name := ref.Registry + "." + ref.Repository

	// Replace / with .
	name = strings.ReplaceAll(name, "/", ".")

	// Extract short digest (first 8 chars after sha256:)
	shortDigest := ref.Digest
	if trimmed, ok := strings.CutPrefix(shortDigest, "sha256:"); ok {
		shortDigest = trimmed
		if len(shortDigest) > 8 {
			shortDigest = shortDigest[:8]
		}
	}

	// Append short digest
	name = name + "." + shortDigest

	// Convert to lowercase
	name = strings.ToLower(name)

	// Replace any remaining invalid characters with -
	name = sanitizeK8sName(name)

	// Ensure max length of 253 characters
	if len(name) > 253 {
		name = name[:253]
	}

	return name
}

// sanitizeK8sName ensures the name is valid for Kubernetes resources
func sanitizeK8sName(name string) string {
	var result strings.Builder
	for i, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			result.WriteRune(r)
		} else if r == '_' || r == '/' {
			result.WriteRune('.')
		} else if i > 0 && i < len(name)-1 {
			// Replace other chars with - in the middle
			result.WriteRune('-')
		}
		// Skip invalid chars at start/end
	}

	// Ensure it starts and ends with alphanumeric
	s := result.String()
	s = strings.Trim(s, ".-")

	return s
}

// DigestToCRName converts a digest (sha256:abc123...) to a valid CR name (sha256-abc123...)
// Deprecated: Use ReferenceToCRName instead for human-readable names
func DigestToCRName(digest string) string {
	// Replace : with - to make it a valid Kubernetes resource name
	return strings.ReplaceAll(digest, ":", "-")
}

// CRNameToDigest converts a CR name back to a digest
// Note: This only works with old-style sha256-based names
func CRNameToDigest(crName string) string {
	// Replace the first - with : (sha256-abc... -> sha256:abc...)
	if suffix, ok := strings.CutPrefix(crName, "sha256-"); ok {
		return "sha256:" + suffix
	}
	return crName
}

// ClassifyRegistry determines the RegistryType based on the registry hostname
func ClassifyRegistry(registry string) securityv1alpha1.RegistryType {
	registry = strings.ToLower(registry)

	// Red Hat registries
	redHatRegistries := []string{
		"registry.redhat.io",
		"registry.access.redhat.com",
		"registry.connect.redhat.com",
	}
	if slices.Contains(redHatRegistries, registry) {
		return securityv1alpha1.RegistryTypeRedHat
	}

	// Partner registry (Quay.io)
	if registry == "quay.io" {
		return securityv1alpha1.RegistryTypePartner
	}

	// Community registries
	communityRegistries := []string{
		"docker.io",
		"ghcr.io",
		"gcr.io",
		"registry.k8s.io",
		"k8s.gcr.io",
	}
	if slices.Contains(communityRegistries, registry) {
		return securityv1alpha1.RegistryTypeCommunity
	}

	// Private registries (local/internal)
	if strings.HasSuffix(registry, ".local") ||
		strings.HasSuffix(registry, ".internal") ||
		registry == "localhost" ||
		strings.HasPrefix(registry, "localhost:") {
		return securityv1alpha1.RegistryTypePrivate
	}

	return securityv1alpha1.RegistryTypeUnknown
}

// IsRedHatRegistry returns true if the registry is a Red Hat registry
func IsRedHatRegistry(registry string) bool {
	return ClassifyRegistry(registry) == securityv1alpha1.RegistryTypeRedHat
}
