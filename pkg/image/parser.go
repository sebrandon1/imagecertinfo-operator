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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	securityv1alpha1 "github.com/sebrandon1/imagecertinfo-operator/api/v1alpha1"
)

const registryDockerIO = "docker.io"

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
		ref.Registry = registryDockerIO
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
			ref.Registry = registryDockerIO
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

	// Keep the readable form when it fits. Otherwise shorten it and add a hash
	// of the untruncated name: a plain slice can end on '.' or '-' (invalid for
	// an object name) and can collapse two long references onto the same name.
	if len(name) > maxCRNameLength {
		name = shortenCRName(name)
	}

	return name
}

const (
	// maxCRNameLength is the DNS-1123 subdomain limit for object names.
	maxCRNameLength = 253
	// crNameHashSuffixLength is the "-" plus the 8 hex characters appended to a
	// shortened name.
	crNameHashSuffixLength = 9
)

// shortenCRName fits a sanitized name into maxCRNameLength and appends a hash
// of the full name so distinct image references stay distinct.
func shortenCRName(name string) string {
	sum := sha256.Sum256([]byte(name))
	hash := hex.EncodeToString(sum[:])[:8]

	// Re-sanitize the prefix so it cannot end on '.' or '-'.
	prefix := sanitizeK8sName(name[:maxCRNameLength-crNameHashSuffixLength])
	if prefix == "" {
		return "image-" + hash
	}

	return prefix + "-" + hash
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

// Known registry sets (package-level to avoid per-call allocation)
var (
	redHatRegistries = []string{
		"registry.redhat.io",
		"registry.access.redhat.com",
		"registry.connect.redhat.com",
	}
	communityRegistries = []string{
		registryDockerIO,
		"ghcr.io",
		"gcr.io",
		"registry.k8s.io",
		"k8s.gcr.io",
	}
)

// ClassifyRegistry determines the RegistryType based on the registry hostname
func ClassifyRegistry(registry string) securityv1alpha1.RegistryType {
	registry = strings.ToLower(registry)

	if slices.Contains(redHatRegistries, registry) {
		return securityv1alpha1.RegistryTypeRedHat
	}

	if registry == "quay.io" {
		return securityv1alpha1.RegistryTypePartner
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
