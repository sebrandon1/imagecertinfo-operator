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
	"testing"

	securityv1alpha1 "github.com/sebrandon1/imagecertinfo-operator/api/v1alpha1"
)

func TestParseImageID(t *testing.T) {
	tests := []struct {
		name    string
		imageID string
		wantErr bool
		wantRef *Reference
	}{
		{
			name:    "empty imageID",
			imageID: "",
			wantErr: true,
		},
		{
			name:    "imageID without digest",
			imageID: "registry.redhat.io/ubi8/ubi:latest",
			wantErr: true,
		},
		{
			name: "docker-pullable prefix with Red Hat registry",
			imageID: "docker-pullable://registry.redhat.io/ubi8/ubi@" +
				"sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			wantErr: false,
			wantRef: &Reference{
				Registry:   "registry.redhat.io",
				Repository: "ubi8/ubi",
				Digest:     "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
				FullReference: "registry.redhat.io/ubi8/ubi@" +
					"sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		},
		{
			name: "docker prefix",
			imageID: "docker://quay.io/openshift/origin-cli@" +
				"sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			wantErr: false,
			wantRef: &Reference{
				Registry:   "quay.io",
				Repository: "openshift/origin-cli",
				Digest:     "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
				FullReference: "quay.io/openshift/origin-cli@" +
					"sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		},
		{
			name:    "simple docker.io image",
			imageID: "nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			wantErr: false,
			wantRef: &Reference{
				Registry:      "docker.io",
				Repository:    "library/nginx",
				Digest:        "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
				FullReference: "nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		},
		{
			name:    "docker.io with user namespace",
			imageID: "myuser/myimage@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			wantErr: false,
			wantRef: &Reference{
				Registry:      "docker.io",
				Repository:    "myuser/myimage",
				Digest:        "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
				FullReference: "myuser/myimage@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		},
		{
			name: "image with tag and digest",
			imageID: "registry.redhat.io/ubi8/ubi:8.5@" +
				"sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			wantErr: false,
			wantRef: &Reference{
				Registry:   "registry.redhat.io",
				Repository: "ubi8/ubi",
				Tag:        "8.5",
				Digest:     "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
				FullReference: "registry.redhat.io/ubi8/ubi:8.5@" +
					"sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		},
		{
			name: "ghcr.io image",
			imageID: "ghcr.io/kubernetes-sigs/controller-runtime@" +
				"sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			wantErr: false,
			wantRef: &Reference{
				Registry:   "ghcr.io",
				Repository: "kubernetes-sigs/controller-runtime",
				Digest:     "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
				FullReference: "ghcr.io/kubernetes-sigs/controller-runtime@" +
					"sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		},
		{
			name:    "registry with port",
			imageID: "localhost:5000/myimage@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			wantErr: false,
			wantRef: &Reference{
				Registry:      "localhost:5000",
				Repository:    "myimage",
				Digest:        "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
				FullReference: "localhost:5000/myimage@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		},
		{
			name: "gcr.io image",
			imageID: "gcr.io/google-containers/pause@" +
				"sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			wantErr: false,
			wantRef: &Reference{
				Registry:   "gcr.io",
				Repository: "google-containers/pause",
				Digest:     "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
				FullReference: "gcr.io/google-containers/pause@" +
					"sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseImageID(tt.imageID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseImageID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got.Registry != tt.wantRef.Registry {
				t.Errorf("ParseImageID() Registry = %v, want %v", got.Registry, tt.wantRef.Registry)
			}
			if got.Repository != tt.wantRef.Repository {
				t.Errorf("ParseImageID() Repository = %v, want %v", got.Repository, tt.wantRef.Repository)
			}
			if got.Digest != tt.wantRef.Digest {
				t.Errorf("ParseImageID() Digest = %v, want %v", got.Digest, tt.wantRef.Digest)
			}
			if got.Tag != tt.wantRef.Tag {
				t.Errorf("ParseImageID() Tag = %v, want %v", got.Tag, tt.wantRef.Tag)
			}
			if got.FullReference != tt.wantRef.FullReference {
				t.Errorf("ParseImageID() FullReference = %v, want %v", got.FullReference, tt.wantRef.FullReference)
			}
		})
	}
}

func TestReferenceToCRName(t *testing.T) {
	tests := []struct {
		name string
		ref  *Reference
		want string
	}{
		{
			name: "Red Hat registry image",
			ref: &Reference{
				Registry:   "registry.redhat.io",
				Repository: "ubi8/ubi",
				Digest:     "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
			want: "registry.redhat.io.ubi8.ubi.abc123de",
		},
		{
			name: "Quay.io image",
			ref: &Reference{
				Registry:   "quay.io",
				Repository: "openshift/origin-cli",
				Digest:     "sha256:fedcba98765432fedcba98765432fedcba98765432fedcba98765432fedcba98",
			},
			want: "quay.io.openshift.origin-cli.fedcba98",
		},
		{
			name: "Docker Hub library image",
			ref: &Reference{
				Registry:   "docker.io",
				Repository: "library/nginx",
				Digest:     "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			want: "docker.io.library.nginx.12345678",
		},
		{
			name: "Deep nested repository",
			ref: &Reference{
				Registry:   "gcr.io",
				Repository: "google-containers/some/deep/path",
				Digest:     "sha256:aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
			},
			want: "gcr.io.google-containers.some.deep.path.aabbccdd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReferenceToCRName(tt.ref); got != tt.want {
				t.Errorf("ReferenceToCRName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDigestToCRName(t *testing.T) {
	tests := []struct {
		digest string
		want   string
	}{
		{
			digest: "sha256:abc123",
			want:   "sha256-abc123",
		},
		{
			digest: "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			want:   "sha256-abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.digest, func(t *testing.T) {
			if got := DigestToCRName(tt.digest); got != tt.want {
				t.Errorf("DigestToCRName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCRNameToDigest(t *testing.T) {
	tests := []struct {
		crName string
		want   string
	}{
		{
			crName: "sha256-abc123",
			want:   "sha256:abc123",
		},
		{
			crName: "sha256-abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			want:   "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
		},
		{
			crName: "other-format",
			want:   "other-format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.crName, func(t *testing.T) {
			if got := CRNameToDigest(tt.crName); got != tt.want {
				t.Errorf("CRNameToDigest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClassifyRegistry(t *testing.T) {
	tests := []struct {
		registry string
		want     securityv1alpha1.RegistryType
	}{
		// Red Hat registries
		{"registry.redhat.io", securityv1alpha1.RegistryTypeRedHat},
		{"registry.access.redhat.com", securityv1alpha1.RegistryTypeRedHat},
		{"registry.connect.redhat.com", securityv1alpha1.RegistryTypeRedHat},
		{"REGISTRY.REDHAT.IO", securityv1alpha1.RegistryTypeRedHat}, // Case insensitive

		// Partner registry
		{"quay.io", securityv1alpha1.RegistryTypePartner},
		{"QUAY.IO", securityv1alpha1.RegistryTypePartner},

		// Community registries
		{"docker.io", securityv1alpha1.RegistryTypeCommunity},
		{"ghcr.io", securityv1alpha1.RegistryTypeCommunity},
		{"gcr.io", securityv1alpha1.RegistryTypeCommunity},
		{"registry.k8s.io", securityv1alpha1.RegistryTypeCommunity},
		{"k8s.gcr.io", securityv1alpha1.RegistryTypeCommunity},

		// Private registries
		{"myregistry.local", securityv1alpha1.RegistryTypePrivate},
		{"registry.internal", securityv1alpha1.RegistryTypePrivate},
		{"localhost", securityv1alpha1.RegistryTypePrivate},
		{"localhost:5000", securityv1alpha1.RegistryTypePrivate},

		// Unknown registries
		{"mycompany.azurecr.io", securityv1alpha1.RegistryTypeUnknown},
		{"ecr.aws", securityv1alpha1.RegistryTypeUnknown},
		{"custom-registry.com", securityv1alpha1.RegistryTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.registry, func(t *testing.T) {
			if got := ClassifyRegistry(tt.registry); got != tt.want {
				t.Errorf("ClassifyRegistry(%s) = %v, want %v", tt.registry, got, tt.want)
			}
		})
	}
}

func TestIsRedHatRegistry(t *testing.T) {
	tests := []struct {
		registry string
		want     bool
	}{
		{"registry.redhat.io", true},
		{"registry.access.redhat.com", true},
		{"registry.connect.redhat.com", true},
		{"quay.io", false},
		{"docker.io", false},
		{"ghcr.io", false},
	}

	for _, tt := range tests {
		t.Run(tt.registry, func(t *testing.T) {
			if got := IsRedHatRegistry(tt.registry); got != tt.want {
				t.Errorf("IsRedHatRegistry(%s) = %v, want %v", tt.registry, got, tt.want)
			}
		})
	}
}
