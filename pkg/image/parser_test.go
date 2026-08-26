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

const (
	testRegistryRedHat = "registry.redhat.io"
	testRegistryQuay   = "quay.io"
	testRegistryGHCR   = "ghcr.io"
	testRegistryGCR    = "gcr.io"
	testRepoUBI        = "ubi8/ubi"
	testFullDigest     = "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
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
				testFullDigest,
			wantErr: false,
			wantRef: &Reference{
				Registry:   testRegistryRedHat,
				Repository: testRepoUBI,
				Digest:     testFullDigest,
				FullReference: "registry.redhat.io/ubi8/ubi@" +
					testFullDigest,
			},
		},
		{
			name: "docker prefix",
			imageID: "docker://quay.io/openshift/origin-cli@" +
				testFullDigest,
			wantErr: false,
			wantRef: &Reference{
				Registry:   testRegistryQuay,
				Repository: "openshift/origin-cli",
				Digest:     testFullDigest,
				FullReference: "quay.io/openshift/origin-cli@" +
					testFullDigest,
			},
		},
		{
			name:    "simple docker.io image",
			imageID: "nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			wantErr: false,
			wantRef: &Reference{
				Registry:      registryDockerIO,
				Repository:    "library/nginx",
				Digest:        testFullDigest,
				FullReference: "nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		},
		{
			name:    "docker.io with user namespace",
			imageID: "myuser/myimage@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			wantErr: false,
			wantRef: &Reference{
				Registry:      registryDockerIO,
				Repository:    "myuser/myimage",
				Digest:        testFullDigest,
				FullReference: "myuser/myimage@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		},
		{
			name: "image with tag and digest",
			imageID: "registry.redhat.io/ubi8/ubi:8.5@" +
				testFullDigest,
			wantErr: false,
			wantRef: &Reference{
				Registry:   testRegistryRedHat,
				Repository: testRepoUBI,
				Tag:        "8.5",
				Digest:     testFullDigest,
				FullReference: "registry.redhat.io/ubi8/ubi:8.5@" +
					testFullDigest,
			},
		},
		{
			name: "ghcr.io image",
			imageID: "ghcr.io/kubernetes-sigs/controller-runtime@" +
				testFullDigest,
			wantErr: false,
			wantRef: &Reference{
				Registry:   testRegistryGHCR,
				Repository: "kubernetes-sigs/controller-runtime",
				Digest:     testFullDigest,
				FullReference: "ghcr.io/kubernetes-sigs/controller-runtime@" +
					testFullDigest,
			},
		},
		{
			name:    "registry with port",
			imageID: "localhost:5000/myimage@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			wantErr: false,
			wantRef: &Reference{
				Registry:      "localhost:5000",
				Repository:    "myimage",
				Digest:        testFullDigest,
				FullReference: "localhost:5000/myimage@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			},
		},
		{
			name: "gcr.io image",
			imageID: "gcr.io/google-containers/pause@" +
				testFullDigest,
			wantErr: false,
			wantRef: &Reference{
				Registry:   testRegistryGCR,
				Repository: "google-containers/pause",
				Digest:     testFullDigest,
				FullReference: "gcr.io/google-containers/pause@" +
					testFullDigest,
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
				Registry:   testRegistryRedHat,
				Repository: testRepoUBI,
				Digest:     testFullDigest,
			},
			want: "registry.redhat.io.ubi8.ubi.abc123de",
		},
		{
			name: "Quay.io image",
			ref: &Reference{
				Registry:   testRegistryQuay,
				Repository: "openshift/origin-cli",
				Digest:     "sha256:fedcba98765432fedcba98765432fedcba98765432fedcba98765432fedcba98",
			},
			want: "quay.io.openshift.origin-cli.fedcba98",
		},
		{
			name: "Docker Hub library image",
			ref: &Reference{
				Registry:   registryDockerIO,
				Repository: "library/nginx",
				Digest:     "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			want: "docker.io.library.nginx.12345678",
		},
		{
			name: "Deep nested repository",
			ref: &Reference{
				Registry:   testRegistryGCR,
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

func TestClassifyRegistry(t *testing.T) {
	tests := []struct {
		registry string
		want     securityv1alpha1.RegistryType
	}{
		// Red Hat registries
		{testRegistryRedHat, securityv1alpha1.RegistryTypeRedHat},
		{"registry.access.redhat.com", securityv1alpha1.RegistryTypeRedHat},
		{"registry.connect.redhat.com", securityv1alpha1.RegistryTypeRedHat},
		{"REGISTRY.REDHAT.IO", securityv1alpha1.RegistryTypeRedHat}, // Case insensitive

		// Partner registry
		{testRegistryQuay, securityv1alpha1.RegistryTypePartner},
		{"QUAY.IO", securityv1alpha1.RegistryTypePartner},

		// Community registries
		{registryDockerIO, securityv1alpha1.RegistryTypeCommunity},
		{testRegistryGHCR, securityv1alpha1.RegistryTypeCommunity},
		{testRegistryGCR, securityv1alpha1.RegistryTypeCommunity},
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
		{testRegistryRedHat, true},
		{"registry.access.redhat.com", true},
		{"registry.connect.redhat.com", true},
		{testRegistryQuay, false},
		{registryDockerIO, false},
		{testRegistryGHCR, false},
	}

	for _, tt := range tests {
		t.Run(tt.registry, func(t *testing.T) {
			if got := IsRedHatRegistry(tt.registry); got != tt.want {
				t.Errorf("IsRedHatRegistry(%s) = %v, want %v", tt.registry, got, tt.want)
			}
		})
	}
}
