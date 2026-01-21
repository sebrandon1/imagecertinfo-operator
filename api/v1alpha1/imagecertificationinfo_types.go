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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RegistryType indicates the type of container registry
// +kubebuilder:validation:Enum=RedHat;Partner;Community;Private;Unknown
type RegistryType string

const (
	RegistryTypeRedHat    RegistryType = "RedHat"
	RegistryTypePartner   RegistryType = "Partner"
	RegistryTypeCommunity RegistryType = "Community"
	RegistryTypePrivate   RegistryType = "Private"
	RegistryTypeUnknown   RegistryType = "Unknown"
)

// CertificationStatus indicates the certification status of an image
// +kubebuilder:validation:Enum=Certified;NotCertified;Pending;Unknown;Error
type CertificationStatus string

const (
	CertificationStatusCertified    CertificationStatus = "Certified"
	CertificationStatusNotCertified CertificationStatus = "NotCertified"
	CertificationStatusPending      CertificationStatus = "Pending"
	CertificationStatusUnknown      CertificationStatus = "Unknown"
	CertificationStatusError        CertificationStatus = "Error"
)

// PodReference contains information about a pod using this image
type PodReference struct {
	// Namespace of the pod
	Namespace string `json:"namespace"`
	// Name of the pod
	Name string `json:"name"`
	// Container name within the pod
	Container string `json:"container"`
}

// VulnerabilitySummary contains vulnerability counts by severity
type VulnerabilitySummary struct {
	// Critical vulnerability count
	// +optional
	Critical int `json:"critical,omitempty"`
	// Important vulnerability count
	// +optional
	Important int `json:"important,omitempty"`
	// Moderate vulnerability count
	// +optional
	Moderate int `json:"moderate,omitempty"`
	// Low vulnerability count
	// +optional
	Low int `json:"low,omitempty"`
}

// PyxisData contains certification data from Red Hat Pyxis API
type PyxisData struct {
	// ProjectID is the Red Hat Connect project ID
	// +optional
	ProjectID string `json:"projectID,omitempty"`
	// Publisher is the certified publisher name
	// +optional
	Publisher string `json:"publisher,omitempty"`
	// HealthIndex is the image health grade (A-F)
	// +optional
	HealthIndex string `json:"healthIndex,omitempty"`
	// CatalogURL is the link to the Red Hat container catalog page
	// +optional
	CatalogURL string `json:"catalogURL,omitempty"`
	// PublishedAt is when the image was published to the registry
	// +optional
	PublishedAt *metav1.Time `json:"publishedAt,omitempty"`
	// Vulnerabilities contains vulnerability counts by severity
	// +optional
	Vulnerabilities *VulnerabilitySummary `json:"vulnerabilities,omitempty"`

	// Lifecycle fields

	// EOLDate is the end-of-life date for this image
	// +optional
	EOLDate *metav1.Time `json:"eolDate,omitempty"`
	// ReleaseCategory indicates the release status (e.g., Generally Available, Deprecated, Tech Preview)
	// +optional
	ReleaseCategory string `json:"releaseCategory,omitempty"`
	// ReplacedBy is the repository name of the image that replaces this one (if deprecated)
	// +optional
	ReplacedBy string `json:"replacedBy,omitempty"`

	// Operational fields

	// Architectures lists the supported CPU architectures (e.g., amd64, arm64, s390x, ppc64le)
	// +optional
	Architectures []string `json:"architectures,omitempty"`
	// CompressedSizeBytes is the compressed image size in bytes
	// +optional
	CompressedSizeBytes int64 `json:"compressedSizeBytes,omitempty"`

	// Security fields

	// AutoRebuildEnabled indicates if automatic CVE rebuilds are enabled for this image
	// +optional
	AutoRebuildEnabled bool `json:"autoRebuildEnabled,omitempty"`
}

// ImageCertificationInfoSpec defines the desired state of ImageCertificationInfo
type ImageCertificationInfoSpec struct {
	// ImageDigest is the sha256 digest of the image
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	ImageDigest string `json:"imageDigest"`

	// FullImageReference is the complete image reference including registry, repo, and digest
	// +kubebuilder:validation:Required
	FullImageReference string `json:"fullImageReference"`

	// Registry is the container registry hostname
	// +kubebuilder:validation:Required
	Registry string `json:"registry"`

	// Repository is the image repository path
	// +kubebuilder:validation:Required
	Repository string `json:"repository"`

	// Tag is the image tag if available
	// +optional
	Tag string `json:"tag,omitempty"`
}

// ImageCertificationInfoStatus defines the observed state of ImageCertificationInfo
type ImageCertificationInfoStatus struct {
	// RegistryType indicates the type of registry (RedHat, Partner, Community, Private, Unknown)
	// +kubebuilder:default=Unknown
	RegistryType RegistryType `json:"registryType,omitempty"`

	// CertificationStatus indicates the certification status (Certified, NotCertified, Pending, Unknown, Error)
	// +kubebuilder:default=Unknown
	CertificationStatus CertificationStatus `json:"certificationStatus,omitempty"`

	// PyxisData contains certification data from Red Hat Pyxis API
	// +optional
	PyxisData *PyxisData `json:"pyxisData,omitempty"`

	// PodReferences lists all pods currently using this image
	// +optional
	PodReferences []PodReference `json:"podReferences,omitempty"`

	// FirstSeenAt is when this image was first observed in the cluster
	// +optional
	FirstSeenAt *metav1.Time `json:"firstSeenAt,omitempty"`

	// LastSeenAt is when this image was last observed in a running pod
	// +optional
	LastSeenAt *metav1.Time `json:"lastSeenAt,omitempty"`

	// LastPyxisCheckAt is when the Pyxis API was last queried for this image
	// +optional
	LastPyxisCheckAt *metav1.Time `json:"lastPyxisCheckAt,omitempty"`

	// Conditions represent the current state of the ImageCertificationInfo resource
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Registry",type=string,JSONPath=`.spec.registry`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.status.registryType`
// +kubebuilder:printcolumn:name="Certified",type=string,JSONPath=`.status.certificationStatus`
// +kubebuilder:printcolumn:name="Health",type=string,JSONPath=`.status.pyxisData.healthIndex`
// +kubebuilder:printcolumn:name="Release",type=string,JSONPath=`.status.pyxisData.releaseCategory`,priority=1
// +kubebuilder:printcolumn:name="EOL",type=date,JSONPath=`.status.pyxisData.eolDate`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ImageCertificationInfo is the Schema for the imagecertificationinfos API
type ImageCertificationInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of ImageCertificationInfo
	// +required
	Spec ImageCertificationInfoSpec `json:"spec"`

	// Status defines the observed state of ImageCertificationInfo
	// +optional
	Status ImageCertificationInfoStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ImageCertificationInfoList contains a list of ImageCertificationInfo
type ImageCertificationInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageCertificationInfo `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageCertificationInfo{}, &ImageCertificationInfoList{})
}
