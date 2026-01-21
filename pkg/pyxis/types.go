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

package pyxis

// CertificationData contains certification information from Pyxis
type CertificationData struct {
	// ProjectID is the Red Hat Connect project ID
	ProjectID string
	// Publisher is the certified publisher name
	Publisher string
	// HealthIndex is the image health grade (A-F)
	HealthIndex string
	// Vulnerabilities contains vulnerability counts
	Vulnerabilities *VulnerabilitySummary
	// CatalogURL is the link to the Red Hat container catalog page
	CatalogURL string
	// ImageID is the Pyxis internal image ID
	ImageID string
	// PublishedAt is when the image was published to the registry
	PublishedAt string
	// CVEs is a list of CVE identifiers affecting this image
	CVEs []string
}

// VulnerabilitySummary contains vulnerability counts by severity
type VulnerabilitySummary struct {
	Critical  int
	Important int
	Moderate  int
	Low       int
}

// PyxisImageResponse represents a single image from the Pyxis API
type PyxisImageResponse struct {
	ID                   string                     `json:"_id"`
	Certified            bool                       `json:"certified"`
	ParsedData           *PyxisImageParsedData      `json:"parsed_data,omitempty"`
	FreshnessGrades      []PyxisFreshnessGrade      `json:"freshness_grades,omitempty"`
	VulnerabilitySummary *PyxisVulnerabilitySummary `json:"vulnerability_summary,omitempty"`
	Repositories         []PyxisImageRepository     `json:"repositories,omitempty"`
}

// PyxisImageRepository represents repository info within an image response
type PyxisImageRepository struct {
	Registry           string `json:"registry"`
	Repository         string `json:"repository"`
	ManifestListDigest string `json:"manifest_list_digest,omitempty"`
	PushDate           string `json:"push_date,omitempty"`
}

// PyxisPagedResponse represents a paginated response from Pyxis
type PyxisPagedResponse struct {
	Data []PyxisImageResponse `json:"data"`
}

// PyxisImageParsedData contains parsed image metadata
type PyxisImageParsedData struct {
	Labels []PyxisLabel `json:"labels,omitempty"`
}

// PyxisLabel represents a label on an image
type PyxisLabel struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// PyxisFreshnessGrade represents a freshness grade
type PyxisFreshnessGrade struct {
	Grade string `json:"grade"`
}

// PyxisVulnerabilitySummary from Pyxis API
type PyxisVulnerabilitySummary struct {
	Critical  int `json:"critical"`
	Important int `json:"important"`
	Moderate  int `json:"moderate"`
	Low       int `json:"low"`
}

// PyxisContainerRepository represents a container repository from Pyxis
type PyxisContainerRepository struct {
	ID              string `json:"_id"`
	PublishedImages int    `json:"published_images"`
	Repository      string `json:"repository"`
	Registry        string `json:"registry"`
	IsPublished     bool   `json:"published"`
}

// PyxisVendor represents a vendor from Pyxis
type PyxisVendor struct {
	Name string `json:"name"`
}

// PyxisVulnerability represents a single CVE from the vulnerabilities endpoint
type PyxisVulnerability struct {
	CVEID      string `json:"cve_id"`
	Severity   string `json:"severity"`
	AdvisoryID string `json:"advisory_id,omitempty"`
}

// PyxisVulnerabilitiesResponse represents the response from the vulnerabilities endpoint
type PyxisVulnerabilitiesResponse struct {
	Data []PyxisVulnerability `json:"data"`
}
