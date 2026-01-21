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

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// DefaultBaseURL is the default Pyxis API base URL
	DefaultBaseURL = "https://catalog.redhat.com/api/containers/v1"
	// DefaultTimeout is the default HTTP client timeout
	DefaultTimeout = 30 * time.Second
)

// Client interface for Pyxis API operations
type Client interface {
	// GetImageCertification retrieves certification data for an image
	GetImageCertification(ctx context.Context, registry, repository, digest string) (*CertificationData, error)
	// IsHealthy checks if the Pyxis API is accessible
	IsHealthy(ctx context.Context) bool
}

// HTTPClient implements the Client interface using HTTP.
// The public Pyxis API works without authentication for read-only queries.
// An optional API key can be provided for authenticated access.
type HTTPClient struct {
	baseURL    string
	apiKey     string // Optional - public API works without auth
	httpClient *http.Client
}

// ClientOption is a function that configures an HTTPClient
type ClientOption func(*HTTPClient)

// WithBaseURL sets a custom base URL
func WithBaseURL(baseURL string) ClientOption {
	return func(c *HTTPClient) {
		c.baseURL = baseURL
	}
}

// WithAPIKey sets an optional API key for authentication.
// The public Pyxis API works without authentication for read-only queries,
// so this is optional and only needed for higher rate limits or authenticated endpoints.
func WithAPIKey(apiKey string) ClientOption {
	return func(c *HTTPClient) {
		c.apiKey = apiKey
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *HTTPClient) {
		c.httpClient = httpClient
	}
}

// WithTimeout sets a custom timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *HTTPClient) {
		c.httpClient.Timeout = timeout
	}
}

// NewHTTPClient creates a new Pyxis HTTP client.
// By default, no authentication is required - the public API works for read-only queries.
// Use WithAPIKey option if you need authenticated access.
func NewHTTPClient(opts ...ClientOption) *HTTPClient {
	client := &HTTPClient{
		baseURL: DefaultBaseURL,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

// GetImageCertification retrieves certification data for an image from Pyxis.
// It tries two API endpoints: first by image_id (single-arch), then by manifest_list_digest (multi-arch).
func (c *HTTPClient) GetImageCertification(ctx context.Context, registry, repository, digest string) (*CertificationData, error) {
	// Try first by image_id (single architecture images)
	certData, err := c.queryByImageID(ctx, digest)
	if err != nil {
		return nil, err
	}
	if certData != nil {
		// Verify this image is from a Red Hat registry
		return certData, nil
	}

	// Try by manifest_list_digest (multi-architecture images)
	certData, err = c.queryByManifestListDigest(ctx, digest)
	if err != nil {
		return nil, err
	}

	return certData, nil
}

// queryByImageID queries the Pyxis API by image_id (single-arch images)
func (c *HTTPClient) queryByImageID(ctx context.Context, digest string) (*CertificationData, error) {
	requestURL := fmt.Sprintf("%s/images?filter=image_id==%s", c.baseURL, url.QueryEscape(digest))
	return c.queryAndParse(ctx, requestURL)
}

// queryByManifestListDigest queries the Pyxis API by manifest_list_digest (multi-arch images)
func (c *HTTPClient) queryByManifestListDigest(ctx context.Context, digest string) (*CertificationData, error) {
	requestURL := fmt.Sprintf("%s/images?filter=repositories.manifest_list_digest==%s", c.baseURL, url.QueryEscape(digest))
	return c.queryAndParse(ctx, requestURL)
}

// queryAndParse executes the request and parses the response
func (c *HTTPClient) queryAndParse(ctx context.Context, requestURL string) (*CertificationData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-KEY", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Handle response status codes
	switch resp.StatusCode {
	case http.StatusOK:
		// Continue processing
	case http.StatusNotFound:
		// Image not found in Pyxis - not certified
		return nil, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("authentication failed: %s", resp.Status)
	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected response status %s: %s", resp.Status, string(body))
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse as paginated response
	var pagedResp PyxisPagedResponse
	if err := json.Unmarshal(body, &pagedResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// No data returned
	if len(pagedResp.Data) == 0 {
		return nil, nil
	}

	// Use the first matching image
	pyxisResp := pagedResp.Data[0]

	// Check if this is from a Red Hat registry
	isRedHatImage := false
	for _, repo := range pyxisResp.Repositories {
		if isRedHatRegistry(repo.Registry) {
			isRedHatImage = true
			break
		}
	}
	if !isRedHatImage && len(pyxisResp.Repositories) > 0 {
		// Image exists but not from a Red Hat registry we recognize
		return nil, nil
	}

	// Convert to CertificationData
	certData := &CertificationData{
		ImageID: pyxisResp.ID,
	}

	// Extract size information
	if pyxisResp.TotalSizeBytes > 0 {
		certData.CompressedSizeBytes = pyxisResp.TotalSizeBytes
	}

	// Extract auto-rebuild setting
	certData.AutoRebuildEnabled = pyxisResp.CanAutoReleaseCVERebuild

	// Extract architectures from content_stream_grades
	archSet := make(map[string]bool)
	for _, grade := range pyxisResp.ContentStreamGrades {
		if grade.Architecture != "" {
			archSet[grade.Architecture] = true
		}
	}
	for arch := range archSet {
		certData.Architectures = append(certData.Architectures, arch)
	}

	// Extract repository info including catalog URL, push date, and lifecycle data
	// Format: https://catalog.redhat.com/software/containers/{repository_id}
	if len(pyxisResp.Repositories) > 0 {
		repo := pyxisResp.Repositories[0]
		// Query the repository endpoint to get full repository info
		repoInfo := c.getRepositoryInfo(ctx, repo.Registry, repo.Repository)
		if repoInfo != nil {
			if repoInfo.ID != "" {
				certData.CatalogURL = fmt.Sprintf("https://catalog.redhat.com/software/containers/%s", repoInfo.ID)
			}
			// Extract lifecycle fields
			certData.EOLDate = repoInfo.EOLDate
			certData.ReleaseCategory = repoInfo.ReleaseCategory
			certData.ReplacedBy = repoInfo.ReplacedByRepositoryName
		}
		// Extract push date (when image was published)
		if repo.PushDate != "" {
			certData.PublishedAt = repo.PushDate
		}
	}

	// Get health index from freshness grades
	if len(pyxisResp.FreshnessGrades) > 0 {
		certData.HealthIndex = pyxisResp.FreshnessGrades[0].Grade
	}

	// Extract publisher from labels
	if pyxisResp.ParsedData != nil {
		for _, label := range pyxisResp.ParsedData.Labels {
			switch label.Name {
			case "vendor", "maintainer":
				if certData.Publisher == "" {
					certData.Publisher = label.Value
				}
			case "com.redhat.component":
				if certData.ProjectID == "" {
					certData.ProjectID = label.Value
				}
			}
		}
	}

	// Copy vulnerability summary
	if pyxisResp.VulnerabilitySummary != nil {
		certData.Vulnerabilities = &VulnerabilitySummary{
			Critical:  pyxisResp.VulnerabilitySummary.Critical,
			Important: pyxisResp.VulnerabilitySummary.Important,
			Moderate:  pyxisResp.VulnerabilitySummary.Moderate,
			Low:       pyxisResp.VulnerabilitySummary.Low,
		}
	}

	// Fetch CVE details if image has vulnerabilities
	if certData.ImageID != "" {
		cves := c.getVulnerabilities(ctx, certData.ImageID)
		if len(cves) > 0 {
			certData.CVEs = cves
		}
	}

	return certData, nil
}

// RepositoryInfo contains repository-level information from Pyxis
type RepositoryInfo struct {
	ID                       string
	EOLDate                  string
	ReleaseCategory          string
	ReplacedByRepositoryName string
}

// getRepositoryInfo fetches repository information from Pyxis including lifecycle data
func (c *HTTPClient) getRepositoryInfo(ctx context.Context, registry, repository string) *RepositoryInfo {
	encodedRepo := url.PathEscape(repository)
	requestURL := fmt.Sprintf("%s/repositories/registry/%s/repository/%s", c.baseURL, registry, encodedRepo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-KEY", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var repoResp PyxisContainerRepository
	if err := json.Unmarshal(body, &repoResp); err != nil {
		return nil
	}

	info := &RepositoryInfo{
		ID:                       repoResp.ID,
		EOLDate:                  repoResp.EOLDate,
		ReplacedByRepositoryName: repoResp.ReplacedByRepositoryName,
	}

	// Convert release_categories array to single category string (use first)
	if len(repoResp.ReleaseCategories) > 0 {
		info.ReleaseCategory = repoResp.ReleaseCategories[0]
	}

	return info
}

// getVulnerabilities fetches CVE IDs for an image from the Pyxis vulnerabilities endpoint
func (c *HTTPClient) getVulnerabilities(ctx context.Context, imageID string) []string {
	requestURL := fmt.Sprintf("%s/images/id/%s/vulnerabilities", c.baseURL, imageID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-KEY", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var vulnResp PyxisVulnerabilitiesResponse
	if err := json.Unmarshal(body, &vulnResp); err != nil {
		return nil
	}

	// Extract CVE IDs, prioritizing critical and important first
	var cves []string
	for _, vuln := range vulnResp.Data {
		if vuln.CVEID != "" {
			cves = append(cves, vuln.CVEID)
		}
	}

	return cves
}

// isRedHatRegistry checks if the registry is a Red Hat registry
func isRedHatRegistry(registry string) bool {
	redHatRegistries := []string{
		"registry.redhat.io",
		"registry.access.redhat.com",
		"registry.connect.redhat.com",
	}
	for _, rhr := range redHatRegistries {
		if registry == rhr {
			return true
		}
	}
	return false
}

// IsHealthy checks if the Pyxis API is accessible
func (c *HTTPClient) IsHealthy(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/ping", nil)
	if err != nil {
		return false
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}
