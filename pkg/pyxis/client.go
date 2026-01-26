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
	"slices"
	"time"

	"github.com/sebrandon1/imagecertinfo-operator/internal/metrics"
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
// It tries two API endpoints: first by image_id (single-arch),
// then by manifest_list_digest (multi-arch).
func (c *HTTPClient) GetImageCertification(
	ctx context.Context, registry, repository, digest string,
) (*CertificationData, error) {
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
	start := time.Now()
	pyxisResp, err := c.fetchAndParseResponse(ctx, requestURL)
	duration := time.Since(start).Seconds()

	// Record metrics
	endpoint := "images"
	if err != nil {
		metrics.RecordPyxisRequest("error", endpoint, duration)
		return nil, err
	}
	if pyxisResp == nil {
		metrics.RecordPyxisRequest("not_found", endpoint, duration)
		return nil, nil
	}
	metrics.RecordPyxisRequest("success", endpoint, duration)

	// Check if this is from a Red Hat registry
	if !c.isFromRedHatRegistry(pyxisResp) {
		return nil, nil
	}

	// Convert to CertificationData
	certData := c.convertToCertificationData(ctx, pyxisResp)

	return certData, nil
}

// fetchAndParseResponse fetches and parses the Pyxis API response
func (c *HTTPClient) fetchAndParseResponse(
	ctx context.Context, requestURL string,
) (*PyxisImageResponse, error) {
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
	defer func() { _ = resp.Body.Close() }()

	// Handle response status codes
	switch resp.StatusCode {
	case http.StatusOK:
		// Continue processing
	case http.StatusNotFound:
		return nil, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("authentication failed: %s", resp.Status)
	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected response status %s: %s", resp.Status, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var pagedResp PyxisPagedResponse
	if err := json.Unmarshal(body, &pagedResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(pagedResp.Data) == 0 {
		return nil, nil
	}

	return &pagedResp.Data[0], nil
}

// isFromRedHatRegistry checks if the image is from a Red Hat registry
func (c *HTTPClient) isFromRedHatRegistry(pyxisResp *PyxisImageResponse) bool {
	if len(pyxisResp.Repositories) == 0 {
		return true // No repos, assume valid
	}
	for _, repo := range pyxisResp.Repositories {
		if isRedHatRegistry(repo.Registry) {
			return true
		}
	}
	return false
}

// convertToCertificationData converts a Pyxis response to CertificationData
func (c *HTTPClient) convertToCertificationData(
	ctx context.Context, pyxisResp *PyxisImageResponse,
) *CertificationData {
	certData := &CertificationData{
		ImageID:            pyxisResp.ID,
		AutoRebuildEnabled: pyxisResp.CanAutoReleaseCVERebuild,
	}

	if pyxisResp.TotalSizeBytes > 0 {
		certData.CompressedSizeBytes = pyxisResp.TotalSizeBytes
	}

	// Enhanced fields for v0.2.0
	if pyxisResp.TotalUncompressedSizeBytes > 0 {
		certData.UncompressedSizeBytes = pyxisResp.TotalUncompressedSizeBytes
	}
	if pyxisResp.LayerCount > 0 {
		certData.LayerCount = pyxisResp.LayerCount
	}
	if pyxisResp.BuildDate != "" {
		certData.BuildDate = pyxisResp.BuildDate
	}

	certData.Architectures = extractArchitectures(pyxisResp.ContentStreamGrades)
	certData.ArchitectureHealth = extractArchitectureHealth(pyxisResp.ContentStreamGrades)
	c.populateRepositoryData(ctx, pyxisResp, certData)

	if len(pyxisResp.FreshnessGrades) > 0 {
		certData.HealthIndex = pyxisResp.FreshnessGrades[0].Grade
	}

	extractPublisherInfo(pyxisResp.ParsedData, certData)
	copyVulnerabilitySummary(pyxisResp.VulnerabilitySummary, certData)

	if certData.ImageID != "" {
		cves, advisoryIDs := c.getVulnerabilitiesWithAdvisories(ctx, certData.ImageID)
		if len(cves) > 0 {
			certData.CVEs = cves
		}
		if len(advisoryIDs) > 0 {
			certData.AdvisoryIDs = advisoryIDs
		}
	}

	return certData
}

// extractArchitectures extracts unique architectures from content stream grades
func extractArchitectures(grades []PyxisContentStreamGrade) []string {
	archSet := make(map[string]bool)
	for _, grade := range grades {
		if grade.Architecture != "" {
			archSet[grade.Architecture] = true
		}
	}
	archs := make([]string, 0, len(archSet))
	for arch := range archSet {
		archs = append(archs, arch)
	}
	return archs
}

// extractArchitectureHealth extracts architecture to health grade mapping
func extractArchitectureHealth(grades []PyxisContentStreamGrade) map[string]string {
	archHealth := make(map[string]string)
	for _, grade := range grades {
		if grade.Architecture != "" && grade.Grade != "" {
			archHealth[grade.Architecture] = grade.Grade
		}
	}
	if len(archHealth) == 0 {
		return nil
	}
	return archHealth
}

// populateRepositoryData populates repository-related fields in CertificationData
func (c *HTTPClient) populateRepositoryData(
	ctx context.Context, pyxisResp *PyxisImageResponse, certData *CertificationData,
) {
	if len(pyxisResp.Repositories) == 0 {
		return
	}

	repo := pyxisResp.Repositories[0]
	repoInfo := c.getRepositoryInfo(ctx, repo.Registry, repo.Repository)
	if repoInfo != nil {
		if repoInfo.ID != "" {
			certData.CatalogURL = fmt.Sprintf(
				"https://catalog.redhat.com/software/containers/%s", repoInfo.ID)
		}
		certData.EOLDate = repoInfo.EOLDate
		certData.ReleaseCategory = repoInfo.ReleaseCategory
		certData.ReplacedBy = repoInfo.ReplacedByRepositoryName
	}

	if repo.PushDate != "" {
		certData.PublishedAt = repo.PushDate
	}
}

// extractPublisherInfo extracts publisher and project ID from parsed data labels
func extractPublisherInfo(parsedData *PyxisImageParsedData, certData *CertificationData) {
	if parsedData == nil {
		return
	}
	for _, label := range parsedData.Labels {
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

// copyVulnerabilitySummary copies vulnerability summary to CertificationData
func copyVulnerabilitySummary(summary *PyxisVulnerabilitySummary, certData *CertificationData) {
	if summary == nil {
		return
	}
	certData.Vulnerabilities = &VulnerabilitySummary{
		Critical:  summary.Critical,
		Important: summary.Important,
		Moderate:  summary.Moderate,
		Low:       summary.Low,
	}
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
	defer func() { _ = resp.Body.Close() }()

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

// getVulnerabilitiesWithAdvisories fetches CVE IDs and advisory IDs for an image from Pyxis
func (c *HTTPClient) getVulnerabilitiesWithAdvisories(ctx context.Context, imageID string) ([]string, []string) {
	start := time.Now()
	requestURL := fmt.Sprintf("%s/images/id/%s/vulnerabilities", c.baseURL, imageID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, nil
	}

	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-KEY", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start).Seconds()
	if err != nil {
		metrics.RecordPyxisRequest("error", "vulnerabilities", duration)
		return nil, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		metrics.RecordPyxisRequest("error", "vulnerabilities", duration)
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil
	}

	var vulnResp PyxisVulnerabilitiesResponse
	if err := json.Unmarshal(body, &vulnResp); err != nil {
		return nil, nil
	}

	metrics.RecordPyxisRequest("success", "vulnerabilities", duration)

	// Extract CVE IDs and advisory IDs
	var cves []string
	advisorySet := make(map[string]bool)
	for _, vuln := range vulnResp.Data {
		if vuln.CVEID != "" {
			cves = append(cves, vuln.CVEID)
		}
		if vuln.AdvisoryID != "" {
			advisorySet[vuln.AdvisoryID] = true
		}
	}

	advisoryIDs := make([]string, 0, len(advisorySet))
	for id := range advisorySet {
		advisoryIDs = append(advisoryIDs, id)
	}

	return cves, advisoryIDs
}

// isRedHatRegistry checks if the registry is a Red Hat registry
func isRedHatRegistry(registry string) bool {
	redHatRegistries := []string{
		"registry.redhat.io",
		"registry.access.redhat.com",
		"registry.connect.redhat.com",
	}
	return slices.Contains(redHatRegistries, registry)
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
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode == http.StatusOK
}
