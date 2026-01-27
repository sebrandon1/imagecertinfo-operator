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

package dockerhub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sebrandon1/imagecertinfo-operator/internal/metrics"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	// DefaultBaseURL is the default Docker Hub API base URL
	DefaultBaseURL = "https://hub.docker.com/v2"
	// DefaultTimeout is the default HTTP client timeout
	DefaultTimeout = 30 * time.Second
)

// Client interface for Docker Hub API operations
type Client interface {
	// GetRepositoryInfo retrieves repository metadata from Docker Hub
	GetRepositoryInfo(ctx context.Context, namespace, repository string) (*RepositoryInfo, error)
	// IsHealthy checks if the Docker Hub API is accessible
	IsHealthy(ctx context.Context) bool
}

// HTTPClient implements the Client interface using HTTP.
// The Docker Hub public API works without authentication for read-only queries.
type HTTPClient struct {
	baseURL    string
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

// NewHTTPClient creates a new Docker Hub HTTP client.
// No authentication is required for the public API.
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

// GetRepositoryInfo retrieves repository metadata from Docker Hub.
// For official images, the namespace should be "library".
func (c *HTTPClient) GetRepositoryInfo(
	ctx context.Context, namespace, repository string,
) (*RepositoryInfo, error) {
	start := time.Now()

	// Build the request URL
	requestURL := fmt.Sprintf("%s/repositories/%s/%s", c.baseURL, namespace, repository)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	duration := time.Since(start).Seconds()
	if err != nil {
		metrics.RecordDockerHubRequest("error", "repository", duration)
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Handle response status codes
	switch resp.StatusCode {
	case http.StatusOK:
		// Continue processing
	case http.StatusNotFound:
		metrics.RecordDockerHubRequest("not_found", "repository", duration)
		return nil, nil
	case http.StatusTooManyRequests:
		metrics.RecordDockerHubRequest("rate_limited", "repository", duration)
		return nil, fmt.Errorf("rate limited by Docker Hub")
	default:
		body, _ := io.ReadAll(resp.Body)
		metrics.RecordDockerHubRequest("error", "repository", duration)
		return nil, fmt.Errorf("unexpected response status %s: %s", resp.Status, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var repoResp DockerHubRepositoryResponse
	if err := json.Unmarshal(body, &repoResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	metrics.RecordDockerHubRequest("success", "repository", duration)

	// Convert to RepositoryInfo
	info := &RepositoryInfo{
		Namespace:   repoResp.Namespace,
		Name:        repoResp.Name,
		IsOfficial:  namespace == "library",
		PullCount:   repoResp.PullCount,
		StarCount:   repoResp.StarCount,
		LastUpdated: repoResp.LastUpdated,
		Description: repoResp.Description,
	}

	// Check for verified publisher status
	// Verified publishers have specific namespace properties
	// We'll check this via an additional API call if needed
	if !info.IsOfficial {
		info.IsVerifiedPublisher = c.checkVerifiedPublisher(ctx, namespace)
	}

	return info, nil
}

// checkVerifiedPublisher checks if a namespace belongs to a Docker Verified Publisher.
// This uses the orgs API endpoint which returns a "badge" field.
func (c *HTTPClient) checkVerifiedPublisher(ctx context.Context, namespace string) bool {
	log := ctrl.Log.WithName("dockerhub")
	requestURL := fmt.Sprintf("%s/orgs/%s", c.baseURL, namespace)

	log.V(1).Info("checking verified publisher status", "namespace", namespace, "url", requestURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		log.V(1).Info("failed to create request", "namespace", namespace, "error", err)
		return false
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.V(1).Info("failed to execute request", "namespace", namespace, "error", err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		log.V(1).Info("non-OK status from orgs endpoint",
			"namespace", namespace, "status", resp.StatusCode)
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.V(1).Info("failed to read response body", "namespace", namespace, "error", err)
		return false
	}

	var orgResp DockerHubOrgResponse
	if err := json.Unmarshal(body, &orgResp); err != nil {
		log.V(1).Info("failed to parse response", "namespace", namespace, "error", err)
		return false
	}

	isVerified := orgResp.Badge == "verified_publisher"
	log.V(1).Info("verified publisher check result",
		"namespace", namespace, "badge", orgResp.Badge, "isVerified", isVerified)

	return isVerified
}

// IsHealthy checks if the Docker Hub API is accessible
func (c *HTTPClient) IsHealthy(ctx context.Context) bool {
	// Docker Hub doesn't have a dedicated health endpoint,
	// so we check if we can access a known repository
	requestURL := fmt.Sprintf("%s/repositories/library/alpine", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, requestURL, nil)
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

// FormatPullCount converts pull count to human-readable format
func FormatPullCount(count int64) string {
	switch {
	case count >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(count)/1_000_000_000)
	case count >= 1_000_000:
		return fmt.Sprintf("%.0fM", float64(count)/1_000_000)
	case count >= 1_000:
		return fmt.Sprintf("%.0fK", float64(count)/1_000)
	default:
		return fmt.Sprintf("%d", count)
	}
}

// CalculateDaysSince returns days since the given time
func CalculateDaysSince(t time.Time) int {
	return int(time.Since(t).Hours() / 24)
}
