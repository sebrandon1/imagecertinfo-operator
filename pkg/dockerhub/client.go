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
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"

	"github.com/sebrandon1/go-toolbox/httpx"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/sebrandon1/imagecertinfo-operator/internal/metrics"
)

const (
	// DefaultBaseURL is the default Docker Hub API base URL
	DefaultBaseURL = "https://hub.docker.com/v2"
	// DefaultTimeout is the default HTTP client timeout
	DefaultTimeout = 30 * time.Second

	// maxRetryAttempts is the total number of attempts, including the first.
	maxRetryAttempts = 3
	// maxRetryDelay caps the exponential part of the backoff.
	maxRetryDelay = 5 * time.Second
	// maxRetryAfterDelay caps a server-requested Retry-After delay.
	maxRetryAfterDelay = 10 * time.Second
	// retryJitterFraction is the relative jitter applied to the backoff.
	retryJitterFraction = 0.3

	// metricResultError labels a failed Docker Hub request.
	metricResultError = "error"
)

// retryBaseDelay is the first backoff step. It is a variable so tests can
// shorten it.
var retryBaseDelay = 100 * time.Millisecond

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
	httpClient *httpx.Client
}

// ClientOption is a function that configures an HTTPClient
type ClientOption func(*HTTPClient)

// WithBaseURL sets a custom base URL
func WithBaseURL(baseURL string) ClientOption {
	return func(c *HTTPClient) {
		c.baseURL = baseURL
		c.httpClient.BaseURL = baseURL
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *HTTPClient) {
		c.httpClient.HTTPClient = httpClient
	}
}

// WithTimeout sets a custom timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *HTTPClient) {
		c.httpClient.HTTPClient.Timeout = timeout
	}
}

// NewHTTPClient creates a new Docker Hub HTTP client.
// No authentication is required for the public API.
func NewHTTPClient(opts ...ClientOption) *HTTPClient {
	client := &HTTPClient{
		baseURL: DefaultBaseURL,
		httpClient: httpx.NewClient(httpx.Options{
			BaseURL: DefaultBaseURL,
			Timeout: DefaultTimeout,
			Headers: http.Header{"Accept": {"application/json"}},
		}),
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

// GetRepositoryInfo retrieves repository metadata from Docker Hub.
// For official images, the namespace should be "library".
// Transport errors and 429/5xx responses are retried with jittered exponential
// backoff; the caller's context deadline wins over the retry budget.
func (c *HTTPClient) GetRepositoryInfo(
	ctx context.Context, namespace, repository string,
) (*RepositoryInfo, error) {
	start := time.Now()

	// Build the request URL
	requestURL := fmt.Sprintf("%s/repositories/%s/%s", c.baseURL, namespace, repository)

	repoResp, status, err := c.fetchRepository(ctx, requestURL)
	duration := time.Since(start).Seconds()

	switch {
	case err != nil:
		metrics.RecordDockerHubRequest(status, "repository", duration)
		return nil, err
	case status == "not_found":
		metrics.RecordDockerHubRequest("not_found", "repository", duration)
		return nil, nil
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

// repositoryResult is the outcome of a single Docker Hub request attempt.
type repositoryResult struct {
	response   *DockerHubRepositoryResponse
	status     string
	err        error
	retryAfter time.Duration
	retryable  bool
}

// fetchRepository requests repository metadata, retrying transport errors and
// 429/5xx responses with jittered exponential backoff. It returns the parsed
// response, or the metric label describing the final outcome.
func (c *HTTPClient) fetchRepository(
	ctx context.Context, requestURL string,
) (*DockerHubRepositoryResponse, string, error) {
	var result repositoryResult

	for attempt := range maxRetryAttempts {
		result = c.fetchRepositoryOnce(ctx, requestURL)
		if result.err == nil || !result.retryable {
			break
		}
		if attempt == maxRetryAttempts-1 {
			break
		}
		if err := sleepWithContext(ctx, retryDelay(attempt, result.retryAfter)); err != nil {
			return nil, metricResultError, err
		}
	}

	return result.response, result.status, result.err
}

// fetchRepositoryOnce performs one repository request attempt.
func (c *HTTPClient) fetchRepositoryOnce(ctx context.Context, requestURL string) repositoryResult {
	req, err := c.httpClient.NewRequest(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return repositoryResult{status: metricResultError, err: fmt.Errorf("failed to create request: %w", err)}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return repositoryResult{status: metricResultError, err: fmt.Errorf("failed to execute request: %w", ctxErr)}
		}
		return repositoryResult{
			status:    metricResultError,
			err:       fmt.Errorf("failed to execute request: %w", err),
			retryable: true,
		}
	}
	defer func() { _ = resp.Body.Close() }()

	// Handle response status codes
	switch resp.StatusCode {
	case http.StatusOK:
		// Continue processing
	case http.StatusNotFound:
		return repositoryResult{status: "not_found"}
	case http.StatusTooManyRequests:
		return repositoryResult{
			status:     "rate_limited",
			err:        fmt.Errorf("rate limited by Docker Hub"),
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
			retryable:  true,
		}
	default:
		body := httpx.ReadErrorBody(resp.Body, c.httpClient.MaxErrorBodyBytes)
		return repositoryResult{
			status:     metricResultError,
			err:        fmt.Errorf("unexpected response status %s: %s", resp.Status, body),
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
			retryable:  isRetryableStatus(resp.StatusCode),
		}
	}

	body, err := httpx.ReadLimited(resp.Body, c.httpClient.MaxResponseBytes)
	if err != nil {
		return repositoryResult{status: metricResultError, err: fmt.Errorf("failed to read response body: %w", err)}
	}

	var repoResp DockerHubRepositoryResponse
	if err := json.Unmarshal(body, &repoResp); err != nil {
		return repositoryResult{status: metricResultError, err: fmt.Errorf("failed to parse response: %w", err)}
	}

	return repositoryResult{response: &repoResp, status: "success"}
}

// isRetryableStatus reports whether a status code warrants another attempt.
func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= http.StatusInternalServerError
}

// retryDelay computes the backoff before the next attempt. An attempt number
// of 0 is the delay after the first failure.
func retryDelay(attempt int, retryAfter time.Duration) time.Duration {
	delay := retryBaseDelay
	for range attempt {
		delay *= 2
		if delay >= maxRetryDelay {
			delay = maxRetryDelay
			break
		}
	}

	// Apply symmetric jitter so retries from many namespaces do not align.
	jitter := 1 + retryJitterFraction*(2*rand.Float64()-1)
	delay = time.Duration(float64(delay) * jitter)

	delay = min(max(delay, retryAfter), maxRetryAfterDelay)

	return delay
}

// parseRetryAfter interprets a Retry-After header value, which may be a
// number of seconds or an HTTP date. Unparseable values yield zero.
func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if delay := time.Until(when); delay > 0 {
			return delay
		}
	}
	return 0
}

// sleepWithContext waits for d or until ctx is cancelled, whichever comes first.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// checkVerifiedPublisher checks if a namespace belongs to a Docker Verified Publisher.
// This uses the orgs API endpoint which returns a "badge" field.
func (c *HTTPClient) checkVerifiedPublisher(ctx context.Context, namespace string) bool {
	log := ctrl.Log.WithName("dockerhub")
	requestURL := fmt.Sprintf("%s/orgs/%s", c.baseURL, namespace)

	log.V(1).Info("checking verified publisher status", "namespace", namespace, "url", requestURL)

	req, err := c.httpClient.NewRequest(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		log.V(1).Info("failed to create request", "namespace", namespace, "error", err)
		return false
	}

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

	body, err := httpx.ReadLimited(resp.Body, c.httpClient.MaxResponseBytes)
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

	req, err := c.httpClient.NewRequest(ctx, http.MethodHead, requestURL, nil)
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
