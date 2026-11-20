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

// Package ghcr reads GitHub Container Registry package metadata from the GitHub
// REST API.
//
// Unlike the Pyxis and Docker Hub clients there is no cache or rate limiter: the
// reconciler only enriches an image when it is first discovered and then on the
// refresh interval, and GitHub's own limits are expressed per token rather than
// per second.
package ghcr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sebrandon1/go-toolbox/httpx"
)

const (
	// DefaultBaseURL is the GitHub REST API base URL.
	DefaultBaseURL = "https://api.github.com"
	// DefaultTimeout caps a whole request.
	DefaultTimeout = 30 * time.Second
	// apiVersion is the pinned GitHub REST API version.
	apiVersion = "2022-11-28"
)

// PackageInfo is the subset of the GitHub package metadata the operator keeps.
type PackageInfo struct {
	Owner        string
	Name         string
	Visibility   string
	VersionCount int
	CreatedAt    time.Time
	UpdatedAt    time.Time
	HTMLURL      string
}

// Client reads container package metadata.
type Client interface {
	// GetPackage returns metadata for owner/name. A package that does not exist
	// returns ErrNotFound.
	GetPackage(ctx context.Context, owner, name string) (*PackageInfo, error)
	// IsHealthy checks that the GitHub API is reachable.
	IsHealthy(ctx context.Context) bool
}

// ErrNotFound reports a package that GitHub does not know about.
var ErrNotFound = errors.New("package not found")

// ErrUnauthorized reports a request GitHub rejected for missing or bad
// credentials. Every package endpoint requires a token, even for public
// packages, so this is the expected result of running without one.
var ErrUnauthorized = errors.New("github api rejected the credentials")

// HTTPClient implements Client against the GitHub REST API.
type HTTPClient struct {
	httpClient *httpx.Client
	token      string
}

// NewHTTPClient builds a client. An empty token is allowed: every package
// endpoint then answers 401, which the reconciler treats as "no enrichment".
func NewHTTPClient(token string) *HTTPClient {
	client := &HTTPClient{token: token}
	client.httpClient = httpx.NewClient(httpx.Options{
		BaseURL: DefaultBaseURL,
		Timeout: DefaultTimeout,
		Headers: http.Header{
			"Accept":               {"application/vnd.github+json"},
			"X-GitHub-Api-Version": {apiVersion},
		},
	})
	if token != "" {
		client.httpClient.Headers.Set("Authorization", "Bearer "+token)
	}

	return client
}

// packageResponse is the JSON shape of the GitHub package endpoints.
type packageResponse struct {
	Name         string    `json:"name"`
	Visibility   string    `json:"visibility"`
	VersionCount int       `json:"version_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	HTMLURL      string    `json:"html_url"`
}

// GetPackage reads package metadata. GitHub exposes the same package under the
// organizations and users endpoints, so both are tried and a 404 from each means
// the package does not exist.
func (c *HTTPClient) GetPackage(ctx context.Context, owner, name string) (*PackageInfo, error) {
	paths := []string{
		fmt.Sprintf("/orgs/%s/packages/container/%s", owner, name),
		fmt.Sprintf("/users/%s/packages/container/%s", owner, name),
	}

	var lastErr error

	for _, path := range paths {
		info, err := c.getPackageAt(ctx, path)
		if err == nil {
			info.Owner = owner
			info.Name = name

			return info, nil
		}

		if errors.Is(err, ErrUnauthorized) {
			return nil, err
		}

		lastErr = err
	}

	if lastErr == nil {
		return nil, ErrNotFound
	}

	return nil, lastErr
}

func (c *HTTPClient) getPackageAt(ctx context.Context, path string) (*PackageInfo, error) {
	req, err := c.httpClient.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get package: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// Decode below.
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, ErrUnauthorized
	default:
		return nil, fmt.Errorf("github api returned %s", resp.Status)
	}

	body, err := httpx.ReadLimited(resp.Body, c.httpClient.MaxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read package response: %w", err)
	}

	var payload packageResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode package response: %w", err)
	}

	return &PackageInfo{
		Visibility:   payload.Visibility,
		VersionCount: payload.VersionCount,
		CreatedAt:    payload.CreatedAt,
		UpdatedAt:    payload.UpdatedAt,
		HTMLURL:      payload.HTMLURL,
	}, nil
}

// IsHealthy reports whether the GitHub API answers requests at all.
func (c *HTTPClient) IsHealthy(ctx context.Context) bool {
	req, err := c.httpClient.NewRequest(ctx, http.MethodGet, "/rate_limit", nil)
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
