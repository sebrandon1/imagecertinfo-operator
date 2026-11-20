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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/sebrandon1/imagecertinfo-operator/internal/metrics"
)

const (
	testPyxisRegistry   = "registry.redhat.io"
	testPyxisRepository = "ubi8/ubi"

	testArchAMD64   = "amd64"
	testArchARM64   = "arm64"
	testArchPPC64LE = "ppc64le"
	testArchS390X   = "s390x"

	testAdvisoryOne = "RHSA-2026:0001"
	testCVEOne      = "CVE-2026-0001"
)

func TestHTTPClient_GetImageCertification(t *testing.T) {
	tests := []struct {
		name          string
		registry      string
		repository    string
		digest        string
		imageResponse *PyxisImageResponse
		repoResponse  *PyxisContainerRepository
		serverStatus  int
		wantErr       bool
		wantNil       bool
		wantHealth    string
	}{
		{
			name:       "certified image found",
			registry:   testPyxisRegistry,
			repository: "ubi8/ubi",
			digest:     "sha256:abc123",
			imageResponse: &PyxisImageResponse{
				ID:        "test-id",
				Certified: true,
				FreshnessGrades: []PyxisFreshnessGrade{
					{Grade: "A"},
				},
				Repositories: []PyxisImageRepository{
					{Registry: testPyxisRegistry, Repository: "ubi8/ubi"},
				},
				ParsedData: &PyxisImageParsedData{
					Labels: []PyxisLabel{
						{Name: "vendor", Value: "Red Hat"},
						{Name: "com.redhat.component", Value: "ubi8-container"},
					},
				},
				VulnerabilitySummary: &PyxisVulnerabilitySummary{
					Critical:  0,
					Important: 1,
					Moderate:  5,
					Low:       10,
				},
				TotalSizeBytes:           100000000,
				CanAutoReleaseCVERebuild: true,
				ContentStreamGrades: []PyxisContentStreamGrade{
					{Architecture: testArchAMD64, Grade: "A"},
					{Architecture: testArchARM64, Grade: "A"},
				},
			},
			repoResponse: &PyxisContainerRepository{
				ID:                       "repo-123",
				EOLDate:                  "2025-12-31",
				ReleaseCategories:        []string{"Generally Available"},
				ReplacedByRepositoryName: "",
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
			wantNil:      false,
			wantHealth:   "A",
		},
		{
			name:         "image not found",
			registry:     testPyxisRegistry,
			repository:   "unknown/image",
			digest:       "sha256:notfound",
			serverStatus: http.StatusNotFound,
			wantErr:      false,
			wantNil:      true,
		},
		{
			name:         "unauthorized",
			registry:     testPyxisRegistry,
			repository:   "protected/image",
			digest:       "sha256:protected",
			serverStatus: http.StatusUnauthorized,
			wantErr:      true,
		},
		{
			name:         "server error",
			registry:     testPyxisRegistry,
			repository:   "error/image",
			digest:       "sha256:error",
			serverStatus: http.StatusInternalServerError,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle repository endpoint
				if strings.Contains(r.URL.Path, "/repositories/registry/") {
					if tt.repoResponse != nil {
						w.WriteHeader(http.StatusOK)
						_ = json.NewEncoder(w).Encode(tt.repoResponse)
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
					return
				}
				// Handle vulnerabilities endpoint
				if strings.Contains(r.URL.Path, "/vulnerabilities") {
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(PyxisVulnerabilitiesResponse{Data: []PyxisVulnerability{}})
					return
				}
				// Handle images endpoint
				w.WriteHeader(tt.serverStatus)
				if tt.imageResponse != nil {
					// Wrap in paged response
					pagedResp := PyxisPagedResponse{
						Data: []PyxisImageResponse{*tt.imageResponse},
					}
					_ = json.NewEncoder(w).Encode(pagedResp)
				}
			}))
			defer server.Close()

			client := NewHTTPClient(
				WithBaseURL(server.URL),
			)

			got, err := client.GetImageCertification(context.Background(), tt.registry, tt.repository, tt.digest)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetImageCertification() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantNil && got != nil {
				t.Errorf("GetImageCertification() = %v, want nil", got)
				return
			}

			if !tt.wantNil && !tt.wantErr {
				if got == nil {
					t.Error("GetImageCertification() returned nil, want non-nil")
					return
				}
				if got.HealthIndex != tt.wantHealth {
					t.Errorf("GetImageCertification() HealthIndex = %v, want %v", got.HealthIndex, tt.wantHealth)
				}
				// Verify new fields are populated
				if got.CompressedSizeBytes == 0 && tt.imageResponse != nil && tt.imageResponse.TotalSizeBytes > 0 {
					t.Error("GetImageCertification() CompressedSizeBytes not populated")
				}
				if len(got.Architectures) == 0 && tt.imageResponse != nil && len(tt.imageResponse.ContentStreamGrades) > 0 {
					t.Error("GetImageCertification() Architectures not populated")
				}
			}
		})
	}
}

func TestHTTPClient_IsHealthy(t *testing.T) {
	tests := []struct {
		name         string
		serverStatus int
		want         bool
	}{
		{
			name:         "healthy",
			serverStatus: http.StatusOK,
			want:         true,
		},
		{
			name:         "unhealthy - server error",
			serverStatus: http.StatusInternalServerError,
			want:         false,
		},
		{
			name:         "unhealthy - not found",
			serverStatus: http.StatusNotFound,
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/ping" {
					w.WriteHeader(tt.serverStatus)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			client := NewHTTPClient(WithBaseURL(server.URL))

			if got := client.IsHealthy(context.Background()); got != tt.want {
				t.Errorf("IsHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewHTTPClient_Options(t *testing.T) {
	client := NewHTTPClient(
		WithBaseURL("https://custom.api.example.com"),
		WithAPIKey("test-api-key"),
	)

	if client.baseURL != "https://custom.api.example.com" {
		t.Errorf("baseURL = %v, want https://custom.api.example.com", client.baseURL)
	}
	if client.APIKey() != "test-api-key" {
		t.Errorf("APIKey() = %v, want test-api-key", client.APIKey())
	}
}

// shortRetryBase shortens the backoff for the duration of a test.
func shortRetryBase(t *testing.T) {
	t.Helper()

	previous := retryBaseDelay
	retryBaseDelay = time.Millisecond
	t.Cleanup(func() { retryBaseDelay = previous })
}

func TestHTTPClient_FetchAndParseResponse_RetriesRateLimit(t *testing.T) {
	shortRetryBase(t)

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"_id":"img-1","certified":true}]}`))
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	resp, err := client.fetchAndParseResponse(context.Background(), server.URL+"/images")
	if err != nil {
		t.Fatalf("fetchAndParseResponse() error = %v, want nil", err)
	}
	if resp == nil || resp.ID != "img-1" {
		t.Fatalf("fetchAndParseResponse() = %+v, want image img-1", resp)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

func TestHTTPClient_FetchAndParseResponse_GivesUpAfterThreeAttempts(t *testing.T) {
	shortRetryBase(t)

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	if _, err := client.fetchAndParseResponse(context.Background(), server.URL+"/images"); err == nil {
		t.Fatal("fetchAndParseResponse() error = nil, want error")
	}
	if got := attempts.Load(); got != maxRetryAttempts {
		t.Errorf("attempts = %d, want %d", got, maxRetryAttempts)
	}
}

func TestHTTPClient_FetchAndParseResponse_DoesNotRetryClientErrors(t *testing.T) {
	shortRetryBase(t)

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	if _, err := client.fetchAndParseResponse(context.Background(), server.URL+"/images"); err == nil {
		t.Fatal("fetchAndParseResponse() error = nil, want error")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
}

func TestHTTPClient_FetchAndParseResponse_StopsWhenContextExpires(t *testing.T) {
	previous := retryBaseDelay
	retryBaseDelay = time.Hour
	t.Cleanup(func() { retryBaseDelay = previous })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := client.fetchAndParseResponse(ctx, server.URL+"/images"); err == nil {
		t.Fatal("fetchAndParseResponse() error = nil, want context error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("fetchAndParseResponse() took %v, want it to stop at the context deadline", elapsed)
	}
}

func TestRetryDelay(t *testing.T) {
	previous := retryBaseDelay
	retryBaseDelay = 100 * time.Millisecond
	t.Cleanup(func() { retryBaseDelay = previous })

	tests := []struct {
		name       string
		attempt    int
		retryAfter time.Duration
		min        time.Duration
		max        time.Duration
	}{
		{name: "first retry", attempt: 0, min: 70 * time.Millisecond, max: 130 * time.Millisecond},
		{name: "second retry doubles", attempt: 1, min: 140 * time.Millisecond, max: 260 * time.Millisecond},
		{name: "caps at max", attempt: 10, min: maxRetryDelay * 7 / 10, max: maxRetryAfterDelay},
		{name: "retry-after wins", attempt: 0, retryAfter: 2 * time.Second, min: 2 * time.Second, max: 2 * time.Second},
		{
			name: "retry-after is capped", attempt: 0, retryAfter: time.Minute,
			min: maxRetryAfterDelay, max: maxRetryAfterDelay,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := retryDelay(tt.attempt, tt.retryAfter)
			if got < tt.min || got > tt.max {
				t.Errorf("retryDelay(%d, %v) = %v, want between %v and %v",
					tt.attempt, tt.retryAfter, got, tt.min, tt.max)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{name: "empty", value: "", want: 0},
		{name: "seconds", value: "3", want: 3 * time.Second},
		{name: "zero", value: "0", want: 0},
		{name: "negative", value: "-5", want: 0},
		{name: "garbage", value: "soon", want: 0},
		{name: "past date", value: "Wed, 21 Oct 2015 07:28:00 GMT", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseRetryAfter(tt.value); got != tt.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestHTTPClient_FetchAndParseResponse_DoesNotRetryBadRequest(t *testing.T) {
	shortRetryBase(t)

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	if _, err := client.fetchAndParseResponse(context.Background(), server.URL+"/images"); err == nil {
		t.Fatal("fetchAndParseResponse() error = nil, want error")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
}

func TestHTTPClient_FetchAndParseResponse_RetriesTransportErrors(t *testing.T) {
	shortRetryBase(t)

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		// Drop the connection without a response so the client sees a
		// transport error rather than an HTTP status.
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = conn.Close()
		}
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	if _, err := client.fetchAndParseResponse(context.Background(), server.URL+"/images"); err == nil {
		t.Fatal("fetchAndParseResponse() error = nil, want error")
	}
	if got := attempts.Load(); got != maxRetryAttempts {
		t.Errorf("attempts = %d, want %d", got, maxRetryAttempts)
	}
}

func TestExtractArchitectures_Sorted(t *testing.T) {
	grades := []PyxisContentStreamGrade{
		{Architecture: testArchS390X, Grade: "A"},
		{Architecture: testArchAMD64, Grade: "A"},
		{Architecture: testArchPPC64LE, Grade: "B"},
		{Architecture: testArchARM64, Grade: "A"},
		{Architecture: testArchAMD64, Grade: "B"},
	}

	want := []string{testArchAMD64, testArchARM64, testArchPPC64LE, testArchS390X}
	for range 20 {
		got := extractArchitectures(grades)
		if len(got) != len(want) {
			t.Fatalf("extractArchitectures() = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("extractArchitectures() = %v, want %v", got, want)
			}
		}
	}
}

func TestExtractArchitectures_Empty(t *testing.T) {
	got := extractArchitectures(nil)
	if got == nil {
		t.Fatal("extractArchitectures(nil) = nil, want an empty non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("extractArchitectures(nil) = %v, want empty", got)
	}
}

func TestHTTPClient_GetVulnerabilitiesWithAdvisories_Sorted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(PyxisVulnerabilitiesResponse{Data: []PyxisVulnerability{
			{CVEID: "CVE-2026-0003", AdvisoryID: "RHSA-2026:0003"},
			{CVEID: testCVEOne, AdvisoryID: testAdvisoryOne},
			{CVEID: "CVE-2026-0002", AdvisoryID: "RHSA-2026:0002"},
			{CVEID: "CVE-2026-0004", AdvisoryID: testAdvisoryOne},
		}})
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	wantAdvisories := []string{testAdvisoryOne, "RHSA-2026:0002", "RHSA-2026:0003"}
	// CVEs keep the API order; only advisories are sorted.
	wantCVEs := []string{"CVE-2026-0003", testCVEOne, "CVE-2026-0002", "CVE-2026-0004"}

	for range 20 {
		cves, advisories := client.getVulnerabilitiesWithAdvisories(context.Background(), "image-id")

		if len(cves) != len(wantCVEs) {
			t.Fatalf("cves = %v, want %v", cves, wantCVEs)
		}
		for i := range wantCVEs {
			if cves[i] != wantCVEs[i] {
				t.Fatalf("cves = %v, want %v (API order must be preserved)", cves, wantCVEs)
			}
		}

		if len(advisories) != len(wantAdvisories) {
			t.Fatalf("advisories = %v, want %v", advisories, wantAdvisories)
		}
		for i := range wantAdvisories {
			if advisories[i] != wantAdvisories[i] {
				t.Fatalf("advisories = %v, want %v", advisories, wantAdvisories)
			}
		}
	}
}

func TestHTTPClient_GetRepositoryInfo_RetriesTransientFailure(t *testing.T) {
	shortRetryBase(t)

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"_id":"repo-1","eol_date":"2030-01-01","release_categories":["Generally Available"]}`))
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	info := client.getRepositoryInfo(context.Background(), "registry.redhat.io", "ubi8/ubi")
	if info == nil {
		t.Fatal("getRepositoryInfo() = nil, want the retried response")
	}
	if info.EOLDate != "2030-01-01" {
		t.Errorf("EOLDate = %q, want 2030-01-01", info.EOLDate)
	}
	if info.ReleaseCategory != "Generally Available" {
		t.Errorf("ReleaseCategory = %q, want Generally Available", info.ReleaseCategory)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
	if got := testutil.ToFloat64(metrics.PyxisRequestsTotal.WithLabelValues("success", "repository")); got < 1 {
		t.Errorf("pyxis_requests_total{endpoint=\"repository\"} = %v, want at least 1", got)
	}
}

func TestHTTPClient_GetRepositoryInfo_Failures(t *testing.T) {
	shortRetryBase(t)

	tests := []struct {
		name       string
		status     int
		wantStatus string
	}{
		{name: "404 is not found", status: http.StatusNotFound, wantStatus: "not_found"},
		{name: "permanent 500 is an error", status: http.StatusInternalServerError, wantStatus: "error"},
		{name: "403 is not retried", status: http.StatusForbidden, wantStatus: "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				attempts.Add(1)
				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			client := NewHTTPClient(WithBaseURL(server.URL))

			if info := client.getRepositoryInfo(context.Background(), "registry.redhat.io", "ubi8/ubi"); info != nil {
				t.Fatalf("getRepositoryInfo() = %+v, want nil so enrichment stays best-effort", info)
			}
			if got := testutil.ToFloat64(metrics.PyxisRequestsTotal.WithLabelValues(tt.wantStatus, "repository")); got < 1 {
				t.Errorf("pyxis_requests_total{status=%q,endpoint=\"repository\"} = %v, want at least 1",
					tt.wantStatus, got)
			}
		})
	}
}

func TestHTTPClient_GetVulnerabilitiesWithAdvisories_RetriesTransientFailure(t *testing.T) {
	shortRetryBase(t)

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"cve_id":"` + testCVEOne + `","severity":"Critical","advisory_id":"RHSA-2026:1"}]}`))
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	cves, advisories := client.getVulnerabilitiesWithAdvisories(context.Background(), "img-1")
	if len(cves) != 1 || cves[0] != testCVEOne {
		t.Errorf("CVEs = %v, want [%s]", cves, testCVEOne)
	}
	if len(advisories) != 1 || advisories[0] != "RHSA-2026:1" {
		t.Errorf("advisories = %v, want [RHSA-2026:1]", advisories)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

func TestHTTPClient_GetVulnerabilitiesWithAdvisories_PermanentFailureIsEmpty(t *testing.T) {
	shortRetryBase(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	cves, advisories := client.getVulnerabilitiesWithAdvisories(context.Background(), "img-1")
	if len(cves) != 0 || len(advisories) != 0 {
		t.Errorf("getVulnerabilitiesWithAdvisories() = %v, %v, want empty slices", cves, advisories)
	}
	if got := testutil.ToFloat64(metrics.PyxisRequestsTotal.WithLabelValues("error", "vulnerabilities")); got < 1 {
		t.Errorf("pyxis_requests_total{status=\"error\",endpoint=\"vulnerabilities\"} = %v, want at least 1", got)
	}
}

func TestHTTPClient_GetVulnerabilitiesWithAdvisories_NotFoundIsEmpty(t *testing.T) {
	shortRetryBase(t)

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	cves, advisories := client.getVulnerabilitiesWithAdvisories(context.Background(), "img-1")
	if len(cves) != 0 || len(advisories) != 0 {
		t.Errorf("getVulnerabilitiesWithAdvisories() = %v, %v, want empty slices", cves, advisories)
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1: a 404 is an answer, not a retryable failure", got)
	}
	if got := testutil.ToFloat64(metrics.PyxisRequestsTotal.WithLabelValues("not_found", "vulnerabilities")); got < 1 {
		t.Errorf("pyxis_requests_total{status=\"not_found\",endpoint=\"vulnerabilities\"} = %v, want at least 1", got)
	}
}

func TestHTTPClient_GetRepositoryInfo_MalformedJSONIsAnError(t *testing.T) {
	shortRetryBase(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`this is not json`))
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	if info := client.getRepositoryInfo(context.Background(), "registry.redhat.io", "ubi8/ubi"); info != nil {
		t.Fatalf("getRepositoryInfo() = %+v, want nil when the body cannot be parsed", info)
	}
	if got := testutil.ToFloat64(metrics.PyxisRequestsTotal.WithLabelValues("error", "repository")); got < 1 {
		t.Errorf("pyxis_requests_total{status=\"error\",endpoint=\"repository\"} = %v, want at least 1", got)
	}
}

func TestHTTPClient_DoJSONWithRetry_StopsWhenContextExpires(t *testing.T) {
	shortRetryBase(t)

	// The server asks for a long backoff; the caller's deadline expires first,
	// so the retry loop must return instead of sleeping through it.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL))

	start := time.Now()
	var out map[string]any
	err := client.doJSONWithRetry(ctx, server.URL+"/repositories", &out)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("doJSONWithRetry() error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("doJSONWithRetry() took %v, want it to stop at the deadline", elapsed)
	}
}

func TestHTTPClient_APIKeyRotation(t *testing.T) {
	const digest = "sha256:abc123"

	var (
		mu   sync.Mutex
		seen []string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get(apiKeyHeader))
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total":0,"data":[]}`))
	}))
	defer server.Close()

	client := NewHTTPClient(WithBaseURL(server.URL), WithAPIKey("first"))

	lastHeader := func() string {
		mu.Lock()
		defer mu.Unlock()

		if len(seen) == 0 {
			t.Fatal("no request reached the server")
		}

		return seen[len(seen)-1]
	}

	request := func() {
		t.Helper()

		if _, err := client.GetImageCertification(
			context.Background(), "registry.redhat.io", "ubi9/ubi", digest); err != nil {
			t.Fatalf("GetImageCertification() error = %v", err)
		}
	}

	request()
	if got := lastHeader(); got != "first" {
		t.Errorf("X-API-KEY = %q, want first", got)
	}

	// A rotated key must apply to the next request without rebuilding the
	// client, which is what makes Secret rotation work.
	client.SetAPIKey("second")
	request()
	if got := lastHeader(); got != "second" {
		t.Errorf("X-API-KEY = %q, want second after SetAPIKey", got)
	}

	// Clearing the key must remove the header rather than send an empty one.
	client.SetAPIKey("")
	request()
	if got := lastHeader(); got != "" {
		t.Errorf("X-API-KEY = %q, want it absent after the key was cleared", got)
	}
}
