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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPClient_GetImageCertification(t *testing.T) {
	tests := []struct {
		name           string
		registry       string
		repository     string
		digest         string
		imageResponse  *PyxisImageResponse
		repoResponse   *PyxisContainerRepository
		serverStatus   int
		wantErr        bool
		wantNil        bool
		wantHealth     string
	}{
		{
			name:       "certified image found",
			registry:   "registry.redhat.io",
			repository: "ubi8/ubi",
			digest:     "sha256:abc123",
			imageResponse: &PyxisImageResponse{
				ID:        "test-id",
				Certified: true,
				FreshnessGrades: []PyxisFreshnessGrade{
					{Grade: "A"},
				},
				Repositories: []PyxisImageRepository{
					{Registry: "registry.redhat.io", Repository: "ubi8/ubi"},
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
					{Architecture: "amd64", Grade: "A"},
					{Architecture: "arm64", Grade: "A"},
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
			registry:     "registry.redhat.io",
			repository:   "unknown/image",
			digest:       "sha256:notfound",
			serverStatus: http.StatusNotFound,
			wantErr:      false,
			wantNil:      true,
		},
		{
			name:         "unauthorized",
			registry:     "registry.redhat.io",
			repository:   "protected/image",
			digest:       "sha256:protected",
			serverStatus: http.StatusUnauthorized,
			wantErr:      true,
		},
		{
			name:         "server error",
			registry:     "registry.redhat.io",
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
	if client.apiKey != "test-api-key" {
		t.Errorf("apiKey = %v, want test-api-key", client.apiKey)
	}
}
