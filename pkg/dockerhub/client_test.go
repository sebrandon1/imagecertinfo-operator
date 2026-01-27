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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPClient_GetRepositoryInfo(t *testing.T) {
	tests := []struct {
		name          string
		namespace     string
		repository    string
		repoResponse  *DockerHubRepositoryResponse
		orgResponse   *DockerHubOrgResponse
		serverStatus  int
		wantErr       bool
		wantNil       bool
		wantOfficial  bool
		wantVerified  bool
		wantPullCount int64
	}{
		{
			name:       "official image found",
			namespace:  "library",
			repository: "nginx",
			repoResponse: &DockerHubRepositoryResponse{
				Namespace:   "library",
				Name:        "nginx",
				PullCount:   10_000_000_000,
				StarCount:   15000,
				LastUpdated: time.Now().Add(-10 * 24 * time.Hour),
				Description: "Official build of Nginx",
			},
			serverStatus:  http.StatusOK,
			wantErr:       false,
			wantNil:       false,
			wantOfficial:  true,
			wantVerified:  false,
			wantPullCount: 10_000_000_000,
		},
		{
			name:       "verified publisher image",
			namespace:  "bitnami",
			repository: "redis",
			repoResponse: &DockerHubRepositoryResponse{
				Namespace:   "bitnami",
				Name:        "redis",
				PullCount:   500_000_000,
				StarCount:   100,
				LastUpdated: time.Now().Add(-5 * 24 * time.Hour),
				Description: "Bitnami Redis",
			},
			orgResponse: &DockerHubOrgResponse{
				Orgname: "bitnami",
				Badge:   "verified_publisher",
			},
			serverStatus:  http.StatusOK,
			wantErr:       false,
			wantNil:       false,
			wantOfficial:  false,
			wantVerified:  true,
			wantPullCount: 500_000_000,
		},
		{
			name:       "community image",
			namespace:  "someuser",
			repository: "myapp",
			repoResponse: &DockerHubRepositoryResponse{
				Namespace:   "someuser",
				Name:        "myapp",
				PullCount:   100,
				StarCount:   0,
				LastUpdated: time.Now().Add(-100 * 24 * time.Hour),
				Description: "My test app",
			},
			orgResponse: &DockerHubOrgResponse{
				Orgname: "someuser",
				Badge:   "",
			},
			serverStatus:  http.StatusOK,
			wantErr:       false,
			wantNil:       false,
			wantOfficial:  false,
			wantVerified:  false,
			wantPullCount: 100,
		},
		{
			name:         "repository not found",
			namespace:    "nonexistent",
			repository:   "unknown",
			serverStatus: http.StatusNotFound,
			wantErr:      false,
			wantNil:      true,
		},
		{
			name:         "rate limited",
			namespace:    "library",
			repository:   "nginx",
			serverStatus: http.StatusTooManyRequests,
			wantErr:      true,
		},
		{
			name:         "server error",
			namespace:    "library",
			repository:   "nginx",
			serverStatus: http.StatusInternalServerError,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle orgs endpoint for verified publisher check
				if r.URL.Path == "/orgs/"+tt.namespace {
					if tt.orgResponse != nil {
						w.WriteHeader(http.StatusOK)
						_ = json.NewEncoder(w).Encode(tt.orgResponse)
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
					return
				}
				// Handle repository endpoint
				w.WriteHeader(tt.serverStatus)
				if tt.repoResponse != nil && tt.serverStatus == http.StatusOK {
					_ = json.NewEncoder(w).Encode(tt.repoResponse)
				}
			}))
			defer server.Close()

			client := NewHTTPClient(WithBaseURL(server.URL))

			got, err := client.GetRepositoryInfo(context.Background(), tt.namespace, tt.repository)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetRepositoryInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantNil && got != nil {
				t.Errorf("GetRepositoryInfo() = %v, want nil", got)
				return
			}

			if !tt.wantNil && !tt.wantErr {
				if got == nil {
					t.Error("GetRepositoryInfo() returned nil, want non-nil")
					return
				}
				if got.IsOfficial != tt.wantOfficial {
					t.Errorf("GetRepositoryInfo() IsOfficial = %v, want %v", got.IsOfficial, tt.wantOfficial)
				}
				if got.IsVerifiedPublisher != tt.wantVerified {
					t.Errorf("GetRepositoryInfo() IsVerifiedPublisher = %v, want %v", got.IsVerifiedPublisher, tt.wantVerified)
				}
				if got.PullCount != tt.wantPullCount {
					t.Errorf("GetRepositoryInfo() PullCount = %v, want %v", got.PullCount, tt.wantPullCount)
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
				// Health check uses HEAD to library/alpine
				if r.URL.Path == "/repositories/library/alpine" {
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
		WithBaseURL("https://custom.hub.example.com"),
	)

	if client.baseURL != "https://custom.hub.example.com" {
		t.Errorf("baseURL = %v, want https://custom.hub.example.com", client.baseURL)
	}
}

func TestFormatPullCount(t *testing.T) {
	tests := []struct {
		count int64
		want  string
	}{
		{count: 0, want: "0"},
		{count: 100, want: "100"},
		{count: 999, want: "999"},
		{count: 1000, want: "1K"},
		{count: 1500, want: "2K"},
		{count: 999999, want: "1000K"},
		{count: 1000000, want: "1M"},
		{count: 12700000, want: "13M"},
		{count: 434000000, want: "434M"},
		{count: 999999999, want: "1000M"},
		{count: 1000000000, want: "1.0B"},
		{count: 12700000000, want: "12.7B"},
		{count: 100000000000, want: "100.0B"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatPullCount(tt.count)
			if got != tt.want {
				t.Errorf("FormatPullCount(%d) = %v, want %v", tt.count, got, tt.want)
			}
		})
	}
}

func TestCalculateDaysSince(t *testing.T) {
	tests := []struct {
		name string
		time time.Time
		want int
	}{
		{
			name: "today",
			time: time.Now(),
			want: 0,
		},
		{
			name: "1 day ago",
			time: time.Now().Add(-25 * time.Hour),
			want: 1,
		},
		{
			name: "10 days ago",
			time: time.Now().Add(-10 * 24 * time.Hour),
			want: 10,
		},
		{
			name: "100 days ago",
			time: time.Now().Add(-100 * 24 * time.Hour),
			want: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateDaysSince(tt.time)
			if got != tt.want {
				t.Errorf("CalculateDaysSince() = %v, want %v", got, tt.want)
			}
		})
	}
}
