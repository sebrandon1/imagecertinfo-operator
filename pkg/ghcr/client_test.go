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

package ghcr

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func withServer(t *testing.T, handler http.HandlerFunc) *HTTPClient {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client := NewHTTPClient("test-token")
	client.httpClient.BaseURL = server.URL

	return client
}

func TestGetPackage(t *testing.T) {
	body := `{"name":"app","visibility":"public","version_count":7,
		"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-02-03T04:05:06Z",
		"html_url":"https://github.com/orgs/example/packages/container/app"}`

	t.Run("reads an organization package", func(t *testing.T) {
		var hits []string

		client := withServer(t, func(w http.ResponseWriter, r *http.Request) {
			hits = append(hits, r.URL.Path)
			if r.URL.Path != "/orgs/example/packages/container/app" {
				http.NotFound(w, r)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})

		info, err := client.GetPackage(context.Background(), "example", "app")
		if err != nil {
			t.Fatalf("GetPackage() error = %v, want nil", err)
		}

		if info.Visibility != "public" || info.VersionCount != 7 {
			t.Errorf("PackageInfo = %+v, want visibility public and 7 versions", info)
		}
		if info.Owner != "example" || info.Name != "app" {
			t.Errorf("Owner/Name = %s/%s, want example/app", info.Owner, info.Name)
		}
		if info.HTMLURL == "" || info.UpdatedAt.IsZero() || info.CreatedAt.IsZero() {
			t.Errorf("PackageInfo = %+v, want the URL and timestamps populated", info)
		}
		if want := []string{"/orgs/example/packages/container/app"}; !reflect.DeepEqual(hits, want) {
			t.Errorf("request paths = %v, want %v: a hit on the orgs endpoint must not fall through", hits, want)
		}
	})

	t.Run("falls back to the users endpoint", func(t *testing.T) {
		client := withServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/users/someone/packages/container/app" {
				http.NotFound(w, r)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})

		if _, err := client.GetPackage(context.Background(), "someone", "app"); err != nil {
			t.Fatalf("GetPackage() error = %v, want nil when the user endpoint has the package", err)
		}
	})

	t.Run("reports a missing package", func(t *testing.T) {
		client := withServer(t, http.NotFound)

		if _, err := client.GetPackage(context.Background(), "example", "missing"); !errors.Is(err, ErrNotFound) {
			t.Errorf("GetPackage() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("stops at an unauthorized answer", func(t *testing.T) {
		calls := 0
		client := withServer(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(http.StatusUnauthorized)
		})

		if _, err := client.GetPackage(context.Background(), "example", "app"); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("GetPackage() error = %v, want ErrUnauthorized", err)
		}
		if calls != 1 {
			t.Errorf("calls = %d, want 1: an auth failure must not be retried against the users endpoint", calls)
		}
	})

	t.Run("reports a server error", func(t *testing.T) {
		client := withServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, err := client.GetPackage(context.Background(), "example", "app")
		if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnauthorized) {
			t.Errorf("GetPackage() error = %v, want a generic error for a 500", err)
		}
	})
}

func TestNewHTTPClient_SendsToken(t *testing.T) {
	var got string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"visibility":"public","version_count":1}`))
	}))
	defer server.Close()

	client := NewHTTPClient("secret-token")
	client.httpClient.BaseURL = server.URL

	if _, err := client.GetPackage(context.Background(), "example", "app"); err != nil {
		t.Fatalf("GetPackage() error = %v", err)
	}
	if want := "Bearer secret-token"; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

func TestIsHealthy(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   bool
	}{
		{name: "ok", status: http.StatusOK, want: true},
		{name: "unauthorized", status: http.StatusUnauthorized, want: false},
		{name: "server error", status: http.StatusInternalServerError, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := withServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			})

			if got := client.IsHealthy(context.Background()); got != tt.want {
				t.Errorf("IsHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}
