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

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

type fakeCachedClient struct {
	started  bool
	interval time.Duration
	stopped  bool
}

func (f *fakeCachedClient) StartCleanupLoop(ctx context.Context, interval time.Duration) {
	f.started = true
	f.interval = interval
	<-ctx.Done()
	f.stopped = true
}

// plainClient does not implement StartCleanupLoop.
type plainClient struct{}

func TestCacheCleanupRunnableFor(t *testing.T) {
	t.Run("cache-wrapped client yields a runnable", func(t *testing.T) {
		client := &fakeCachedClient{}

		runnable, ok := cacheCleanupRunnableFor(client, time.Minute)
		if !ok {
			t.Fatal("cacheCleanupRunnableFor() = false, want true for a cached client")
		}
		if runnable.interval != time.Minute {
			t.Errorf("interval = %v, want 1m", runnable.interval)
		}
		if runnable.NeedLeaderElection() {
			t.Error("NeedLeaderElection() = true, want false: cache pruning is per-replica")
		}
	})

	t.Run("uncached client is reported", func(t *testing.T) {
		if _, ok := cacheCleanupRunnableFor(&plainClient{}, time.Minute); ok {
			t.Error("cacheCleanupRunnableFor() = true, want false so the caller can log it")
		}
	})

	t.Run("nil client is reported", func(t *testing.T) {
		if _, ok := cacheCleanupRunnableFor(nil, time.Minute); ok {
			t.Error("cacheCleanupRunnableFor() = true, want false for a nil client")
		}
	})
}

func TestCacheCleanupRunnable_Start(t *testing.T) {
	client := &fakeCachedClient{}
	runnable, ok := cacheCleanupRunnableFor(client, time.Minute)
	if !ok {
		t.Fatal("cacheCleanupRunnableFor() = false, want true for a cached client")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- runnable.Start(ctx) }()

	// Start must block until the context is cancelled, otherwise the manager
	// treats the runnable as finished.
	select {
	case err := <-done:
		t.Fatalf("Start() returned before shutdown: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if !client.started {
		t.Error("StartCleanupLoop was not called")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start() did not return after the context was cancelled")
	}

	if !client.stopped {
		t.Error("cleanup loop did not observe cancellation")
	}
}

func TestRefreshLoopEnabled(t *testing.T) {
	client := &fakeCachedClient{}
	var nilClient any

	tests := []struct {
		name     string
		interval time.Duration
		clients  []any
		want     bool
	}{
		{name: "pyxis only", interval: time.Hour, clients: []any{client, nilClient, nilClient}, want: true},
		{name: "dockerhub only", interval: time.Hour, clients: []any{nilClient, client, nilClient}, want: true},
		{name: "quay only", interval: time.Hour, clients: []any{nilClient, nilClient, client}, want: true},
		{name: "all clients nil", interval: time.Hour, clients: []any{nilClient, nilClient, nilClient}, want: false},
		{name: "zero interval with a client", interval: 0, clients: []any{client}, want: false},
		{name: "negative interval with a client", interval: -time.Hour, clients: []any{client}, want: false},
		{name: "no clients passed", interval: time.Hour, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refreshLoopEnabled(tt.interval, tt.clients...); got != tt.want {
				t.Errorf("refreshLoopEnabled(%v, %d clients) = %v, want %v", tt.interval, len(tt.clients), got, tt.want)
			}
		})
	}
}

func TestValidateIntervals(t *testing.T) {
	const (
		cleanup = 5 * time.Minute
		ttl     = time.Hour
	)

	tests := []struct {
		name    string
		cleanup time.Duration
		pyxis   time.Duration
		docker  time.Duration
		quay    time.Duration
		refresh time.Duration
		wantErr string
	}{
		{
			name:    "defaults are valid",
			cleanup: cleanup, pyxis: ttl, docker: ttl, quay: ttl, refresh: 24 * time.Hour,
		},
		{
			name:    "zero refresh interval is valid (disabled)",
			cleanup: cleanup, pyxis: ttl, docker: ttl, quay: ttl, refresh: 0,
		},
		{
			name:    "zero cleanup interval is rejected",
			cleanup: 0, pyxis: ttl, docker: ttl, quay: ttl, refresh: time.Hour,
			wantErr: "--cleanup-interval",
		},
		{
			name:    "negative pyxis cache TTL is rejected",
			cleanup: cleanup, pyxis: -time.Hour, docker: ttl, quay: ttl, refresh: time.Hour,
			wantErr: "--pyxis-cache-ttl",
		},
		{
			name:    "zero dockerhub cache TTL is rejected",
			cleanup: cleanup, pyxis: ttl, docker: 0, quay: ttl, refresh: time.Hour,
			wantErr: "--dockerhub-cache-ttl",
		},
		{
			name:    "zero quay cache TTL is rejected",
			cleanup: cleanup, pyxis: ttl, docker: ttl, quay: 0, refresh: time.Hour,
			wantErr: "--quay-cache-ttl",
		},
		{
			name:    "negative refresh interval is rejected",
			cleanup: cleanup, pyxis: ttl, docker: ttl, quay: ttl, refresh: -time.Hour,
			wantErr: "--pyxis-refresh-interval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIntervals(tt.cleanup, tt.pyxis, tt.docker, tt.quay, tt.refresh)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateIntervals() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateIntervals() = nil, want an error naming %s", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validateIntervals() error = %q, want it to name %s", err, tt.wantErr)
			}
		})
	}
}

const (
	nsDefault    = "default"
	nsKubeSystem = "kube-system"
)

func TestParseWatchNamespaces(t *testing.T) {
	tests := []struct {
		name    string
		csv     string
		want    []string
		wantErr string
	}{
		{name: "empty means all namespaces", csv: ""},
		{name: "whitespace only means all namespaces", csv: " , "},
		{name: "single namespace", csv: nsDefault, want: []string{nsDefault}},
		{
			name: "list with padding and empty entries",
			csv:  " default , kube-system ,, monitoring ",
			want: []string{nsDefault, nsKubeSystem, "monitoring"},
		},
		{name: "duplicates collapse", csv: "a,a", want: []string{"a"}},
		{name: "invalid name is rejected", csv: "Bad_NS", wantErr: `invalid namespace "Bad_NS"`},
		{name: "one bad name rejects the whole list", csv: nsDefault + ",UPPER", wantErr: "UPPER"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWatchNamespaces(tt.csv)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseWatchNamespaces(%q) = nil error, want one containing %q", tt.csv, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseWatchNamespaces() error = %q, want it to contain %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseWatchNamespaces() error = %v, want nil", err)
			}
			if tt.want == nil {
				if got != nil {
					t.Errorf("parseWatchNamespaces(%q) = %v, want nil so the manager watches everything", tt.csv, got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseWatchNamespaces(%q) = %v, want %v", tt.csv, got, tt.want)
			}
			for _, ns := range tt.want {
				if _, ok := got[ns]; !ok {
					t.Errorf("namespace %q missing from %v", ns, got)
				}
			}
		})
	}
}

type fakeHealthClient struct {
	healthy bool
}

func (f *fakeHealthClient) IsHealthy(_ context.Context) bool {
	return f.healthy
}

const (
	checkPyxis     = "pyxis"
	checkDockerHub = "dockerhub"
)

func TestAPIHealthChecks(t *testing.T) {
	t.Run("healthy client yields a passing check", func(t *testing.T) {
		checks := apiHealthChecks(namedClient{name: checkPyxis, client: &fakeHealthClient{healthy: true}})
		if len(checks) != 1 {
			t.Fatalf("apiHealthChecks() returned %d checks, want 1", len(checks))
		}
		if checks[0].name != checkPyxis {
			t.Errorf("check name = %q, want pyxis", checks[0].name)
		}
		if err := checks[0].check(httptest.NewRequest(http.MethodGet, "/healthz/pyxis", nil)); err != nil {
			t.Errorf("check() error = %v, want nil for a healthy API", err)
		}
	})

	t.Run("unhealthy client fails the check and names the API", func(t *testing.T) {
		checks := apiHealthChecks(namedClient{name: checkDockerHub, client: &fakeHealthClient{healthy: false}})
		if len(checks) != 1 {
			t.Fatalf("apiHealthChecks() returned %d checks, want 1", len(checks))
		}
		err := checks[0].check(httptest.NewRequest(http.MethodGet, "/healthz/dockerhub", nil))
		if err == nil {
			t.Fatal("check() = nil, want an error for an unreachable API")
		}
		if !strings.Contains(err.Error(), "dockerhub") {
			t.Errorf("check() error = %q, want it to name dockerhub", err)
		}
	})

	t.Run("clients without a health method are skipped", func(t *testing.T) {
		checks := apiHealthChecks(
			namedClient{name: checkPyxis, client: &plainClient{}},
			namedClient{name: checkDockerHub, client: &fakeHealthClient{healthy: true}},
		)
		if len(checks) != 1 {
			t.Fatalf("apiHealthChecks() returned %d checks, want 1", len(checks))
		}
		if checks[0].name != checkDockerHub {
			t.Errorf("check name = %q, want dockerhub", checks[0].name)
		}
	})

	t.Run("nil and typed-nil clients are skipped", func(t *testing.T) {
		var typedNil *fakeHealthClient

		checks := apiHealthChecks(
			namedClient{name: checkPyxis, client: nil},
			namedClient{name: checkDockerHub, client: typedNil},
		)
		if len(checks) != 0 {
			t.Fatalf("apiHealthChecks() returned %d checks, want 0", len(checks))
		}
	})

	t.Run("checks keep the order they were given", func(t *testing.T) {
		checks := apiHealthChecks(
			namedClient{name: checkPyxis, client: &fakeHealthClient{healthy: true}},
			namedClient{name: checkDockerHub, client: &fakeHealthClient{healthy: true}},
		)
		if len(checks) != 2 {
			t.Fatalf("apiHealthChecks() returned %d checks, want 2", len(checks))
		}
		if checks[0].name != checkPyxis || checks[1].name != checkDockerHub {
			t.Errorf("check order = [%s %s], want [pyxis dockerhub]", checks[0].name, checks[1].name)
		}
	})
}

// stubManager records health checks instead of serving them.
type stubManager struct {
	ctrl.Manager

	checks map[string]healthz.Checker
	err    error
}

func (s *stubManager) AddHealthzCheck(name string, check healthz.Checker) error {
	if s.err != nil {
		return s.err
	}

	s.checks[name] = check

	return nil
}

func TestAddAPIChecks(t *testing.T) {
	t.Run("registers one check per capable client", func(t *testing.T) {
		mgr := &stubManager{checks: map[string]healthz.Checker{}}

		err := addAPIChecks(mgr,
			namedClient{name: checkPyxis, client: &fakeHealthClient{healthy: true}},
			namedClient{name: checkDockerHub, client: &fakeHealthClient{healthy: false}},
		)
		if err != nil {
			t.Fatalf("addAPIChecks() error = %v, want nil", err)
		}
		if len(mgr.checks) != 2 {
			t.Fatalf("registered %d checks, want 2", len(mgr.checks))
		}

		req := httptest.NewRequest(http.MethodGet, "/healthz/"+checkPyxis, nil)
		if err := mgr.checks[checkPyxis](req); err != nil {
			t.Errorf("pyxis check error = %v, want nil for a healthy API", err)
		}
		if err := mgr.checks[checkDockerHub](req); err == nil {
			t.Error("dockerhub check = nil, want an error for an unreachable API")
		}
	})

	t.Run("joins registration failures", func(t *testing.T) {
		mgr := &stubManager{checks: map[string]healthz.Checker{}, err: errors.New("boom")}

		err := addAPIChecks(mgr,
			namedClient{name: checkPyxis, client: &fakeHealthClient{healthy: true}},
			namedClient{name: checkDockerHub, client: &fakeHealthClient{healthy: true}},
		)
		if err == nil {
			t.Fatal("addAPIChecks() = nil, want a registration error")
		}
		if !strings.Contains(err.Error(), checkPyxis) || !strings.Contains(err.Error(), checkDockerHub) {
			t.Errorf("addAPIChecks() error = %q, want it to name both checks", err)
		}
	})

	t.Run("registers nothing without clients", func(t *testing.T) {
		mgr := &stubManager{checks: map[string]healthz.Checker{}}

		if err := addAPIChecks(mgr); err != nil {
			t.Fatalf("addAPIChecks() error = %v, want nil", err)
		}
		if len(mgr.checks) != 0 {
			t.Errorf("registered %d checks, want 0", len(mgr.checks))
		}
	})
}
