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
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/sebrandon1/imagecertinfo-operator/internal/metrics"
)

// stubClient is a Client that always returns data and counts its calls.
type stubClient struct {
	calls   atomic.Int64
	healthy bool
}

func (s *stubClient) GetImageCertification(
	_ context.Context, registry, repository, digest string,
) (*CertificationData, error) {
	s.calls.Add(1)
	return &CertificationData{ImageID: cacheKey(registry, repository, digest)}, nil
}

func (s *stubClient) IsHealthy(_ context.Context) bool { return s.healthy }

func TestCachedClient_EvictsOldestEntriesWhenFull(t *testing.T) {
	client := NewCachedClient(&stubClient{}, WithMaxEntries(5))

	for i := range 100 {
		if _, err := client.GetImageCertification(
			context.Background(), "registry.redhat.io", "repo", fmt.Sprintf("sha256:%d", i)); err != nil {
			t.Fatalf("GetImageCertification() error = %v", err)
		}
	}

	if got := client.Size(); got > 5 {
		t.Errorf("Size() = %d, want <= 5", got)
	}
	if got := client.Size(); got != 5 {
		t.Errorf("Size() = %d, want 5", got)
	}
}

func TestCachedClient_EvictsExpiredEntriesBeforeLiveOnes(t *testing.T) {
	client := NewCachedClient(&stubClient{}, WithMaxEntries(2), WithCacheTTL(time.Nanosecond))

	for i := range 3 {
		if _, err := client.GetImageCertification(
			context.Background(), "registry.redhat.io", "repo", fmt.Sprintf("sha256:%d", i)); err != nil {
			t.Fatalf("GetImageCertification() error = %v", err)
		}
	}

	// Every previous entry is expired by the time the next insert runs, so
	// only the newest one survives.
	if got := client.Size(); got != 1 {
		t.Errorf("Size() = %d, want 1", got)
	}
}

func TestCachedClient_UnlimitedWhenMaxEntriesDisabled(t *testing.T) {
	client := NewCachedClient(&stubClient{}, WithMaxEntries(0))

	for i := range 50 {
		if _, err := client.GetImageCertification(
			context.Background(), "registry.redhat.io", "repo", fmt.Sprintf("sha256:%d", i)); err != nil {
			t.Fatalf("GetImageCertification() error = %v", err)
		}
	}

	if got := client.Size(); got != 50 {
		t.Errorf("Size() = %d, want 50", got)
	}
}

func TestCachedClient_ReportsSizeGauge(t *testing.T) {
	client := NewCachedClient(&stubClient{}, WithMaxEntries(10))

	if _, err := client.GetImageCertification(context.Background(), "registry.redhat.io", "repo", "sha256:a"); err != nil {
		t.Fatalf("GetImageCertification() error = %v", err)
	}
	if got := testutil.ToFloat64(metrics.PyxisCacheEntries); got != 1 {
		t.Errorf("pyxis_cache_entries = %v, want 1", got)
	}

	client.ClearCache()
	if got := testutil.ToFloat64(metrics.PyxisCacheEntries); got != 0 {
		t.Errorf("pyxis_cache_entries after ClearCache = %v, want 0", got)
	}
}

func TestCachedClient_CleanupExpiredReportsSize(t *testing.T) {
	client := NewCachedClient(&stubClient{}, WithCacheTTL(time.Nanosecond))

	if _, err := client.GetImageCertification(context.Background(), "registry.redhat.io", "repo", "sha256:a"); err != nil {
		t.Fatalf("GetImageCertification() error = %v", err)
	}

	client.CleanupExpired()

	if got := client.Size(); got != 0 {
		t.Errorf("Size() after CleanupExpired = %d, want 0", got)
	}
	if got := testutil.ToFloat64(metrics.PyxisCacheEntries); got != 0 {
		t.Errorf("pyxis_cache_entries = %v, want 0", got)
	}
}

func TestNewCachedRateLimitedClient_AppliesMaxEntries(t *testing.T) {
	client := NewCachedRateLimitedClient(&stubClient{}, time.Hour, 1000, 1000, 3)

	for i := range 20 {
		if _, err := client.GetImageCertification(
			context.Background(), "registry.redhat.io", "repo", fmt.Sprintf("sha256:%d", i)); err != nil {
			t.Fatalf("GetImageCertification() error = %v", err)
		}
	}

	cached, ok := client.(*CachedClient)
	if !ok {
		t.Fatalf("NewCachedRateLimitedClient() = %T, want *CachedClient", client)
	}
	if got := cached.Size(); got != 3 {
		t.Errorf("Size() = %d, want 3", got)
	}
}

func TestCachedClient_StartCleanupLoop_NonPositiveInterval(t *testing.T) {
	client := NewCachedRateLimitedClient(&stubClient{}, time.Hour, 100, 100, 10)

	cached, ok := client.(*CachedClient)
	if !ok {
		t.Fatalf("NewCachedRateLimitedClient() = %T, want *CachedClient", client)
	}

	if _, err := cached.GetImageCertification(context.Background(), "registry.redhat.io", "repo", "sha256:x"); err != nil {
		t.Fatalf("GetImageCertification() error = %v", err)
	}

	ctx := t.Context()

	// time.NewTicker panics on a non-positive duration; the guard must return
	// without starting a ticker.
	cached.StartCleanupLoop(ctx, 0)
	cached.StartCleanupLoop(ctx, -time.Second)

	if got := cached.Size(); got != 1 {
		t.Errorf("Size() = %d, want 1: a non-positive interval must not prune the cache", got)
	}
}

func TestCachedClient_StartCleanupLoop_PrunesExpiredEntries(t *testing.T) {
	client := NewCachedRateLimitedClient(&stubClient{}, time.Millisecond, 100, 100, 10)

	cached, ok := client.(*CachedClient)
	if !ok {
		t.Fatalf("NewCachedRateLimitedClient() = %T, want *CachedClient", client)
	}

	if _, err := cached.GetImageCertification(t.Context(), "registry.redhat.io", "repo", "sha256:x"); err != nil {
		t.Fatalf("GetImageCertification() error = %v", err)
	}
	if got := cached.Size(); got != 1 {
		t.Fatalf("Size() = %d, want 1 after the miss was cached", got)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	cached.StartCleanupLoop(ctx, time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cached.Size() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Fatalf("Size() = %d, want 0 after the cleanup loop pruned the expired entry", cached.Size())
}

func TestCachedClient_ServesFromCacheWithinTTL(t *testing.T) {
	stub := &stubClient{}
	client := NewCachedClient(stub, WithCacheTTL(time.Hour))

	for range 3 {
		if _, err := client.GetImageCertification(
			context.Background(), "registry.redhat.io", "repo", "sha256:abc"); err != nil {
			t.Fatalf("GetImageCertification() error = %v", err)
		}
	}

	if got := stub.calls.Load(); got != 1 {
		t.Errorf("underlying calls = %d, want 1: reads inside the TTL must be cache hits", got)
	}
}

func TestCachedClient_RefetchesExpiredEntry(t *testing.T) {
	stub := &stubClient{}
	// A zero TTL expires every entry on arrival, which exercises the miss
	// branch without sleeping.
	client := NewCachedClient(stub, WithCacheTTL(0))

	for range 2 {
		if _, err := client.GetImageCertification(
			context.Background(), "registry.redhat.io", "repo", "sha256:abc"); err != nil {
			t.Fatalf("GetImageCertification() error = %v", err)
		}
	}

	if got := stub.calls.Load(); got != 2 {
		t.Errorf("underlying calls = %d, want 2: an expired entry must be refetched", got)
	}
}

func TestCachedClient_ClearCacheDropsEntries(t *testing.T) {
	stub := &stubClient{}
	client := NewCachedClient(stub, WithCacheTTL(time.Hour))

	if _, err := client.GetImageCertification(
		context.Background(), "registry.redhat.io", "repo", "sha256:abc"); err != nil {
		t.Fatalf("GetImageCertification() error = %v", err)
	}
	if got := client.Size(); got != 1 {
		t.Fatalf("Size() = %d, want 1 after one lookup", got)
	}

	client.ClearCache()
	if got := client.Size(); got != 0 {
		t.Errorf("Size() = %d, want 0 after ClearCache", got)
	}

	if _, err := client.GetImageCertification(
		context.Background(), "registry.redhat.io", "repo", "sha256:abc"); err != nil {
		t.Fatalf("GetImageCertification() error = %v", err)
	}
	if got := stub.calls.Load(); got != 2 {
		t.Errorf("underlying calls = %d, want 2: a cleared cache must refetch", got)
	}
}

func TestCachedClient_IsHealthyDelegates(t *testing.T) {
	for _, healthy := range []bool{true, false} {
		client := NewCachedClient(&stubClient{healthy: healthy})
		if got := client.IsHealthy(context.Background()); got != healthy {
			t.Errorf("IsHealthy() = %v, want %v: the wrapper must not mask the upstream state", got, healthy)
		}
	}
}

func TestRateLimitedClient_IsHealthyDelegates(t *testing.T) {
	for _, healthy := range []bool{true, false} {
		client := NewRateLimitedClient(&stubClient{healthy: healthy})
		if got := client.IsHealthy(context.Background()); got != healthy {
			t.Errorf("IsHealthy() = %v, want %v: health checks must bypass the limiter, not be gated by it", got, healthy)
		}
	}
}

func TestRateLimitedClient_GatesRequests(t *testing.T) {
	stub := &stubClient{}
	client := NewRateLimitedClient(stub, WithRateLimit(0.001), WithBurst(1))

	if _, err := client.GetImageCertification(
		context.Background(), "registry.redhat.io", "repo", "sha256:abc"); err != nil {
		t.Fatalf("GetImageCertification() error = %v, want nil: the single burst token must let the first call through", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := client.GetImageCertification(ctx, "registry.redhat.io", "repo", "sha256:abc"); err == nil {
		t.Error("GetImageCertification() = nil error, want the second call blocked by the rate limiter")
	}
}

func TestCachedClient_ConcurrentAccess(t *testing.T) {
	stub := &stubClient{}
	client := NewCachedClient(stub, WithCacheTTL(time.Hour), WithMaxEntries(10))

	var wg sync.WaitGroup

	for i := range 50 {
		wg.Go(func() {
			// Every goroutine also races on one shared key, so the hit, miss and
			// store paths run concurrently under the race detector.
			for _, key := range []string{"shared", fmt.Sprintf("sha256:%d", i)} {
				if _, err := client.GetImageCertification(context.Background(), "registry.redhat.io", "repo", key); err != nil {
					t.Errorf("GetImageCertification() error = %v", err)
				}
			}
		})
	}

	wg.Wait()

	if got := client.Size(); got > 10 {
		t.Errorf("Size() = %d, want <= 10: the cap must hold under concurrency", got)
	}
}
