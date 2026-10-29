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
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/sebrandon1/imagecertinfo-operator/internal/metrics"
)

// stubClient is a Client that always returns data and counts its calls.
type stubClient struct {
	calls int
}

func (s *stubClient) GetImageCertification(
	_ context.Context, registry, repository, digest string,
) (*CertificationData, error) {
	s.calls++
	return &CertificationData{ImageID: cacheKey(registry, repository, digest)}, nil
}

func (s *stubClient) IsHealthy(_ context.Context) bool { return true }

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
