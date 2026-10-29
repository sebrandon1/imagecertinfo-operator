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
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/sebrandon1/imagecertinfo-operator/internal/metrics"
)

// DefaultCacheTTL is the default time-to-live for cache entries
const DefaultCacheTTL = 1 * time.Hour

// DefaultCacheMaxEntries is the default cap on resident cache entries
const DefaultCacheMaxEntries = 10_000

// DefaultRateLimit is the default rate limit (requests per second)
const DefaultRateLimit = 10.0

// DefaultRateBurst is the default burst size for rate limiting
const DefaultRateBurst = 20

// cacheEntry represents a cached certification data entry
type cacheEntry struct {
	data      *CertificationData
	expiresAt time.Time
}

// CachedClient wraps a Client with caching capabilities
type CachedClient struct {
	client     Client
	cache      map[string]cacheEntry
	mu         sync.RWMutex
	ttl        time.Duration
	maxEntries int
}

// CacheOption is a function that configures a CachedClient
type CacheOption func(*CachedClient)

// WithCacheTTL sets the cache time-to-live
func WithCacheTTL(ttl time.Duration) CacheOption {
	return func(c *CachedClient) {
		c.ttl = ttl
	}
}

// WithMaxEntries caps the number of resident entries. A value of zero or less
// disables the cap, restoring the unbounded behaviour.
func WithMaxEntries(maxEntries int) CacheOption {
	return func(c *CachedClient) {
		c.maxEntries = maxEntries
	}
}

// NewCachedClient creates a new cached client wrapper
func NewCachedClient(client Client, opts ...CacheOption) *CachedClient {
	c := &CachedClient{
		client:     client,
		cache:      make(map[string]cacheEntry),
		ttl:        DefaultCacheTTL,
		maxEntries: DefaultCacheMaxEntries,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// cacheKey generates a cache key from registry, repository, and digest
func cacheKey(registry, repository, digest string) string {
	return registry + "/" + repository + "@" + digest
}

// GetImageCertification retrieves certification data, using cache when available
func (c *CachedClient) GetImageCertification(
	ctx context.Context, registry, repository, digest string,
) (*CertificationData, error) {
	key := cacheKey(registry, repository, digest)

	// Try to get from cache first
	c.mu.RLock()
	entry, found := c.cache[key]
	c.mu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		metrics.RecordCacheHit()
		return entry.data, nil
	}

	metrics.RecordCacheMiss()

	// Fetch from underlying client
	data, err := c.client.GetImageCertification(ctx, registry, repository, digest)
	if err != nil {
		return nil, err
	}

	// Store in cache
	c.store(key, cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(c.ttl),
	})

	return data, nil
}

// store inserts an entry, evicting expired entries and then the entries
// closest to expiry when the cache is at capacity.
func (c *CachedClient) store(key string, entry cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maxEntries > 0 && len(c.cache) >= c.maxEntries {
		c.cleanupExpiredLocked()
		c.evictLocked()
	}

	c.cache[key] = entry

	metrics.SetPyxisCacheEntries(len(c.cache))
}

// evictLocked drops entries with the earliest expiry until there is room for
// one more. The caller must hold the write lock.
func (c *CachedClient) evictLocked() {
	if c.maxEntries <= 0 {
		return
	}

	for len(c.cache) >= c.maxEntries {
		oldestKey := ""
		var oldestExpiry time.Time

		for key, entry := range c.cache {
			if oldestKey == "" || entry.expiresAt.Before(oldestExpiry) {
				oldestKey = key
				oldestExpiry = entry.expiresAt
			}
		}

		if oldestKey == "" {
			return
		}
		delete(c.cache, oldestKey)
	}
}

// Size returns the number of resident cache entries.
func (c *CachedClient) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.cache)
}

// IsHealthy delegates to the underlying client
func (c *CachedClient) IsHealthy(ctx context.Context) bool {
	return c.client.IsHealthy(ctx)
}

// ClearCache removes all entries from the cache
func (c *CachedClient) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]cacheEntry)
	metrics.SetPyxisCacheEntries(0)
}

// CleanupExpired removes expired entries from the cache
func (c *CachedClient) CleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cleanupExpiredLocked()
	metrics.SetPyxisCacheEntries(len(c.cache))
}

// cleanupExpiredLocked drops expired entries. The caller must hold the write
// lock.
func (c *CachedClient) cleanupExpiredLocked() {
	now := time.Now()

	for key, entry := range c.cache {
		if now.After(entry.expiresAt) {
			delete(c.cache, key)
		}
	}
}

// StartCleanupLoop starts a goroutine that periodically cleans up expired cache entries
func (c *CachedClient) StartCleanupLoop(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.CleanupExpired()
			}
		}
	}()
}

// RateLimitedClient wraps a Client with rate limiting capabilities
type RateLimitedClient struct {
	client  Client
	limiter *rate.Limiter
}

// RateLimitOption is a function that configures a RateLimitedClient
type RateLimitOption func(*RateLimitedClient)

// WithRateLimit sets the rate limit (requests per second)
func WithRateLimit(rps float64) RateLimitOption {
	return func(c *RateLimitedClient) {
		c.limiter.SetLimit(rate.Limit(rps))
	}
}

// WithBurst sets the burst size
func WithBurst(burst int) RateLimitOption {
	return func(c *RateLimitedClient) {
		c.limiter.SetBurst(burst)
	}
}

// NewRateLimitedClient creates a new rate-limited client wrapper
func NewRateLimitedClient(client Client, opts ...RateLimitOption) *RateLimitedClient {
	c := &RateLimitedClient{
		client:  client,
		limiter: rate.NewLimiter(rate.Limit(DefaultRateLimit), DefaultRateBurst),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetImageCertification retrieves certification data with rate limiting
func (c *RateLimitedClient) GetImageCertification(
	ctx context.Context, registry, repository, digest string,
) (*CertificationData, error) {
	// Wait for rate limiter
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	return c.client.GetImageCertification(ctx, registry, repository, digest)
}

// IsHealthy delegates to the underlying client (no rate limiting for health checks)
func (c *RateLimitedClient) IsHealthy(ctx context.Context) bool {
	return c.client.IsHealthy(ctx)
}

// NewCachedRateLimitedClient creates a client with both caching and rate limiting
func NewCachedRateLimitedClient(
	baseClient Client, cacheTTL time.Duration, rateLimit float64, burst, cacheMaxEntries int,
) Client {
	// Apply rate limiting first, then caching
	rateLimited := NewRateLimitedClient(baseClient, WithRateLimit(rateLimit), WithBurst(burst))
	cached := NewCachedClient(rateLimited, WithCacheTTL(cacheTTL), WithMaxEntries(cacheMaxEntries))
	return cached
}
