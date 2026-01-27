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
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/sebrandon1/imagecertinfo-operator/internal/metrics"
)

// DefaultCacheTTL is the default time-to-live for cache entries
const DefaultCacheTTL = 1 * time.Hour

// DefaultRateLimit is the default rate limit (requests per second)
const DefaultRateLimit = 5.0

// DefaultRateBurst is the default burst size for rate limiting
const DefaultRateBurst = 10

// cacheEntry represents a cached repository info entry
type cacheEntry struct {
	data      *RepositoryInfo
	expiresAt time.Time
}

// CachedClient wraps a Client with caching capabilities
type CachedClient struct {
	client Client
	cache  map[string]cacheEntry
	mu     sync.RWMutex
	ttl    time.Duration
}

// CacheOption is a function that configures a CachedClient
type CacheOption func(*CachedClient)

// WithCacheTTL sets the cache time-to-live
func WithCacheTTL(ttl time.Duration) CacheOption {
	return func(c *CachedClient) {
		c.ttl = ttl
	}
}

// NewCachedClient creates a new cached client wrapper
func NewCachedClient(client Client, opts ...CacheOption) *CachedClient {
	c := &CachedClient{
		client: client,
		cache:  make(map[string]cacheEntry),
		ttl:    DefaultCacheTTL,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// cacheKey generates a cache key from namespace and repository
func cacheKey(namespace, repository string) string {
	return namespace + "/" + repository
}

// GetRepositoryInfo retrieves repository info, using cache when available
func (c *CachedClient) GetRepositoryInfo(
	ctx context.Context, namespace, repository string,
) (*RepositoryInfo, error) {
	key := cacheKey(namespace, repository)

	// Try to get from cache first
	c.mu.RLock()
	entry, found := c.cache[key]
	c.mu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		metrics.RecordDockerHubCacheHit()
		return entry.data, nil
	}

	metrics.RecordDockerHubCacheMiss()

	// Fetch from underlying client
	data, err := c.client.GetRepositoryInfo(ctx, namespace, repository)
	if err != nil {
		return nil, err
	}

	// Store in cache
	c.mu.Lock()
	c.cache[key] = cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()

	return data, nil
}

// IsHealthy delegates to the underlying client
func (c *CachedClient) IsHealthy(ctx context.Context) bool {
	return c.client.IsHealthy(ctx)
}

// ClearCache removes all entries from the cache
func (c *CachedClient) ClearCache() {
	c.mu.Lock()
	c.cache = make(map[string]cacheEntry)
	c.mu.Unlock()
}

// CleanupExpired removes expired entries from the cache
func (c *CachedClient) CleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

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

// GetRepositoryInfo retrieves repository info with rate limiting
func (c *RateLimitedClient) GetRepositoryInfo(
	ctx context.Context, namespace, repository string,
) (*RepositoryInfo, error) {
	// Wait for rate limiter
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	return c.client.GetRepositoryInfo(ctx, namespace, repository)
}

// IsHealthy delegates to the underlying client (no rate limiting for health checks)
func (c *RateLimitedClient) IsHealthy(ctx context.Context) bool {
	return c.client.IsHealthy(ctx)
}

// NewCachedRateLimitedClient creates a client with both caching and rate limiting
func NewCachedRateLimitedClient(baseClient Client, cacheTTL time.Duration, rateLimit float64, burst int) Client {
	// Apply rate limiting first, then caching
	rateLimited := NewRateLimitedClient(baseClient, WithRateLimit(rateLimit), WithBurst(burst))
	cached := NewCachedClient(rateLimited, WithCacheTTL(cacheTTL))
	return cached
}
