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
	"testing"
	"time"
)

type fakeCachedClient struct {
	started  bool
	interval time.Duration
}

func (f *fakeCachedClient) StartCleanupLoop(_ context.Context, interval time.Duration) {
	f.started = true
	f.interval = interval
}

// plainClient does not implement StartCleanupLoop.
type plainClient struct{}

func TestStartCacheCleanup(t *testing.T) {
	ctx := context.Background()

	t.Run("cache-wrapped client starts the loop", func(t *testing.T) {
		client := &fakeCachedClient{}

		if ok := startCacheCleanup(ctx, client, time.Minute); !ok {
			t.Fatal("startCacheCleanup() = false, want true for a cached client")
		}
		if !client.started {
			t.Error("StartCleanupLoop was not called")
		}
		if client.interval != time.Minute {
			t.Errorf("interval = %v, want 1m", client.interval)
		}
	})

	t.Run("uncached client is reported", func(t *testing.T) {
		if ok := startCacheCleanup(ctx, &plainClient{}, time.Minute); ok {
			t.Error("startCacheCleanup() = true, want false so the caller can log it")
		}
	})

	t.Run("nil client is reported", func(t *testing.T) {
		if ok := startCacheCleanup(ctx, nil, time.Minute); ok {
			t.Error("startCacheCleanup() = true, want false for a nil client")
		}
	})
}
