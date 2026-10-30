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
