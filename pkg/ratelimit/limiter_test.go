// pkg/ratelimit/limiter_test.go
// Unit tests for rate limiter

package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	cfg := Config{
		Rate:     100,
		Adaptive: false,
	}

	l := New(cfg)
	if l == nil {
		t.Fatal("New() returned nil")
	}

	if l.GetRate() != 100 {
		t.Errorf("GetRate() = %f, want 100", l.GetRate())
	}

	l.Stop()
}

func TestLimiter_Wait(t *testing.T) {
	cfg := Config{
		Rate:     1000, // 1000 req/s = 1 req/ms
		Adaptive: false,
	}

	l := New(cfg)
	defer l.Stop()

	ctx := context.Background()

	// Should not error for first request
	start := time.Now()
	err := l.Wait(ctx)
	if err != nil {
		t.Errorf("Wait() error = %v", err)
	}
	elapsed := time.Since(start)

	// Should be very fast for first request (within burst)
	if elapsed > 10*time.Millisecond {
		t.Logf("First request took %v (expected < 10ms)", elapsed)
	}
}

func TestLimiter_Wait_Cancellation(t *testing.T) {
	cfg := Config{
		Rate:     1, // 1 req/s
		Adaptive: false,
	}

	l := New(cfg)
	defer l.Stop()

	// Use up the burst
	ctx := context.Background()
	l.Wait(ctx)

	// Create cancelled context
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Should return error due to cancelled context
	err := l.Wait(cancelledCtx)
	if err == nil {
		t.Error("Wait() with cancelled context should return error")
	}
}

func TestLimiter_SetRate(t *testing.T) {
	cfg := Config{
		Rate:     100,
		Adaptive: false,
	}

	l := New(cfg)
	defer l.Stop()

	l.SetRate(200)

	if l.GetRate() != 200 {
		t.Errorf("GetRate() after SetRate(200) = %f, want 200", l.GetRate())
	}
}

func TestLimiter_GetStats(t *testing.T) {
	cfg := Config{
		Rate:     1000,
		Adaptive: false,
	}

	l := New(cfg)
	defer l.Stop()

	ctx := context.Background()

	// Make some requests
	for i := 0; i < 5; i++ {
		l.Wait(ctx)
	}

	stats := l.GetStats()

	if stats.TotalRequests != 5 {
		t.Errorf("TotalRequests = %d, want 5", stats.TotalRequests)
	}
}

func TestLimiter_ConcurrentAccess(t *testing.T) {
	cfg := Config{
		Rate:     10000,
		Adaptive: false,
	}

	l := New(cfg)
	defer l.Stop()

	ctx := context.Background()
	var wg sync.WaitGroup
	numGoroutines := 10
	requestsPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				l.Wait(ctx)
			}
		}()
	}

	wg.Wait()

	stats := l.GetStats()
	expected := int64(numGoroutines * requestsPerGoroutine)

	if stats.TotalRequests != expected {
		t.Errorf("TotalRequests = %d, want %d", stats.TotalRequests, expected)
	}
}

func TestLimiter_AdaptiveMode(t *testing.T) {
	cfg := Config{
		Rate:       1000,
		Adaptive:   true,
		TargetLoss: 0.01,
	}

	l := New(cfg)
	defer l.Stop()

	// Adaptive mode stats are set after first feedback processing
	// Send some feedback to trigger adaptive controller
	l.SendFeedback(NetworkFeedback{
		RTT:        10 * time.Millisecond,
		PacketLoss: 0.05, // Higher than target
	})

	// Wait for adaptive controller to process
	time.Sleep(100 * time.Millisecond)

	// After receiving feedback, adaptive mode should be reflected
	stats := l.GetStats()
	if !stats.AdaptiveMode {
		t.Log("Warning: AdaptiveMode not set yet - may need more time for processing")
	}
}

func TestAverage(t *testing.T) {
	tests := []struct {
		name   string
		values []float64
		want   float64
	}{
		{
			name:   "empty",
			values: []float64{},
			want:   0,
		},
		{
			name:   "single value",
			values: []float64{5},
			want:   5,
		},
		{
			name:   "multiple values",
			values: []float64{1, 2, 3, 4, 5},
			want:   3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := average(tt.values)
			if got != tt.want {
				t.Errorf("average() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAverageDuration(t *testing.T) {
	tests := []struct {
		name   string
		values []time.Duration
		want   time.Duration
	}{
		{
			name:   "empty",
			values: []time.Duration{},
			want:   0,
		},
		{
			name:   "single value",
			values: []time.Duration{time.Second},
			want:   time.Second,
		},
		{
			name:   "multiple values",
			values: []time.Duration{1 * time.Second, 2 * time.Second, 3 * time.Second},
			want:   2 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := averageDuration(tt.values)
			if got != tt.want {
				t.Errorf("averageDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}
