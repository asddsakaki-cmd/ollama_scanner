// internal/scanner/native.go
// Native Go TCP scanner with high-performance worker pool
// FIXED: Connection leak, context cancellation, error handling

package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/aspnmy/ollama_scanner/internal/models"
	"github.com/aspnmy/ollama_scanner/pkg/logger"
	"github.com/aspnmy/ollama_scanner/pkg/ratelimit"
)

// NativeScanner implements high-performance TCP scanning in pure Go
type NativeScanner struct {
	config      NativeConfig
	limiter     *ratelimit.Limiter
	dialer      *net.Dialer
	workers     int
	timeout     time.Duration
}

// NativeConfig holds native scanner configuration
type NativeConfig struct {
	Workers    int
	Retry      int
	RetryDelay time.Duration
}

// NewNativeScanner creates a new native scanner
func NewNativeScanner(cfg NativeConfig, rateLimit int, timeout time.Duration) *NativeScanner {
	return &NativeScanner{
		config: cfg,
		limiter: ratelimit.New(ratelimit.Config{
			Rate:       rateLimit,
			Adaptive:   true,
			TargetLoss: 0.01,
		}),
		dialer: &net.Dialer{
			Timeout:   timeout,
			KeepAlive: -1, // Disable keep-alive for scanning
		},
		workers: cfg.Workers,
		timeout: timeout,
	}
}

// Name returns scanner name
func (s *NativeScanner) Name() string {
	return "native"
}

// Scan scans all targets and returns results via channel
func (s *NativeScanner) Scan(ctx context.Context, targets []models.Target) (<-chan models.ScanResult, error) {
	// FIXED: Use bounded buffer instead of len(targets) to prevent memory issue
	bufferSize := s.workers * 4
	if bufferSize > len(targets) {
		bufferSize = len(targets)
	}
	
	targetChan := make(chan models.Target, bufferSize)
	resultChan := make(chan models.ScanResult, s.workers*2)

	// Feed targets with context awareness
	go func() {
		defer close(targetChan)
		for _, target := range targets {
			select {
			case <-ctx.Done():
				return
			case targetChan <- target:
			}
		}
	}()

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, targetChan, resultChan)
	}

	// Close result channel when done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	return resultChan, nil
}

// ScanStream scans from streaming target channel
func (s *NativeScanner) ScanStream(ctx context.Context, targets <-chan models.Target) (<-chan models.ScanResult, error) {
	resultChan := make(chan models.ScanResult, s.workers*2)

	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, targets, resultChan)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	return resultChan, nil
}

// worker processes targets from input channel
func (s *NativeScanner) worker(ctx context.Context, wg *sync.WaitGroup, targets <-chan models.Target, results chan<- models.ScanResult) {
	defer wg.Done()

	for target := range targets {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Rate limiting with error handling
		if err := s.limiter.Wait(ctx); err != nil {
			// FIXED: Report rate limit error instead of silently dropping
			results <- models.ScanResult{
				Target:    target,
				Open:      false,
				Error:     fmt.Sprintf("rate limit wait failed: %v", err),
				Timestamp: time.Now(),
			}
			continue
		}

		// Scan target
		result := s.scanPort(ctx, target)

		select {
		case results <- result:
		case <-ctx.Done():
			return
		}
	}
}

// scanPort performs TCP connect scan
// FIXED: Proper connection handling and context cancellation
func (s *NativeScanner) scanPort(ctx context.Context, target models.Target) models.ScanResult {
	address := target.Address()
	
	// Track retry errors
	var lastErr error
	var conn net.Conn
	
	start := time.Now()
	conn, err := s.dialer.DialContext(ctx, "tcp", address)
	lastErr = err

	if err != nil {
		// FIXED: Context-aware retry with proper error handling
		for i := 0; i < s.config.Retry; i++ {
			// Check context before sleep
			select {
			case <-ctx.Done():
				return models.ScanResult{
					Target:    target,
					Open:      false,
					Error:     fmt.Sprintf("context cancelled during retry: %v", ctx.Err()),
					Timestamp: time.Now(),
				}
			case <-time.After(s.config.RetryDelay):
			}

			// FIXED: Reset start time for accurate latency on retry
			start = time.Now()
			conn, err = s.dialer.DialContext(ctx, "tcp", address)
			lastErr = err
			if err == nil {
				break
			}
		}
	}

	latency := time.Since(start)

	result := models.ScanResult{
		Target:    target,
		Open:      err == nil,
		Latency:   latency,
		Timestamp: time.Now(),
	}

	if err != nil {
		result.Error = lastErr.Error()
	}

	// FIXED: Always close connection properly
	if conn != nil {
		conn.Close()
	}

	return result
}

// Close cleans up resources
func (s *NativeScanner) Close() error {
	s.limiter.Stop()
	return nil
}

// NativeEngineFactory creates native scanner from config
// FIXED: Safe type assertions with fallback
func NativeEngineFactory(config map[string]interface{}) (Engine, error) {
	workers := 1000
	if w, ok := config["workers"]; ok {
		switch v := w.(type) {
		case int:
			workers = v
		case float64:
			workers = int(v)
		}
	}

	rateLimit := 5000
	if r, ok := config["rate_limit"]; ok {
		switch v := r.(type) {
		case int:
			rateLimit = v
		case float64:
			rateLimit = int(v)
		}
	}

	timeout := 3 * time.Second
	if t, ok := config["timeout"]; ok {
		switch v := t.(type) {
		case time.Duration:
			timeout = v
		case string:
			if d, err := time.ParseDuration(v); err == nil {
				timeout = d
			}
		case float64:
			timeout = time.Duration(v) * time.Second
		}
	}

	retry := 1
	if r, ok := config["retry"]; ok {
		switch v := r.(type) {
		case int:
			retry = v
		case float64:
			retry = int(v)
		}
	}

	retryDelay := 1 * time.Second
	if rd, ok := config["retry_delay"]; ok {
		switch v := rd.(type) {
		case time.Duration:
			retryDelay = v
		case string:
			if d, err := time.ParseDuration(v); err == nil {
				retryDelay = d
			}
		case float64:
			retryDelay = time.Duration(v) * time.Second
		}
	}

	return NewNativeScanner(NativeConfig{
		Workers:    workers,
		Retry:      retry,
		RetryDelay: retryDelay,
	}, rateLimit, timeout), nil
}

func init() {
	Register("native", NativeEngineFactory)
}

// ValidateRateLimit checks if rate limit is reasonable for the target size
func ValidateRateLimit(targetCount uint64, rateLimit int) error {
	// Warn for internet-wide scanning
	if targetCount > 100000000 { // > 100M targets
		logger.Warn("Very large target set detected",
			logger.Int64("targets", int64(targetCount)),
			logger.String("estimate", fmt.Sprintf("~%.1f days at %d req/s", float64(targetCount)/float64(rateLimit*86400), rateLimit)),
		)
		return fmt.Errorf("target count exceeds safety limit (100M). Use -rate flag to increase speed or specify smaller CIDR")
	}
	return nil
}

// EstimateDuration calculates estimated scan duration
func EstimateDuration(targetCount uint64, rateLimit int) time.Duration {
	seconds := float64(targetCount) / float64(rateLimit)
	return time.Duration(seconds * float64(time.Second))
}
