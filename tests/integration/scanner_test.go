// tests/integration/scanner_test.go
// Integration tests for the scanner

package integration

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/aspnmy/ollama_scanner/internal/models"
	"github.com/aspnmy/ollama_scanner/internal/scanner"
)

// mockServer creates a simple TCP listener for testing
func mockServer(t *testing.T, addr string) (net.Listener, func()) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Simple echo/read
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				c.Read(buf)
			}(conn)
		}
	}()

	cleanup := func() {
		ln.Close()
	}

	return ln, cleanup
}

func TestNativeScanner_Scan(t *testing.T) {
	// Create mock server on localhost
	ln, cleanup := mockServer(t, "127.0.0.1:0")
	defer cleanup()

	addr := ln.Addr().(*net.TCPAddr)
	targetPort := addr.Port

	// Create scanner
	s := scanner.NewNativeScanner(scanner.NativeConfig{
		Workers:    10,
		Retry:      1,
		RetryDelay: 100 * time.Millisecond,
	}, 1000, 3*time.Second)
	defer s.Close()

	// Create targets
	targets := []models.Target{
		{IP: netip.AddrFrom4([4]byte{127, 0, 0, 1}), Port: targetPort}, // Open port
		{IP: netip.AddrFrom4([4]byte{127, 0, 0, 1}), Port: 65432},       // Closed port
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Run scan
	resultChan, err := s.Scan(ctx, targets)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Collect results
	var results []models.ScanResult
	for result := range resultChan {
		results = append(results, result)
	}

	// Verify results
	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}

	// Check that open port was detected
	foundOpen := false
	foundClosed := false
	for _, r := range results {
		if r.Target.Port == targetPort && r.Open {
			foundOpen = true
		}
		if r.Target.Port == 65432 && !r.Open {
			foundClosed = true
		}
	}

	if !foundOpen {
		t.Error("Expected to find open port")
	}
	if !foundClosed {
		t.Error("Expected to find closed port")
	}
}

func TestNativeScanner_Scan_ContextCancellation(t *testing.T) {
	s := scanner.NewNativeScanner(scanner.NativeConfig{
		Workers:    10,
		Retry:      1,
		RetryDelay: 100 * time.Millisecond,
	}, 1000, 3*time.Second)
	defer s.Close()

	// Create many targets
	targets := make([]models.Target, 100)
	for i := 0; i < 100; i++ {
		targets[i] = models.Target{
			IP:   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			Port: 60000 + i,
		}
	}

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Start scan
	resultChan, err := s.Scan(ctx, targets)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Cancel after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	// Collect results (should stop early due to cancellation)
	var results []models.ScanResult
	for result := range resultChan {
		results = append(results, result)
	}

	// Should have processed some but not all targets
	if len(results) == 0 {
		t.Error("Expected some results before cancellation")
	}
	if len(results) == 100 {
		t.Log("Warning: All targets processed before cancellation")
	}
}

func TestNativeScanner_ScanStream(t *testing.T) {
	s := scanner.NewNativeScanner(scanner.NativeConfig{
		Workers:    5,
		Retry:      1,
		RetryDelay: 50 * time.Millisecond,
	}, 1000, 3*time.Second)
	defer s.Close()

	// Create target channel
	targetChan := make(chan models.Target, 10)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start scan
	resultChan, err := s.ScanStream(ctx, targetChan)
	if err != nil {
		t.Fatalf("ScanStream() error = %v", err)
	}

	// Send targets
	go func() {
		defer close(targetChan)
		for i := 0; i < 5; i++ {
			targetChan <- models.Target{
				IP:   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
				Port: 65000 + i,
			}
		}
	}()

	// Collect results
	var results []models.ScanResult
	for result := range resultChan {
		results = append(results, result)
	}

	if len(results) != 5 {
		t.Errorf("Expected 5 results, got %d", len(results))
	}
}

func TestNativeScanner_ConcurrentSafety(t *testing.T) {
	s := scanner.NewNativeScanner(scanner.NativeConfig{
		Workers:    20,
		Retry:      1,
		RetryDelay: 10 * time.Millisecond,
	}, 5000, 2*time.Second)
	defer s.Close()

	// Run multiple scans concurrently
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			targets := []models.Target{
				{IP: netip.AddrFrom4([4]byte{127, 0, 0, 1}), Port: 60000 + idx},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resultChan, err := s.Scan(ctx, targets)
			if err != nil {
				t.Errorf("Scan() error = %v", err)
				return
			}

			for range resultChan {
				// Drain results
			}
		}(i)
	}

	wg.Wait()
}

// BenchmarkNativeScanner_Scan benchmarks the scanner performance
func BenchmarkNativeScanner_Scan(b *testing.B) {
	s := scanner.NewNativeScanner(scanner.NativeConfig{
		Workers:    100,
		Retry:      0,
		RetryDelay: 0,
	}, 10000, 1*time.Second)
	defer s.Close()

	// Create targets (all to closed ports)
	targets := make([]models.Target, 100)
	for i := 0; i < 100; i++ {
		targets[i] = models.Target{
			IP:   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			Port: 60000 + i,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		resultChan, _ := s.Scan(ctx, targets)
		for range resultChan {
			// Drain
		}

		cancel()
	}
}
