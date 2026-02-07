// pkg/ratelimit/limiter.go
// Token bucket rate limiter with adaptive control
// FIXED: Race condition in stats, proper goroutine lifecycle

package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter wraps golang.org/x/time/rate with additional features
type Limiter struct {
	limiter     *rate.Limiter
	baseRate    rate.Limit
	currentRate rate.Limit
	mu          sync.RWMutex
	
	// Adaptive control
	adaptive    bool
	targetLoss  float64
	feedback    chan NetworkFeedback
	done        chan struct{}  // FIXED: For proper goroutine shutdown
	
	// Statistics
	stats       Stats
	statsMu     sync.Mutex  // FIXED: Separate mutex for stats
}

// Stats contains rate limiter statistics
type Stats struct {
	TotalRequests   int64
	DelayedRequests int64
	CurrentRate     float64
	AdaptiveMode    bool
}

// NetworkFeedback for adaptive rate adjustment
type NetworkFeedback struct {
	RTT        time.Duration
	PacketLoss float64
	Jitter     time.Duration
}

// Config holds rate limiter configuration
type Config struct {
	Rate       int     // requests per second
	Adaptive   bool    // enable adaptive mode
	TargetLoss float64 // target packet loss rate (default 0.01 = 1%)
}

// New creates a new rate limiter
func New(cfg Config) *Limiter {
	r := rate.Limit(cfg.Rate)
	if r <= 0 {
		r = rate.Inf
	}
	
	l := &Limiter{
		limiter:     rate.NewLimiter(r, int(r)),
		baseRate:    r,
		currentRate: r,
		adaptive:    cfg.Adaptive,
		targetLoss:  cfg.TargetLoss,
		feedback:    make(chan NetworkFeedback, 100),
		done:        make(chan struct{}),  // FIXED: Initialize done channel
	}
	
	if l.targetLoss == 0 {
		l.targetLoss = 0.01 // Default 1%
	}
	
	// Start adaptive controller if enabled
	if l.adaptive {
		go l.adaptiveController()
	}
	
	return l
}

// Wait blocks until a token is available
func (l *Limiter) Wait(ctx context.Context) error {
	// FIXED: Properly update stats with mutex lock
	err := l.limiter.Wait(ctx)
	
	l.statsMu.Lock()
	l.stats.TotalRequests++
	if err != nil {
		l.stats.DelayedRequests++
	}
	l.statsMu.Unlock()
	
	return err
}

// WaitN blocks until n tokens are available
func (l *Limiter) WaitN(ctx context.Context, n int) error {
	if l.limiter.Limit() == rate.Inf {
		return nil
	}
	return l.limiter.WaitN(ctx, n)
}

// SetRate updates the rate limit dynamically
func (l *Limiter) SetRate(rps int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	r := rate.Limit(rps)
	if r <= 0 {
		r = rate.Inf
	}
	
	l.limiter.SetLimit(r)
	l.currentRate = r
	
	l.statsMu.Lock()
	l.stats.CurrentRate = float64(r)
	l.statsMu.Unlock()
}

// GetRate returns current rate
func (l *Limiter) GetRate() float64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return float64(l.currentRate)
}

// GetStats returns current statistics
func (l *Limiter) GetStats() Stats {
	l.statsMu.Lock()
	defer l.statsMu.Unlock()
	return l.stats
}

// SendFeedback sends network feedback for adaptive control
func (l *Limiter) SendFeedback(feedback NetworkFeedback) {
	if !l.adaptive {
		return
	}
	
	select {
	case l.feedback <- feedback:
	case <-l.done:  // FIXED: Don't block if stopped
	default:
		// Drop if channel is full
	}
}

// adaptiveController adjusts rate based on network conditions
// FIXED: Proper goroutine lifecycle with done channel
func (l *Limiter) adaptiveController() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	var (
		packetLossHistory []float64
		rttHistory        []time.Duration
	)
	
	for {
		select {
		case <-l.done:  // FIXED: Proper exit mechanism
			return
			
		case feedback := <-l.feedback:
			packetLossHistory = append(packetLossHistory, feedback.PacketLoss)
			rttHistory = append(rttHistory, feedback.RTT)
			
			// Keep only last 10 samples
			if len(packetLossHistory) > 10 {
				packetLossHistory = packetLossHistory[1:]
				rttHistory = rttHistory[1:]
			}
			
		case <-ticker.C:
			if len(packetLossHistory) == 0 {
				continue
			}
			
			// Calculate averages
			avgLoss := average(packetLossHistory)
			avgRTT := averageDuration(rttHistory)
			
			l.adjustRate(avgLoss, avgRTT)
			
			// Clear history
			packetLossHistory = nil
			rttHistory = nil
		}
	}
}

// adjustRate applies PID-like control to adjust rate
func (l *Limiter) adjustRate(avgLoss float64, avgRTT time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	currentRate := float64(l.currentRate)
	baseRate := float64(l.baseRate)
	
	// PID parameters
	kp := 0.5 // Proportional gain
	ki := 0.1 // Integral gain
	
	// Error calculation
	error := l.targetLoss - avgLoss
	
	// Proportional term
	p := kp * error
	
	// Integral term (accumulated error)
	l.statsMu.Lock()
	l.stats.AdaptiveMode = true
	l.statsMu.Unlock()
	
	// Calculate adjustment
	adjustment := p + ki*error
	
	// Apply adjustment
	newRate := currentRate * (1 + adjustment)
	
	// Bounds checking
	minRate := baseRate * 0.1  // Don't go below 10% of base
	maxRate := baseRate * 2.0  // Don't exceed 200% of base
	
	if newRate < minRate {
		newRate = minRate
	} else if newRate > maxRate {
		newRate = maxRate
	}
	
	// Apply new rate
	l.limiter.SetLimit(rate.Limit(newRate))
	l.currentRate = rate.Limit(newRate)
	
	l.statsMu.Lock()
	l.stats.CurrentRate = newRate
	l.statsMu.Unlock()
}

// Stop stops the adaptive controller
// FIXED: Proper shutdown
func (l *Limiter) Stop() {
	select {
	case <-l.done:
		// Already closed
		return
	default:
		close(l.done)
	}
}

// Helper functions
func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func averageDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	
	var sum time.Duration
	for _, v := range values {
		sum += v
	}
	return sum / time.Duration(len(values))
}
