// Package graceful demonstrates graceful shutdown patterns
package graceful

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ShutdownFunc is a cleanup function
type ShutdownFunc func(ctx context.Context) error

// Manager handles graceful shutdown
type Manager struct {
	timeout        time.Duration
	shutdownFuncs  []ShutdownFunc
	mu             sync.Mutex
	isShuttingDown bool
}

// NewManager creates a new shutdown manager
func NewManager(timeout time.Duration) *Manager {
	return &Manager{
		timeout:       timeout,
		shutdownFuncs: make([]ShutdownFunc, 0),
	}
}

// Register adds a shutdown function
func (m *Manager) Register(fn ShutdownFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shutdownFuncs = append(m.shutdownFuncs, fn)
}

// Shutdown executes all registered cleanup functions
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if m.isShuttingDown {
		m.mu.Unlock()
		return fmt.Errorf("shutdown already in progress")
	}
	m.isShuttingDown = true
	
	// Copy functions
	fns := make([]ShutdownFunc, len(m.shutdownFuncs))
	copy(fns, m.shutdownFuncs)
	m.mu.Unlock()

	// Execute in reverse order (LIFO)
	var errs []error
	for i := len(fns) - 1; i >= 0; i-- {
		if err := fns[i](ctx); err != nil {
			errs = append(errs, err)
			slog.Error("shutdown function failed", slog.String("error", err.Error()))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown completed with %d errors", len(errs))
	}
	return nil
}

// Run starts the application and handles graceful shutdown
func (m *Manager) Run(appFunc func(ctx context.Context) error) error {
	// Create signal context
	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	// Run application in background
	appDone := make(chan error, 1)
	go func() {
		appDone <- appFunc(ctx)
	}()

	// Wait for signal or app completion
	select {
	case err := <-appDone:
		if err != nil {
			slog.Error("application error", slog.String("error", err.Error()))
		}

	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}

	// Stop signal handling
	stop()

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	// Run shutdown
	if err := m.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}

	slog.Info("graceful shutdown complete")
	return nil
}

// Context-aware sleep
func Sleep(ctx context.Context, duration time.Duration) error {
	select {
	case <-time.After(duration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WorkerPool with graceful shutdown
type WorkerPool struct {
	workers int
	wg      sync.WaitGroup
	tasks   chan func(context.Context)
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewWorkerPool(workers, queueSize int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		workers: workers,
		tasks:   make(chan func(context.Context), queueSize),
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (p *WorkerPool) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

func (p *WorkerPool) worker() {
	defer p.wg.Done()
	for task := range p.tasks {
		task(p.ctx)
	}
}

func (p *WorkerPool) Submit(task func(context.Context)) bool {
	select {
	case p.tasks <- task:
		return true
	case <-p.ctx.Done():
		return false
	default:
		return false
	}
}

func (p *WorkerPool) Stop(timeout time.Duration) {
	p.cancel()
	
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("worker pool stop timeout")
	}
	
	close(p.tasks)
}
