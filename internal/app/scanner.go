// internal/app/scanner.go
// Application orchestrator for Ollama Scanner
// FIXED: Graceful shutdown, proper error handling, dependency injection
// ADDED: Checkpoint/Resume support

package app

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/aspnmy/ollama_scanner/internal/checkpoint"
	"github.com/aspnmy/ollama_scanner/internal/core"
	"github.com/aspnmy/ollama_scanner/internal/detector"
	"github.com/aspnmy/ollama_scanner/internal/models"
	"github.com/aspnmy/ollama_scanner/internal/output"
	"github.com/aspnmy/ollama_scanner/internal/scanner"
	"github.com/aspnmy/ollama_scanner/pkg/logger"
)

// ScannerApp orchestrates the scanning process
type ScannerApp struct {
	config     *core.Config
	engine     scanner.Engine
	detector   *detector.Detector
	formatters []output.Formatter
	reporter   output.ProgressReporter
	checkpoint *checkpoint.Manager

	// Lifecycle management
	wg     sync.WaitGroup
	cancel context.CancelFunc
	mu     sync.Mutex
}

// ScannerDeps holds dependencies for the scanner app
type ScannerDeps struct {
	Config     *core.Config
	Engine     scanner.Engine
	Detector   *detector.Detector
	Formatters []output.Formatter
	Reporter   output.ProgressReporter
	Checkpoint *checkpoint.Manager
}

// NewScannerApp creates a new scanner application
func NewScannerApp(deps ScannerDeps) *ScannerApp {
	return &ScannerApp{
		config:     deps.Config,
		engine:     deps.Engine,
		detector:   deps.Detector,
		formatters: deps.Formatters,
		reporter:   deps.Reporter,
		checkpoint: deps.Checkpoint,
	}
}

// Run executes the scanning process
func (app *ScannerApp) Run(ctx context.Context, targets []models.Target, totalTargets int64, detect, security bool) error {
	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	app.cancel = cancel
	defer cancel()

	// Start checkpoint tracking
	var scanID string
	if app.checkpoint != nil {
		var err error
		scanID, err = app.checkpoint.StartScan(totalTargets, map[string]interface{}{
			"engine":   app.config.Scanner.Engine,
			"targets":  len(targets),
			"ports":    app.config.Scanner.Targets.Ports,
			"detect":   detect,
			"security": security,
		})
		if err != nil {
			logger.Warn("Failed to start checkpoint tracking", logger.Err(err))
		}
	}

	logger.Info("Starting scan",
		logger.Int64("targets", totalTargets),
		logger.Bool("detection", detect),
		logger.Bool("security_audit", security),
	)

	// Create multi-formatter
	multiFormatter := output.NewMultiFormatter(app.formatters...)
	defer multiFormatter.Close()

	// Start scanning
	resultChan, err := app.engine.Scan(ctx, targets)
	if err != nil {
		if app.checkpoint != nil {
			app.checkpoint.Fail(err.Error())
		}
		return fmt.Errorf("failed to start scan: %w", err)
	}

	// Process results
	stats := &scanStats{
		totalTargets: totalTargets,
		startTime:    time.Now(),
	}

	// Process results with proper lifecycle management
	app.wg.Add(1)
	go func() {
		defer app.wg.Done()
		app.processResults(ctx, resultChan, multiFormatter, stats, detect, security, targets)
	}()

	// Wait for completion
	app.wg.Wait()

	// Final flush
	if err := multiFormatter.Flush(); err != nil {
		logger.Error("Failed to flush output", logger.Err(err))
	}

	// Mark checkpoint as complete if successful
	if app.checkpoint != nil && ctx.Err() == nil {
		if err := app.checkpoint.Complete(); err != nil {
			logger.Warn("Failed to mark scan as complete", logger.Err(err))
		}
	}

	// Show final stats
	if app.reporter != nil {
		app.reporter.Finish(models.Progress{
			ScanID:       scanID,
			TotalTargets: totalTargets,
			Processed:    stats.processed,
			OpenHosts:    stats.openHosts,
			OllamaHosts:  stats.ollamaHosts,
			StartTime:    stats.startTime,
			Elapsed:      time.Since(stats.startTime),
		})
	}

	// Security summary
	if security && stats.ollamaHosts > 0 {
		app.printSecuritySummary(stats)
	}

	logger.Info("Scan complete",
		logger.Int64("processed", stats.processed),
		logger.Int64("open_hosts", stats.openHosts),
		logger.Int64("ollama_hosts", stats.ollamaHosts),
		logger.Int64("high_risk_hosts", stats.highRiskHosts),
		logger.String("duration", time.Since(stats.startTime).String()),
	)

	return nil
}

// RunWithResume runs a scan with resume capability
func (app *ScannerApp) RunWithResume(ctx context.Context, resumeInfo *checkpoint.ResumeInfo, detect, security bool) error {
	// Convert remaining targets back to Target structs
	targets := make([]models.Target, 0, len(resumeInfo.RemainingTargets))
	for _, addrPort := range resumeInfo.RemainingTargets {
		// Parse "ip:port" format
		var ip netip.Addr
		var port int
		fmt.Sscanf(addrPort, "%s:%d", &ip, &port)
		if ip.IsValid() && port > 0 {
			targets = append(targets, models.Target{IP: ip, Port: port})
		}
	}

	logger.Info("Resuming scan",
		logger.String("scan_id", resumeInfo.ScanID),
		logger.Int64("previously_processed", resumeInfo.ProcessedCount),
		logger.Int("remaining", len(targets)),
	)

	return app.Run(ctx, targets, resumeInfo.TotalTargets, detect, security)
}

// Shutdown gracefully shuts down the scanner
func (app *ScannerApp) Shutdown(ctx context.Context) error {
	logger.Info("Shutting down scanner...")

	// Cancel context
	if app.cancel != nil {
		app.cancel()
	}

	// Wait for graceful shutdown with timeout
	done := make(chan struct{})
	go func() {
		app.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("Graceful shutdown complete")
	case <-ctx.Done():
		logger.Warn("Shutdown timeout exceeded")
	}

	// Close engine
	if app.engine != nil {
		if err := app.engine.Close(); err != nil {
			logger.Error("Error closing engine", logger.Err(err))
		}
	}

	// Close checkpoint manager
	if app.checkpoint != nil {
		if err := app.checkpoint.Pause(); err != nil {
			logger.Error("Error pausing checkpoint", logger.Err(err))
		}
		if err := app.checkpoint.Close(); err != nil {
			logger.Error("Error closing checkpoint manager", logger.Err(err))
		}
	}

	return nil
}

// processResults processes scan results
// FIXED: Memory-efficient remaining target tracking with periodic compaction
func (app *ScannerApp) processResults(ctx context.Context, resultChan <-chan models.ScanResult, formatter output.Formatter, stats *scanStats, detect, security bool, targets []models.Target) {
	// Efficient remaining target tracking to prevent memory leak
	// Uses offset + periodic compaction instead of slice re-slicing
	type remainingState struct {
		targets []string
		offset  int
	}
	
	var state *remainingState
	if app.checkpoint != nil {
		// Pre-calculate remaining targets for checkpoint
		remaining := make([]string, 0, len(targets))
		for _, t := range targets {
			remaining = append(remaining, t.Address())
		}
		state = &remainingState{targets: remaining, offset: 0}
	}

	var checkpointResults []models.ScanResult
	checkpointInterval := 100 // Save every 100 results
	compactionInterval := 1000 // Compact every 1000 targets to free memory

	for portResult := range resultChan {
		stats.processed++

		var finalResult models.ScanResult = portResult

		// If port is open, perform Ollama detection
		if portResult.Open && app.detector != nil && detect {
			detectCtx, cancel := context.WithTimeout(ctx, app.config.Scanner.Timeout*3)
			detectResult, err := app.detector.Detect(detectCtx, portResult.Target)
			cancel()

			if err == nil && detectResult != nil {
				finalResult = *detectResult
				if finalResult.IsOllama {
					stats.ollamaHosts++

					// Check risk level
					if finalResult.SecurityReport != nil && finalResult.SecurityReport.RiskScore >= 7 {
						stats.highRiskHosts++
					}
				}
			}
		}

		if finalResult.Open {
			stats.openHosts++
		}

		// Write to output with error handling
		if err := formatter.Write(&finalResult); err != nil {
			logger.Error("Failed to write result",
				logger.String("target", finalResult.Target.String()),
				logger.Err(err))
		}

		// Update progress
		if app.reporter != nil && stats.processed%100 == 0 {
			app.reporter.UpdateProgress(models.Progress{
				ScanID:        "scan_001",
				TotalTargets:  stats.totalTargets,
				Processed:     stats.processed,
				OpenHosts:     stats.openHosts,
				OllamaHosts:   stats.ollamaHosts,
				StartTime:     stats.startTime,
				Elapsed:       time.Since(stats.startTime),
			})
		}

		// Checkpoint handling
		if app.checkpoint != nil && state != nil {
			// Update remaining list using offset (memory-efficient)
			state.offset++
			
			// Periodic compaction to free memory (every 1000 targets)
			if state.offset >= compactionInterval {
				if len(state.targets) > state.offset {
					state.targets = state.targets[state.offset:]
				} else {
					state.targets = state.targets[:0]
				}
				state.offset = 0
			}

			// Collect results for checkpoint
			checkpointResults = append(checkpointResults, finalResult)

			// Save checkpoint periodically
			if len(checkpointResults) >= checkpointInterval {
				// Get current remaining slice (accounting for offset)
				var currentRemaining []string
				if state.offset < len(state.targets) {
					currentRemaining = state.targets[state.offset:]
				}
				
				if err := app.checkpoint.MaybeSave(stats.processed, currentRemaining, checkpointResults); err != nil {
					logger.Warn("Failed to save checkpoint", logger.Err(err))
				}
				checkpointResults = checkpointResults[:0] // Clear but keep capacity
			}
		}

		// Check context
		select {
		case <-ctx.Done():
			logger.Info("Result processing interrupted")
			// Save final checkpoint before exit
			if app.checkpoint != nil && state != nil {
				var currentRemaining []string
				if state.offset < len(state.targets) {
					currentRemaining = state.targets[state.offset:]
				}
				if err := app.checkpoint.Save(stats.processed, currentRemaining, checkpointResults); err != nil {
					logger.Warn("Failed to save final checkpoint", logger.Err(err))
				}
			}
			return
		default:
		}
	}

	// Final checkpoint save
	if app.checkpoint != nil && len(checkpointResults) > 0 && state != nil {
		var currentRemaining []string
		if state.offset < len(state.targets) {
			currentRemaining = state.targets[state.offset:]
		}
		if err := app.checkpoint.Save(stats.processed, currentRemaining, checkpointResults); err != nil {
			logger.Warn("Failed to save final checkpoint", logger.Err(err))
		}
	}
}

// printSecuritySummary prints security summary
func (app *ScannerApp) printSecuritySummary(stats *scanStats) {
	fmt.Println()
	fmt.Println("=============================================================")
	fmt.Println("SECURITY SUMMARY")
	fmt.Println("=============================================================")
	fmt.Printf("Ollama instances found: %d\n", stats.ollamaHosts)
	fmt.Printf("High/Critical risk: %d\n", stats.highRiskHosts)
	fmt.Println()
	fmt.Println("Note: Use -no-security to skip security audit")
	fmt.Println("      Use -no-detect for port scan only")
	fmt.Println("=============================================================")
}

// scanStats holds scan statistics
type scanStats struct {
	totalTargets  int64
	processed     int64
	openHosts     int64
	ollamaHosts   int64
	highRiskHosts int64
	startTime     time.Time
}
