// cmd/scanner/main.go
// Ollama Scanner 3.0 - Main entry point
// FIXED: Graceful shutdown, proper error handling, refactored to use app package
// ADDED: Checkpoint/Resume support

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aspnmy/ollama_scanner/internal/app"
	"github.com/aspnmy/ollama_scanner/internal/checkpoint"
	"github.com/aspnmy/ollama_scanner/internal/core"
	"github.com/aspnmy/ollama_scanner/internal/detector"
	"github.com/aspnmy/ollama_scanner/internal/models"
	"github.com/aspnmy/ollama_scanner/internal/output"
	"github.com/aspnmy/ollama_scanner/internal/scanner"
	"github.com/aspnmy/ollama_scanner/pkg/cidr"
	"github.com/aspnmy/ollama_scanner/pkg/logger"
)

var (
	version   = "3.0.0"
	buildTime = "unknown"
)

func main() {
	// Command line flags
	var (
		configFile      = flag.String("config", "configs/config.yaml", "Path to config file")
		cidrs           = flag.String("targets", "", "Comma-separated CIDRs (e.g., 10.0.0.0/24,192.168.1.0/24)")
		ports           = flag.String("ports", "11434", "Comma-separated ports to scan")
		engine          = flag.String("engine", "native", "Scanner engine: native, zmap, masscan")
		outputFormat    = flag.String("output", "jsonl", "Output format: jsonl, csv, console")
		workers         = flag.Int("workers", 1000, "Number of concurrent workers")
		rateLimit       = flag.Int("rate", 5000, "Max requests per second")
		timeout         = flag.Duration("timeout", 3*time.Second, "Connection timeout")
		maxTargets      = flag.Int64("max-targets", 10000000, "Maximum targets to scan (safety limit)")
		noDetect        = flag.Bool("no-detect", false, "Skip Ollama detection (port scan only)")
		noSecurity      = flag.Bool("no-security", false, "Skip security audit")
		showVersion     = flag.Bool("version", false, "Show version and exit")
		verbose         = flag.Bool("v", false, "Verbose output (debug level)")
		listEngines     = flag.Bool("list-engines", false, "List available scanner engines")
		// Safety flags
		forceLargeScan  = flag.Bool("force", false, "Force scan of large CIDRs without confirmation (DANGEROUS)")
		assumeYes       = flag.Bool("yes", false, "Auto-confirm all warnings and prompts")
		// Checkpoint flags
		resumeScan      = flag.String("resume", "", "Resume scan from checkpoint (scan ID)")
		listCheckpoints = flag.Bool("list-checkpoints", false, "List available checkpoints")
		deleteCheckpoint = flag.String("delete-checkpoint", "", "Delete a checkpoint (scan ID)")
		checkpointDB    = flag.String("checkpoint-db", "checkpoints.db", "Checkpoint database path")
		noCheckpoint    = flag.Bool("no-checkpoint", false, "Disable checkpointing")
	)
	flag.Parse()

	// Show version
	if *showVersion {
		fmt.Printf("Ollama Scanner v%s (built: %s)\n", version, buildTime)
		fmt.Println("Modern Go-based Ollama security scanner")
		fmt.Println("Based on SentinelOne/Censys research (Jan 2026)")
		fmt.Println()
		fmt.Println("Features:")
		fmt.Println("  - Native Go TCP scanner (no external dependencies)")
		fmt.Println("  - Ollama detection and security audit")
		fmt.Println("  - Checkpoint/Resume capability for long scans")
		fmt.Println("  - Risk scoring based on 175K exposed instances research")
		os.Exit(0)
	}

	// List engines
	if *listEngines {
		fmt.Println("Available scanner engines:")
		for name := range scanner.Registry {
			fmt.Printf("  - %s\n", name)
		}
		os.Exit(0)
	}

	// List checkpoints
	if *listCheckpoints {
		if err := listCheckpointsFunc(*checkpointDB); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Delete checkpoint
	if *deleteCheckpoint != "" {
		if err := checkpoint.DeleteScan(*checkpointDB, *deleteCheckpoint); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting checkpoint: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Checkpoint %s deleted successfully\n", *deleteCheckpoint)
		os.Exit(0)
	}

	// Setup logger
	logConfig := logger.Config{
		Level:  "info",
		Format: "console",
	}
	if *verbose {
		logConfig.Level = "debug"
	}

	if err := logger.Init(logConfig); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("Starting Ollama Scanner",
		logger.String("version", version),
		logger.String("build_time", buildTime),
	)

	// Load configuration
	cfg, err := core.Load(*configFile)
	if err != nil {
		logger.Error("Failed to load configuration", logger.Err(err))
		cfg = core.Get()
	}

	// Override with command line flags
	applyFlags(cfg, *cidrs, *ports, *engine, *outputFormat, *workers, *rateLimit, *timeout)

	// Print configuration
	core.Print()

	// Handle resume
	if *resumeScan != "" {
		if err := resumeScanFunc(*checkpointDB, *resumeScan, cfg, *noDetect, *noSecurity); err != nil {
			logger.Error("Failed to resume scan", logger.Err(err))
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Validate and prepare targets
	targets, targetCount, err := prepareTargets(cfg, *maxTargets)
	if err != nil {
		logger.Error("Failed to prepare targets", logger.Err(err))
		os.Exit(1)
	}

	if targetCount == 0 {
		logger.Error("No targets to scan")
		os.Exit(1)
	}

	logger.Info("Targets prepared",
		logger.Int64("count", targetCount),
		logger.Int("ports", len(cfg.Scanner.Targets.Ports)),
	)

	// Check CIDR size and show warnings
	cidrInfo, err := cidr.CheckCIDRSize(cfg.Scanner.Targets.CIDRs, cfg.Scanner.Targets.Ports)
	if err != nil {
		logger.Error("Failed to check CIDR size", logger.Err(err))
		os.Exit(1)
	}

	// Show size warning if applicable
	if cidrInfo.Warning != "" {
		fmt.Println("\n╔════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                    ⚠️  SCAN SIZE WARNING                        ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════╣")
		fmt.Printf("║ %s\n", cidrInfo.Warning)
		fmt.Println("╠════════════════════════════════════════════════════════════════╣")
		estimatedDuration := time.Duration(float64(cidrInfo.TotalHosts)/float64(cfg.Scanner.RateLimit)) * time.Second
		fmt.Printf("║ Total targets: %d\n", cidrInfo.TotalHosts)
		fmt.Printf("║ Estimated time: %s\n", estimatedDuration)
		fmt.Printf("║ Memory required: ~%.1f MB\n", float64(cidrInfo.TotalHosts)*0.01/1024)
		fmt.Println("╚════════════════════════════════════════════════════════════════╝\n")

		// Require confirmation for very large scans
		if cidrInfo.IsVeryLarge && !*forceLargeScan {
			if *assumeYes {
				logger.Warn("Large scan auto-confirmed via -yes flag")
			} else {
				fmt.Print("Continue with this scan? [y/N]: ")
				var response string
				fmt.Scanln(&response)
				if response != "y" && response != "Y" && response != "yes" {
					logger.Info("Scan cancelled by user")
					os.Exit(0)
				}
			}
		}
	}

	// Show warning for 0.0.0.0/0
	for _, cidrStr := range cfg.Scanner.Targets.CIDRs {
		if cidrStr == "0.0.0.0/0" || cidrStr == "::/0" {
			fmt.Println("\n╔════════════════════════════════════════════════════════════════╗")
			fmt.Println("║              🚨 INTERNET-WIDE SCAN WARNING                      ║")
			fmt.Println("╠════════════════════════════════════════════════════════════════╣")
			fmt.Println("║ You are about to scan the ENTIRE INTERNET!                    ║")
			fmt.Println("║ This will take hours/days and consume massive resources.      ║")
			fmt.Println("╚════════════════════════════════════════════════════════════════╝\n")
			
			if !*forceLargeScan {
				if *assumeYes {
					logger.Warn("Internet-wide scan auto-confirmed via -yes flag")
				} else {
					fmt.Print("Are you ABSOLUTELY SURE? Type 'YES' to continue: ")
					var response string
					fmt.Scanln(&response)
					if response != "YES" {
						logger.Info("Scan cancelled")
						os.Exit(0)
					}
				}
			}
		}
	}

	// Build dependencies
	deps, err := buildDependencies(cfg, *checkpointDB, *noCheckpoint, targetCount)
	if err != nil {
		logger.Error("Failed to build dependencies", logger.Err(err))
		os.Exit(1)
	}

	// Create scanner app
	scannerApp := app.NewScannerApp(deps)

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal, initiating graceful shutdown...")

		// Create shutdown context with timeout
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if shutdownErr := scannerApp.Shutdown(shutdownCtx); shutdownErr != nil {
			logger.Error("Error during shutdown", logger.Err(shutdownErr))
		}

		cancel() // Cancel main context
	}()

	// Run the scanner
	if err := scannerApp.Run(ctx, targets, targetCount, !*noDetect, !*noSecurity); err != nil {
		logger.Error("Scan failed", logger.Err(err))
		os.Exit(1)
	}

	logger.Info("Scan completed successfully")
}

// listCheckpointsFunc lists available checkpoints
func listCheckpointsFunc(dbPath string) error {
	scans, err := checkpoint.ListScans(dbPath, "")
	if err != nil {
		return err
	}

	if len(scans) == 0 {
		fmt.Println("No checkpoints found")
		return nil
	}

	fmt.Println("Available checkpoints:")
	fmt.Println("----------------------")
	fmt.Printf("%-20s %-12s %-10s %s\n", "SCAN ID", "STATUS", "PROGRESS", "UPDATED")
	fmt.Println(strings.Repeat("-", 70))

	for _, scan := range scans {
		progress := fmt.Sprintf("%d/%d", scan.ProcessedTargets, scan.TotalTargets)
		updated := scan.UpdatedAt.Format("2006-01-02 15:04")
		fmt.Printf("%-20s %-12s %-10s %s\n", scan.ScanID, scan.Status, progress, updated)
	}

	fmt.Println()
	fmt.Println("To resume a scan: ./ollama-scanner -resume <scan_id>")
	fmt.Println("To delete a checkpoint: ./ollama-scanner -delete-checkpoint <scan_id>")

	return nil
}

// resumeScanFunc resumes a scan from checkpoint
func resumeScanFunc(dbPath, scanID string, cfg *core.Config, noDetect, noSecurity bool) error {
	// Check if resumable
	if !checkpoint.IsResumable(dbPath, scanID) {
		return fmt.Errorf("scan %s cannot be resumed (not found or already completed)", scanID)
	}

	// Create checkpoint manager
	cpCfg := checkpoint.DefaultConfig()
	cpCfg.DBPath = dbPath
	cpManager, err := checkpoint.NewManager(cpCfg)
	if err != nil {
		return fmt.Errorf("failed to create checkpoint manager: %w", err)
	}
	defer cpManager.Close()

	// Get resume info
	resumeInfo, err := cpManager.ResumeScan(scanID)
	if err != nil {
		return fmt.Errorf("failed to resume scan: %w", err)
	}

	// Build dependencies
	deps, err := buildDependencies(cfg, dbPath, false, resumeInfo.TotalTargets)
	if err != nil {
		return fmt.Errorf("failed to build dependencies: %w", err)
	}

	// Use existing checkpoint manager
	deps.Checkpoint = cpManager

	// Create scanner app
	scannerApp := app.NewScannerApp(deps)

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal, initiating graceful shutdown...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := scannerApp.Shutdown(shutdownCtx); err != nil {
			logger.Error("Error during shutdown", logger.Err(err))
		}
		cancel()
	}()

	// Run with resume
	return scannerApp.RunWithResume(ctx, resumeInfo, !noDetect, !noSecurity)
}

// buildDependencies builds all dependencies for the scanner app
func buildDependencies(cfg *core.Config, checkpointDB string, noCheckpoint bool, targetCount int64) (app.ScannerDeps, error) {
	// Create scanner engine
	engineConfig := map[string]interface{}{
		"workers":     cfg.Scanner.Concurrency,
		"rate_limit":  cfg.Scanner.RateLimit,
		"timeout":     cfg.Scanner.Timeout,
		"retry":       cfg.Scanner.Native.Retry,
		"retry_delay": cfg.Scanner.Native.RetryDelay,
	}

	engine, err := scanner.Get(cfg.Scanner.Engine, engineConfig)
	if err != nil {
		return app.ScannerDeps{}, fmt.Errorf("failed to create scanner engine: %w", err)
	}

	// Create Ollama detector
	ollamaDetector := detector.NewDetector(cfg.Scanner.Timeout)

	// Setup output formatters
	var formatters []output.Formatter
	for _, format := range cfg.Output.Formats {
		switch format {
		case "jsonl":
			filename := fmt.Sprintf("%s/%s_%s.jsonl",
				cfg.Output.Directory, cfg.Output.FilePrefix, time.Now().Format("20060102_150405"))
			jf, err := output.NewJSONLFormatter(filename)
			if err != nil {
				return app.ScannerDeps{}, fmt.Errorf("failed to create JSONL formatter: %w", err)
			}
			formatters = append(formatters, jf)
			logger.Info("JSONL output enabled", logger.String("file", filename))

		case "console":
			formatters = append(formatters, output.NewConsoleFormatter(cfg.Output.Console.Dashboard))
		}
	}

	if len(formatters) == 0 {
		return app.ScannerDeps{}, fmt.Errorf("no output formatters configured")
	}

	// Setup progress reporter
	var reporter output.ProgressReporter
	if cfg.Output.Console.Progress {
		reporter = output.NewSimpleProgressReporter(targetCount)
	}

	// Create checkpoint manager
	var cpManager *checkpoint.Manager
	if !noCheckpoint {
		cpCfg := checkpoint.DefaultConfig()
		cpCfg.DBPath = checkpointDB
		cpManager, err = checkpoint.NewManager(cpCfg)
		if err != nil {
			logger.Warn("Failed to create checkpoint manager, continuing without checkpointing", logger.Err(err))
		}
	}

	return app.ScannerDeps{
		Config:     cfg,
		Engine:     engine,
		Detector:   ollamaDetector,
		Formatters: formatters,
		Reporter:   reporter,
		Checkpoint: cpManager,
	}, nil
}

// applyFlags applies command line flag overrides to config
func applyFlags(cfg *core.Config, cidrs, ports, engine, outputFormat string, workers, rateLimit int, timeout time.Duration) {
	if engine != "" {
		cfg.Scanner.Engine = engine
	}

	if outputFormat != "" {
		cfg.Output.Formats = strings.Split(outputFormat, ",")
	}

	if cidrs != "" {
		cfg.Scanner.Targets.CIDRs = parseList(cidrs)
	}

	if ports != "" {
		portList := parseList(ports)
		cfg.Scanner.Targets.Ports = parseInts(portList)
	}

	if workers > 0 {
		cfg.Scanner.Concurrency = workers
		cfg.Scanner.Native.Workers = workers
	}

	if rateLimit > 0 {
		cfg.Scanner.RateLimit = rateLimit
	}

	if timeout > 0 {
		cfg.Scanner.Timeout = timeout
	}
}

// parseList parses comma-separated string into slice
func parseList(s string) []string {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// parseInts converts string slice to int slice
func parseInts(s []string) []int {
	var result []int
	for _, str := range s {
		var port int
		if _, err := fmt.Sscanf(str, "%d", &port); err == nil {
			if port > 0 && port <= 65535 {
				result = append(result, port)
			}
		}
	}
	return result
}

// prepareTargets validates and prepares target list
func prepareTargets(cfg *core.Config, maxTargets int64) ([]models.Target, int64, error) {
	cidrs := cfg.Scanner.Targets.CIDRs

	// Load from file if specified
	if cfg.Scanner.Targets.File != "" {
		fileCIDRs, err := cidr.ParseCIDRFile(cfg.Scanner.Targets.File)
		if err != nil {
			return nil, 0, err
		}
		cidrs = append(cidrs, fileCIDRs...)
	}

	if len(cidrs) == 0 {
		return nil, 0, fmt.Errorf("no targets specified")
	}

	// Validate CIDRs
	if err := cidr.ValidateCIDRs(cidrs); err != nil {
		return nil, 0, err
	}

	// Count targets
	targetCount, err := cidr.CountTargets(cidrs, cfg.Scanner.Targets.Ports)
	if err != nil {
		return nil, 0, err
	}

	// Check max targets limit
	// SECURITY: Prevent integer overflow by comparing same types
	if maxTargets > 0 && targetCount > uint64(maxTargets) {
		return nil, 0, fmt.Errorf("target count %d exceeds maximum allowed %d. Use -max-targets flag to override",
			targetCount, maxTargets)
	}

	// Generate targets
	targetChan, err := cidr.GenerateTargets(cidrs, cfg.Scanner.Targets.Ports, 10000)
	if err != nil {
		return nil, 0, err
	}

	// Convert channel to slice
	var targets []models.Target
	for addrPort := range targetChan {
		targets = append(targets, models.Target{
			IP:   addrPort.Addr(),
			Port: int(addrPort.Port()),
		})
	}

	return targets, int64(len(targets)), nil
}
