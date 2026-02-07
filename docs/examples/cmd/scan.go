package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/knadh/koanf/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"strings"
)

// ScanConfig holds scan configuration with struct tags for koanf
type ScanConfig struct {
	Target      string   `koanf:"target"`
	Ports       []int    `koanf:"ports"`
	Timeout     int      `koanf:"timeout"`
	Output      string   `koanf:"output"`
	Verbose     bool     `koanf:"verbose"`
	Concurrency int      `koanf:"concurrency"`
}

// DefaultScanConfig returns default configuration
func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		Ports:       []int{22, 80, 443},
		Timeout:     5,
		Output:      "table",
		Verbose:     false,
		Concurrency: 100,
	}
}

func newScanCmd() *cobra.Command {
	var cfg ScanConfig
	var k = koanf.New(":")
	var configFile string

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Scan a target host or network",
		Example: `  scanner scan 192.168.1.1
  scanner scan 10.0.0.0/24 -p 22,80,443
  scanner scan example.com -o json -v`,
		Args: cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			cfg.Target = args[0]

			// 1. Load defaults
			if err := k.Load(structs.Provider(DefaultScanConfig(), "koanf"), nil); err != nil {
				return fmt.Errorf("loading defaults: %w", err)
			}

			// 2. Load config file if specified
			if configFile != "" {
				if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
					return fmt.Errorf("loading config file: %w", err)
				}
			}

			// 3. Load environment variables
			// SCANNER_PORTS, SCANNER_TIMEOUT, etc.
			if err := k.Load(env.Provider("SCANNER_", ":", func(s string) string {
				return strings.ToLower(strings.TrimPrefix(s, "SCANNER_"))
			}), nil); err != nil {
				return fmt.Errorf("loading env vars: %w", err)
			}

			// 4. Unmarshal to struct (CLI flags already bound via BindPFlags)
			if err := k.Unmarshal("", &cfg); err != nil {
				return fmt.Errorf("unmarshaling config: %w", err)
			}

			// Setup logger
			opts := &slog.HandlerOptions{
				Level: func() slog.Level {
					if cfg.Verbose {
						return slog.LevelDebug
					}
					return slog.LevelInfo
				}(),
			}

			var handler slog.Handler
			if cfg.Output == "json" {
				handler = slog.NewJSONHandler(os.Stderr, opts)
			} else {
				handler = slog.NewTextHandler(os.Stderr, opts)
			}
			slog.SetDefault(slog.New(handler))

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Setup graceful shutdown context
			ctx, stop := signal.NotifyContext(
				context.Background(),
				syscall.SIGINT,
				syscall.SIGTERM,
			)
			defer stop()

			// Log configuration (only in debug)
			slog.Debug("starting scan",
				slog.String("target", cfg.Target),
				slog.Any("ports", cfg.Ports),
				slog.Int("timeout", cfg.Timeout),
				slog.String("output", cfg.Output),
				slog.Int("concurrency", cfg.Concurrency),
			)

			// Run the scan with graceful shutdown
			return runScan(ctx, &cfg)
		},
	}

	// Flags
	cmd.Flags().IntSliceP("ports", "p", []int{22, 80, 443}, "Ports to scan")
	cmd.Flags().IntP("timeout", "t", 5, "Timeout in seconds")
	cmd.Flags().StringP("output", "o", "table", "Output format (table, json, csv)")
	cmd.Flags().BoolP("verbose", "v", false, "Verbose output")
	cmd.Flags().IntP("concurrency", "c", 100, "Concurrent workers")
	cmd.Flags().StringVar(&configFile, "config", "", "Config file path")

	return cmd
}

func runScan(ctx context.Context, cfg *ScanConfig) error {
	slog.Info("starting scan", slog.String("target", cfg.Target))

	// Simulate work with context awareness
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	progress := 0
	total := 10

	for {
		select {
		case <-ctx.Done():
			slog.Warn("scan interrupted", slog.String("reason", ctx.Err().Error()))
			return fmt.Errorf("scan interrupted: %w", ctx.Err())

		case <-ticker.C:
			progress++
			slog.Debug("scan progress",
				slog.Int("progress", progress),
				slog.Int("total", total),
			)

			if progress >= total {
				slog.Info("scan complete")
				return nil
			}
		}
	}
}
