// Package main demonstrates modern Go CLI patterns for 2026
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "scanner",
		Short: "Modern network scanner with 2026 patterns",
		Long: `A network scanner demonstrating modern Go CLI patterns:
  
- Structured logging with slog
- Configuration priority: Defaults < File < Env < Flags
- Graceful shutdown with context cancellation
- Rich terminal output with lipgloss
- State persistence for resume capability`,
	}

	// Add subcommands
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newVersionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
