// internal/output/console.go
// Console output formatter with security report display

package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/aspnmy/ollama_scanner/internal/models"
)

// ConsoleFormatter writes results to console
type ConsoleFormatter struct {
	verbose      bool
	showSecurity bool
}

// NewConsoleFormatter creates a new console formatter
func NewConsoleFormatter(verbose bool) *ConsoleFormatter {
	return &ConsoleFormatter{
		verbose:      verbose,
		showSecurity: true,
	}
}

// Write writes a result to console
func (f *ConsoleFormatter) Write(result *models.ScanResult) error {
	// Skip closed ports unless verbose
	if !result.Open {
		if f.verbose {
			fmt.Printf("[CLOSED] %s (%v)\n", result.Target.Address(), result.Latency)
		}
		return nil
	}

	// Build output line
	status := "OPEN"
	if result.IsOllama {
		status = "🔴 OLLAMA"
	}

	line := fmt.Sprintf("[%s] %s", status, result.Target.Address())

	if result.IsOllama {
		// Add version
		if result.Version != "" {
			line += fmt.Sprintf(" (v%s)", result.Version)
		}

		// Add model count
		if len(result.Models) > 0 {
			line += fmt.Sprintf(" [%d models]", len(result.Models))
		}

		// Add security info
		if result.SecurityReport != nil {
			sr := result.SecurityReport
			line += fmt.Sprintf(" RISK:%s(%d/10)", sr.RiskRating, sr.RiskScore)

			// Add critical warnings
			warnings := []string{}
			if !sr.AuthEnabled {
				warnings = append(warnings, "NO_AUTH")
			}
			if sr.ToolCallingEnabled {
				warnings = append(warnings, "TOOLS")
			}
			if sr.MCPEnabled {
				warnings = append(warnings, "MCP")
			}
			if len(sr.UncensoredModels) > 0 {
				warnings = append(warnings, fmt.Sprintf("UNCENSORED(%d)", len(sr.UncensoredModels)))
			}

			if len(warnings) > 0 {
				line += " [" + strings.Join(warnings, ",") + "]"
			}

			// Print detailed security info in verbose mode
			if f.verbose && sr.RiskScore >= 5 {
				fmt.Println()
				f.printSecurityDetails(sr)
			}
		}
	}

	fmt.Println(line)
	return nil
}

// printSecurityDetails prints detailed security report
func (f *ConsoleFormatter) printSecurityDetails(sr *models.SecurityReport) {
	fmt.Println("  ┌─────────────────────────────────────────────────────────┐")
	fmt.Printf("  │ SECURITY REPORT - Risk: %s (%d/10)\n", sr.RiskRating, sr.RiskScore)
	fmt.Println("  ├─────────────────────────────────────────────────────────┤")

	if !sr.AuthEnabled {
		fmt.Println("  │ ⚠️  NO AUTHENTICATION - Anyone can access this instance")
	}

	if sr.ToolCallingEnabled {
		fmt.Printf("  │ ⚠️  TOOL-CALLING ENABLED (%d models) - Can execute code!\n", len(sr.ToolCallingModels))
	}

	if sr.MCPEnabled {
		fmt.Printf("  │ ⚠️  MCP ENABLED - Can access Kubernetes/cloud/shell\n")
	}

	if len(sr.UncensoredModels) > 0 {
		fmt.Printf("  │ ⚠️  UNCENSORED MODELS: %s\n", strings.Join(sr.UncensoredModels, ", "))
	}

	if len(sr.Vulnerabilities) > 0 {
		fmt.Println("  │ 🚨 CVEs DETECTED:")
		for _, cve := range sr.Vulnerabilities {
			fmt.Printf("  │    - %s [%s] %s\n", cve.ID, cve.Severity, cve.Description)
		}
	}

	criticalEndpoints := []string{}
	for _, ep := range sr.ExposedEndpoints {
		if ep.Accessible && ep.RiskLevel == "CRITICAL" {
			criticalEndpoints = append(criticalEndpoints, ep.Path)
		}
	}
	if len(criticalEndpoints) > 0 {
		fmt.Printf("  │ 🔓 Critical endpoints without auth: %s\n", strings.Join(criticalEndpoints, ", "))
	}

	fmt.Println("  └─────────────────────────────────────────────────────────┘")
}

// Flush is a no-op for console
func (f *ConsoleFormatter) Flush() error {
	return nil
}

// Close is a no-op for console
func (f *ConsoleFormatter) Close() error {
	return nil
}

// SimpleProgressReporter shows simple progress
type SimpleProgressReporter struct {
	total     int64
	current   int64
	startTime time.Time
	lastUpdate time.Time
}

// NewSimpleProgressReporter creates a simple progress reporter
func NewSimpleProgressReporter(total int64) *SimpleProgressReporter {
	return &SimpleProgressReporter{
		total:      total,
		startTime:  time.Now(),
		lastUpdate: time.Now(),
	}
}

// UpdateProgress updates progress display
func (r *SimpleProgressReporter) UpdateProgress(progress models.Progress) {
	r.current = progress.Processed
	
	// Throttle updates to every 500ms
	if time.Since(r.lastUpdate) < 500*time.Millisecond {
		return
	}
	r.lastUpdate = time.Now()

	percent := float64(r.current) * 100 / float64(r.total)
	elapsed := time.Since(r.startTime)

	var eta time.Duration
	if r.current > 0 {
		rate := float64(r.current) / elapsed.Seconds()
		if rate > 0 {
			remaining := float64(r.total-r.current) / rate
			eta = time.Duration(remaining) * time.Second
		}
	}

	// Simple progress line
	fmt.Printf("\r[%6.2f%%] %d/%d | Open: %d | Ollama: %d | ETA: %v",
		percent, r.current, r.total, progress.OpenHosts, progress.OllamaHosts, eta)
}

// Finish shows final stats
func (r *SimpleProgressReporter) Finish(finalStats models.Progress) {
	fmt.Println() // New line after progress bar
	fmt.Println(stringsRepeat("=", 60))
	fmt.Printf("Scan Summary:\n")
	fmt.Printf("  Total hosts scanned: %d\n", finalStats.Processed)
	fmt.Printf("  Open ports found: %d\n", finalStats.OpenHosts)
	fmt.Printf("  Ollama instances: %d\n", finalStats.OllamaHosts)
	fmt.Printf("  Total time: %v\n", finalStats.Elapsed)
	fmt.Println(stringsRepeat("=", 60))
}

// Helper function
func stringsRepeat(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
