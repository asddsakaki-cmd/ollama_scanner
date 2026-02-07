# Modern Go CLI Patterns 2026

## Executive Summary

Rekomendasi stack untuk Network Scanner CLI di 2026:

| Component | Recommendation | Alternative |
|-----------|---------------|-------------|
| CLI Framework | **Cobra** | urfave/cli (simpler tools) |
| Configuration | **Koanf** | Viper (Cobra integration) |
| Output Formatting | **charmbracelet/lipgloss** + **charmbracelet/bubbles** | pterm |
| Progress Bars | **charmbracelet/bubbles/progress** | mpb (multi-bar) |
| Logging | **slog** (std lib) | zap (high perf) |
| Error Handling | **fmt.Errorf + %w** | errors.Join (Go 1.20+) |
| Graceful Shutdown | **signal.NotifyContext** | Manual signal handling |

---

## 1. CLI Framework

### 1.1 Cobra vs urfave/cli vs stdlib flag (2026 Verdict)

**🏆 Winner: Cobra untuk tools kompleks**

| Aspect | Cobra | urfave/cli | stdlib flag |
|--------|-------|------------|-------------|
| Ecosystem | ⭐⭐⭐ Excellent | ⭐⭐ Good | ⭐ Basic |
| Viper Integration | Native | Via altsrc | Manual |
| Shell Completion | Auto-generated | Manual | N/A |
| Learning Curve | Moderate | Low | Low |
| Binary Size | Larger | Medium | Smallest |
| Subcommands | Native | Native | Manual |

**Kapan menggunakan masing-masing:**
- **Cobra**: Multi-command tools (kubectl, docker style), butuh shell completion, integration dengan Viper/Koanf
- **urfave/cli**: Single or few commands, quick prototypes, smaller footprint
- **stdlib flag**: Minimal tools, learning purposes, zero dependencies

**Modern Pattern dengan Cobra (2026):**

```go
package cmd

import (
    "context"
    "fmt"
    "os"
    "os/signal"
    "syscall"

    "github.com/spf13/cobra"
    "github.com/knadh/koanf/v2"
)

// Config holds all configuration
type Config struct {
    Target      string   `koanf:"target"`
    Ports       []int    `koanf:"ports"`
    Timeout     int      `koanf:"timeout"`
    Output      string   `koanf:"output"`
    Verbose     bool     `koanf:"verbose"`
    Concurrency int      `koanf:"concurrency"`
}

var (
    cfg = &Config{}
    k   = koanf.New(":")
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
    Use:   "scanner [target]",
    Short: "A modern network scanner",
    Long: `A fast, configurable network scanner with rich output.
    
Examples:
  scanner 192.168.1.1
  scanner 192.168.1.0/24 --ports 22,80,443
  scanner example.com --output json`,
    Args: cobra.ExactArgs(1),
    RunE: runScan,
}

func init() {
    // Persistent flags (available to all subcommands)
    rootCmd.PersistentFlags().StringSliceP("ports", "p", []string{"22", "80", "443"}, "ports to scan")
    rootCmd.PersistentFlags().IntP("timeout", "t", 5, "timeout in seconds")
    rootCmd.PersistentFlags().StringP("output", "o", "table", "output format (table, json, csv)")
    rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
    rootCmd.PersistentFlags().IntP("concurrency", "c", 100, "concurrent workers")
    
    // Bind flags to koanf
    _ = k.BindPFlags(rootCmd.PersistentFlags())
}

func runScan(cmd *cobra.Command, args []string) error {
    cfg.Target = args[0]
    
    // Unmarshal to struct
    if err := k.Unmarshal("", cfg); err != nil {
        return fmt.Errorf("failed to parse config: %w", err)
    }
    
    // Setup context with graceful shutdown
    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()
    
    return executeScan(ctx, cfg)
}

func executeScan(ctx context.Context, cfg *Config) error {
    // Implementation here
    return nil
}

func Execute() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
```

### 1.2 Pattern untuk Subcommands

```go
// scan.go - Port scanning subcommand
var scanCmd = &cobra.Command{
    Use:   "scan [target]",
    Short: "Scan ports on target",
    Example: `  scanner scan 192.168.1.1
  scanner scan 10.0.0.0/24 -p 1-65535 -o json`,
    Args: cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        // Scan implementation
        return nil
    },
}

// audit.go - Security audit subcommand
var auditCmd = &cobra.Command{
    Use:   "audit [target]",
    Short: "Run security audit on target",
    RunE: func(cmd *cobra.Command, args []string) error {
        // Audit implementation
        return nil
    },
}

// benchmark.go - Performance benchmark subcommand
var benchmarkCmd = &cobra.Command{
    Use:   "benchmark [target]",
    Short: "Benchmark scan performance",
    RunE: func(cmd *cobra.Command, args []string) error {
        // Benchmark implementation
        return nil
    },
}

func init() {
    rootCmd.AddCommand(scanCmd)
    rootCmd.AddCommand(auditCmd)
    rootCmd.AddCommand(benchmarkCmd)
}
```

---

## 2. Configuration Priority

### 2.1 Best Practice: Defaults < Config File < Env Vars < CLI Flags

**🏆 Winner: Koanf (2026)**

Alasan memilih Koanf vs Viper:
- **Koanf**: Lebih modular, lebih cepat, tidak bloat, type-safe
- **Viper**: Integration lebih seamless dengan Cobra, tapi lebih berat

```go
package config

import (
    "fmt"
    "strings"

    "github.com/knadh/koanf/parsers/yaml"
    "github.com/knadh/koanf/providers/confmap"
    "github.com/knadh/koanf/providers/env"
    "github.com/knadh/koanf/providers/file"
    "github.com/knadh/koanf/providers/structs"
    "github.com/knadh/koanf/v2"
)

// Provider priority (highest to lowest):
// 1. CLI Flags (passed via Set())
// 2. Environment Variables
// 3. Config Files
// 4. Default Values

type Config struct {
    Server struct {
        Host string `koanf:"host"`
        Port int    `koanf:"port"`
    } `koanf:"server"`
    
    Scan struct {
        Timeout     int    `koanf:"timeout"`
        Concurrency int    `koanf:"concurrency"`
        Ports       []int  `koanf:"ports"`
    } `koanf:"scan"`
    
    Output struct {
        Format   string `koanf:"format"`
        File     string `koanf:"file"`
        Color    bool   `koanf:"color"`
    } `koanf:"output"`
}

func DefaultConfig() Config {
    var c Config
    c.Server.Host = "0.0.0.0"
    c.Server.Port = 8080
    c.Scan.Timeout = 5
    c.Scan.Concurrency = 100
    c.Scan.Ports = []int{22, 80, 443}
    c.Output.Format = "table"
    c.Output.Color = true
    return c
}

func Load(configPath string, flags map[string]interface{}) (*Config, error) {
    k := koanf.New(":")
    
    // 1. Load defaults
    if err := k.Load(structs.Provider(DefaultConfig(), "koanf"), nil); err != nil {
        return nil, fmt.Errorf("loading defaults: %w", err)
    }
    
    // 2. Load config file (if exists)
    if configPath != "" {
        if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
            // File not found is OK for defaults
            if !strings.Contains(err.Error(), "no such file") {
                return nil, fmt.Errorf("loading config file: %w", err)
            }
        }
    }
    
    // 3. Load environment variables
    // SCANNERSERVER_HOST, SCANNERSERVER_PORT, etc.
    if err := k.Load(env.Provider("SCANNER", ":", func(s string) string {
        return strings.ToLower(strings.ReplaceAll(s, "_", "."))
    }), nil); err != nil {
        return nil, fmt.Errorf("loading env vars: %w", err)
    }
    
    // 4. Load CLI flags (highest priority)
    if len(flags) > 0 {
        if err := k.Load(confmap.Provider(flags, ":"), nil); err != nil {
            return nil, fmt.Errorf("loading flags: %w", err)
        }
    }
    
    var cfg Config
    if err := k.Unmarshal("", &cfg); err != nil {
        return nil, fmt.Errorf("unmarshaling config: %w", err)
    }
    
    return &cfg, nil
}
```

### 2.2 Environment Variable Pattern

```go
// .env.example
SCANNER_SERVER_HOST=0.0.0.0
SCANNER_SERVER_PORT=8080
SCANNER_SCAN_TIMEOUT=10
SCANNER_SCAN_CONCURRENCY=200
SCANNER_OUTPUT_FORMAT=json
SCANNER_OUTPUT_COLOR=true

// Loading dengan custom env prefix
func loadWithPrefix(k *koanf.Koanf, prefix string) error {
    return k.Load(env.Provider(prefix, ":", func(s string) string {
        // SCANNERSERVER_HOST -> server.host
        s = strings.TrimPrefix(s, prefix)
        s = strings.ToLower(s)
        return strings.ReplaceAll(s, "_", ".")
    }), nil)
}
```

---

## 3. Output Formatting

### 3.1 Modern Table Formatting (2026)

**🏆 Winner: charmbracelet/lipgloss + table subpackage**

```go
package output

import (
    "encoding/csv"
    "encoding/json"
    "fmt"
    "io"

    "github.com/charmbracelet/lipgloss"
    "github.com/charmbracelet/lipgloss/table"
)

// ScanResult represents a single scan result
type ScanResult struct {
    Host     string `json:"host" csv:"host"`
    Port     int    `json:"port" csv:"port"`
    Protocol string `json:"protocol" csv:"protocol"`
    State    string `json:"state" csv:"state"`
    Service  string `json:"service" csv:"service"`
    Version  string `json:"version,omitempty" csv:"version"`
    Latency  string `json:"latency" csv:"latency"`
}

// Formatter handles output formatting
type Formatter struct {
    format string
    color  bool
    writer io.Writer
}

func NewFormatter(format string, color bool, w io.Writer) *Formatter {
    return &Formatter{
        format: format,
        color:  color,
        writer: w,
    }
}

func (f *Formatter) Format(results []ScanResult) error {
    switch f.format {
    case "json":
        return f.formatJSON(results)
    case "csv":
        return f.formatCSV(results)
    case "table":
        return f.formatTable(results)
    default:
        return fmt.Errorf("unknown format: %s", f.format)
    }
}

func (f *Formatter) formatJSON(results []ScanResult) error {
    encoder := json.NewEncoder(f.writer)
    encoder.SetIndent("", "  ")
    return encoder.Encode(results)
}

func (f *Formatter) formatCSV(results []ScanResult) error {
    if len(results) == 0 {
        return nil
    }
    
    writer := csv.NewWriter(f.writer)
    defer writer.Flush()
    
    // Header
    headers := []string{"Host", "Port", "Protocol", "State", "Service", "Version", "Latency"}
    if err := writer.Write(headers); err != nil {
        return err
    }
    
    // Rows
    for _, r := range results {
        row := []string{
            r.Host,
            fmt.Sprintf("%d", r.Port),
            r.Protocol,
            r.State,
            r.Service,
            r.Version,
            r.Latency,
        }
        if err := writer.Write(row); err != nil {
            return err
        }
    }
    
    return nil
}

func (f *Formatter) formatTable(results []ScanResult) error {
    if len(results) == 0 {
        fmt.Fprintln(f.writer, "No results found")
        return nil
    }
    
    // Define styles
    headerStyle := lipgloss.NewStyle().
        Bold(true).
        Foreground(lipgloss.Color("#FAFAFA")).
        Background(lipgloss.Color("#7D56F4")).
        Padding(0, 1)
    
    cellStyle := lipgloss.NewStyle().Padding(0, 1)
    
    openStyle := cellStyle.Foreground(lipgloss.Color("#04B575"))  // Green
    closedStyle := cellStyle.Foreground(lipgloss.Color("#FF6B6B")) // Red
    filteredStyle := cellStyle.Foreground(lipgloss.Color("#FFD93D")) // Yellow
    
    // Build rows
    rows := [][]string{}
    for _, r := range results {
        rows = append(rows, []string{
            r.Host,
            fmt.Sprintf("%d", r.Port),
            r.Protocol,
            r.State,
            r.Service,
            r.Version,
            r.Latency,
        })
    }
    
    // Style function for row colors
    styleFunc := func(row, col int) lipgloss.Style {
        if row == 0 {
            return headerStyle
        }
        
        if !f.color {
            return cellStyle
        }
        
        // Color by state (column 3)
        if col == 3 {
            state := rows[row-1][3]
            switch state {
            case "open":
                return openStyle
            case "closed":
                return closedStyle
            case "filtered":
                return filteredStyle
            }
        }
        return cellStyle
    }
    
    t := table.New().
        Border(lipgloss.NormalBorder()).
        BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))).
        Headers("HOST", "PORT", "PROTO", "STATE", "SERVICE", "VERSION", "LATENCY").
        Rows(rows...).
        StyleFunc(styleFunc)
    
    fmt.Fprintln(f.writer, t.Render())
    fmt.Fprintf(f.writer, "\nTotal: %d hosts scanned\n", len(results))
    
    return nil
}
```

### 3.2 Modern Progress Bars

**🏆 Winner: charmbracelet/bubbles/progress**

```go
package ui

import (
    "fmt"
    "os"
    "strings"

    "github.com/charmbracelet/bubbles/progress"
    "github.com/charmbracelet/bubbles/spinner"
    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/lipgloss"
)

// ProgressModel is a Bubble Tea model for scan progress
type ProgressModel struct {
    progress   progress.Model
    spinner    spinner.Model
    total      int
    completed  int
    currentHost string
    results    []string
    done       bool
}

func NewProgressModel(total int) ProgressModel {
    p := progress.New(
        progress.WithDefaultGradient(),
        progress.WithWidth(40),
    )
    
    s := spinner.New()
    s.Spinner = spinner.Dot
    s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))
    
    return ProgressModel{
        progress: p,
        spinner:  s,
        total:    total,
    }
}

func (m ProgressModel) Init() tea.Cmd {
    return tea.Batch(m.spinner.Tick, m.tickCmd())
}

type tickMsg struct{}

func (m ProgressModel) tickCmd() tea.Cmd {
    return nil // Replace with actual scan command
}

type scanResultMsg struct {
    host   string
    status string
}

func (m ProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg := msg.(type) {
    case tea.KeyMsg:
        if msg.String() == "q" || msg.String() == "ctrl+c" {
            return m, tea.Quit
        }
        
    case tea.WindowSizeMsg:
        m.progress.Width = msg.Width - 20
        
    case tickMsg:
        // Update progress
        m.completed++
        if m.completed >= m.total {
            m.done = true
            return m, tea.Quit
        }
        return m, m.tickCmd()
        
    case scanResultMsg:
        m.currentHost = msg.host
        m.results = append(m.results, fmt.Sprintf("%s: %s", msg.host, msg.status))
        
    case spinner.TickMsg:
        var cmd tea.Cmd
        m.spinner, cmd = m.spinner.Update(msg)
        return m, cmd
        
    case progress.FrameMsg:
        progressModel, cmd := m.progress.Update(msg)
        m.progress = progressModel.(progress.Model)
        return m, cmd
    }
    
    return m, nil
}

func (m ProgressModel) View() string {
    if m.done {
        return fmt.Sprintf("\n✓ Scan complete! %d/%d hosts scanned\n", m.completed, m.total)
    }
    
    percent := float64(m.completed) / float64(m.total)
    
    var b strings.Builder
    b.WriteString("\n")
    b.WriteString(m.spinner.View())
    b.WriteString(fmt.Sprintf(" Scanning: %s\n\n", m.currentHost))
    b.WriteString(m.progress.ViewAs(percent))
    b.WriteString(fmt.Sprintf("\n\n%d/%d (%.0f%%)\n", m.completed, m.total, percent*100))
    
    // Show last 3 results
    if len(m.results) > 0 {
        b.WriteString("\nRecent results:\n")
        start := len(m.results) - 3
        if start < 0 {
            start = 0
        }
        for _, r := range m.results[start:] {
            b.WriteString(fmt.Sprintf("  • %s\n", r))
        }
    }
    
    b.WriteString("\nPress 'q' to quit\n")
    
    return b.String()
}

// SimpleProgress is a simpler progress for non-TUI mode
type SimpleProgress struct {
    total     int
    completed int
    width     int
}

func NewSimpleProgress(total int) *SimpleProgress {
    return &SimpleProgress{
        total: total,
        width: 40,
    }
}

func (p *SimpleProgress) Update(current int) {
    p.completed = current
    percent := float64(p.completed) / float64(p.total)
    filled := int(percent * float64(p.width))
    
    bar := strings.Repeat("█", filled) + strings.Repeat("░", p.width-filled)
    fmt.Printf("\r[%s] %d/%d (%.0f%%)", bar, p.completed, p.total, percent*100)
    
    if p.completed >= p.total {
        fmt.Println() // New line when done
    }
}

func (p *SimpleProgress) Finish() {
    fmt.Printf("\r[%s] %d/%d (100%%) ✓\n", 
        strings.Repeat("█", p.width), p.total, p.total)
}
```

---

## 4. Logging

### 4.1 Structured Logging (2026 Verdict)

**🏆 Winner: slog (standard library)**

| Feature | slog | zap | logrus |
|---------|------|-----|--------|
| Performance | Good | ⭐ Best | Slower |
| Std Library | ✅ Yes | No | No |
| JSON Output | Native | Native | Plugin |
| Context Support | Native | Manual | Manual |
| Allocation | Moderate | Low | Higher |

**Rekomendasi**: Gunakan **slog** untuk semua project baru. Gunakan **zap** hanya jika butuh throughput logging yang ekstrem.

```go
package logger

import (
    "context"
    "io"
    "log/slog"
    "os"
    "path/filepath"
    "runtime"
    "time"

    "gopkg.in/natefinch/lumberjack.v2"
)

// Config holds logger configuration
type Config struct {
    Level       string
    Format      string // "json" or "text"
    Output      string // "stdout", "stderr", or file path
    AddSource   bool
    Rotate      bool
    MaxSize     int  // MB
    MaxBackups  int
    MaxAge      int  // days
}

func DefaultConfig() Config {
    return Config{
        Level:      "info",
        Format:     "json",
        Output:     "stdout",
        AddSource:  false,
        Rotate:     true,
        MaxSize:    100,
        MaxBackups: 3,
        MaxAge:     7,
    }
}

// New creates a new slog.Logger
func New(cfg Config) *slog.Logger {
    level := parseLevel(cfg.Level)
    
    opts := &slog.HandlerOptions{
        Level:     level,
        AddSource: cfg.AddSource,
        ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
            // Custom time format
            if a.Key == slog.TimeKey {
                if t, ok := a.Value.Any().(time.Time); ok {
                    return slog.Attr{
                        Key:   slog.TimeKey,
                        Value: slog.StringValue(t.Format(time.RFC3339)),
                    }
                }
            }
            return a
        },
    }
    
    var handler slog.Handler
    var output io.Writer = os.Stdout
    
    // Setup output
    switch cfg.Output {
    case "stdout":
        output = os.Stdout
    case "stderr":
        output = os.Stderr
    case "":
        output = os.Stdout
    default:
        // File output with optional rotation
        if cfg.Rotate {
            output = &lumberjack.Logger{
                Filename:   cfg.Output,
                MaxSize:    cfg.MaxSize,    // megabytes
                MaxBackups: cfg.MaxBackups,
                MaxAge:     cfg.MaxAge,     // days
                Compress:   true,
            }
        } else {
            f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
            if err != nil {
                // Fall back to stdout on error
                output = os.Stdout
            } else {
                output = f
            }
        }
    }
    
    // Create handler based on format
    if cfg.Format == "json" {
        handler = slog.NewJSONHandler(output, opts)
    } else {
        handler = slog.NewTextHandler(output, opts)
    }
    
    return slog.New(handler)
}

// NewWithContext creates a logger that extracts values from context
func NewWithContext(cfg Config) *slog.Logger {
    base := New(cfg)
    return slog.New(&contextHandler{base.Handler()})
}

// contextHandler wraps a handler to extract context values
type contextHandler struct {
    slog.Handler
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
    // Add correlation ID from context if present
    if cid, ok := ctx.Value("correlation_id").(string); ok {
        r.AddAttrs(slog.String("correlation_id", cid))
    }
    
    // Add trace ID if present (OpenTelemetry)
    if traceID, ok := ctx.Value("trace_id").(string); ok {
        r.AddAttrs(slog.String("trace_id", traceID))
    }
    
    return h.Handler.Handle(ctx, r)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
    return &contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
    return &contextHandler{h.Handler.WithGroup(name)}
}

func parseLevel(s string) slog.Level {
    switch s {
    case "debug":
        return slog.LevelDebug
    case "info":
        return slog.LevelInfo
    case "warn":
        return slog.LevelWarn
    case "error":
        return slog.LevelError
    default:
        return slog.LevelInfo
    }
}

// Helper functions
func Err(err error) slog.Attr {
    return slog.String("error", err.Error())
}

func Duration(key string, d time.Duration) slog.Attr {
    return slog.String(key, d.String())
}

// Source returns the source location of the caller
func Source() slog.Attr {
    _, file, line, ok := runtime.Caller(2)
    if !ok {
        return slog.String("source", "unknown")
    }
    return slog.String("source", fmt.Sprintf("%s:%d", filepath.Base(file), line))
}
```

### 4.2 Log Levels dan Rotation

```go
// Usage example
func main() {
    cfg := logger.Config{
        Level:      os.Getenv("LOG_LEVEL"),
        Format:     "json",
        Output:     "/var/log/scanner/app.log",
        AddSource:  true,
        Rotate:     true,
        MaxSize:    100,
        MaxBackups: 5,
        MaxAge:     30,
    }
    
    log := logger.New(cfg)
    slog.SetDefault(log)
    
    // Basic logging
    slog.Info("scanner started",
        slog.String("version", "2.0.0"),
        slog.Int("workers", 100),
    )
    
    // Error logging with context
    if err := doSomething(); err != nil {
        slog.Error("operation failed",
            logger.Err(err),
            slog.String("operation", "scan"),
            logger.Source(),
        )
    }
    
    // Debug with expensive computation guard
    if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
        slog.Debug("detailed state",
            slog.Any("state", getExpensiveState()),
        )
    }
}
```

---

## 5. Error Handling

### 5.1 Error Wrapping dan Propagation (2026 Best Practice)

```go
package errors

import (
    "errors"
    "fmt"
)

// Sentinel errors untuk kondisi umum
var (
    ErrInvalidTarget   = errors.New("invalid target specified")
    ErrTimeout         = errors.New("operation timed out")
    ErrConnectionRefused = errors.New("connection refused")
    ErrPermissionDenied  = errors.New("permission denied")
    ErrScanInterrupted   = errors.New("scan interrupted")
)

// ScanError adalah custom error untuk hasil scan
type ScanError struct {
    Host    string
    Port    int
    Op      string
    Cause   error
}

func (e *ScanError) Error() string {
    return fmt.Sprintf("scan %s on %s:%d failed: %v", e.Op, e.Host, e.Port, e.Cause)
}

func (e *ScanError) Unwrap() error {
    return e.Cause
}

// ValidationError untuk error validasi input
type ValidationError struct {
    Field   string
    Value   interface{}
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation failed for field %q: %s (got: %v)", 
        e.Field, e.Message, e.Value)
}

// AggregateError untuk menggabungkan multiple errors (Go 1.20+)
type AggregateError struct {
    Errors []error
}

func (e *AggregateError) Error() string {
    if len(e.Errors) == 0 {
        return "no errors"
    }
    if len(e.Errors) == 1 {
        return e.Errors[0].Error()
    }
    return fmt.Sprintf("%d errors occurred: %v", len(e.Errors), e.Errors)
}

func (e *AggregateError) Unwrap() []error {
    return e.Errors
}

// Helper functions

// Wrap menambahkan context ke error
func Wrap(err error, context string) error {
    if err == nil {
        return nil
    }
    return fmt.Errorf("%s: %w", context, err)
}

// Wrapf menambahkan context dengan format
func Wrapf(err error, format string, args ...interface{}) error {
    if err == nil {
        return nil
    }
    return fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), err)
}

// Is checks if error matches target (supports wrapping)
var Is = errors.Is

// As extracts error of specific type (supports wrapping)
var As = errors.As

// Join multiple errors (Go 1.20+)
var Join = errors.Join

// Must panics if error is not nil
func Must(err error) {
    if err != nil {
        panic(err)
    }
}
```

### 5.2 User-Friendly Error Messages

```go
package errors

import (
    "fmt"
    "strings"
)

// UserError adalah error yang ditampilkan ke user
type UserError struct {
    Code    string
    Title   string
    Message string
    Suggest string
    Cause   error
}

func (e *UserError) Error() string {
    var parts []string
    
    if e.Code != "" {
        parts = append(parts, fmt.Sprintf("[%s]", e.Code))
    }
    
    if e.Title != "" {
        parts = append(parts, e.Title)
    } else {
        parts = append(parts, "Error")
    }
    
    parts = append(parts, ": ")
    parts = append(parts, e.Message)
    
    if e.Suggest != "" {
        parts = append(parts, fmt.Sprintf("\n\nSuggestion: %s", e.Suggest))
    }
    
    if e.Cause != nil {
        parts = append(parts, fmt.Sprintf("\n\nTechnical details: %v", e.Cause))
    }
    
    return strings.Join(parts, "")
}

func (e *UserError) Unwrap() error {
    return e.Cause
}

// Helper untuk membuat user-friendly errors
func NewUserError(code, message string) *UserError {
    return &UserError{
        Code:    code,
        Message: message,
    }
}

func NewUserErrorWithSuggest(code, message, suggest string) *UserError {
    return &UserError{
        Code:    code,
        Message: message,
        Suggest: suggest,
    }
}

// Predefined user errors untuk common scenarios
func InvalidTargetError(target string, cause error) *UserError {
    return &UserError{
        Code:    "E001",
        Title:   "Invalid Target",
        Message: fmt.Sprintf("The target %q is not valid", target),
        Suggest: "Please provide a valid IP address (e.g., 192.168.1.1) or hostname (e.g., example.com)",
        Cause:   cause,
    }
}

func PermissionError(operation string, cause error) *UserError {
    return &UserError{
        Code:    "E002",
        Title:   "Permission Denied",
        Message: fmt.Sprintf("Unable to %s: permission denied", operation),
        Suggest: "Try running with elevated privileges (sudo) or check file permissions",
        Cause:   cause,
    }
}

func TimeoutError(operation string, duration interface{}, cause error) *UserError {
    return &UserError{
        Code:    "E003",
        Title:   "Operation Timeout",
        Message: fmt.Sprintf("%s timed out after %v", operation, duration),
        Suggest: "Try increasing the timeout with --timeout flag or check network connectivity",
        Cause:   cause,
    }
}

func NetworkError(host string, cause error) *UserError {
    return &UserError{
        Code:    "E004",
        Title:   "Network Error",
        Message: fmt.Sprintf("Unable to reach %s", host),
        Suggest: "Check your network connection and ensure the target is reachable",
        Cause:   cause,
    }
}
```

---

## 6. Graceful Shutdown

### 6.1 Signal Handling (2026 Pattern)

**🏆 Winner: signal.NotifyContext**

```go
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

// ShutdownFunc is a function that performs cleanup
type ShutdownFunc func(ctx context.Context) error

// Manager handles graceful shutdown
type Manager struct {
    timeout      time.Duration
    shutdownFns  []ShutdownFunc
    mu           sync.Mutex
    isShuttingDown bool
}

// NewManager creates a new shutdown manager
func NewManager(timeout time.Duration) *Manager {
    return &Manager{
        timeout:     timeout,
        shutdownFns: make([]ShutdownFunc, 0),
    }
}

// Register adds a shutdown function
func (m *Manager) Register(fn ShutdownFunc) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.shutdownFns = append(m.shutdownFns, fn)
}

// RegisterCloser registers an io.Closer
func (m *Manager) RegisterCloser(name string, closer interface{ Close() error }) {
    m.Register(func(ctx context.Context) error {
        done := make(chan error, 1)
        go func() {
            done <- closer.Close()
        }()
        
        select {
        case err := <-done:
            if err != nil {
                return fmt.Errorf("closing %s: %w", name, err)
            }
            slog.Info("closed resource", slog.String("name", name))
            return nil
        case <-ctx.Done():
            return fmt.Errorf("timeout closing %s: %w", name, ctx.Err())
        }
    })
}

// Shutdown executes all registered shutdown functions
func (m *Manager) Shutdown(ctx context.Context) error {
    m.mu.Lock()
    if m.isShuttingDown {
        m.mu.Unlock()
        return fmt.Errorf("shutdown already in progress")
    }
    m.isShuttingDown = true
    fns := make([]ShutdownFunc, len(m.shutdownFns))
    copy(fns, m.shutdownFns)
    m.mu.Unlock()
    
    // Execute in reverse order (LIFO)
    var errs []error
    for i := len(fns) - 1; i >= 0; i-- {
        if err := fns[i](ctx); err != nil {
            errs = append(errs, err)
        }
    }
    
    if len(errs) > 0 {
        return fmt.Errorf("shutdown errors: %v", errs)
    }
    return nil
}

// Run starts the application and waits for shutdown signal
func (m *Manager) Run(appFunc func(ctx context.Context) error) error {
    // Create signal context
    ctx, stop := signal.NotifyContext(
        context.Background(),
        syscall.SIGINT,
        syscall.SIGTERM,
    )
    defer stop()
    
    // Channel for app result
    appDone := make(chan error, 1)
    
    // Start application
    go func() {
        appDone <- appFunc(ctx)
    }()
    
    // Wait for signal or app completion
    select {
    case err := <-appDone:
        // App finished normally
        if err != nil {
            slog.Error("application error", slog.String("error", err.Error()))
        }
        
    case <-ctx.Done():
        // Signal received
        slog.Info("shutdown signal received, starting graceful shutdown...")
    }
    
    // Stop signal handling to allow force exit on second signal
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
```

### 6.2 Context Cancellation Patterns

```go
package graceful

import (
    "context"
    "sync"
    "time"
)

// WorkerPool manages a pool of workers with graceful shutdown
type WorkerPool struct {
    workers   int
    wg        sync.WaitGroup
    tasks     chan func(context.Context)
    ctx       context.Context
    cancel    context.CancelFunc
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workers, queueSize int) *WorkerPool {
    ctx, cancel := context.WithCancel(context.Background())
    return &WorkerPool{
        workers: workers,
        tasks:   make(chan func(context.Context), queueSize),
        ctx:     ctx,
        cancel:  cancel,
    }
}

// Start initializes the worker goroutines
func (p *WorkerPool) Start() {
    for i := 0; i < p.workers; i++ {
        p.wg.Add(1)
        go p.worker(i)
    }
}

func (p *WorkerPool) worker(id int) {
    defer p.wg.Done()
    
    for {
        select {
        case <-p.ctx.Done():
            // Drain remaining tasks
            for task := range p.tasks {
                task(p.ctx)
            }
            return
            
        case task, ok := <-p.tasks:
            if !ok {
                return
            }
            task(p.ctx)
        }
    }
}

// Submit adds a task to the queue
func (p *WorkerPool) Submit(task func(context.Context)) bool {
    select {
    case p.tasks <- task:
        return true
    case <-p.ctx.Done():
        return false
    default:
        // Queue full
        return false
    }
}

// Stop gracefully shuts down the pool
func (p *WorkerPool) Stop(timeout time.Duration) {
    p.cancel()
    
    done := make(chan struct{})
    go func() {
        p.wg.Wait()
        close(done)
    }()
    
    select {
    case <-done:
        // All workers finished
    case <-time.After(timeout):
        // Timeout - workers will exit on ctx.Done() check
    }
    
    close(p.tasks)
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

// Context-aware ticker
type Ticker struct {
    C      <-chan time.Time
    ticker *time.Ticker
    stop   chan struct{}
}

func NewTicker(ctx context.Context, d time.Duration) *Ticker {
    t := time.NewTicker(d)
    stop := make(chan struct{})
    
    go func() {
        select {
        case <-ctx.Done():
            t.Stop()
        case <-stop:
            t.Stop()
        }
    }()
    
    return &Ticker{
        C:      t.C,
        ticker: t,
        stop:   stop,
    }
}

func (t *Ticker) Stop() {
    close(t.stop)
}
```

### 6.3 State Persistence (Resume Capability)

```go
package graceful

import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "time"
)

// State represents the application state for resumption
type State struct {
    Version   string                 `json:"version"`
    Timestamp time.Time              `json:"timestamp"`
    Progress  ScanProgress           `json:"progress"`
    Results   []ScanResult           `json:"results"`
    Metadata  map[string]interface{} `json:"metadata"`
}

// ScanProgress tracks scan progress
type ScanProgress struct {
    TotalHosts     int      `json:"total_hosts"`
    CompletedHosts int      `json:"completed_hosts"`
    CurrentHost    string   `json:"current_host"`
    PendingHosts   []string `json:"pending_hosts"`
    ScannedPorts   []int    `json:"scanned_ports"`
}

// ScanResult is a single scan result
type ScanResult struct {
    Host   string `json:"host"`
    Port   int    `json:"port"`
    Status string `json:"status"`
}

// StateManager handles state persistence
type StateManager struct {
    stateFile string
    mu        sync.RWMutex
    state     State
}

// NewStateManager creates a new state manager
func NewStateManager(stateDir string) *StateManager {
    return &StateManager{
        stateFile: filepath.Join(stateDir, "scanner.state.json"),
        state: State{
            Metadata: make(map[string]interface{}),
        },
    }
}

// Load loads the state from disk
func (sm *StateManager) Load() error {
    sm.mu.Lock()
    defer sm.mu.Unlock()
    
    data, err := os.ReadFile(sm.stateFile)
    if err != nil {
        if os.IsNotExist(err) {
            return nil // No previous state
        }
        return fmt.Errorf("reading state file: %w", err)
    }
    
    if err := json.Unmarshal(data, &sm.state); err != nil {
        return fmt.Errorf("parsing state file: %w", err)
    }
    
    return nil
}

// Save saves the state to disk
func (sm *StateManager) Save() error {
    sm.mu.RLock()
    state := sm.state
    sm.mu.RUnlock()
    
    state.Timestamp = time.Now()
    
    // Ensure directory exists
    dir := filepath.Dir(sm.stateFile)
    if err := os.MkdirAll(dir, 0755); err != nil {
        return fmt.Errorf("creating state directory: %w", err)
    }
    
    // Write to temp file first, then rename (atomic)
    tmpFile := sm.stateFile + ".tmp"
    data, err := json.MarshalIndent(state, "", "  ")
    if err != nil {
        return fmt.Errorf("marshaling state: %w", err)
    }
    
    if err := os.WriteFile(tmpFile, data, 0644); err != nil {
        return fmt.Errorf("writing temp state file: %w", err)
    }
    
    if err := os.Rename(tmpFile, sm.stateFile); err != nil {
        return fmt.Errorf("renaming state file: %w", err)
    }
    
    return nil
}

// Update updates the state (thread-safe)
func (sm *StateManager) Update(fn func(*State)) {
    sm.mu.Lock()
    defer sm.mu.Unlock()
    fn(&sm.state)
}

// Get returns a copy of the current state
func (sm *StateManager) Get() State {
    sm.mu.RLock()
    defer sm.mu.RUnlock()
    return sm.state
}

// Clear removes the state file
func (sm *StateManager) Clear() error {
    sm.mu.Lock()
    defer sm.mu.Unlock()
    
    sm.state = State{
        Metadata: make(map[string]interface{}),
    }
    
    if err := os.Remove(sm.stateFile); err != nil && !os.IsNotExist(err) {
        return err
    }
    return nil
}

// CanResume checks if a previous scan can be resumed
func (sm *StateManager) CanResume() bool {
    sm.mu.RLock()
    defer sm.mu.RUnlock()
    
    // Check if state is less than 24 hours old
    if sm.state.Timestamp.IsZero() {
        return false
    }
    
    age := time.Since(sm.state.Timestamp)
    if age > 24*time.Hour {
        return false
    }
    
    // Check if there's pending work
    return len(sm.state.Progress.PendingHosts) > 0
}

// GetPendingHosts returns hosts that still need to be scanned
func (sm *StateManager) GetPendingHosts() []string {
    sm.mu.RLock()
    defer sm.mu.RUnlock()
    return sm.state.Progress.PendingHosts
}
```

---

## 7. Complete Example: Network Scanner CLI

```go
package main

import (
    "context"
    "fmt"
    "log/slog"
    "os"
    "time"

    "github.com/spf13/cobra"
    "github.com/knadh/koanf/v2"
)

// Config holds all configuration
type Config struct {
    Target      string   `koanf:"target"`
    Ports       []int    `koanf:"ports"`
    Timeout     int      `koanf:"timeout"`
    Output      string   `koanf:"output"`
    Verbose     bool     `koanf:"verbose"`
    Concurrency int      `koanf:"concurrency"`
    Resume      bool     `koanf:"resume"`
    StateDir    string   `koanf:"state_dir"`
}

func main() {
    var cfg Config
    var k = koanf.New(":")
    
    cmd := &cobra.Command{
        Use:   "scanner [target]",
        Short: "Modern network scanner",
        RunE: func(cmd *cobra.Command, args []string) error {
            cfg.Target = args[0]
            
            // Setup logger
            log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
                Level: func() slog.Level {
                    if cfg.Verbose {
                        return slog.LevelDebug
                    }
                    return slog.LevelInfo
                }(),
            }))
            slog.SetDefault(log)
            
            // Setup graceful shutdown
            shutdownMgr := graceful.NewManager(30 * time.Second)
            
            // Setup state manager
            stateMgr := graceful.NewStateManager(cfg.StateDir)
            if cfg.Resume {
                if err := stateMgr.Load(); err != nil {
                    return err
                }
            }
            
            // Register cleanup
            shutdownMgr.Register(func(ctx context.Context) error {
                return stateMgr.Save()
            })
            
            // Run
            return shutdownMgr.Run(func(ctx context.Context) error {
                return runScan(ctx, &cfg, stateMgr)
            })
        },
    }
    
    // Flags
    cmd.Flags().IntSliceP("ports", "p", []int{22, 80, 443}, "Ports to scan")
    cmd.Flags().IntP("timeout", "t", 5, "Timeout in seconds")
    cmd.Flags().StringP("output", "o", "table", "Output format (table, json, csv)")
    cmd.Flags().BoolP("verbose", "v", false, "Verbose output")
    cmd.Flags().IntP("concurrency", "c", 100, "Concurrent workers")
    cmd.Flags().BoolP("resume", "r", false, "Resume previous scan")
    cmd.Flags().String("state-dir", ".scanner", "State directory")
    
    if err := cmd.Execute(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func runScan(ctx context.Context, cfg *Config, stateMgr *graceful.StateManager) error {
    // Implementation...
    return nil
}
```

---

## 8. Dependencies (go.mod)

```go
module github.com/example/scanner

go 1.23

require (
    // CLI Framework
    github.com/spf13/cobra v1.8.1
    
    // Configuration
    github.com/knadh/koanf/v2 v2.1.1
    github.com/knadh/koanf/parsers/yaml v0.1.0
    github.com/knadh/koanf/providers/confmap v0.1.0
    github.com/knadh/koanf/providers/env v0.1.0
    github.com/knadh/koanf/providers/file v0.1.0
    github.com/knadh/koanf/providers/structs v0.1.0
    
    // Output Formatting
    github.com/charmbracelet/lipgloss v0.13.0
    github.com/charmbracelet/bubbles v0.20.0
    github.com/charmbracelet/bubbletea v1.1.0
    
    // Log rotation
    gopkg.in/natefinch/lumberjack.v2 v2.2.1
    
    // Testing
    github.com/stretchr/testify v1.9.0
)
```

---

## Summary

Stack rekomendasi untuk Network Scanner CLI modern di 2026:

1. **CLI**: Cobra untuk structure, subcommands, dan shell completion
2. **Config**: Koanf untuk type-safe, modular configuration management
3. **Output**: charmbracelet/lipgloss untuk styling, bubbles untuk progress/spinner
4. **Logging**: slog (std lib) untuk structured logging dengan JSON handler
5. **Errors**: fmt.Errorf dengan %w, errors.Join, dan custom error types
6. **Shutdown**: signal.NotifyContext dengan context timeout dan cleanup LIFO
7. **State**: JSON-based state persistence dengan atomic writes untuk resume capability

Key takeaways:
- Gunakan **slog** daripada zap/logrus kecuali butuh throughput ekstrem
- Gunakan **Koanf** daripada Viper untuk lebih modular dan ringan
- Gunakan **signal.NotifyContext** (Go 1.16+) untuk graceful shutdown
- Implementasikan **state persistence** untuk resume capability pada long-running scans
