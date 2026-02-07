// internal/core/config.go
// Configuration management using Koanf (2026 best practice)

package core

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

var (
	k      = koanf.New(".")
	config *Config
	once   sync.Once
	mu     sync.RWMutex
)

// Config represents the complete application configuration
type Config struct {
	Scanner ScannerConfig `koanf:"scanner"`
	Output  OutputConfig  `koanf:"output"`
	Database DBConfig     `koanf:"database"`
	Log     LogConfig     `koanf:"log"`
}

// ScannerConfig contains scanner-specific settings
type ScannerConfig struct {
	Engine      string        `koanf:"engine"`       // native, zmap, masscan
	Concurrency int           `koanf:"concurrency"`
	Timeout     time.Duration `koanf:"timeout"`
	RateLimit   int           `koanf:"rate_limit"`   // requests per second
	Adaptive    bool          `koanf:"adaptive"`     // adaptive rate limiting
	
	Targets TargetConfig `koanf:"targets"`
	Security SecurityConfig `koanf:"security"`
	
	// Engine-specific settings
	Native  NativeConfig  `koanf:"native"`
	Zmap    ZmapConfig    `koanf:"zmap"`
	Masscan MasscanConfig `koanf:"masscan"`
}

// TargetConfig contains target specification
type TargetConfig struct {
	CIDRs []string `koanf:"cidrs"`
	Ports []int    `koanf:"ports"`
	File  string   `koanf:"file"` // Input file dengan CIDR list
}

// SecurityConfig contains security audit settings
type SecurityConfig struct {
	CheckAuth       bool `koanf:"check_auth"`
	CheckTools      bool `koanf:"check_tools"`      // Tool-calling detection
	CheckMCP        bool `koanf:"check_mcp"`        // MCP detection
	CheckUncensored bool `koanf:"check_uncensored"` // Uncensored model detection
	CheckCVEs       bool `koanf:"check_cves"`
	Benchmark       bool `koanf:"benchmark"`        // Performance benchmark
	BenchmarkPrompt string `koanf:"benchmark_prompt"`
}

// NativeConfig for native Go scanner
type NativeConfig struct {
	Workers    int           `koanf:"workers"`
	Retry      int           `koanf:"retry"`
	RetryDelay time.Duration `koanf:"retry_delay"`
}

// ZmapConfig for zmap wrapper
type ZmapConfig struct {
	Threads   int    `koanf:"threads"`
	Interface string `koanf:"interface"`
	GatewayMAC string `koanf:"gateway_mac"`
}

// MasscanConfig for masscan wrapper
type MasscanConfig struct {
	Rate      int    `koanf:"rate"`
	Interface string `koanf:"interface"`
}

// OutputConfig contains output settings
type OutputConfig struct {
	Formats     []string `koanf:"formats"`      // jsonl, csv, console
	FilePrefix  string   `koanf:"file_prefix"`
	Directory   string   `koanf:"directory"`
	
	Console ConsoleConfig `koanf:"console"`
}

// ConsoleConfig for CLI dashboard
type ConsoleConfig struct {
	Enabled   bool `koanf:"enabled"`
	Dashboard bool `koanf:"dashboard"` // Bubble Tea dashboard
	Progress  bool `koanf:"progress"`  // Simple progress bar
}

// DBConfig contains database settings
type DBConfig struct {
	Primary  string `koanf:"primary"`  // PostgreSQL connection string
	SQLite   string `koanf:"sqlite"`   // SQLite path for checkpoint
	MongoDB  string `koanf:"mongodb"`  // MongoDB connection string
}

// LogConfig contains logging settings
type LogConfig struct {
	Level      string `koanf:"level"`       // debug, info, warn, error
	Format     string `koanf:"format"`      // json, console
	File       string `koanf:"file"`
	MaxSize    int    `koanf:"max_size"`    // MB
	MaxBackups int    `koanf:"max_backups"`
	MaxAge     int    `koanf:"max_age"`     // days
}

// Load initializes the configuration
func Load(configPath string) (*Config, error) {
	var loadErr error
	once.Do(func() {
		loadErr = loadConfig(configPath)
	})
	
	if loadErr != nil {
		return nil, loadErr
	}
	
	mu.RLock()
	defer mu.RUnlock()
	return config, nil
}

// loadConfig performs the actual loading
func loadConfig(configPath string) error {
	// 1. Load default values
	defaults := map[string]interface{}{
		"scanner.engine":                     "native",
		"scanner.concurrency":               1000,
		"scanner.timeout":                   "3s",
		"scanner.rate_limit":                5000,
		"scanner.adaptive":                  true,
		"scanner.targets.ports":             []int{11434},
		"scanner.security.check_auth":       true,
		"scanner.security.check_tools":      true,
		"scanner.security.check_mcp":        true,
		"scanner.security.check_uncensored": true,
		"scanner.security.check_cves":       true,
		"scanner.security.benchmark":        true,
		"scanner.security.benchmark_prompt": "Why does the sun shine? Answer in one sentence.",
		"scanner.native.workers":            1000,
		"scanner.native.retry":              1,
		"scanner.native.retry_delay":        "1s",
		"scanner.zmap.threads":              10,
		"scanner.zmap.interface":            "eth0",
		"scanner.masscan.rate":              1000,
		"output.formats":                    []string{"jsonl", "console"},
		"output.file_prefix":                "ollama_scan",
		"output.directory":                  "./results",
		"output.console.enabled":            true,
		"output.console.dashboard":          true,
		"output.console.progress":           true,
		"database.sqlite":                   "scanner.db",
		"log.level":                         "info",
		"log.format":                        "console",
	}
	
	if err := k.Load(confmap.Provider(defaults, ""), nil); err != nil {
		return fmt.Errorf("failed to load defaults: %w", err)
	}
	
	// 2. Load from config file (if exists)
	if configPath != "" {
		if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
			log.Printf("Config file not found or invalid: %v (using defaults)", err)
		} else {
			log.Printf("Loaded config from: %s", configPath)
		}
	}
	
	// 3. Load from environment variables (highest priority)
	// Format: SCANNER_ENGINE=native, SCANNER_CONCURRENCY=2000, etc.
	envProvider := env.Provider("SCANNER_", ".", func(s string) string {
		// Convert SCANNER_ENGINE to scanner.engine
		return strings.ToLower(strings.TrimPrefix(s, "SCANNER_"))
	})
	
	if err := k.Load(envProvider, nil); err != nil {
		return fmt.Errorf("failed to load env vars: %w", err)
	}
	
	// 4. Unmarshal to struct
	mu.Lock()
	defer mu.Unlock()
	
	config = &Config{}
	if err := k.Unmarshal("", config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// 5. Validate configuration
	if err := validateConfig(config); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}
	
	return nil
}

// validateConfig performs validation on loaded config
func validateConfig(cfg *Config) error {
	// Validate scanner engine
	validEngines := map[string]bool{"native": true, "zmap": true, "masscan": true}
	if !validEngines[cfg.Scanner.Engine] {
		return fmt.Errorf("invalid scanner engine: %s (must be native, zmap, or masscan)", cfg.Scanner.Engine)
	}
	
	// Validate concurrency
	if cfg.Scanner.Concurrency < 1 || cfg.Scanner.Concurrency > 100000 {
		return fmt.Errorf("invalid concurrency: %d (must be between 1 and 100000)", cfg.Scanner.Concurrency)
	}
	
	// Validate rate limit
	if cfg.Scanner.RateLimit < 1 || cfg.Scanner.RateLimit > 1000000 {
		return fmt.Errorf("invalid rate_limit: %d (must be between 1 and 1000000)", cfg.Scanner.RateLimit)
	}
	
	// Validate timeout
	if cfg.Scanner.Timeout < 100*time.Millisecond || cfg.Scanner.Timeout > 5*time.Minute {
		return fmt.Errorf("invalid timeout: %v (must be between 100ms and 5m)", cfg.Scanner.Timeout)
	}
	
	// Validate ports
	for _, port := range cfg.Scanner.Targets.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port: %d", port)
		}
	}
	
	return nil
}

// Get returns the current configuration (thread-safe)
func Get() *Config {
	mu.RLock()
	defer mu.RUnlock()
	
	if config == nil {
		// Return default config if not loaded
		return &Config{
			Scanner: ScannerConfig{
				Engine:      "native",
				Concurrency: 1000,
				Timeout:     3 * time.Second,
				RateLimit:   5000,
				Adaptive:    true,
				Targets: TargetConfig{
					Ports: []int{11434},
				},
			},
		}
	}
	
	return config
}

// Reload reloads configuration from file
func Reload(configPath string) error {
	mu.Lock()
	defer mu.Unlock()
	
	if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}
	
	if err := k.Unmarshal("", config); err != nil {
		return fmt.Errorf("failed to unmarshal reloaded config: %w", err)
	}
	
	return nil
}

// Print prints the current configuration (for debugging)
func Print() {
	mu.RLock()
	defer mu.RUnlock()
	
	if config == nil {
		log.Println("Configuration not loaded")
		return
	}
	
	log.Printf("Configuration:")
	log.Printf("  Engine: %s", config.Scanner.Engine)
	log.Printf("  Concurrency: %d", config.Scanner.Concurrency)
	log.Printf("  Timeout: %v", config.Scanner.Timeout)
	log.Printf("  Rate Limit: %d req/s", config.Scanner.RateLimit)
	log.Printf("  Adaptive: %v", config.Scanner.Adaptive)
	log.Printf("  Ports: %v", config.Scanner.Targets.Ports)
	log.Printf("  Output Formats: %v", config.Output.Formats)
}
