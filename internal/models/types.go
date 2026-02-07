// internal/models/types.go
// Core data models for Ollama Scanner

package models

import (
	"net/netip"
	"time"
)

// Target represents a scanning target
type Target struct {
	IP   netip.Addr
	Port int
}

// Address returns the target as "ip:port" string
func (t Target) Address() string {
	return netip.AddrPortFrom(t.IP, uint16(t.Port)).String()
}

// String returns human-readable target info
func (t Target) String() string {
	return t.Address()
}

// ScanResult represents the result of scanning a single target
type ScanResult struct {
	Target    Target        `json:"target"`
	Open      bool          `json:"open"`
	Latency   time.Duration `json:"latency"`
	Timestamp time.Time     `json:"timestamp"`
	Error     string        `json:"error,omitempty"`

	// Ollama-specific fields (populated by detector)
	IsOllama      bool           `json:"is_ollama,omitempty"`
	Version       string         `json:"version,omitempty"`
	Models        []OllamaModel  `json:"models,omitempty"`
	SecurityReport *SecurityReport `json:"security_report,omitempty"`
}

// OllamaModel represents an AI model found on Ollama instance
type OllamaModel struct {
	Name       string            `json:"name"`
	Size       int64             `json:"size,omitempty"`
	Modified   time.Time         `json:"modified,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// SecurityReport contains security audit findings
type SecurityReport struct {
	RiskScore          int               `json:"risk_score"` // 1-10
	RiskRating         string            `json:"risk_rating"` // MINIMAL/LOW/MEDIUM/HIGH/CRITICAL
	
	// Authentication
	AuthEnabled        bool              `json:"auth_enabled"`
	NoAuthEndpoints    []string          `json:"no_auth_endpoints,omitempty"`
	
	// Tool-calling (48% hosts - CRITICAL!)
	ToolCallingEnabled bool              `json:"tool_calling_enabled"`
	ToolCallingModels  []string          `json:"tool_calling_models,omitempty"`
	
	// MCP (Model Context Protocol)
	MCPEnabled         bool              `json:"mcp_enabled"`
	MCPEndpoints       []string          `json:"mcp_endpoints,omitempty"`
	
	// Uncensored Models
	UncensoredModels   []string          `json:"uncensored_models,omitempty"`
	
	// CVEs
	Vulnerabilities    []CVEInfo         `json:"vulnerabilities,omitempty"`
	
	// CORS
	CORSIssues         []string          `json:"cors_issues,omitempty"`
	
	// Exposed Endpoints
	ExposedEndpoints   []EndpointInfo    `json:"exposed_endpoints,omitempty"`
}

// CVEInfo represents a CVE vulnerability
type CVEInfo struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"` // CRITICAL/HIGH/MEDIUM/LOW
	Description string `json:"description"`
	MaxVersion  string `json:"max_version"` // Max affected version
}

// EndpointInfo represents an exposed API endpoint
type EndpointInfo struct {
	Path        string `json:"path"`
	Method      string `json:"method"`
	Accessible  bool   `json:"accessible"`
	RequiresAuth bool  `json:"requires_auth"`
	RiskLevel   string `json:"risk_level"` // CRITICAL/HIGH/MEDIUM/LOW/INFO
}

// Progress represents scan progress
type Progress struct {
	ScanID        string    `json:"scan_id"`
	TotalTargets  int64     `json:"total_targets"`
	Processed     int64     `json:"processed"`
	OpenHosts     int64     `json:"open_hosts"`
	OllamaHosts   int64     `json:"ollama_hosts"`
	StartTime     time.Time `json:"start_time"`
	Elapsed       time.Duration `json:"elapsed"`
	ETA           time.Duration `json:"eta"`
	Percent       float64   `json:"percent"`
}

// ScanState represents the state of a scan (for checkpoint/resume)
type ScanState struct {
	ScanID         string        `json:"scan_id"`
	StartedAt      time.Time     `json:"started_at"`
	LastCheckpoint time.Time     `json:"last_checkpoint"`
	
	// Progress tracking
	TotalTargets   int64         `json:"total_targets"`
	ProcessedIPs   int64         `json:"processed_ips"`
	RemainingIPs   []string      `json:"remaining_ips"`
	
	// Results checkpoint
	Results        []ScanResult  `json:"results,omitempty"`
	
	// Config snapshot
	ConfigVersion  string        `json:"config_version"`
}

// NetworkFeedback for adaptive rate limiting
type NetworkFeedback struct {
	RTT        time.Duration
	PacketLoss float64
	Jitter     time.Duration
}
