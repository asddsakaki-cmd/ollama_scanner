// internal/scanner/interface.go
// Scanner engine interface definitions

package scanner

import (
	"context"
	"net/netip"

	"github.com/aspnmy/ollama_scanner/internal/models"
)

// Engine is the interface for all scanning engines
type Engine interface {
	// Name returns the scanner name (native, zmap, masscan)
	Name() string
	
	// Scan starts scanning the given targets and returns results via channel
	// The engine is responsible for managing its own workers and rate limiting
	Scan(ctx context.Context, targets []models.Target) (<-chan models.ScanResult, error)
	
	// ScanStream is for large target sets (streaming mode)
	// Uses iterator pattern to avoid loading all IPs into memory
	ScanStream(ctx context.Context, targets <-chan models.Target) (<-chan models.ScanResult, error)
	
	// Close cleans up resources
	Close() error
}

// TargetGenerator generates scanning targets from CIDRs/ports
type TargetGenerator interface {
	// Generate creates targets from CIDR list and ports
	Generate(cidrs []string, ports []int) ([]models.Target, error)
	
	// GenerateStream streams targets without loading all into memory
	GenerateStream(cidrs []string, ports []int) (<-chan models.Target, error)
	
	// EstimateCount estimates total targets (for progress calculation)
	EstimateCount(cidrs []string, ports []int) int64
}

// PortScanner is the low-level port scanning interface
type PortScanner interface {
	// ScanPort checks if a single port is open
	ScanPort(ctx context.Context, target models.Target) (models.ScanResult, error)
	
	// ScanPorts checks multiple ports on same host
	ScanPorts(ctx context.Context, ip netip.Addr, ports []int) ([]models.ScanResult, error)
}

// EngineFactory creates scanner engines
type EngineFactory func(config map[string]interface{}) (Engine, error)

// Registry holds available scanner engines
var Registry = make(map[string]EngineFactory)

// Register registers a scanner engine
func Register(name string, factory EngineFactory) {
	Registry[name] = factory
}

// Get creates a scanner engine by name
func Get(name string, config map[string]interface{}) (Engine, error) {
	factory, ok := Registry[name]
	if !ok {
		return nil, ErrEngineNotFound
	}
	return factory(config)
}

// ErrEngineNotFound is returned when engine name is not registered
var ErrEngineNotFound = &ScannerError{Message: "scanner engine not found"}

// ScannerError represents a scanner-specific error
type ScannerError struct {
	Message string
	Cause   error
}

func (e *ScannerError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

func (e *ScannerError) Unwrap() error {
	return e.Cause
}
