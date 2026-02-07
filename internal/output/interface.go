// internal/output/interface.go
// Output formatter interfaces

package output

import (
	"context"
	"errors"

	"github.com/aspnmy/ollama_scanner/internal/models"
)

// Formatter is the base interface for all output formatters
type Formatter interface {
	// Write writes a single scan result
	Write(result *models.ScanResult) error
	
	// Flush ensures all buffered data is written
	Flush() error
	
	// Close closes the formatter and releases resources
	Close() error
}

// ProgressReporter handles scan progress updates
type ProgressReporter interface {
	// UpdateProgress updates the current progress
	UpdateProgress(progress models.Progress)
	
	// Finish marks the scan as complete
	Finish(finalStats models.Progress)
}

// ResultHandler combines Formatter and ProgressReporter
type ResultHandler interface {
	Formatter
	ProgressReporter
}

// MultiFormatter allows writing to multiple formatters simultaneously
type MultiFormatter struct {
	formatters []Formatter
}

// NewMultiFormatter creates a new multi-formatter
func NewMultiFormatter(formatters ...Formatter) *MultiFormatter {
	return &MultiFormatter{formatters: formatters}
}

// Write writes to all formatters
func (m *MultiFormatter) Write(result *models.ScanResult) error {
	for _, f := range m.formatters {
		if err := f.Write(result); err != nil {
			return err
		}
	}
	return nil
}

// Flush flushes all formatters
func (m *MultiFormatter) Flush() error {
	for _, f := range m.formatters {
		if err := f.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// Close closes all formatters
func (m *MultiFormatter) Close() error {
	var errs []error
	for _, f := range m.formatters {
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.New("multiple close errors occurred")
	}
	return nil
}

// CheckpointStore handles scan state persistence
type CheckpointStore interface {
	// Save saves the current scan state
	Save(state *models.ScanState) error
	
	// Load loads a scan state by ID
	Load(scanID string) (*models.ScanState, error)
	
	// List returns all available checkpoints
	List() ([]*models.ScanState, error)
	
	// Delete removes a checkpoint
	Delete(scanID string) error
	
	// Close closes the store
	Close() error
}

// DatabaseWriter handles database output
type DatabaseWriter interface {
	Formatter
	
	// WriteBatch writes multiple results efficiently
	WriteBatch(results []*models.ScanResult) error
	
	// Query allows querying stored results
	Query(ctx context.Context, query string) ([]*models.ScanResult, error)
}

// ConsoleUI handles interactive console output
type ConsoleUI interface {
	// Start initializes the UI
	Start() error
	
	// Stop shuts down the UI
	Stop() error
	
	// HandleResults receives results for display
	HandleResults(results <-chan models.ScanResult)
	
	// HandleProgress receives progress updates
	HandleProgress(progress <-chan models.Progress)
}

// WebServer handles web dashboard output
type WebServer interface {
	// Start starts the web server
	Start(addr string) error
	
	// Stop stops the web server
	Stop() error
	
	// BroadcastResult sends result to connected clients
	BroadcastResult(result *models.ScanResult)
	
	// BroadcastProgress sends progress to connected clients
	BroadcastProgress(progress models.Progress)
}

// FormatterFactory creates formatters by name
type FormatterFactory func(config map[string]interface{}) (Formatter, error)

// Registry holds available formatters
var Registry = make(map[string]FormatterFactory)

// Register registers a formatter
func Register(name string, factory FormatterFactory) {
	Registry[name] = factory
}

// Get creates a formatter by name
func Get(name string, config map[string]interface{}) (Formatter, error) {
	factory, ok := Registry[name]
	if !ok {
		return nil, ErrFormatterNotFound
	}
	return factory(config)
}

// ErrFormatterNotFound is returned when formatter name is not registered
var ErrFormatterNotFound = errors.New("formatter not found")

// Common formatter errors
var (
	ErrOutputFileNotWritable = errors.New("output file is not writable")
	ErrDatabaseConnection    = errors.New("database connection failed")
	ErrInvalidFormat         = errors.New("invalid output format")
)
