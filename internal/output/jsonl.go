// internal/output/jsonl.go
// JSON Lines output formatter

package output

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/aspnmy/ollama_scanner/internal/models"
)

// JSONLFormatter writes results as JSON Lines
type JSONLFormatter struct {
	encoder *json.Encoder
	writer  io.WriteCloser
	buffer  *bufio.Writer
	mu      sync.Mutex
}

// NewJSONLFormatter creates a new JSONL formatter
func NewJSONLFormatter(filename string) (*JSONLFormatter, error) {
	// Ensure directory exists
	dir := filepath.Dir(filename)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}

	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	buffer := bufio.NewWriterSize(file, 64*1024) // 64KB buffer

	return &JSONLFormatter{
		encoder: json.NewEncoder(buffer),
		writer:  file,
		buffer:  buffer,
	}, nil
}

// Write writes a single result
func (f *JSONLFormatter) Write(result *models.ScanResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.encoder.Encode(result)
}

// Flush flushes the buffer
func (f *JSONLFormatter) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.buffer.Flush()
}

// Close closes the file
func (f *JSONLFormatter) Close() error {
	f.Flush()
	return f.writer.Close()
}
