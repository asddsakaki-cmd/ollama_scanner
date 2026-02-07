# Modern Output & Storage Patterns for Go CLI Tools 2026

## Executive Summary

Research untuk modern patterns output dan storage yang cocok untuk scanner dengan 100k+ hosts, mendukung multiple output formats, dan arsitektur plugin yang extensible.

---

## 1. Core Interface Design: OutputWriter

### Interface Definition (Recommended)

```go
package output

import (
	"context"
	"io"
)

// ScanResult adalah core data model
type ScanResult struct {
	Version     string      `json:"version" bson:"version"`         // Data format version
	Timestamp   int64       `json:"timestamp" bson:"timestamp"`     // Unix timestamp
	ScanID      string      `json:"scan_id" bson:"scan_id"`         // UUID untuk tracking
	IP          string      `json:"ip" bson:"ip"`
	Port        int         `json:"port" bson:"port"`
	Models      []ModelInfo `json:"models" bson:"models"`
	RawResponse string      `json:"raw_response,omitempty" bson:"raw_response,omitempty"`
	Metadata    Metadata    `json:"metadata" bson:"metadata"`
}

type ModelInfo struct {
	Name            string  `json:"name" bson:"name"`
	FirstTokenDelay int64   `json:"first_token_delay_ms" bson:"first_token_delay_ms"` // in ms
	TokensPerSec    float64 `json:"tokens_per_sec" bson:"tokens_per_sec"`
	Status          string  `json:"status" bson:"status"`
}

type Metadata struct {
	ScannerVersion string            `json:"scanner_version" bson:"scanner_version"`
	Source         string            `json:"source" bson:"source"` // zmap/masscan/manual
	Tags           []string          `json:"tags,omitempty" bson:"tags,omitempty"`
	CustomFields   map[string]string `json:"custom_fields,omitempty" bson:"custom_fields,omitempty"`
}

// OutputWriter adalah interface utama untuk semua output formats
type OutputWriter interface {
	// Init initializes the writer with configuration
	Init(ctx context.Context, config Config) error
	
	// Write writes a single scan result
	// Thread-safe untuk concurrent writes
	Write(ctx context.Context, result ScanResult) error
	
	// WriteBatch writes multiple results (batch optimization)
	WriteBatch(ctx context.Context, results []ScanResult) error
	
	// Flush forces any buffered data to be written
	Flush() error
	
	// Close closes the writer and releases resources
	Close() error
	
	// Name returns the writer identifier
	Name() string
	
	// Capabilities returns what this writer supports
	Capabilities() Capabilities
}

type Capabilities struct {
	Streaming    bool // Supports real-time streaming
	BatchWrite   bool // Supports batch operations
	SchemaAware  bool // Supports schema validation/versioning
	Concurrent   bool // Thread-safe for concurrent writes
}

// Config untuk inisialisasi writer
type Config struct {
	OutputPath   string
	BufferSize   int
	Format       FormatType
	PrettyPrint  bool // untuk JSON
	SchemaVersion string
}

type FormatType string

const (
	FormatJSON     FormatType = "json"
	FormatCSV      FormatType = "csv"
	FormatConsole  FormatType = "console"
	FormatSQLite   FormatType = "sqlite"
	FormatMongoDB  FormatType = "mongodb"
	FormatHTML     FormatType = "html"
	FormatExcel    FormatType = "excel"
	FormatProtobuf FormatType = "protobuf"
)
```

---

## 2. Database Options Analysis

### 2.1 SQLite (Pure Go)

#### Options Comparison

| Library | CGO | Performance | Compatibility | Maintenance | Recommendation |
|---------|-----|-------------|---------------|-------------|----------------|
| `github.com/mattn/go-sqlite3` | ✅ Yes | ⭐⭐⭐⭐⭐ Best | Standard | Very active | Legacy only |
| `modernc.org/sqlite` | ❌ No | ⭐⭐⭐⭐ Good | Good | Active | ✅ **Recommended** |
| `github.com/glebarez/go-sqlite` | ❌ No | ⭐⭐⭐⭐ Good | Good (GORM) | Moderate | GORM users |
| `github.com/glebarez/sqlite` | ❌ No | ⭐⭐⭐⭐ Good | GORM wrapper | Moderate | GORM users |

#### Key Differences: mattn vs modernc

```go
// github.com/mattn/go-sqlite3 - requires CGO
import (
    "database/sql"
    _ "github.com/mattn/go-sqlite3"
)
// Build: CGO_ENABLED=1 required
// Cross-compile: Complex (need musl-cross for static builds)

// modernc.org/sqlite - Pure Go
import (
    "database/sql"
    _ "modernc.org/sqlite"
)
// Build: CGO_ENABLED=0 (default)
// Cross-compile: Simple, works everywhere
```

#### Why modernc.org/sqlite?

1. **No CGO**: Simplifies build process, cross-compilation, Docker builds
2. **File Compatibility**: SQLite files are compatible between drivers
3. **Production Ready**: Used by Grafana, Gogs, and others in production
4. **Performance**: ~90% of C version performance, "good enough" for most use cases

#### Implementation Pattern

```go
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	
	_ "modernc.org/sqlite"
	"github.com/aspnmy/ollama_scanner/output"
)

type Writer struct {
	db       *sql.DB
	stmt     *sql.Stmt
	buffer   []output.ScanResult
	bufSize  int
}

func (w *Writer) Init(ctx context.Context, config output.Config) error {
	dsn := config.OutputPath + "?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +  // Write-Ahead Logging untuk concurrent writes
		"&_pragma=synchronous(NORMAL)"  // Balance safety/speed
	
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	
	w.db = db
	w.bufSize = config.BufferSize
	if w.bufSize == 0 {
		w.bufSize = 100 // default batch size
	}
	
	return w.createSchema(ctx, config.SchemaVersion)
}

func (w *Writer) createSchema(ctx context.Context, version string) error {
	schema := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS scan_results_%s (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT,
			timestamp INTEGER,
			ip TEXT,
			port INTEGER,
			model_name TEXT,
			first_token_delay_ms INTEGER,
			tokens_per_sec REAL,
			status TEXT,
			scanner_version TEXT,
			source TEXT,
			raw_json TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_scan_id ON scan_results_%s(scan_id);
		CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_results_%s(timestamp);
		CREATE INDEX IF NOT EXISTS idx_ip ON scan_results_%s(ip);
	`, version, version, version, version)
	
	_, err := w.db.ExecContext(ctx, schema)
	return err
}

func (w *Writer) Write(ctx context.Context, result output.ScanResult) error {
	w.buffer = append(w.buffer, result)
	if len(w.buffer) >= w.bufSize {
		return w.Flush()
	}
	return nil
}

func (w *Writer) Flush() error {
	if len(w.buffer) == 0 {
		return nil
	}
	
	tx, err := w.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	
	stmt, err := tx.Prepare(`
		INSERT INTO scan_results (scan_id, timestamp, ip, port, model_name, 
			first_token_delay_ms, tokens_per_sec, status, scanner_version, source, raw_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	
	for _, r := range w.buffer {
		for _, m := range r.Models {
			rawJSON, _ := json.Marshal(r)
			_, err = stmt.Exec(r.ScanID, r.Timestamp, r.IP, r.Port, m.Name,
				m.FirstTokenDelay, m.TokensPerSec, m.Status,
				r.Metadata.ScannerVersion, r.Metadata.Source, rawJSON)
			if err != nil {
				return err
			}
		}
	}
	
	w.buffer = w.buffer[:0]
	return tx.Commit()
}
```

### 2.2 MongoDB

#### Driver: mongo-driver v2 (2025+)

```go
import "go.mongodb.org/mongo-driver/v2/mongo"  // v2 API
```

Key changes in v2:
- Simplified connection API
- Better performance with connection pooling
- Native support for generics
- Better context handling

```go
package mongodb

import (
	"context"
	"time"
	
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type Writer struct {
	client     *mongo.Client
	collection *mongo.Collection
	buffer     []interface{}
	bufSize    int
}

func (w *Writer) Init(ctx context.Context, config output.Config) error {
	uri := config.OutputPath // mongodb://localhost:27017
	
	clientOpts := options.Client().
		ApplyURI(uri).
		SetMaxPoolSize(100).
		SetMinPoolSize(10).
		SetMaxConnIdleTime(30 * time.Second)
	
	client, err := mongo.Connect(clientOpts)
	if err != nil {
		return err
	}
	
	w.client = client
	w.collection = client.Database("ollama_scanner").Collection("results")
	w.bufSize = config.BufferSize
	if w.bufSize == 0 {
		w.bufSize = 1000 // MongoDB handles batch inserts well
	}
	
	// Create indexes
	return w.createIndexes(ctx)
}

func (w *Writer) createIndexes(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		{Keys: bson.D{{"scan_id", 1}}},
		{Keys: bson.D{{"timestamp", -1}}},
		{Keys: bson.D{{"ip", 1}}},
		{Keys: bson.D{{"models.name", 1}}},
	}
	_, err := w.collection.Indexes().CreateMany(ctx, indexes)
	return err
}

func (w *Writer) Write(ctx context.Context, result output.ScanResult) error {
	w.buffer = append(w.buffer, result)
	if len(w.buffer) >= w.bufSize {
		return w.Flush()
	}
	return nil
}

func (w *Writer) Flush() error {
	if len(w.buffer) == 0 {
		return nil
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	_, err := w.collection.InsertMany(ctx, w.buffer)
	w.buffer = w.buffer[:0]
	return err
}
```

### 2.3 PostgreSQL (Enterprise)

```go
package postgres

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Writer struct {
	pool    *pgxpool.Pool
	buffer  []*output.ScanResult
}

func (w *Writer) Init(ctx context.Context, config output.Config) error {
	poolConfig, err := pgxpool.ParseConfig(config.OutputPath)
	if err != nil {
		return err
	}
	
	poolConfig.MaxConns = 20
	poolConfig.MinConns = 5
	
	w.pool, err = pgxpool.NewWithConfig(ctx, poolConfig)
	return err
}

func (w *Writer) WriteBatch(ctx context.Context, results []output.ScanResult) error {
	// Use COPY FROM for bulk insert (fastest method)
	copyCount, err := w.pool.CopyFrom(
		ctx,
		pgx.Identifier{"scan_results"},
		[]string{"scan_id", "timestamp", "ip", "port", "model_name", "status"},
		pgx.CopyFromSlice(len(results), func(i int) ([]interface{}, error) {
			r := results[i]
			return []interface{}{
				r.ScanID, r.Timestamp, r.IP, r.Port, 
				r.Models[0].Name, r.Models[0].Status,
			}, nil
		}),
	)
	return err
}
```

---

## 3. Multiple Output Formats (Simultaneous)

### MultiWriter Pattern

```go
package output

import (
	"context"
	"sync"
)

// MultiWriter writes to multiple outputs concurrently
type MultiWriter struct {
	writers []OutputWriter
	mu      sync.RWMutex
}

func NewMultiWriter(writers ...OutputWriter) *MultiWriter {
	return &MultiWriter{writers: writers}
}

func (m *MultiWriter) Init(ctx context.Context, configs map[string]Config) error {
	for _, w := range m.writers {
		name := w.Name()
		config, ok := configs[name]
		if !ok {
			config = Config{} // default config
		}
		if err := w.Init(ctx, config); err != nil {
			return fmt.Errorf("failed to init %s: %w", name, err)
		}
	}
	return nil
}

func (m *MultiWriter) Write(ctx context.Context, result ScanResult) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var wg sync.WaitGroup
	errChan := make(chan error, len(m.writers))
	
	for _, w := range m.writers {
		wg.Add(1)
		go func(writer OutputWriter) {
			defer wg.Done()
			if err := writer.Write(ctx, result); err != nil {
				errChan <- fmt.Errorf("%s: %w", writer.Name(), err)
			}
		}(w)
	}
	
	wg.Wait()
	close(errChan)
	
	// Collect errors
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("multiwriter errors: %v", errs)
	}
	return nil
}

// Flush flushes all writers concurrently
func (m *MultiWriter) Flush() error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(m.writers))
	
	for _, w := range m.writers {
		wg.Add(1)
		go func(writer OutputWriter) {
			defer wg.Done()
			if err := writer.Flush(); err != nil {
				errChan <- fmt.Errorf("%s: %w", writer.Name(), err)
			}
		}(w)
	}
	
	wg.Wait()
	close(errChan)
	
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("flush errors: %v", errs)
	}
	return nil
}

func (m *MultiWriter) Close() error {
	var errs []error
	for _, w := range m.writers {
		if err := w.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", w.Name(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}
```

### Factory Pattern untuk Plugin Architecture

```go
package output

import (
	"context"
	"fmt"
	"sync"
)

// WriterFactory manages output writer plugins
type WriterFactory struct {
	mu       sync.RWMutex
	registry map[FormatType]WriterConstructor
}

type WriterConstructor func() OutputWriter

var (
	globalFactory = &WriterFactory{
		registry: make(map[FormatType]WriterConstructor),
	}
)

// Register registers a writer constructor
func Register(format FormatType, ctor WriterConstructor) {
	globalFactory.mu.Lock()
	defer globalFactory.mu.Unlock()
	globalFactory.registry[format] = ctor
}

// Create creates a writer by format type
func Create(format FormatType) (OutputWriter, error) {
	globalFactory.mu.RLock()
	defer globalFactory.mu.RUnlock()
	
	ctor, ok := globalFactory.registry[format]
	if !ok {
		return nil, fmt.Errorf("unknown output format: %s", format)
	}
	return ctor(), nil
}

// CreateMultiple creates multiple writers
func CreateMultiple(formats []FormatType) ([]OutputWriter, error) {
	var writers []OutputWriter
	for _, f := range formats {
		w, err := Create(f)
		if err != nil {
			return nil, err
		}
		writers = append(writers, w)
	}
	return writers, nil
}

// Usage in init() of each writer package
func init() {
	output.Register(output.FormatJSON, func() output.OutputWriter {
		return &JSONWriter{}
	})
	output.Register(output.FormatCSV, func() output.OutputWriter {
		return &CSVWriter{}
	})
	output.Register(output.FormatSQLite, func() output.OutputWriter {
		return &sqlite.Writer{}
	})
	output.Register(output.FormatMongoDB, func() output.OutputWriter {
		return &mongodb.Writer{}
	})
}
```

---

## 4. Data Export Patterns

### 4.1 JSON: encoding/json vs json/v2

```go
package json

import (
	"encoding/json"
	"os"
	"sync"
)

type Writer struct {
	file     *os.File
	encoder  *json.Encoder
	mu       sync.Mutex
	first    bool
}

func (w *Writer) Init(ctx context.Context, config output.Config) error {
	f, err := os.Create(config.OutputPath)
	if err != nil {
		return err
	}
	w.file = f
	w.encoder = json.NewEncoder(f)
	if config.PrettyPrint {
		w.encoder.SetIndent("", "  ")
	}
	w.first = true
	
	// Start JSON array
	_, err = f.WriteString("[\n")
	return err
}

func (w *Writer) Write(ctx context.Context, result output.ScanResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	if !w.first {
		w.file.WriteString(",\n")
	}
	w.first = false
	
	return w.encoder.Encode(result)
}

func (w *Writer) Close() error {
	w.file.WriteString("\n]")
	return w.file.Close()
}

// Streaming with json/v2 (Go 1.25+)
// GOEXPERIMENT=jsonv2 required
func (w *Writer) WriteV2(ctx context.Context, result ScanResult) error {
	// Use jsontext for true streaming
	enc := jsontext.NewEncoder(w.file)
	
	// Manual array construction for minimal memory
	if w.first {
		enc.WriteToken(jsontext.BeginArray)
		w.first = false
	} else {
		enc.WriteToken(jsontext.Comma)
	}
	
	return json.MarshalEncode(enc, result)
}
```

### 4.2 CSV: encoding/csv (Standard)

```go
package csv

import (
	"encoding/csv"
	"os"
	"strconv"
	"sync"
)

type Writer struct {
	file   *os.File
	writer *csv.Writer
	mu     sync.Mutex
}

func (w *Writer) Init(ctx context.Context, config output.Config) error {
	f, err := os.Create(config.OutputPath)
	if err != nil {
		return err
	}
	w.file = f
	w.writer = csv.NewWriter(f)
	
	// Write header
	return w.writer.Write([]string{
		"timestamp", "scan_id", "ip", "port", 
		"model_name", "first_token_ms", "tokens_per_sec", "status",
	})
}

func (w *Writer) Write(ctx context.Context, result output.ScanResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	for _, m := range result.Models {
		record := []string{
			strconv.FormatInt(result.Timestamp, 10),
			result.ScanID,
			result.IP,
			strconv.Itoa(result.Port),
			m.Name,
			strconv.FormatInt(m.FirstTokenDelay, 10),
			strconv.FormatFloat(m.TokensPerSec, 'f', 2, 64),
			m.Status,
		}
		if err := w.writer.Write(record); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) Flush() error {
	w.writer.Flush()
	return w.writer.Error()
}
```

### 4.3 HTML Reports

```go
package html

import (
	"html/template"
	"os"
)

const reportTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Ollama Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .status-ok { color: green; }
        .status-error { color: red; }
    </style>
</head>
<body>
    <h1>Scan Results</h1>
    <p>Scan ID: {{.ScanID}} | Generated: {{.Generated}}</p>
    <table>
        <tr>
            <th>IP</th>
            <th>Model</th>
            <th>Status</th>
            <th>First Token (ms)</th>
            <th>Tokens/sec</th>
        </tr>
        {{range .Results}}
        {{range .Models}}
        <tr>
            <td>{{$.IP}}</td>
            <td>{{.Name}}</td>
            <td class="status-{{if eq .Status "完成"}}ok{{else}}error{{end}}">{{.Status}}</td>
            <td>{{.FirstTokenDelay}}</td>
            <td>{{.TokensPerSec}}</td>
        </tr>
        {{end}}
        {{end}}
    </table>
</body>
</html>
`

type Writer struct {
	template *template.Template
	results  []output.ScanResult
	scanID   string
}

func (w *Writer) Close() error {
	data := struct {
		ScanID    string
		Generated string
		Results   []output.ScanResult
	}{
		ScanID:    w.scanID,
		Generated: time.Now().Format(time.RFC3339),
		Results:   w.results,
	}
	
	f, _ := os.Create("report.html")
	defer f.Close()
	return w.template.Execute(f, data)
}
```

### 4.4 Excel: excelize

```go
package excel

import (
	"github.com/xuri/excelize/v2"
)

type Writer struct {
	file    *excelize.File
	sheet   string
	row     int
}

func (w *Writer) Init(ctx context.Context, config output.Config) error {
	w.file = excelize.NewFile()
	w.sheet = "Scan Results"
	w.file.NewSheet(w.sheet)
	w.row = 1
	
	// Headers
	headers := []string{"Timestamp", "IP", "Port", "Model", "Status", "Latency", "TPS"}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, w.row)
		w.file.SetCellValue(w.sheet, cell, h)
	}
	w.row++
	return nil
}

func (w *Writer) Write(ctx context.Context, result output.ScanResult) error {
	for _, m := range result.Models {
		w.file.SetCellValue(w.sheet, "A"+strconv.Itoa(w.row), result.Timestamp)
		w.file.SetCellValue(w.sheet, "B"+strconv.Itoa(w.row), result.IP)
		w.file.SetCellValue(w.sheet, "C"+strconv.Itoa(w.row), result.Port)
		w.file.SetCellValue(w.sheet, "D"+strconv.Itoa(w.row), m.Name)
		w.file.SetCellValue(w.sheet, "E"+strconv.Itoa(w.row), m.Status)
		w.file.SetCellValue(w.sheet, "F"+strconv.Itoa(w.row), m.FirstTokenDelay)
		w.file.SetCellValue(w.sheet, "G"+strconv.Itoa(w.row), m.TokensPerSec)
		w.row++
	}
	return nil
}

func (w *Writer) Close() error {
	return w.file.SaveAs("results.xlsx")
}
```

---

## 5. Real-time Streaming

### 5.1 Server-Sent Events (SSE) - Recommended untuk Dashboard

```go
package sse

import (
	"context"
	"fmt"
	"net/http"
	"sync"
)

type Writer struct {
	clients map[chan<- string]struct{}
	mu      sync.RWMutex
}

func (w *Writer) Init(ctx context.Context, config output.Config) error {
	w.clients = make(map[chan<- string]struct{})
	
	go w.startServer(config.OutputPath) // :8080
	return nil
}

func (w *Writer) Write(ctx context.Context, result output.ScanResult) error {
	data, _ := json.Marshal(result)
	
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	for client := range w.clients {
		select {
		case client <- string(data):
		default: // Drop if client is slow
		}
	}
	return nil
}

func (w *Writer) startServer(addr string) {
	http.HandleFunc("/events", w.handleSSE)
	http.ListenAndServe(addr, nil)
}

func (w *Writer) handleSSE(rw http.ResponseWriter, req *http.Request) {
	flusher, ok := rw.(http.Flusher)
	if !ok {
		http.Error(rw, "Streaming not supported", http.StatusInternalServerError)
		return
	}
	
	rw.Header().Set("Content-Type", "text/event-stream")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("Connection", "keep-alive")
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	
	msgChan := make(chan string, 100)
	w.mu.Lock()
	w.clients[msgChan] = struct{}{}
	w.mu.Unlock()
	
	defer func() {
		w.mu.Lock()
		delete(w.clients, msgChan)
		w.mu.Unlock()
		close(msgChan)
	}()
	
	for {
		select {
		case msg := <-msgChan:
			fmt.Fprintf(rw, "data: %s\n\n", msg)
			flusher.Flush()
		case <-req.Context().Done():
			return
		}
	}
}
```

### 5.2 WebSocket (Bidirectional)

```go
package websocket

import (
	"github.com/gorilla/websocket"
)

type Writer struct {
	upgrader websocket.Upgrader
	clients  map[*websocket.Conn]struct{}
	mu       sync.RWMutex
}

func (w *Writer) Write(ctx context.Context, result output.ScanResult) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	data, _ := json.Marshal(result)
	
	for client := range w.clients {
		if err := client.WriteMessage(websocket.TextMessage, data); err != nil {
			// Remove failed client
			go w.removeClient(client)
		}
	}
	return nil
}
```

### 5.3 gRPC untuk Distributed Scanning

```go
// proto/scan.proto
syntax = "proto3";

service ScanService {
  rpc StreamResults(stream ScanResult) returns (Ack);
  rpc Subscribe(SubscribeRequest) returns (stream ScanResult);
}

message ScanResult {
  string scan_id = 1;
  int64 timestamp = 2;
  string ip = 3;
  int32 port = 4;
  repeated ModelInfo models = 5;
}

message ModelInfo {
  string name = 1;
  int64 first_token_delay_ms = 2;
  double tokens_per_sec = 3;
  string status = 4;
}
```

---

## 6. Data Model Versioning

```go
package output

import (
	"fmt"
)

const CurrentSchemaVersion = "v2"

// MigrationStrategy handles data format changes
type MigrationStrategy interface {
	MigrateV1ToV2(old map[string]interface{}) (ScanResult, error)
	MigrateV2ToV3(old ScanResult) (ScanResult, error)
}

// SchemaValidator validates data against schema version
type SchemaValidator struct {
	version string
}

func (v *SchemaValidator) Validate(data []byte) (ScanResult, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return ScanResult{}, err
	}
	
	version, _ := raw["version"].(string)
	if version == "" {
		version = "v1" // default for legacy data
	}
	
	switch version {
	case "v1":
		return v.migrateV1(raw)
	case CurrentSchemaVersion:
		var result ScanResult
		err := json.Unmarshal(data, &result)
		return result, err
	default:
		return ScanResult{}, fmt.Errorf("unsupported schema version: %s", version)
	}
}
```

---

## 7. Streaming vs Batch untuk 100k+ Hosts

### Memory Comparison

| Approach | Memory Usage | Latency | Use Case |
|----------|--------------|---------|----------|
| Full In-Memory | O(n) - grows with data | Low | <10k hosts |
| Batched (1000) | O(batch_size) | Medium | 10k-100k hosts |
| Streaming | O(1) - constant | Per-item | 100k+ hosts |

### Streaming Implementation

```go
package output

// StreamingWriter untuk 100k+ hosts
type StreamingWriter struct {
	encoder interface{} // json.Encoder atau jsontext.Encoder
	mu      sync.Mutex
}

func (w *StreamingWriter) WriteStream(ctx context.Context, results <-chan ScanResult) error {
	for result := range results {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := w.Write(ctx, result); err != nil {
				return err
			}
		}
	}
	return nil
}
```

---

## 8. Recommended Configuration untuk Scanner

### Default (CSV + Console)

```go
func DefaultOutputs() ([]output.OutputWriter, error) {
	return output.CreateMultiple([]output.FormatType{
		output.FormatCSV,
		output.FormatConsole,
	})
}
```

### With Optional JSON

```go
func ExtendedOutputs(enableJSON, enableSQLite bool) ([]output.OutputWriter, error) {
	formats := []output.FormatType{
		output.FormatCSV,
		output.FormatConsole,
	}
	
	if enableJSON {
		formats = append(formats, output.FormatJSON)
	}
	if enableSQLite {
		formats = append(formats, output.FormatSQLite)
	}
	
	return output.CreateMultiple(formats)
}
```

### Full Featured (Enterprise)

```go
func EnterpriseOutputs(config OutputConfig) (*output.MultiWriter, error) {
	var writers []output.OutputWriter
	
	// Always
	writers = append(writers, &csv.Writer{})
	writers = append(writers, &console.Writer{})
	
	// Optional
	if config.EnableJSON {
		writers = append(writers, &json.Writer{})
	}
	if config.EnableSQLite {
		writers = append(writers, &sqlite.Writer{})
	}
	if config.EnableMongoDB {
		writers = append(writers, &mongodb.Writer{})
	}
	if config.EnableSSE {
		writers = append(writers, &sse.Writer{})
	}
	
	multi := output.NewMultiWriter(writers...)
	return multi, nil
}
```

---

## 9. Summary: Pros/Cons Table

| Storage | Pros | Cons | Best For |
|---------|------|------|----------|
| **CSV** | Simple, universal, streaming | No schema, no query | Default export |
| **JSON** | Structured, streaming (v2) | Larger size | API integration |
| **SQLite (modernc)** | No CGO, SQL queries, local | Single file limit | Local storage, analysis |
| **MongoDB** | Schema flexible, horizontal | Requires server, setup | Distributed scanning |
| **PostgreSQL** | ACID, robust, enterprise | Setup complexity | Production deployment |
| **SSE** | Real-time, simple | Unidirectional only | Live dashboard |
| **WebSocket** | Bidirectional | More complex | Interactive features |
| **gRPC** | Efficient, typed | Setup complexity | Distributed systems |

---

## 10. Implementation Checklist

- [ ] Implement `OutputWriter` interface
- [ ] Set up plugin factory dengan `Register()` pattern
- [ ] Implement `MultiWriter` untuk simultaneous outputs
- [ ] Add proper error handling dan graceful degradation
- [ ] Implement batching dengan configurable buffer sizes
- [ ] Add schema versioning untuk data compatibility
- [ ] Add metrics dan monitoring hooks
- [ ] Document thread-safety guarantees
