// internal/checkpoint/store.go
// SQLite-based checkpoint storage for scan resume capability

package checkpoint

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aspnmy/ollama_scanner/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

// Store handles persistence of checkpoint data
type Store struct {
	db *sql.DB
}

// NewStore creates a new checkpoint store
// PERFORMANCE: Enables WAL mode for better concurrent write performance
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open checkpoint database: %w", err)
	}

	// Enable WAL mode for better performance and concurrency
	// WAL mode allows readers to not block writers and vice versa
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close() //nolint:gosec // G104: secondary error, primary error returned
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Set synchronous to NORMAL for better performance while maintaining safety
	if _, err := db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		_ = db.Close() //nolint:gosec // G104: secondary error, primary error returned
		return nil, fmt.Errorf("failed to set synchronous mode: %w", err)
	}

	// Increase cache size for better performance (10MB)
	if _, err := db.Exec("PRAGMA cache_size=-10000"); err != nil {
		_ = db.Close() //nolint:gosec // G104: secondary error, primary error returned
		return nil, fmt.Errorf("failed to set cache size: %w", err)
	}

	// Create tables if not exist
	if err := createTables(db); err != nil {
		_ = db.Close() //nolint:gosec // G104: secondary error, primary error returned
		return nil, err
	}

	return &Store{db: db}, nil
}

// createTables creates the necessary database tables
func createTables(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		scan_id TEXT PRIMARY KEY,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		status TEXT DEFAULT 'running',
		total_targets INTEGER DEFAULT 0,
		processed_targets INTEGER DEFAULT 0,
		config_json TEXT,
		metadata TEXT
	);

	CREATE TABLE IF NOT EXISTS checkpoints (
		checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		processed_count INTEGER DEFAULT 0,
		remaining_targets TEXT, -- JSON array of strings
		results_json TEXT, -- JSON array of scan results
		FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_checkpoints_scan_id ON checkpoints(scan_id);
	CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
	`

	_, err := db.Exec(schema)
	return err
}

// CreateScan creates a new scan record
func (s *Store) CreateScan(scanID string, totalTargets int64, config map[string]interface{}) error {
	configJSON, _ := json.Marshal(config)
	
	_, err := s.db.Exec(
		`INSERT INTO scans (scan_id, total_targets, config_json, status) VALUES (?, ?, ?, 'running')`,
		scanID, totalTargets, string(configJSON),
	)
	return err
}

// SaveCheckpoint saves a checkpoint for a scan
func (s *Store) SaveCheckpoint(scanID string, processed int64, remaining []string, results []models.ScanResult) error {
	remainingJSON, _ := json.Marshal(remaining)
	resultsJSON, _ := json.Marshal(results)

	// Use transaction for atomicity
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Insert checkpoint
	_, err = tx.Exec(
		`INSERT INTO checkpoints (scan_id, processed_count, remaining_targets, results_json) VALUES (?, ?, ?, ?)`,
		scanID, processed, string(remainingJSON), string(resultsJSON),
	)
	if err != nil {
		return err
	}

	// Update scan record
	_, err = tx.Exec(
		`UPDATE scans SET processed_targets = ?, updated_at = CURRENT_TIMESTAMP WHERE scan_id = ?`,
		processed, scanID,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// GetLatestCheckpoint retrieves the most recent checkpoint for a scan
func (s *Store) GetLatestCheckpoint(scanID string) (*Checkpoint, error) {
	var cp Checkpoint
	var remainingJSON, resultsJSON string

	err := s.db.QueryRow(
		`SELECT checkpoint_id, scan_id, created_at, processed_count, remaining_targets, results_json 
		 FROM checkpoints WHERE scan_id = ? ORDER BY created_at DESC LIMIT 1`,
		scanID,
	).Scan(&cp.ID, &cp.ScanID, &cp.CreatedAt, &cp.ProcessedCount, &remainingJSON, &resultsJSON)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal([]byte(remainingJSON), &cp.RemainingTargets); err != nil {
		return nil, fmt.Errorf("failed to unmarshal remaining targets: %w", err)
	}
	if err := json.Unmarshal([]byte(resultsJSON), &cp.Results); err != nil {
		return nil, fmt.Errorf("failed to unmarshal results: %w", err)
	}

	return &cp, nil
}

// GetScan retrieves scan information
func (s *Store) GetScan(scanID string) (*ScanInfo, error) {
	var info ScanInfo
	var configJSON string

	err := s.db.QueryRow(
		`SELECT scan_id, created_at, updated_at, status, total_targets, processed_targets, config_json 
		 FROM scans WHERE scan_id = ?`,
		scanID,
	).Scan(&info.ScanID, &info.CreatedAt, &info.UpdatedAt, &info.Status, &info.TotalTargets, &info.ProcessedTargets, &configJSON)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(configJSON), &info.Config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return &info, nil
}

// ListScans lists all scans with optional status filter
func (s *Store) ListScans(status string) ([]ScanInfo, error) {
	var query string
	var args []interface{}

	if status != "" {
		query = `SELECT scan_id, created_at, updated_at, status, total_targets, processed_targets 
				 FROM scans WHERE status = ? ORDER BY updated_at DESC`
		args = append(args, status)
	} else {
		query = `SELECT scan_id, created_at, updated_at, status, total_targets, processed_targets 
				 FROM scans ORDER BY updated_at DESC`
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []ScanInfo
	for rows.Next() {
		var info ScanInfo
		err := rows.Scan(&info.ScanID, &info.CreatedAt, &info.UpdatedAt, &info.Status, &info.TotalTargets, &info.ProcessedTargets)
		if err != nil {
			return nil, err
		}
		scans = append(scans, info)
	}

	return scans, nil
}

// UpdateScanStatus updates the status of a scan
func (s *Store) UpdateScanStatus(scanID string, status string) error {
	_, err := s.db.Exec(
		`UPDATE scans SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE scan_id = ?`,
		status, scanID,
	)
	return err
}

// DeleteScan deletes a scan and all its checkpoints
func (s *Store) DeleteScan(scanID string) error {
	_, err := s.db.Exec(`DELETE FROM scans WHERE scan_id = ?`, scanID)
	return err
}

// CleanupOldCheckpoints removes old checkpoints keeping only the most recent N
func (s *Store) CleanupOldCheckpoints(scanID string, keep int) error {
	_, err := s.db.Exec(
		`DELETE FROM checkpoints WHERE scan_id = ? AND checkpoint_id NOT IN (
			SELECT checkpoint_id FROM checkpoints WHERE scan_id = ? ORDER BY created_at DESC LIMIT ?
		)`,
		scanID, scanID, keep,
	)
	return err
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// Checkpoint represents a saved checkpoint
type Checkpoint struct {
	ID               int64
	ScanID           string
	CreatedAt        time.Time
	ProcessedCount   int64
	RemainingTargets []string
	Results          []models.ScanResult
}

// ScanInfo represents scan metadata
type ScanInfo struct {
	ScanID           string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	Status           string // running, completed, failed, paused
	TotalTargets     int64
	ProcessedTargets int64
	Config           map[string]interface{}
}
