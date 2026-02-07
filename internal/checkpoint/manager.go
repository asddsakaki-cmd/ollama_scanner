// internal/checkpoint/manager.go
// Checkpoint manager for automatic save/resume functionality

package checkpoint

import (
	"fmt"
	"sync"
	"time"

	"github.com/aspnmy/ollama_scanner/internal/models"
	"github.com/aspnmy/ollama_scanner/pkg/logger"
	"github.com/google/uuid"
)

// Manager handles checkpoint lifecycle during scanning
type Manager struct {
	store          *Store
	scanID         string
	interval       time.Duration
	keepCount      int
	lastCheckpoint time.Time
	mu             sync.Mutex
}

// Config holds checkpoint manager configuration
type Config struct {
	Enabled     bool
	DBPath      string
	Interval    time.Duration // How often to save
	KeepCount   int           // How many checkpoints to keep per scan
}

// DefaultConfig returns default checkpoint configuration
func DefaultConfig() Config {
	return Config{
		Enabled:   true,
		DBPath:    "checkpoints.db",
		Interval:  30 * time.Second,
		KeepCount: 5,
	}
}

// NewManager creates a new checkpoint manager
func NewManager(cfg Config) (*Manager, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	store, err := NewStore(cfg.DBPath)
	if err != nil {
		return nil, err
	}

	return &Manager{
		store:     store,
		interval:  cfg.Interval,
		keepCount: cfg.KeepCount,
	}, nil
}

// StartScan initializes a new scan with checkpointing
func (m *Manager) StartScan(totalTargets int64, config map[string]interface{}) (string, error) {
	m.scanID = generateScanID()

	err := m.store.CreateScan(m.scanID, totalTargets, config)
	if err != nil {
		return "", fmt.Errorf("failed to create scan record: %w", err)
	}

	logger.Info("Checkpoint manager started",
		logger.String("scan_id", m.scanID),
		logger.Int64("total_targets", totalTargets),
	)

	return m.scanID, nil
}

// ResumeScan resumes a scan from a checkpoint
func (m *Manager) ResumeScan(scanID string) (*ResumeInfo, error) {
	m.scanID = scanID

	// Get scan info
	scanInfo, err := m.store.GetScan(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan info: %w", err)
	}
	if scanInfo == nil {
		return nil, fmt.Errorf("scan not found: %s", scanID)
	}

	// Get latest checkpoint
	checkpoint, err := m.store.GetLatestCheckpoint(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get checkpoint: %w", err)
	}
	if checkpoint == nil {
		return nil, fmt.Errorf("no checkpoint found for scan: %s", scanID)
	}

	// Update status to running
	m.store.UpdateScanStatus(scanID, "running")

	logger.Info("Resuming scan from checkpoint",
		logger.String("scan_id", scanID),
		logger.Int64("processed", checkpoint.ProcessedCount),
		logger.Int("remaining", len(checkpoint.RemainingTargets)),
	)

	return &ResumeInfo{
		ScanID:           scanID,
		TotalTargets:     scanInfo.TotalTargets,
		ProcessedCount:   checkpoint.ProcessedCount,
		RemainingTargets: checkpoint.RemainingTargets,
		PreviousResults:  checkpoint.Results,
		Config:           scanInfo.Config,
	}, nil
}

// MaybeSave conditionally saves a checkpoint based on interval
func (m *Manager) MaybeSave(processed int64, remaining []string, results []models.ScanResult) error {
	if m == nil || m.store == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if enough time has passed
	if time.Since(m.lastCheckpoint) < m.interval {
		return nil
	}

	return m.Save(processed, remaining, results)
}

// Save immediately saves a checkpoint
func (m *Manager) Save(processed int64, remaining []string, results []models.ScanResult) error {
	if m == nil || m.store == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	err := m.store.SaveCheckpoint(m.scanID, processed, remaining, results)
	if err != nil {
		return fmt.Errorf("failed to save checkpoint: %w", err)
	}

	m.lastCheckpoint = time.Now()

	// Cleanup old checkpoints
	go m.store.CleanupOldCheckpoints(m.scanID, m.keepCount)

	logger.Debug("Checkpoint saved",
		logger.String("scan_id", m.scanID),
		logger.Int64("processed", processed),
		logger.Int("remaining", len(remaining)),
	)

	return nil
}

// Complete marks the scan as completed
func (m *Manager) Complete() error {
	if m == nil || m.store == nil {
		return nil
	}

	return m.store.UpdateScanStatus(m.scanID, "completed")
}

// Fail marks the scan as failed
func (m *Manager) Fail(reason string) error {
	if m == nil || m.store == nil {
		return nil
	}

	logger.Warn("Scan failed, checkpoint preserved",
		logger.String("scan_id", m.scanID),
		logger.String("reason", reason),
	)

	return m.store.UpdateScanStatus(m.scanID, "failed")
}

// Pause marks the scan as paused
func (m *Manager) Pause() error {
	if m == nil || m.store == nil {
		return nil
	}

	return m.store.UpdateScanStatus(m.scanID, "paused")
}

// Close closes the checkpoint manager
func (m *Manager) Close() error {
	if m == nil || m.store == nil {
		return nil
	}

	return m.store.Close()
}

// ListScans lists available scans
func ListScans(dbPath string, status string) ([]ScanInfo, error) {
	store, err := NewStore(dbPath)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	return store.ListScans(status)
}

// DeleteScan deletes a scan and its checkpoints
func DeleteScan(dbPath, scanID string) error {
	store, err := NewStore(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	return store.DeleteScan(scanID)
}

// generateScanID generates a unique scan ID
func generateScanID() string {
	return fmt.Sprintf("scan_%s", uuid.New().String()[:8])
}

// ResumeInfo contains information for resuming a scan
type ResumeInfo struct {
	ScanID           string
	TotalTargets     int64
	ProcessedCount   int64
	RemainingTargets []string
	PreviousResults  []models.ScanResult
	Config           map[string]interface{}
}

// IsResumable checks if a scan can be resumed
func IsResumable(dbPath, scanID string) bool {
	store, err := NewStore(dbPath)
	if err != nil {
		return false
	}
	defer store.Close()

	scanInfo, err := store.GetScan(scanID)
	if err != nil || scanInfo == nil {
		return false
	}

	// Can resume if status is running, paused, or failed
	if scanInfo.Status != "completed" {
		checkpoint, err := store.GetLatestCheckpoint(scanID)
		if err != nil {
			return false
		}
		return checkpoint != nil
	}

	return false
}
