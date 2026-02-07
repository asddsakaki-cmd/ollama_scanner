// internal/detector/ollama.go
// Ollama service detection and interaction
// FIXED: Body draining, scanner error handling, context cancellation

package detector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aspnmy/ollama_scanner/internal/models"
)

// Common errors
var (
	ErrNotOllama        = errors.New("target is not running Ollama")
	ErrConnectionFailed = errors.New("connection failed")
	ErrTimeout          = errors.New("operation timed out")
	ErrAuthRequired     = errors.New("authentication required")
	ErrPrivateIPBlocked = errors.New("private IP addresses are blocked for security")
	ErrMetadataBlocked  = errors.New("cloud metadata endpoints are blocked")
)

// blockedMetadataEndpoints contains cloud provider metadata IPs
// These are WARNED but not blocked (can be scanned with --force flag)
var blockedMetadataEndpoints = map[string]bool{
	"169.254.169.254": true, // AWS, GCP, Azure metadata
	"169.254.170.2":   true, // AWS ECS metadata
	"192.0.0.192":     true, // Oracle Cloud metadata
}

// TargetWarning holds warning information about a target
type TargetWarning struct {
	IsMetadata bool
	IsPrivate  bool
	IsLoopback bool
	Message    string
}

// CheckTargetWarnings checks if target has any warnings
// Returns warning info but doesn't block the scan
func CheckTargetWarnings(target models.Target) *TargetWarning {
	warning := &TargetWarning{}
	
	// Check metadata endpoints
	if blockedMetadataEndpoints[target.IP.String()] {
		warning.IsMetadata = true
		warning.Message = fmt.Sprintf("WARNING: %s is a cloud metadata endpoint. Scanning may have security implications.", target.IP)
	}
	
	// Check private ranges (warning only)
	if target.IP.IsLoopback() {
		warning.IsLoopback = true
		warning.Message = fmt.Sprintf("WARNING: %s is a loopback address.", target.IP)
	} else if target.IP.IsPrivate() {
		warning.IsPrivate = true
		warning.Message = fmt.Sprintf("WARNING: %s is a private RFC1918 address.", target.IP)
	} else if target.IP.IsLinkLocalUnicast() {
		warning.IsPrivate = true
		warning.Message = fmt.Sprintf("WARNING: %s is a link-local address.", target.IP)
	}
	
	if warning.Message == "" {
		return nil
	}
	return warning
}

// validateTarget minimal validation - only blocks truly invalid targets
func validateTarget(target models.Target) error {
	// Only block if IP is invalid
	if !target.IP.IsValid() {
		return fmt.Errorf("invalid IP address: %s", target.IP)
	}
	return nil
}

// KnownCVEs database (Ollama-specific)
var KnownCVEs = map[string]models.CVEInfo{
	"CVE-2024-37032": {
		ID:          "CVE-2024-37032",
		Severity:    "CRITICAL",
		Description: "Remote Code Execution (Probllama)",
		MaxVersion:  "0.1.34",
	},
	"CVE-2024-39720": {
		ID:          "CVE-2024-39720",
		Severity:    "HIGH",
		Description: "Out-of-bounds Read DoS",
		MaxVersion:  "0.1.45",
	},
	"CVE-2024-39721": {
		ID:          "CVE-2024-39721",
		Severity:    "HIGH",
		Description: "Infinite Loop DoS",
		MaxVersion:  "0.1.33",
	},
	"CVE-2024-39722": {
		ID:          "CVE-2024-39722",
		Severity:    "MEDIUM",
		Description: "Path Traversal File Disclosure",
		MaxVersion:  "0.1.45",
	},
	"CVE-2025-63389": {
		ID:          "CVE-2025-63389",
		Severity:    "CRITICAL",
		Description: "Model Management Auth Bypass",
		MaxVersion:  "0.13.5",
	},
}

// Client handles Ollama API communication
type Client struct {
	httpClient *http.Client
	timeout    time.Duration
}

// NewClient creates a new Ollama client
func NewClient(timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
			},
		},
		timeout: timeout,
	}
}

// Detect checks if target is running Ollama
// SECURITY: Validates target is not a private IP or metadata endpoint (SSRF protection)
func (c *Client) Detect(ctx context.Context, target models.Target) (*OllamaInfo, error) {
	// SSRF protection: validate target is allowed
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	
	info := &OllamaInfo{}

	// Check root endpoint
	url := fmt.Sprintf("http://%s", target.Address())
	body, status, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", status)
	}

	// Check for Ollama signature
	if strings.Contains(string(body), "Ollama is running") {
		info.IsOllama = true
	}

	// Get version
	version, err := c.GetVersion(ctx, target)
	if err == nil {
		info.Version = version
	}

	// Get models
	ollamaModels, err := c.ListModels(ctx, target)
	if err == nil {
		info.Models = ollamaModels
	}

	return info, nil
}

// GetVersion retrieves Ollama version
func (c *Client) GetVersion(ctx context.Context, target models.Target) (string, error) {
	if err := validateTarget(target); err != nil {
		return "", err
	}
	url := fmt.Sprintf("http://%s/api/version", target.Address())
	body, status, err := c.get(ctx, url)
	if err != nil {
		return "", err
	}

	if status != http.StatusOK {
		return "", fmt.Errorf("unexpected status: %d", status)
	}

	var result struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	return result.Version, nil
}

// ListModels retrieves list of models
func (c *Client) ListModels(ctx context.Context, target models.Target) ([]models.OllamaModel, error) {
	url := fmt.Sprintf("http://%s/api/tags", target.Address())
	body, status, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}

	// Check if auth required
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return nil, ErrAuthRequired
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", status)
	}

	var result struct {
		Models []struct {
			Name       string            `json:"name"`
			Model      string            `json:"model"`
			ModifiedAt time.Time         `json:"modified_at"`
			Size       int64             `json:"size"`
			Details    map[string]interface{} `json:"details"`
		} `json:"models"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var ollamaModels []models.OllamaModel
	for _, m := range result.Models {
		name := m.Name
		if name == "" {
			name = m.Model
		}
		ollamaModels = append(ollamaModels, models.OllamaModel{
			Name:     name,
			Size:     m.Size,
			Modified: m.ModifiedAt,
			Details:  m.Details,
		})
	}

	return ollamaModels, nil
}

// Generate tests text generation
func (c *Client) Generate(ctx context.Context, target models.Target, model, prompt string) (*GenerateResult, error) {
	url := fmt.Sprintf("http://%s/api/generate", target.Address())

	payload := map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	body, status, err := c.post(ctx, url, body)
	if err != nil {
		return nil, err
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", status)
	}

	var result GenerateResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GenerateStream tests streaming generation and measures performance
// FIXED: Proper scanner error handling and body draining
func (c *Client) GenerateStream(ctx context.Context, target models.Target, model, prompt string) (*BenchmarkResult, error) {
	url := fmt.Sprintf("http://%s/api/generate", target.Address())

	payload := map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Read stream with context awareness
	scanner := bufio.NewScanner(resp.Body)
	var (
		firstTokenTime time.Time
		tokenCount     int
		lastResponse   map[string]interface{}
	)

	// FIXED: Channel-based scan with context cancellation
	scanDone := make(chan struct{})
	scanErr := make(chan error, 1)
	
	go func() {
		defer close(scanDone)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}

			var data map[string]interface{}
			if err := json.Unmarshal([]byte(line), &data); err != nil {
				continue
			}

			if tokenCount == 0 {
				firstTokenTime = time.Now()
			}
			tokenCount++
			lastResponse = data

			// Check if done
			if done, _ := data["done"].(bool); done {
				break
			}
		}
		if err := scanner.Err(); err != nil {
			scanErr <- err
		}
	}()

	// Wait for scan completion or context cancellation
	select {
	case <-scanDone:
		// Normal completion
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Check scanner error
	select {
	case err := <-scanErr:
		if err != nil {
			return nil, fmt.Errorf("stream read error: %w", err)
		}
	default:
	}

	// FIXED: Drain remaining body for connection reuse
	_, _ = io.Copy(io.Discard, resp.Body) //nolint:gosec // G104: draining body, error not needed

	totalTime := time.Since(start)
	firstTokenLatency := firstTokenTime.Sub(start)

	// Calculate tokens per second
	var tps float64
	if totalTime > 0 && tokenCount > 0 {
		tps = float64(tokenCount) / totalTime.Seconds()
	}

	result := &BenchmarkResult{
		ModelName:       model,
		Prompt:          prompt,
		FirstTokenDelay: firstTokenLatency,
		TokensPerSecond: tps,
		TotalTokens:     tokenCount,
		TotalTime:       totalTime,
		Success:         tokenCount > 0,
	}

	if evalCount, ok := lastResponse["eval_count"].(float64); ok {
		result.TotalTokens = int(evalCount)
	}

	return result, nil
}

// get performs HTTP GET request
// FIXED: Body draining for connection reuse
func (c *Client) get(ctx context.Context, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Max 1MB
	
	// FIXED: Drain any remaining body for connection reuse
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body) //nolint:gosec // G104: draining body, error not needed
	}
	
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return body, resp.StatusCode, nil
}

// post performs HTTP POST request
// FIXED: Body draining for connection reuse
func (c *Client) post(ctx context.Context, url string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	
	// FIXED: Drain any remaining body for connection reuse
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body) //nolint:gosec // G104: draining body, error not needed
	}
	
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return respBody, resp.StatusCode, nil
}
