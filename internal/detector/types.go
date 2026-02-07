// internal/detector/types.go
// Type definitions for Ollama detector

package detector

import (
	"time"

	"github.com/aspnmy/ollama_scanner/internal/models"
)

// OllamaInfo contains basic Ollama service information
type OllamaInfo struct {
	IsOllama  bool                `json:"is_ollama"`
	Version   string              `json:"version"`
	Models    []models.OllamaModel `json:"models,omitempty"`
	Endpoints []string            `json:"endpoints,omitempty"`
}

// BenchmarkResult contains performance test results
type BenchmarkResult struct {
	ModelName       string        `json:"model_name"`
	Prompt          string        `json:"prompt"`
	FirstTokenDelay time.Duration `json:"first_token_delay"`
	TokensPerSecond float64       `json:"tokens_per_second"`
	TotalTokens     int           `json:"total_tokens"`
	TotalTime       time.Duration `json:"total_time"`
	Success         bool          `json:"success"`
	Error           string        `json:"error,omitempty"`
}

// AuthCheckResult contains authentication check results
type AuthCheckResult struct {
	AuthEnabled        bool     `json:"auth_enabled"`
	NoAuthEndpoints    []string `json:"no_auth_endpoints,omitempty"`
	ProtectedEndpoints []string `json:"protected_endpoints,omitempty"`
}

// ToolCheckResult contains tool-calling detection results
type ToolCheckResult struct {
	Enabled       bool     `json:"enabled"`
	Models        []string `json:"models,omitempty"`
	Executable    bool     `json:"executable"`
	ToolEndpoints []string `json:"tool_endpoints,omitempty"`
}

// MCPCheckResult contains MCP detection results
type MCPCheckResult struct {
	Enabled   bool     `json:"enabled"`
	Endpoints []string `json:"endpoints,omitempty"`
	Version   string   `json:"version,omitempty"`
}

// GenerateResult holds generate API response
type GenerateResult struct {
	Model     string `json:"model"`
	Response  string `json:"response"`
	Done      bool   `json:"done"`
	EvalCount int    `json:"eval_count"`
}


