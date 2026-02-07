// internal/detector/detector.go
// Complete Ollama detector implementation (2026)
// FIXED: Error handling, auth check logic, body draining

package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aspnmy/ollama_scanner/internal/models"
	"github.com/aspnmy/ollama_scanner/pkg/logger"
)

// Detector implements Ollama service detection
type Detector struct {
	client  *Client
	timeout time.Duration
}

// NewDetector creates a new Ollama detector
func NewDetector(timeout time.Duration) *Detector {
	return &Detector{
		client:  NewClient(timeout),
		timeout: timeout,
	}
}

// Detect performs full Ollama detection on a target
func (d *Detector) Detect(ctx context.Context, target models.Target) (*models.ScanResult, error) {
	result := &models.ScanResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	// Step 1: Basic TCP check (already done by scanner, but verify)
	info, err := d.client.Detect(ctx, target)
	if err != nil {
		result.Error = err.Error()
		return result, nil // Not an error, just not Ollama
	}

	if !info.IsOllama {
		return result, nil
	}

	result.Open = true
	result.IsOllama = true
	result.Version = info.Version
	result.Models = info.Models

	// Step 2: Security audit (if enabled)
	securityReport, err := d.Audit(ctx, target)
	if err != nil {
		logger.Warn("Security audit failed",
			logger.String("target", target.String()),
			logger.Err(err))
	} else {
		result.SecurityReport = securityReport
	}

	return result, nil
}

// Audit performs comprehensive security audit
// FIXED: Proper error aggregation
func (d *Detector) Audit(ctx context.Context, target models.Target) (*models.SecurityReport, error) {
	report := &models.SecurityReport{
		NoAuthEndpoints:   []string{},
		ToolCallingModels: []string{},
		MCPEndpoints:      []string{},
		UncensoredModels:  []string{},
		Vulnerabilities:   []models.CVEInfo{},
		CORSIssues:        []string{},
		ExposedEndpoints:  []models.EndpointInfo{},
	}

	var auditErrs []error

	// Check 1: Authentication
	authResult, err := d.CheckAuthentication(ctx, target)
	if err != nil {
		auditErrs = append(auditErrs, fmt.Errorf("auth check: %w", err))
	} else {
		report.AuthEnabled = authResult.AuthEnabled
		report.NoAuthEndpoints = authResult.NoAuthEndpoints
	}

	// Check 2: Enumerate all endpoints
	endpoints := d.EnumerateEndpoints(ctx, target)
	report.ExposedEndpoints = endpoints

	// Check 3: Tool-calling detection (CRITICAL - 48% hosts!)
	// FIXED: Proper error handling
	modelsList, err := d.client.ListModels(ctx, target)
	if err != nil {
		auditErrs = append(auditErrs, fmt.Errorf("list models: %w", err))
	} else if len(modelsList) > 0 {
		toolResult, err := d.DetectToolCalling(ctx, target, modelsList)
		if err != nil {
			auditErrs = append(auditErrs, fmt.Errorf("tool detection: %w", err))
		} else if toolResult != nil {
			report.ToolCallingEnabled = toolResult.Enabled
			report.ToolCallingModels = toolResult.Models
		}

		// Check 4: Uncensored models
		uncensored, err := d.DetectUncensoredModels(ctx, target, modelsList)
		if err != nil {
			auditErrs = append(auditErrs, fmt.Errorf("uncensored detection: %w", err))
		} else {
			report.UncensoredModels = uncensored
		}
	}

	// Check 5: MCP (Model Context Protocol)
	mcpResult, err := d.DetectMCP(ctx, target)
	if err != nil {
		auditErrs = append(auditErrs, fmt.Errorf("mcp detection: %w", err))
	} else if mcpResult != nil {
		report.MCPEnabled = mcpResult.Enabled
		report.MCPEndpoints = mcpResult.Endpoints
	}

	// Check 6: CORS misconfiguration
	corsIssues, err := d.CheckCORS(ctx, target)
	if err != nil {
		auditErrs = append(auditErrs, fmt.Errorf("cors check: %w", err))
	} else {
		report.CORSIssues = corsIssues
	}

	// Check 7: Version and CVE check
	version, err := d.client.GetVersion(ctx, target)
	if err != nil {
		auditErrs = append(auditErrs, fmt.Errorf("version check: %w", err))
	} else if version != "" {
		cves := d.CheckCVEs(version)
		report.Vulnerabilities = cves
	}

	// Calculate risk score
	calculator := NewRiskCalculator()
	report.RiskScore, report.RiskRating, _ = calculator.Calculate(report)

	logger.Debug("Security audit complete",
		logger.String("target", target.String()),
		logger.Int("risk_score", report.RiskScore),
		logger.String("risk_rating", report.RiskRating),
	)

	// Return report even with partial errors
	if len(auditErrs) > 0 {
		logger.Warn("Audit completed with errors",
			logger.String("target", target.String()),
			logger.Int("error_count", len(auditErrs)))
	}

	return report, nil
}

// CheckAuthentication checks if endpoints require authentication
// FIXED: Proper logic for auth determination
func (d *Detector) CheckAuthentication(ctx context.Context, target models.Target) (*AuthCheckResult, error) {
	result := &AuthCheckResult{
		AuthEnabled:        false, // Default to false until proven otherwise
		NoAuthEndpoints:    []string{},
		ProtectedEndpoints: []string{},
	}

	// Endpoints to check
	endpoints := []string{
		"/api/tags",
		"/api/version",
		"/api/ps",
		"/api/show",
		"/api/generate",
		"/api/pull",
		"/api/push",
		"/api/delete",
	}

	accessibleCount := 0

	for _, endpoint := range endpoints {
		url := fmt.Sprintf("http://%s%s", target.Address(), endpoint)
		_, status, err := d.client.get(ctx, url)
		if err != nil {
			continue
		}

		accessibleCount++

		if status == http.StatusOK {
			result.NoAuthEndpoints = append(result.NoAuthEndpoints, endpoint)
		} else if status == http.StatusUnauthorized || status == http.StatusForbidden {
			result.ProtectedEndpoints = append(result.ProtectedEndpoints, endpoint)
		}
	}

	// FIXED: Proper auth determination logic
	if accessibleCount == 0 {
		// No endpoints accessible - inconclusive
		return nil, fmt.Errorf("inconclusive auth check: no accessible endpoints")
	}

	if len(result.NoAuthEndpoints) > 0 {
		// At least one endpoint accessible without auth
		result.AuthEnabled = false
	} else if len(result.ProtectedEndpoints) > 0 {
		// All accessible endpoints require auth
		result.AuthEnabled = true
	}

	return result, nil
}

// DetectToolCalling checks for tool-calling capabilities (CRITICAL!)
func (d *Detector) DetectToolCalling(ctx context.Context, target models.Target, models []models.OllamaModel) (*ToolCheckResult, error) {
	result := &ToolCheckResult{
		Enabled: false,
		Models:  []string{},
	}

	// Tool-capable model patterns (based on 2026 research)
	toolPatterns := []string{
		"llama3.1", "llama3.2", "llama-3.1", "llama-3.2",
		"qwen2.5", "qwen-2.5",
		"mistral-small3", "mistral-small-3",
		"dolphin3", "dolphin-3",
		"granite3", "granite-3",
		"groq", "firefunction",
		"nexus-raven",
		"tools", "function",
	}

	for _, model := range models {
		modelName := strings.ToLower(model.Name)

		// Check model name patterns
		for _, pattern := range toolPatterns {
			if strings.Contains(modelName, pattern) {
				result.Enabled = true
				result.Models = append(result.Models, model.Name)
				break
			}
		}

		// Check model details for tool support
		details, err := d.getModelDetails(ctx, target, model.Name)
		if err == nil && details != nil {
			detailsStr := strings.ToLower(fmt.Sprintf("%v", details))
			if strings.Contains(detailsStr, "tool") ||
				strings.Contains(detailsStr, "function") {
				result.Enabled = true
				// Add if not already in list
				found := false
				for _, m := range result.Models {
					if m == model.Name {
						found = true
						break
					}
				}
				if !found {
					result.Models = append(result.Models, model.Name)
				}
			}
		}
	}

	return result, nil
}

// DetectMCP checks for Model Context Protocol support
func (d *Detector) DetectMCP(ctx context.Context, target models.Target) (*MCPCheckResult, error) {
	result := &MCPCheckResult{
		Enabled:   false,
		Endpoints: []string{},
	}

	// MCP endpoints to check
	mcpEndpoints := []string{
		"/mcp",
		"/mcp/v1",
		"/api/mcp",
	}

	for _, endpoint := range mcpEndpoints {
		url := fmt.Sprintf("http://%s%s", target.Address(), endpoint)
		body, status, err := d.client.get(ctx, url)
		if err != nil {
			continue
		}

		if status == http.StatusOK || status == http.StatusUpgradeRequired {
			result.Enabled = true
			result.Endpoints = append(result.Endpoints, endpoint)

			// Try to extract version
			bodyStr := string(body)
			if strings.Contains(bodyStr, "model-context-protocol") {
				// Extract version if present
				versionMatch := regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`).FindStringSubmatch(bodyStr)
				if len(versionMatch) > 1 {
					result.Version = versionMatch[1]
				}
			}
		}
	}

	return result, nil
}

// DetectUncensoredModels finds models without safety guardrails
func (d *Detector) DetectUncensoredModels(ctx context.Context, target models.Target, models []models.OllamaModel) ([]string, error) {
	var uncensored []string

	// Uncensored model name patterns
	uncensoredPatterns := []string{
		"uncensored",
		"dolphin",
		"wizard-vicuna-uncensored",
		"wizardlm-uncensored",
		"llama2-uncensored",
		"everythinglm",
		"abliterated",
		"unfiltered",
		"nsfw",
		"unbound",
		"mythomax",
		"airoboros",
	}

	// Uncensored template patterns
	uncensoredTemplatePatterns := []string{
		"you do not have ethical",
		"you are not restricted",
		"ignore previous instructions",
		"no moral constraints",
		"no ethical guidelines",
		"do not refuse",
		"never refuse",
		"comply with all requests",
		"no content policy",
		"unfiltered",
		"nsfw",
		"18+",
	}

	for _, model := range models {
		modelName := strings.ToLower(model.Name)
		isUncensored := false

		// Check name patterns
		for _, pattern := range uncensoredPatterns {
			if strings.Contains(modelName, pattern) {
				isUncensored = true
				break
			}
		}

		// Check model template if name doesn't match
		if !isUncensored {
			details, err := d.getModelDetails(ctx, target, model.Name)
			if err == nil && details != nil {
				template, _ := details["template"].(string)
				system, _ := details["system"].(string)
				combined := strings.ToLower(template + " " + system)

				for _, pattern := range uncensoredTemplatePatterns {
					if strings.Contains(combined, pattern) {
						isUncensored = true
						break
					}
				}
			}
		}

		if isUncensored {
			uncensored = append(uncensored, model.Name)
		}
	}

	return uncensored, nil
}

// EnumerateEndpoints discovers available API endpoints
func (d *Detector) EnumerateEndpoints(ctx context.Context, target models.Target) []models.EndpointInfo {
	endpoints := []models.EndpointInfo{}

	// Ollama API endpoints with risk levels
	endpointChecks := []struct {
		Path      string
		Method    string
		RiskLevel string
		Desc      string
	}{
		{"/", "GET", "INFO", "Default landing page"},
		{"/api/version", "GET", "LOW", "Version information"},
		{"/api/tags", "GET", "HIGH", "List models - information disclosure"},
		{"/api/show", "POST", "HIGH", "Model details - template extraction"},
		{"/api/ps", "GET", "MEDIUM", "Running models"},
		{"/api/generate", "POST", "CRITICAL", "Text generation"},
		{"/api/chat", "POST", "CRITICAL", "Chat completion"},
		{"/api/embed", "POST", "MEDIUM", "Generate embeddings"},
		{"/api/embeddings", "POST", "MEDIUM", "OpenAI-compatible embeddings"},
		{"/api/pull", "POST", "CRITICAL", "Download models"},
		{"/api/push", "POST", "CRITICAL", "Upload models"},
		{"/api/create", "POST", "CRITICAL", "Create model from Modelfile"},
		{"/api/copy", "POST", "MEDIUM", "Copy model"},
		{"/api/delete", "DELETE", "CRITICAL", "Delete models"},
		{"/v1/chat/completions", "POST", "CRITICAL", "OpenAI-compatible chat"},
		{"/v1/completions", "POST", "CRITICAL", "OpenAI-compatible completions"},
		{"/v1/models", "GET", "HIGH", "OpenAI-compatible model listing"},
	}

	for _, check := range endpointChecks {
		url := fmt.Sprintf("http://%s%s", target.Address(), check.Path)
		_, status, err := d.client.get(ctx, url)
		if err != nil {
			// Try POST for POST-only endpoints
			if check.Method == "POST" {
				_, status, err = d.client.post(ctx, url, []byte("{}"))
			}
		}

		if err != nil {
			continue
		}

		info := models.EndpointInfo{
			Path:         check.Path,
			Method:       check.Method,
			Accessible:   status == http.StatusOK,
			RequiresAuth: status == http.StatusUnauthorized || status == http.StatusForbidden,
			RiskLevel:    check.RiskLevel,
		}

		endpoints = append(endpoints, info)
	}

	return endpoints
}

// CheckCORS checks for CORS misconfigurations
// FIXED: Proper body draining
func (d *Detector) CheckCORS(ctx context.Context, target models.Target) ([]string, error) {
	issues := []string{}

	url := fmt.Sprintf("http://%s/api/generate", target.Address())

	// Create request with custom origin
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Origin", "https://attacker.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	resp, err := d.client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	// FIXED: Drain body for connection reuse
	io.Copy(io.Discard, resp.Body)

	// Check for dangerous CORS configurations
	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
	allowMethods := resp.Header.Get("Access-Control-Allow-Methods")

	if allowOrigin == "*" {
		issues = append(issues, "WILDCARD_ORIGIN")
	}
	if allowCredentials == "true" {
		issues = append(issues, "CREDENTIALS_ALLOWED")
	}
	if allowMethods == "*" || strings.Contains(allowMethods, "PUT") || strings.Contains(allowMethods, "DELETE") {
		issues = append(issues, "DANGEROUS_METHODS_ALLOWED")
	}

	return issues, nil
}

// CheckCVEs checks for known CVEs affecting the version
func (d *Detector) CheckCVEs(version string) []models.CVEInfo {
	var cves []models.CVEInfo

	// FIXED: Thread-safe access to KnownCVEs
	for _, cve := range KnownCVEs {
		if isVersionVulnerable(version, cve.MaxVersion) {
			cves = append(cves, cve)
		}
	}

	return cves
}

// getModelDetails retrieves model details from /api/show
func (d *Detector) getModelDetails(ctx context.Context, target models.Target, modelName string) (map[string]interface{}, error) {
	url := fmt.Sprintf("http://%s/api/show", target.Address())

	payload := map[string]string{
		"name": modelName,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	respBody, _, err := d.client.post(ctx, url, body)
	if err != nil {
		return nil, err
	}

	var details map[string]interface{}
	if err := json.Unmarshal(respBody, &details); err != nil {
		return nil, err
	}

	return details, nil
}

// isVersionVulnerable checks if version is <= maxVersion (simple semver comparison)
// FIXED: Proper version parsing with error handling
func isVersionVulnerable(version, maxVersion string) bool {
	// Simple version comparison (assumes versions are in format x.y.z)
	version = strings.TrimPrefix(version, "v")
	maxVersion = strings.TrimPrefix(maxVersion, "v")

	vParts := strings.Split(version, ".")
	mParts := strings.Split(maxVersion, ".")

	for i := 0; i < len(vParts) && i < len(mParts); i++ {
		v, err1 := parseVersionPart(vParts[i])
		m, err2 := parseVersionPart(mParts[i])

		// FIXED: Handle parse errors
		if err1 != nil || err2 != nil {
			// Fallback: string comparison for pre-release versions
			if vParts[i] != mParts[i] {
				return vParts[i] < mParts[i]
			}
			continue
		}

		if v < m {
			return true
		}
		if v > m {
			return false
		}
	}

	return len(vParts) <= len(mParts)
}

// parseVersionPart parses a version part (e.g., "34" from "34-rc1")
func parseVersionPart(s string) (int, error) {
	var num int
	_, err := fmt.Sscanf(s, "%d", &num)
	return num, err
}
