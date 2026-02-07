// internal/detector/risk.go
// Risk scoring calculator based on SentinelOne/Censys research (Jan 2026)
// FIXED: CVE overflow, double counting, proper thresholds

package detector

import (
	"errors"
	"math"

	"github.com/aspnmy/ollama_scanner/internal/models"
)

// RiskScoreCalculator calculates security risk scores (1-10)
type RiskScoreCalculator struct {
	targetLossRate float64 // Target packet loss rate for adaptive control
}

// NewRiskCalculator creates a new risk calculator
func NewRiskCalculator() *RiskScoreCalculator {
	return &RiskScoreCalculator{
		targetLossRate: 0.01, // 1% default
	}
}

// Calculate computes risk score (1-10) and rating from security report
// FIXED: CVE overflow cap, remove double counting
func (rc *RiskScoreCalculator) Calculate(report *models.SecurityReport) (int, string, error) {
	if report == nil {
		return 0, "UNKNOWN", errors.New("nil security report")
	}

	score := 0.0

	// 1. Base exposure risk (only if we have data)
	if len(report.ExposedEndpoints) > 0 {
		score += 1.5
	}

	// 2. Authentication status (CRITICAL factor)
	// FIXED: Only count critical unauth endpoints
	if !report.AuthEnabled {
		criticalUnauth := 0
		for _, endpoint := range report.ExposedEndpoints {
			if endpoint.Accessible && !endpoint.RequiresAuth && endpoint.RiskLevel == "CRITICAL" {
				criticalUnauth++
			}
		}
		score += math.Min(float64(criticalUnauth)*1.5, 3.0) // Max +3
	}

	// 3. Tool-calling capability (48% hosts - MAJOR RISK!)
	// Based on TheHackerNews Jan 2026: "48% of exposed hosts have tool-calling"
	if report.ToolCallingEnabled {
		score += 2.5
		// Extra risk if many models support tools
		if len(report.ToolCallingModels) > 2 {
			score += 0.5
		}
	}

	// 4. MCP (Model Context Protocol) support (New 2026 risk)
	if report.MCPEnabled {
		score += 2.0
	}

	// 5. Uncensored Models (201+ hosts found)
	if len(report.UncensoredModels) > 0 {
		score += 1.0
		if len(report.UncensoredModels) > 3 {
			score += 0.5
		}
	}

	// 6. Model management endpoints exposed
	// FIXED: Use helper function for consistency
	managementExposed := rc.hasManagementEndpointsExposed(report)
	if managementExposed {
		score += 1.5
	}

	// 7. CVE vulnerabilities
	// FIXED: Cap CVE score to prevent overflow
	cveScore := 0.0
	for _, cve := range report.Vulnerabilities {
		switch cve.Severity {
		case "CRITICAL":
			cveScore += 1.0
		case "HIGH":
			cveScore += 0.7
		case "MEDIUM":
			cveScore += 0.4
		case "LOW":
			cveScore += 0.2
		}
	}
	// Cap CVE contribution at 3.0
	score += math.Min(cveScore, 3.0)

	// 8. CORS misconfiguration
	if len(report.CORSIssues) > 0 {
		score += 0.5
	}

	// FIXED: Remove section 9 (double counting of critical endpoints)
	// The critical unauth endpoints are already counted in section 2

	// Validate and cap at 10
	finalScore := int(math.Min(math.Max(score, 0.0), 10.0))
	if finalScore < 1 && score > 0 {
		finalScore = 1
	}

	rating := rc.GetRating(finalScore)

	return finalScore, rating, nil
}

// hasManagementEndpointsExposed checks if management endpoints are exposed
// FIXED: Single source of truth for management endpoints
func (rc *RiskScoreCalculator) hasManagementEndpointsExposed(report *models.SecurityReport) bool {
	managementPaths := []string{"/api/pull", "/api/push", "/api/delete", "/api/create"}
	
	for _, endpoint := range report.ExposedEndpoints {
		if !endpoint.Accessible {
			continue
		}
		for _, path := range managementPaths {
			if endpoint.Path == path {
				return true
			}
		}
	}
	return false
}

// GetRating returns risk rating string from score
// FIXED: More granular distribution
func (rc *RiskScoreCalculator) GetRating(score int) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score >= 2:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

// GetRatingDescription returns detailed description for rating
func (rc *RiskScoreCalculator) GetRatingDescription(score int, rating string) string {
	descriptions := map[string]string{
		"CRITICAL": "Immediate action required - instance is highly vulnerable to LLMjacking and unauthorized access",
		"HIGH":     "Severe risk - tool-calling or management endpoints exposed without authentication",
		"MEDIUM":   "Moderate risk - multiple security issues present that should be addressed",
		"LOW":      "Low risk - some exposure but limited impact",
		"MINIMAL":  "Minimal risk - good security posture with proper authentication",
	}

	desc, ok := descriptions[rating]
	if !ok {
		return "Unknown risk level"
	}
	return desc
}

// GetRecommendations returns security recommendations based on findings
// FIXED: Use helper function for consistency
func (rc *RiskScoreCalculator) GetRecommendations(report *models.SecurityReport) []string {
	recommendations := []string{}

	if !report.AuthEnabled {
		recommendations = append(recommendations,
			"IMMEDIATE: Enable authentication on all Ollama endpoints",
			"Use reverse proxy with OAuth2/API keys (e.g., nginx with auth)",
		)
	}

	if report.ToolCallingEnabled {
		recommendations = append(recommendations,
			"CRITICAL: Disable tool-calling if not required (48% of exposed hosts have this enabled)",
			"Tool-enabled endpoints can execute privileged operations without proper sandboxing",
		)
	}

	if report.MCPEnabled {
		recommendations = append(recommendations,
			"Disable MCP (Model Context Protocol) if not needed",
			"MCP allows LLM to interact with Kubernetes, cloud services, and shell commands",
		)
	}

	if len(report.UncensoredModels) > 0 {
		recommendations = append(recommendations,
			"Review uncensored models - they bypass safety guardrails",
			"Consider using models with built-in safety filters",
		)
	}

	// FIXED: Use helper function for consistency
	managementExposed := rc.hasManagementEndpointsExposed(report)
	if managementExposed {
		recommendations = append(recommendations,
			"Restrict access to model management endpoints (/api/pull, /api/delete)",
			"These endpoints can be used for DoS attacks or model theft",
		)
	}

	if len(report.Vulnerabilities) > 0 {
		recommendations = append(recommendations,
			"Update Ollama to latest version to patch known CVEs",
		)
	}

	if len(report.CORSIssues) > 0 {
		recommendations = append(recommendations,
			"Fix CORS configuration - avoid wildcard origins",
		)
	}

	// Always add baseline recommendations
	recommendations = append(recommendations,
		"Bind Ollama to 127.0.0.1 only (OLLAMA_HOST=127.0.0.1)",
		"Implement network segmentation/firewall rules",
		"Enable audit logging for all API calls",
		"Monitor for LLMjacking indicators (unusual token usage patterns)",
	)

	return recommendations
}

// CalculateThreatLevel returns threat level for LLMjacking likelihood
func (rc *RiskScoreCalculator) CalculateThreatLevel(report *models.SecurityReport) string {
	// Based on Operation Bizarre Bazaar research
	threatScore := 0

	if !report.AuthEnabled {
		threatScore += 3
	}
	if report.ToolCallingEnabled {
		threatScore += 3
	}
	if report.MCPEnabled {
		threatScore += 2
	}
	if len(report.UncensoredModels) > 0 {
		threatScore += 1
	}
	if len(report.Vulnerabilities) > 0 {
		threatScore += 1
	}

	switch {
	case threatScore >= 7:
		return "CRITICAL - Prime target for LLMjacking"
	case threatScore >= 5:
		return "HIGH - Likely target for automated scanning"
	case threatScore >= 3:
		return "MEDIUM - May be targeted"
	default:
		return "LOW - Unlikely to be targeted"
	}
}
