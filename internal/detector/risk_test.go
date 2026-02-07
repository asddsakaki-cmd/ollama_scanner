// internal/detector/risk_test.go
// Unit tests for risk calculator

package detector

import (
	"testing"

	"github.com/aspnmy/ollama_scanner/internal/models"
)

func TestNewRiskCalculator(t *testing.T) {
	rc := NewRiskCalculator()
	if rc == nil {
		t.Fatal("NewRiskCalculator() returned nil")
	}

	if rc.targetLossRate != 0.01 {
		t.Errorf("targetLossRate = %f, want 0.01", rc.targetLossRate)
	}
}

func TestRiskScoreCalculator_Calculate(t *testing.T) {
	rc := NewRiskCalculator()

	tests := []struct {
		name       string
		report     *models.SecurityReport
		wantScore  int
		wantRating string
		wantErr    bool
	}{
		{
			name:       "nil report",
			report:     nil,
			wantScore:  0,
			wantRating: "UNKNOWN",
			wantErr:    true,
		},
		{
			name: "minimal risk - secure",
			report: &models.SecurityReport{
				AuthEnabled:        true,
				ToolCallingEnabled: false,
				MCPEnabled:         false,
				ExposedEndpoints:   []models.EndpointInfo{},
			},
			wantScore:  1,
			wantRating: "MINIMAL",
			wantErr:    false,
		},
		{
			name: "high risk - no auth + tool calling",
			report: &models.SecurityReport{
				AuthEnabled:        false,
				ToolCallingEnabled: true,
				ToolCallingModels:  []string{"llama3.1"},
				MCPEnabled:         false,
				ExposedEndpoints: []models.EndpointInfo{
					{Path: "/api/generate", Accessible: true, RiskLevel: "CRITICAL"},
				},
			},
			wantScore:  7,
			wantRating: "HIGH",
			wantErr:    false,
		},
		{
			name: "critical risk - all bad",
			report: &models.SecurityReport{
				AuthEnabled:        false,
				ToolCallingEnabled: true,
				ToolCallingModels:  []string{"llama3.1", "qwen2.5"},
				MCPEnabled:         true,
				UncensoredModels:   []string{"dolphin"},
				ExposedEndpoints: []models.EndpointInfo{
					{Path: "/api/generate", Accessible: true, RiskLevel: "CRITICAL"},
					{Path: "/api/pull", Accessible: true, RiskLevel: "CRITICAL"},
				},
				Vulnerabilities: []models.CVEInfo{
					{Severity: "CRITICAL"},
				},
			},
			wantScore:  10,
			wantRating: "CRITICAL",
			wantErr:    false,
		},
		{
			name: "CVE overflow protection",
			report: &models.SecurityReport{
				AuthEnabled:      true,
				ExposedEndpoints: []models.EndpointInfo{},
				Vulnerabilities: []models.CVEInfo{
					{Severity: "CRITICAL"},
					{Severity: "CRITICAL"},
					{Severity: "CRITICAL"},
					{Severity: "CRITICAL"},
					{Severity: "CRITICAL"},
					{Severity: "CRITICAL"},
					{Severity: "CRITICAL"},
					{Severity: "CRITICAL"},
					{Severity: "CRITICAL"},
					{Severity: "CRITICAL"}, // 10 critical CVEs
				},
			},
			wantScore:  4, // Should be capped, not 10+ from CVEs alone
			wantRating: "MEDIUM",
			wantErr:    false,
		},
		{
			name: "management endpoints exposed",
			report: &models.SecurityReport{
				AuthEnabled:      false,
				ExposedEndpoints: []models.EndpointInfo{
					{Path: "/api/pull", Accessible: true, RiskLevel: "CRITICAL"},
					{Path: "/api/delete", Accessible: true, RiskLevel: "CRITICAL"},
				},
			},
			wantScore:  4,
			wantRating: "MEDIUM",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, rating, err := rc.Calculate(tt.report)

			if (err != nil) != tt.wantErr {
				t.Errorf("Calculate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if score != tt.wantScore {
				t.Errorf("Calculate() score = %d, want %d", score, tt.wantScore)
			}

			if rating != tt.wantRating {
				t.Errorf("Calculate() rating = %s, want %s", rating, tt.wantRating)
			}
		})
	}
}

func TestRiskScoreCalculator_GetRating(t *testing.T) {
	rc := NewRiskCalculator()

	tests := []struct {
		score int
		want  string
	}{
		{0, "MINIMAL"},
		{1, "MINIMAL"},
		{2, "LOW"},
		{3, "LOW"},
		{4, "MEDIUM"},
		{5, "MEDIUM"},
		{6, "MEDIUM"},
		{7, "HIGH"},
		{8, "HIGH"},
		{9, "CRITICAL"},
		{10, "CRITICAL"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := rc.GetRating(tt.score)
			if got != tt.want {
				t.Errorf("GetRating(%d) = %s, want %s", tt.score, got, tt.want)
			}
		})
	}
}

func TestRiskScoreCalculator_GetRatingDescription(t *testing.T) {
	rc := NewRiskCalculator()

	tests := []struct {
		rating string
		want   string
	}{
		{"CRITICAL", "Immediate action required"},
		{"HIGH", "Severe risk"},
		{"MEDIUM", "Moderate risk"},
		{"LOW", "Low risk"},
		{"MINIMAL", "Minimal risk"},
		{"UNKNOWN", "Unknown risk level"},
	}

	for _, tt := range tests {
		t.Run(tt.rating, func(t *testing.T) {
			got := rc.GetRatingDescription(0, tt.rating)
			if got == "" {
				t.Errorf("GetRatingDescription(%s) returned empty string", tt.rating)
			}

			// Check that description contains expected keywords
			contains := false
			for _, keyword := range []string{"Immediate", "Severe", "Moderate", "Low", "Minimal", "Unknown"} {
				if len(got) > 0 && got[0:len(keyword)] == keyword || (len(keyword) <= len(got) && containsSubstring(got, keyword)) {
					contains = true
					break
				}
			}

			if !contains {
				t.Errorf("GetRatingDescription(%s) = %s, doesn't contain expected keywords", tt.rating, got)
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestRiskScoreCalculator_GetRecommendations(t *testing.T) {
	rc := NewRiskCalculator()

	tests := []struct {
		name   string
		report *models.SecurityReport
		minLen int
	}{
		{
			name: "no auth",
			report: &models.SecurityReport{
				AuthEnabled: false,
			},
			minLen: 4, // Baseline recommendations
		},
		{
			name: "tool calling enabled",
			report: &models.SecurityReport{
				AuthEnabled:        true,
				ToolCallingEnabled: true,
			},
			minLen: 4,
		},
		{
			name: "all issues",
			report: &models.SecurityReport{
				AuthEnabled:        false,
				ToolCallingEnabled: true,
				MCPEnabled:         true,
				UncensoredModels:   []string{"dolphin"},
				Vulnerabilities:    []models.CVEInfo{{Severity: "CRITICAL"}},
			},
			minLen: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rc.GetRecommendations(tt.report)
			if len(got) < tt.minLen {
				t.Errorf("GetRecommendations() returned %d recommendations, want at least %d", len(got), tt.minLen)
			}
		})
	}
}

func TestRiskScoreCalculator_CalculateThreatLevel(t *testing.T) {
	rc := NewRiskCalculator()

	tests := []struct {
		name   string
		report *models.SecurityReport
		want   string
	}{
		{
			name: "low threat",
			report: &models.SecurityReport{
				AuthEnabled: true,
			},
			want: "LOW",
		},
		{
			name: "medium threat",
			report: &models.SecurityReport{
				AuthEnabled: false,
			},
			want: "MEDIUM",
		},
		{
			name: "high threat",
			report: &models.SecurityReport{
				AuthEnabled:        false,
				ToolCallingEnabled: true,
			},
			want: "HIGH",
		},
		{
			name: "critical threat",
			report: &models.SecurityReport{
				AuthEnabled:        false,
				ToolCallingEnabled: true,
				MCPEnabled:         true,
				UncensoredModels:   []string{"dolphin"},
				Vulnerabilities:    []models.CVEInfo{{Severity: "CRITICAL"}},
			},
			want: "CRITICAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rc.CalculateThreatLevel(tt.report)
			if got[0:len(tt.want)] != tt.want {
				t.Errorf("CalculateThreatLevel() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRiskScoreCalculator_hasManagementEndpointsExposed(t *testing.T) {
	rc := NewRiskCalculator()

	tests := []struct {
		name   string
		report *models.SecurityReport
		want   bool
	}{
		{
			name: "no management endpoints",
			report: &models.SecurityReport{
				ExposedEndpoints: []models.EndpointInfo{
					{Path: "/api/tags", Accessible: true},
				},
			},
			want: false,
		},
		{
			name: "management endpoint exposed",
			report: &models.SecurityReport{
				ExposedEndpoints: []models.EndpointInfo{
					{Path: "/api/pull", Accessible: true},
				},
			},
			want: true,
		},
		{
			name: "management endpoint not accessible",
			report: &models.SecurityReport{
				ExposedEndpoints: []models.EndpointInfo{
					{Path: "/api/pull", Accessible: false},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rc.hasManagementEndpointsExposed(tt.report)
			if got != tt.want {
				t.Errorf("hasManagementEndpointsExposed() = %v, want %v", got, tt.want)
			}
		})
	}
}
