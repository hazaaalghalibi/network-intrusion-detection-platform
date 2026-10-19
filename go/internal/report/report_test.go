package report

import (
	"strings"
	"testing"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

func TestGenerateMarkdownIncludesKeySections(t *testing.T) {
	alert := models.Alert{
		ID:          "test-id-1",
		CreatedAt:   time.Date(2026, 6, 30, 14, 3, 30, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 6, 30, 14, 10, 0, 0, time.UTC),
		AlertType:   models.AlertBruteForce,
		Severity:    models.SeverityCritical,
		Title:       "SSH brute force from 198.51.100.23 against 10.0.0.10",
		Description: "24 failed SSH authentication attempts.",
		SrcIP:       "198.51.100.23",
		DstIP:       "10.0.0.10",
		DstPort:     22,
		EventCount:  24,
		ThreatIntel: []models.ThreatIntelMatch{
			{Indicator: "198.51.100.23", IndicatorType: "ip", Category: "scanner", Source: "internal-honeypot", Confidence: "high"},
		},
		Status: models.StatusInvestigating,
	}
	notes := []models.AlertNote{
		{Author: "analyst1", Note: "Confirmed compromised host, isolating.", CreatedAt: time.Date(2026, 6, 30, 14, 20, 0, 0, time.UTC)},
	}

	md := GenerateMarkdown(alert, notes)

	for _, want := range []string{
		"# Incident Report:",
		"## Summary",
		"## Indicators",
		"## Threat intelligence matches",
		"## Analyst notes",
		"## Recommended next steps",
		"198.51.100.23",
		"10.0.0.10",
		"Confirmed compromised host",
		"Rotate credentials",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report missing expected content %q\n---\n%s", want, md)
		}
	}
}

func TestGenerateMarkdownHandlesNoNotes(t *testing.T) {
	alert := models.Alert{ID: "x", AlertType: models.AlertPortScan, Severity: models.SeverityMedium}
	md := GenerateMarkdown(alert, nil)
	if !strings.Contains(md, "No analyst notes recorded") {
		t.Error("expected placeholder text when there are no notes")
	}
}
