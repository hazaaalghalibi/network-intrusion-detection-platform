// Package detect is the detection engine: it turns a stream of normalized
// models.Event into models.Alert, using Redis-backed sliding windows so the
// same logic works whether events arrive live or are replayed in a batch.
// Each exported Detect*/Process* method corresponds to one requirement from
// the project brief (port scanning, brute force, DNS anomalies, known-bad
// IPs, high-volume traffic, beaconing, Suricata passthrough, YARA matches)
// and to one Sigma rule under rules/sigma/.
package detect

import (
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
	"github.com/tsebro/network-intrusion-detection-platform/internal/threatintel"
)

type Engine struct {
	rdb       *redis.Client
	ti        *threatintel.Blocklist
	hostnames map[string]string // ip -> hostname, from data/assets.json
}

func NewEngine(rdb *redis.Client, ti *threatintel.Blocklist, hostnames map[string]string) *Engine {
	return &Engine{rdb: rdb, ti: ti, hostnames: hostnames}
}

func (e *Engine) hostnameFor(ip string) string {
	return e.hostnames[ip]
}

func newAlert(ts time.Time, t models.AlertType, sev models.Severity, title, desc string) models.Alert {
	return models.Alert{
		ID:          uuid.NewString(),
		CreatedAt:   ts,
		AlertType:   t,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Status:      models.StatusOpen,
		EventCount:  1,
	}
}

// enrichIP checks each given IP against the threat intel blocklist, attaches
// any matches to the alert, and escalates severity based on match
// confidence. This is the "enrich alerts with threat intelligence... assign
// severity" step applied uniformly across detectors.
func (e *Engine) enrichIP(a *models.Alert, ips ...string) {
	seen := map[string]bool{}
	for _, ip := range ips {
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		if m, ok := e.ti.MatchIP(ip); ok {
			a.ThreatIntel = append(a.ThreatIntel, m)
			a.Severity = a.Severity.Max(confidenceSeverity(m.Confidence))
		}
	}
}

// confidenceSeverity maps a threat-intel confidence rating onto this
// platform's severity scale. Even a "low" confidence match is a confirmed
// indicator hit, so it floors at Medium rather than falling to Low —
// unrecognized/missing confidence values use that same safe default.
func confidenceSeverity(confidence string) models.Severity {
	switch confidence {
	case "high":
		return models.SeverityCritical
	case "medium":
		return models.SeverityHigh
	default:
		return models.SeverityMedium
	}
}
