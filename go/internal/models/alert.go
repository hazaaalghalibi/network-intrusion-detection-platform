package models

import "time"

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityRank lets detectors compare/upgrade severities without string logic.
var severityRank = map[Severity]int{
	SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4,
}

// Max returns the higher-ranked of the two severities.
func (s Severity) Max(other Severity) Severity {
	if severityRank[other] > severityRank[s] {
		return other
	}
	return s
}

type AlertStatus string

const (
	StatusOpen          AlertStatus = "open"
	StatusInvestigating AlertStatus = "investigating"
	StatusResolved      AlertStatus = "resolved"
	StatusFalsePositive AlertStatus = "false_positive"
)

type AlertType string

const (
	AlertPortScan       AlertType = "port_scan"
	AlertBruteForce     AlertType = "brute_force"
	AlertDNSAnomaly     AlertType = "dns_anomaly"
	AlertKnownBadIP     AlertType = "known_bad_ip"
	AlertKnownBadDomain AlertType = "known_bad_domain"
	AlertHighVolume     AlertType = "high_volume_traffic"
	AlertBeaconing      AlertType = "beaconing"
	AlertSuricataIDS    AlertType = "suricata_ids"
	AlertMalwareFile    AlertType = "malware_file_match"
)

// ThreatIntelMatch records one local-blocklist hit used to enrich an alert.
type ThreatIntelMatch struct {
	Indicator     string `json:"indicator"`
	IndicatorType string `json:"indicator_type"` // "ip" | "domain"
	Category      string `json:"category"`
	Source        string `json:"source"`
	Confidence    string `json:"confidence"`
}

// Alert is what the detection engine emits onto the Redis stream, what the
// worker persists to OpenSearch + Postgres, and what the API serves back to
// analysts.
type Alert struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	AlertType   AlertType `json:"alert_type"`
	Severity    Severity  `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`

	SrcIP         string `json:"src_ip,omitempty"`
	DstIP         string `json:"dst_ip,omitempty"`
	DstPort       int    `json:"dst_port,omitempty"`
	AssetHostname string `json:"asset_hostname,omitempty"`

	EventCount  int                `json:"event_count"`
	ThreatIntel []ThreatIntelMatch `json:"threat_intel,omitempty"`
	SourceRefs  []string           `json:"source_refs,omitempty"`

	Status    AlertStatus `json:"status"`
	UpdatedAt time.Time   `json:"updated_at"`
}

// IndexName returns the daily OpenSearch index this alert belongs in.
func (a Alert) IndexName() string {
	return "alerts-" + a.CreatedAt.Format("2006.01.02")
}
