// Package models holds the normalized types shared across ingest, worker,
// and api: the common Event schema (step 2 of the pipeline: "normalize
// events into a common alert format") and the Alert schema produced by
// the detection engine.
package models

import "time"

// EventSource identifies which upstream tool produced a normalized Event.
type EventSource string

const (
	SourceZeekConn EventSource = "zeek_conn"
	SourceZeekDNS  EventSource = "zeek_dns"
	SourceZeekSSH  EventSource = "zeek_ssh"
	SourceSuricata EventSource = "suricata_alert"
)

// Event is the common normalized representation of a single raw log line,
// regardless of whether it originated from a Zeek log or a Suricata alert.
// Fields not applicable to a given source are left zero-valued.
type Event struct {
	ID        string      `json:"id"`
	Timestamp time.Time   `json:"timestamp"`
	Source    EventSource `json:"source"`

	SrcIP   string `json:"src_ip,omitempty"`
	SrcPort int    `json:"src_port,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	DstPort int    `json:"dst_port,omitempty"`
	Proto   string `json:"proto,omitempty"`
	Service string `json:"service,omitempty"`

	// conn.log fields
	Duration  float64 `json:"duration,omitempty"`
	OrigBytes int64   `json:"orig_bytes,omitempty"`
	RespBytes int64   `json:"resp_bytes,omitempty"`
	ConnState string  `json:"conn_state,omitempty"`

	// dns.log fields
	DNSQuery string `json:"dns_query,omitempty"`
	DNSQType string `json:"dns_qtype,omitempty"`
	DNSRcode string `json:"dns_rcode,omitempty"`

	// ssh.log fields
	SSHAuthSuccess *bool `json:"ssh_auth_success,omitempty"`
	SSHAttempts    int   `json:"ssh_auth_attempts,omitempty"`

	// Suricata eve.json alert fields
	SuricataSignature string `json:"suricata_signature,omitempty"`
	SuricataCategory  string `json:"suricata_category,omitempty"`
	SuricataSeverity  int    `json:"suricata_severity,omitempty"`
}

// IndexName returns the daily OpenSearch index this event belongs in,
// following the common "events-YYYY.MM.DD" convention.
func (e Event) IndexName() string {
	return "events-" + e.Timestamp.Format("2006.01.02")
}
