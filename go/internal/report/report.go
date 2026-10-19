// Package report generates analyst-ready incident reports from an alert and
// its notes — the "export incident report" analyst workflow requirement.
package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

// GenerateMarkdown builds a standard-shape IR report for a single alert:
// summary, indicators, threat intel, analyst notes, recommended next steps.
func GenerateMarkdown(a models.Alert, notes []models.AlertNote) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Incident Report: %s\n\n", a.Title)
	fmt.Fprintf(&b, "- **Alert ID:** `%s`\n", a.ID)
	fmt.Fprintf(&b, "- **Alert type:** %s\n", a.AlertType)
	fmt.Fprintf(&b, "- **Severity:** %s\n", strings.ToUpper(string(a.Severity)))
	fmt.Fprintf(&b, "- **Status:** %s\n", a.Status)
	fmt.Fprintf(&b, "- **Detected:** %s\n", a.CreatedAt.Format(time.RFC1123))
	fmt.Fprintf(&b, "- **Last updated:** %s\n\n", a.UpdatedAt.Format(time.RFC1123))

	b.WriteString("## Summary\n\n")
	b.WriteString(a.Description)
	b.WriteString("\n\n")

	b.WriteString("## Indicators\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	if a.SrcIP != "" {
		fmt.Fprintf(&b, "| Source IP | %s |\n", a.SrcIP)
	}
	if a.DstIP != "" {
		fmt.Fprintf(&b, "| Destination IP | %s |\n", a.DstIP)
	}
	if a.DstPort != 0 {
		fmt.Fprintf(&b, "| Destination port | %d |\n", a.DstPort)
	}
	if a.AssetHostname != "" {
		fmt.Fprintf(&b, "| Affected asset | %s |\n", a.AssetHostname)
	}
	fmt.Fprintf(&b, "| Related event count | %d |\n", a.EventCount)
	b.WriteString("\n")

	if len(a.ThreatIntel) > 0 {
		b.WriteString("## Threat intelligence matches\n\n")
		b.WriteString("| Indicator | Type | Category | Confidence | Source |\n|---|---|---|---|---|\n")
		for _, ti := range a.ThreatIntel {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				ti.Indicator, ti.IndicatorType, ti.Category, ti.Confidence, ti.Source)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Analyst notes\n\n")
	if len(notes) == 0 {
		b.WriteString("_No analyst notes recorded._\n\n")
	} else {
		for _, n := range notes {
			fmt.Fprintf(&b, "- **%s** (%s): %s\n", n.Author, n.CreatedAt.Format(time.RFC1123), n.Note)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Recommended next steps\n\n")
	for _, step := range recommendationsFor(a.AlertType) {
		fmt.Fprintf(&b, "- %s\n", step)
	}

	return b.String()
}

func recommendationsFor(t models.AlertType) []string {
	switch t {
	case models.AlertBruteForce:
		return []string{
			"Rotate credentials for the targeted account and host.",
			"Review authentication logs for other hosts contacted by the same source.",
			"Block the source IP at the perimeter and enforce MFA / auth throttling.",
		}
	case models.AlertPortScan:
		return []string{
			"Confirm whether the source is an authorized vulnerability scanner.",
			"Review firewall rules exposing the scanned host/ports.",
			"Watch for follow-on exploitation attempts against the scanned ports.",
		}
	case models.AlertBeaconing, models.AlertKnownBadIP, models.AlertKnownBadDomain:
		return []string{
			"Isolate the affected host from the network pending investigation.",
			"Capture memory/disk forensics before remediation if feasible.",
			"Block the indicator at DNS/firewall/proxy layers.",
			"Hunt for the same indicator across other hosts.",
		}
	case models.AlertHighVolume:
		return []string{
			"Identify what data was transferred and to whom.",
			"Check DLP / proxy logs for the same destination.",
			"Confirm whether this matches a known, approved data transfer.",
		}
	case models.AlertDNSAnomaly:
		return []string{
			"Block the destination domain at the DNS resolver / firewall.",
			"Isolate the querying host and inspect for tunneling malware.",
		}
	case models.AlertMalwareFile:
		return []string{
			"Quarantine the affected file/host immediately.",
			"Run a full AV/EDR scan on the host.",
			"Identify how the file arrived (email, download, removable media).",
		}
	default:
		return []string{"Review the alert details and escalate per your IR playbook."}
	}
}
