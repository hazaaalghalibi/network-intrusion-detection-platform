package detect

import (
	"context"
	"fmt"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

const badIPCooldown = 10 * time.Minute

// DetectKnownBadIP matches either side of a connection (Zeek conn.log or a
// Suricata alert — both populate SrcIP/DstIP) against the local IP
// blocklist. See rules/sigma/known_bad_ip.yml.
func (e *Engine) DetectKnownBadIP(ctx context.Context, ev models.Event) (*models.Alert, error) {
	if ev.SrcIP == "" && ev.DstIP == "" {
		return nil, nil
	}
	var match models.ThreatIntelMatch
	var flagged string
	if m, ok := e.ti.MatchIP(ev.DstIP); ok {
		match, flagged = m, ev.DstIP
	} else if m, ok := e.ti.MatchIP(ev.SrcIP); ok {
		match, flagged = m, ev.SrcIP
	} else {
		return nil, nil
	}

	cdKey := "detect:cooldown:badip:" + ev.SrcIP + "->" + ev.DstIP
	down, err := coolingDown(ctx, e.rdb, cdKey, ev.Timestamp, badIPCooldown)
	if err != nil || down {
		return nil, err
	}

	a := newAlert(ev.Timestamp, models.AlertKnownBadIP, confidenceSeverity(match.Confidence),
		fmt.Sprintf("Connection to known-malicious IP %s", flagged),
		fmt.Sprintf("Connection between %s and %s involves %s, which matches local threat intel "+
			"(category: %s, confidence: %s, source: %s).",
			ev.SrcIP, ev.DstIP, flagged, match.Category, match.Confidence, match.Source))
	a.SrcIP, a.DstIP, a.DstPort = ev.SrcIP, ev.DstIP, ev.DstPort
	a.AssetHostname = e.hostnameFor(ev.SrcIP)
	if a.AssetHostname == "" {
		a.AssetHostname = e.hostnameFor(ev.DstIP)
	}
	a.ThreatIntel = []models.ThreatIntelMatch{match}
	return &a, nil
}
