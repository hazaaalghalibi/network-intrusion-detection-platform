package detect

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

const (
	dnsTunnelWindow    = 5 * time.Minute
	dnsTunnelThreshold = 8
	dnsTunnelCooldown  = 10 * time.Minute
	highEntropyMinLen  = 20
	highEntropyBits    = 3.3 // bits/char; random alnum strings run ~4.0-4.7
	baddomainCooldown  = 10 * time.Minute
)

// DetectDNSAnomaly runs two independent checks over dns.log queries: a
// known-malicious-domain match against local threat intel, and a DNS
// tunneling heuristic (repeated long, high-entropy subdomain labels — see
// rules/sigma/dns_tunneling.yml). A single query can trigger both, zero,
// or one of these, so this returns a slice rather than a single alert.
func (e *Engine) DetectDNSAnomaly(ctx context.Context, ev models.Event) ([]models.Alert, error) {
	if ev.Source != models.SourceZeekDNS || ev.DNSQuery == "" {
		return nil, nil
	}
	var alerts []models.Alert

	if m, ok := e.ti.MatchDomain(ev.DNSQuery); ok {
		cdKey := "detect:cooldown:baddomain:" + ev.SrcIP + ":" + m.Indicator
		down, err := coolingDown(ctx, e.rdb, cdKey, ev.Timestamp, baddomainCooldown)
		if err != nil {
			return nil, err
		}
		if !down {
			a := newAlert(ev.Timestamp, models.AlertKnownBadDomain, confidenceSeverity(m.Confidence),
				fmt.Sprintf("DNS query for known-malicious domain %s", m.Indicator),
				fmt.Sprintf("%s queried %s, which matches local threat intel (category: %s, confidence: %s).",
					ev.SrcIP, ev.DNSQuery, m.Category, m.Confidence))
			a.SrcIP = ev.SrcIP
			a.AssetHostname = e.hostnameFor(ev.SrcIP)
			a.ThreatIntel = []models.ThreatIntelMatch{m}
			alerts = append(alerts, a)
		}
	}

	label := strings.SplitN(ev.DNSQuery, ".", 2)[0]
	if len(label) >= highEntropyMinLen && shannonEntropy(label) >= highEntropyBits {
		key := "detect:dnstunnel:" + ev.SrcIP
		count, err := windowCount(ctx, e.rdb, key, ev.ID, ev.Timestamp, dnsTunnelWindow)
		if err != nil {
			return nil, err
		}
		if count >= dnsTunnelThreshold {
			down, err := coolingDown(ctx, e.rdb, "detect:cooldown:dnstunnel:"+ev.SrcIP, ev.Timestamp, dnsTunnelCooldown)
			if err != nil {
				return nil, err
			}
			if !down {
				a := newAlert(ev.Timestamp, models.AlertDNSAnomaly, models.SeverityHigh,
					fmt.Sprintf("Possible DNS tunneling from %s", ev.SrcIP),
					fmt.Sprintf("%s issued %d high-entropy/long-subdomain DNS queries within %s "+
						"(most recent: %s). This pattern is consistent with DNS tunneling or C2 over DNS.",
						ev.SrcIP, count, dnsTunnelWindow, ev.DNSQuery))
				a.SrcIP = ev.SrcIP
				a.AssetHostname = e.hostnameFor(ev.SrcIP)
				a.EventCount = int(count)
				alerts = append(alerts, a)
			}
		}
	}
	return alerts, nil
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len(s))
	var entropy float64
	for _, c := range counts {
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
