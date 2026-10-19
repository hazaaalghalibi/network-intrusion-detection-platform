// Package threatintel loads the local blocklist CSVs (data/threat_intel/)
// and matches event IPs/domains against them. In a production system this
// would sync from a feed (MISP, abuse.ch, a commercial TIP); here it's a
// deliberately simple local-file lookup, matching the project's stated
// scope ("Enrich alerts with threat intelligence from local blocklists").
package threatintel

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

type indicator struct {
	value      string
	category   string
	source     string
	confidence string
}

type Blocklist struct {
	ips     map[string]indicator
	domains map[string]indicator
}

// Load reads malicious_ips.csv and malicious_domains.csv from dir.
func Load(dir string) (*Blocklist, error) {
	bl := &Blocklist{ips: map[string]indicator{}, domains: map[string]indicator{}}

	if err := loadCSV(filepath.Join(dir, "malicious_ips.csv"), "ip", bl.ips); err != nil {
		return nil, err
	}
	if err := loadCSV(filepath.Join(dir, "malicious_domains.csv"), "domain", bl.domains); err != nil {
		return nil, err
	}
	return bl, nil
}

func loadCSV(path, keyCol string, into map[string]indicator) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open threat intel file %s: %w", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.Comment = '#'
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("read header %s: %w", path, err)
	}
	colIdx := map[string]int{}
	for i, h := range header {
		colIdx[h] = i
	}
	keyI, catI, srcI, confI := colIdx[keyCol], colIdx["category"], colIdx["source"], colIdx["confidence"]

	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read row %s: %w", path, err)
		}
		key := strings.ToLower(strings.TrimSpace(rec[keyI]))
		into[key] = indicator{
			value:      key,
			category:   rec[catI],
			source:     rec[srcI],
			confidence: rec[confI],
		}
	}
	return nil
}

// MatchIP returns a ThreatIntelMatch if ip is on the blocklist.
func (b *Blocklist) MatchIP(ip string) (models.ThreatIntelMatch, bool) {
	ind, ok := b.ips[strings.ToLower(ip)]
	if !ok {
		return models.ThreatIntelMatch{}, false
	}
	return models.ThreatIntelMatch{
		Indicator: ind.value, IndicatorType: "ip",
		Category: ind.category, Source: ind.source, Confidence: ind.confidence,
	}, true
}

// MatchDomain returns a ThreatIntelMatch if domain (or a parent domain of
// it, since DNS queries are often subdomains of a flagged domain) is on the
// blocklist.
func (b *Blocklist) MatchDomain(domain string) (models.ThreatIntelMatch, bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		if ind, ok := b.domains[candidate]; ok {
			return models.ThreatIntelMatch{
				Indicator: ind.value, IndicatorType: "domain",
				Category: ind.category, Source: ind.source, Confidence: ind.confidence,
			}, true
		}
	}
	return models.ThreatIntelMatch{}, false
}
