package parse

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

// eveAlert mirrors the subset of Suricata's eve.json "alert" event type we
// use. eve.json has many event_types (flow, dns, http, alert, ...); this
// platform only ingests "alert" events, matching the project's stated scope
// ("Ingest ... Suricata IDS alerts").
type eveAlert struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     struct {
		SignatureID int    `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
}

// ParseSuricataEveFile reads a line-delimited eve.json file and returns
// normalized Events for every "alert" record. Non-alert event types
// (flow, dns, http, ...) are skipped.
func ParseSuricataEveFile(path string) ([]models.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open eve.json %s: %w", path, err)
	}
	defer f.Close()

	var events []models.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e eveAlert
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("eve.json %s line %d: %w", path, lineNo, err)
		}
		if e.EventType != "alert" {
			continue
		}
		ts, err := time.Parse("2006-01-02T15:04:05.000-0700", e.Timestamp)
		if err != nil {
			ts, err = time.Parse(time.RFC3339, e.Timestamp)
			if err != nil {
				return nil, fmt.Errorf("eve.json %s line %d: bad timestamp %q: %w", path, lineNo, e.Timestamp, err)
			}
		}
		events = append(events, models.Event{
			ID:                fmt.Sprintf("suricata-%d-%d", e.Alert.SignatureID, ts.UnixNano()),
			Timestamp:         ts.UTC(),
			Source:            models.SourceSuricata,
			SrcIP:             e.SrcIP,
			SrcPort:           e.SrcPort,
			DstIP:             e.DestIP,
			DstPort:           e.DestPort,
			Proto:             strings.ToLower(e.Proto),
			SuricataSignature: e.Alert.Signature,
			SuricataCategory:  e.Alert.Category,
			SuricataSeverity:  e.Alert.Severity,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan eve.json %s: %w", path, err)
	}
	return events, nil
}
