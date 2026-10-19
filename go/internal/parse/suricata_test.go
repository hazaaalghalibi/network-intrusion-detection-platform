package parse

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSuricataEveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	content := `{"timestamp":"2026-06-30T14:00:00.000+0000","event_type":"alert","src_ip":"198.51.100.23","src_port":51000,"dest_ip":"10.0.0.10","dest_port":22,"proto":"TCP","alert":{"signature_id":1,"signature":"test sig","category":"test cat","severity":1}}
{"timestamp":"2026-06-30T14:00:01.000+0000","event_type":"flow","src_ip":"10.0.0.10","dest_ip":"10.0.0.11"}
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	events, err := ParseSuricataEveFile(path)
	if err != nil {
		t.Fatalf("ParseSuricataEveFile: %v", err)
	}
	// The "flow" event type must be filtered out — only "alert" is ingested.
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1 (non-alert events must be skipped)", len(events))
	}
	ev := events[0]
	if ev.SrcIP != "198.51.100.23" || ev.DstIP != "10.0.0.10" {
		t.Errorf("src/dst = %s/%s, want 198.51.100.23/10.0.0.10", ev.SrcIP, ev.DstIP)
	}
	if ev.SuricataSignature != "test sig" || ev.SuricataSeverity != 1 {
		t.Errorf("signature/severity = %q/%d, want %q/1", ev.SuricataSignature, ev.SuricataSeverity, "test sig")
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp is zero, want parsed time")
	}
}
