package parse

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleConnLog = "#separator \\x09\n" +
	"#set_separator\t,\n" +
	"#empty_field\t(empty)\n" +
	"#unset_field\t-\n" +
	"#path\tconn\n" +
	"#open\t2026-06-30-00-00-00\n" +
	"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n" +
	"#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\n" +
	"1782777667.036025\tCabc123\t10.0.0.10\t51000\t10.0.0.20\t22\ttcp\tssh\t0.400000\t900\t700\tSF\n" +
	"#close\t2026-07-01-00-00-00\n"

func TestParseZeekFileAndConnEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conn.log")
	if err := os.WriteFile(path, []byte(sampleConnLog), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	log, err := ParseZeekFile(path)
	if err != nil {
		t.Fatalf("ParseZeekFile: %v", err)
	}
	if log.Path != "conn" {
		t.Errorf("Path = %q, want %q", log.Path, "conn")
	}
	if len(log.Rows) != 1 {
		t.Fatalf("len(Rows) = %d, want 1", len(log.Rows))
	}

	events := ConnEvents(log)
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.SrcIP != "10.0.0.10" || ev.DstIP != "10.0.0.20" {
		t.Errorf("src/dst = %s/%s, want 10.0.0.10/10.0.0.20", ev.SrcIP, ev.DstIP)
	}
	if ev.DstPort != 22 {
		t.Errorf("DstPort = %d, want 22", ev.DstPort)
	}
	if ev.OrigBytes != 900 || ev.RespBytes != 700 {
		t.Errorf("bytes = %d/%d, want 900/700", ev.OrigBytes, ev.RespBytes)
	}
	if ev.ConnState != "SF" {
		t.Errorf("ConnState = %q, want SF", ev.ConnState)
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp is zero, want parsed time")
	}
}
