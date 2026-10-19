// Package parse converts raw Zeek TSV logs and Suricata eve.json alerts
// into the common models.Event schema.
package parse

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

// ZeekLog is a parsed Zeek TSV file: the #path this log came from, the
// column order declared in #fields, and the raw string rows. Zeek always
// documents its own schema in the header, so we read that instead of
// hardcoding column positions per log type.
type ZeekLog struct {
	Path   string
	Fields []string
	Rows   []map[string]string
}

// ParseZeekFile reads a Zeek TSV log (conn.log, dns.log, ssh.log, ...) using
// its self-describing #fields header.
func ParseZeekFile(path string) (*ZeekLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open zeek log %s: %w", path, err)
	}
	defer f.Close()

	log := &ZeekLog{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "#path\t") {
				log.Path = strings.TrimPrefix(line, "#path\t")
			}
			if strings.HasPrefix(line, "#fields\t") {
				log.Fields = strings.Split(strings.TrimPrefix(line, "#fields\t"), "\t")
			}
			continue
		}
		if line == "" {
			continue
		}
		if log.Fields == nil {
			return nil, fmt.Errorf("zeek log %s: data row before #fields header", path)
		}
		cols := strings.Split(line, "\t")
		row := make(map[string]string, len(log.Fields))
		for i, name := range log.Fields {
			if i < len(cols) {
				row[name] = cols[i]
			}
		}
		log.Rows = append(log.Rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan zeek log %s: %w", path, err)
	}
	return log, nil
}

func zeekTime(s string) time.Time {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return time.Time{}
	}
	sec := int64(f)
	nsec := int64((f - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC()
}

func zeekInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func zeekInt64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func zeekFloat(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

func zeekBool(s string) *bool {
	switch s {
	case "T":
		b := true
		return &b
	case "F":
		b := false
		return &b
	default:
		return nil
	}
}

// ConnEvents converts a parsed conn.log into normalized Events.
func ConnEvents(log *ZeekLog) []models.Event {
	events := make([]models.Event, 0, len(log.Rows))
	for _, r := range log.Rows {
		events = append(events, models.Event{
			ID:        "zeek-conn-" + r["uid"],
			Timestamp: zeekTime(r["ts"]),
			Source:    models.SourceZeekConn,
			SrcIP:     r["id.orig_h"],
			SrcPort:   zeekInt(r["id.orig_p"]),
			DstIP:     r["id.resp_h"],
			DstPort:   zeekInt(r["id.resp_p"]),
			Proto:     r["proto"],
			Service:   r["service"],
			Duration:  zeekFloat(r["duration"]),
			OrigBytes: zeekInt64(r["orig_bytes"]),
			RespBytes: zeekInt64(r["resp_bytes"]),
			ConnState: r["conn_state"],
		})
	}
	return events
}

// DNSEvents converts a parsed dns.log into normalized Events.
func DNSEvents(log *ZeekLog) []models.Event {
	events := make([]models.Event, 0, len(log.Rows))
	for _, r := range log.Rows {
		events = append(events, models.Event{
			ID:        "zeek-dns-" + r["uid"] + "-" + r["trans_id"],
			Timestamp: zeekTime(r["ts"]),
			Source:    models.SourceZeekDNS,
			SrcIP:     r["id.orig_h"],
			SrcPort:   zeekInt(r["id.orig_p"]),
			DstIP:     r["id.resp_h"],
			DstPort:   zeekInt(r["id.resp_p"]),
			Proto:     r["proto"],
			DNSQuery:  r["query"],
			DNSQType:  r["qtype_name"],
			DNSRcode:  r["rcode_name"],
		})
	}
	return events
}

// SSHEvents converts a parsed ssh.log into normalized Events.
func SSHEvents(log *ZeekLog) []models.Event {
	events := make([]models.Event, 0, len(log.Rows))
	for _, r := range log.Rows {
		events = append(events, models.Event{
			ID:             "zeek-ssh-" + r["uid"],
			Timestamp:      zeekTime(r["ts"]),
			Source:         models.SourceZeekSSH,
			SrcIP:          r["id.orig_h"],
			SrcPort:        zeekInt(r["id.orig_p"]),
			DstIP:          r["id.resp_h"],
			DstPort:        zeekInt(r["id.resp_p"]),
			Proto:          "tcp",
			SSHAuthSuccess: zeekBool(r["auth_success"]),
			SSHAttempts:    zeekInt(r["auth_attempts"]),
		})
	}
	return events
}
