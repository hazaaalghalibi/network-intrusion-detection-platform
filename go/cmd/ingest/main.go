// Command ingest is the log ingestion + detection service. It reads the
// sample Zeek and Suricata logs, normalizes them into the common Event
// schema, writes them to OpenSearch, runs every detector in internal/detect
// over the merged chronological event stream, runs the YARA file scanner,
// and publishes every resulting alert onto the Redis "alerts" stream for
// cmd/worker to persist.
//
// It processes a fixed batch of files and exits — see the README for why
// this project uses pre-generated sample logs rather than a live tail.
package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/detect"
	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
	"github.com/tsebro/network-intrusion-detection-platform/internal/parse"
	redisq "github.com/tsebro/network-intrusion-detection-platform/internal/queue/redis"
	osstore "github.com/tsebro/network-intrusion-detection-platform/internal/store/opensearch"
	"github.com/tsebro/network-intrusion-detection-platform/internal/threatintel"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	ctx := context.Background()

	openSearchURL := getenv("OPENSEARCH_URL", "http://localhost:9200")
	redisAddr := getenv("REDIS_ADDR", "localhost:6379")
	sampleLogsDir := getenv("SAMPLE_LOGS_DIR", "/data/sample_logs")
	malwareSamplesDir := getenv("MALWARE_SAMPLES_DIR", "/data/malware_samples")
	yaraRulesDir := getenv("YARA_RULES_DIR", "/rules/yara")
	threatIntelDir := getenv("THREAT_INTEL_DIR", "/data/threat_intel")
	assetsFile := getenv("ASSETS_FILE", "/data/assets.json")

	log.Println("ingest: loading threat intel and asset inventory")
	blocklist, err := threatintel.Load(threatIntelDir)
	if err != nil {
		log.Fatalf("load threat intel: %v", err)
	}
	assets, err := models.LoadAssets(assetsFile)
	if err != nil {
		log.Fatalf("load assets: %v", err)
	}
	hostnames := models.AssetHostnameMap(assets)

	log.Println("ingest: connecting to OpenSearch and Redis")
	osClient, err := osstore.New(openSearchURL)
	if err != nil {
		log.Fatalf("connect opensearch: %v", err)
	}
	rdb := redisq.NewClient(redisAddr)
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("connect redis: %v", err)
	}
	if err := redisq.EnsureConsumerGroup(ctx, rdb); err != nil {
		log.Fatalf("ensure consumer group: %v", err)
	}

	log.Println("ingest: parsing sample logs")
	events, err := parseAllLogs(sampleLogsDir)
	if err != nil {
		log.Fatalf("parse logs: %v", err)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
	log.Printf("ingest: parsed %d normalized events", len(events))

	log.Println("ingest: writing normalized events to OpenSearch")
	if err := bulkIndexInChunks(ctx, osClient, events, 500); err != nil {
		log.Fatalf("index events: %v", err)
	}

	log.Println("ingest: running detection engine over the chronological event stream")
	engine := detect.NewEngine(rdb, blocklist, hostnames)
	alertCount := 0
	for _, ev := range events {
		alerts := runDetectors(ctx, engine, ev)
		for _, a := range alerts {
			if err := redisq.PublishAlert(ctx, rdb, a); err != nil {
				log.Fatalf("publish alert: %v", err)
			}
			alertCount++
		}
	}

	scanTime := time.Now().UTC()
	if len(events) > 0 {
		scanTime = events[len(events)-1].Timestamp
	}
	log.Println("ingest: running YARA scan over malware sample directory")
	yaraAlerts, err := engine.ScanMalwareSamples(ctx, yaraRulesDir, malwareSamplesDir, scanTime)
	if err != nil {
		log.Fatalf("yara scan: %v", err)
	}
	for _, a := range yaraAlerts {
		if err := redisq.PublishAlert(ctx, rdb, a); err != nil {
			log.Fatalf("publish yara alert: %v", err)
		}
		alertCount++
	}

	log.Printf("ingest: done. %d events indexed, %d alerts published to Redis stream %q",
		len(events), alertCount, redisq.AlertStream)
}

// runDetectors dispatches one event to every detector relevant to its
// source and returns whatever alerts fired.
func runDetectors(ctx context.Context, e *detect.Engine, ev models.Event) []models.Alert {
	var alerts []models.Alert

	if ev.Source == models.SourceZeekConn || ev.Source == models.SourceSuricata {
		if a, err := e.DetectKnownBadIP(ctx, ev); err != nil {
			log.Printf("detect known-bad-ip: %v", err)
		} else if a != nil {
			alerts = append(alerts, *a)
		}
	}

	switch ev.Source {
	case models.SourceZeekConn:
		if a, err := e.DetectPortScan(ctx, ev); err != nil {
			log.Printf("detect port scan: %v", err)
		} else if a != nil {
			alerts = append(alerts, *a)
		}
		if a, err := e.DetectHighVolume(ctx, ev); err != nil {
			log.Printf("detect high volume: %v", err)
		} else if a != nil {
			alerts = append(alerts, *a)
		}
		if a, err := e.DetectBeaconing(ctx, ev); err != nil {
			log.Printf("detect beaconing: %v", err)
		} else if a != nil {
			alerts = append(alerts, *a)
		}
	case models.SourceZeekSSH:
		if a, err := e.DetectBruteForce(ctx, ev); err != nil {
			log.Printf("detect brute force: %v", err)
		} else if a != nil {
			alerts = append(alerts, *a)
		}
	case models.SourceZeekDNS:
		if dnsAlerts, err := e.DetectDNSAnomaly(ctx, ev); err != nil {
			log.Printf("detect dns anomaly: %v", err)
		} else {
			alerts = append(alerts, dnsAlerts...)
		}
	case models.SourceSuricata:
		if a, err := e.ProcessSuricataAlert(ctx, ev); err != nil {
			log.Printf("process suricata alert: %v", err)
		} else if a != nil {
			alerts = append(alerts, *a)
		}
	}
	return alerts
}

func parseAllLogs(dir string) ([]models.Event, error) {
	var events []models.Event

	connLog, err := parse.ParseZeekFile(filepath.Join(dir, "conn.log"))
	if err != nil {
		return nil, err
	}
	events = append(events, parse.ConnEvents(connLog)...)

	dnsLog, err := parse.ParseZeekFile(filepath.Join(dir, "dns.log"))
	if err != nil {
		return nil, err
	}
	events = append(events, parse.DNSEvents(dnsLog)...)

	sshLog, err := parse.ParseZeekFile(filepath.Join(dir, "ssh.log"))
	if err != nil {
		return nil, err
	}
	events = append(events, parse.SSHEvents(sshLog)...)

	suricataEvents, err := parse.ParseSuricataEveFile(filepath.Join(dir, "eve.json"))
	if err != nil {
		return nil, err
	}
	events = append(events, suricataEvents...)

	return events, nil
}

func bulkIndexInChunks(ctx context.Context, c *osstore.Client, events []models.Event, chunkSize int) error {
	for i := 0; i < len(events); i += chunkSize {
		end := i + chunkSize
		if end > len(events) {
			end = len(events)
		}
		if err := c.BulkIndexEvents(ctx, events[i:end]); err != nil {
			return err
		}
	}
	return nil
}
