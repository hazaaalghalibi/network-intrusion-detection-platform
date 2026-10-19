// Command worker consumes the Redis "alerts" stream (via a consumer group,
// so multiple worker replicas could safely share the load) and persists
// each alert to both OpenSearch (for search/Grafana) and PostgreSQL (the
// system of record for the analyst triage workflow). It runs continuously,
// decoupled from cmd/ingest by the queue.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/queue/redis"
	osstore "github.com/tsebro/network-intrusion-detection-platform/internal/store/opensearch"
	"github.com/tsebro/network-intrusion-detection-platform/internal/store/postgres"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	openSearchURL := getenv("OPENSEARCH_URL", "http://localhost:9200")
	redisAddr := getenv("REDIS_ADDR", "localhost:6379")
	postgresDSN := getenv("POSTGRES_DSN", "postgresql://nidr:nidr_dev_password@localhost:5432/nidr")
	consumerName := getenv("HOSTNAME", "worker-1")

	osClient, err := osstore.New(openSearchURL)
	if err != nil {
		log.Fatalf("connect opensearch: %v", err)
	}
	pg, err := postgres.New(ctx, postgresDSN)
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pg.Close()

	rdb := redis.NewClient(redisAddr)
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("connect redis: %v", err)
	}
	if err := redis.EnsureConsumerGroup(ctx, rdb); err != nil {
		log.Fatalf("ensure consumer group: %v", err)
	}

	log.Printf("worker: consuming stream %q as %q", redis.AlertStream, consumerName)
	processed := 0
	for {
		select {
		case <-ctx.Done():
			log.Printf("worker: shutting down after processing %d alerts", processed)
			return
		default:
		}

		deliveries, err := redis.ReadAlerts(ctx, rdb, consumerName, 20, 5000)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				continue
			}
			log.Printf("worker: read alerts: %v", err)
			time.Sleep(time.Second)
			continue
		}
		for _, d := range deliveries {
			if err := osClient.IndexAlert(ctx, d.Alert); err != nil {
				log.Printf("worker: index alert %s in opensearch: %v", d.Alert.ID, err)
				continue // don't ack — will be redelivered
			}
			if err := pg.UpsertAlert(ctx, d.Alert); err != nil {
				log.Printf("worker: upsert alert %s in postgres: %v", d.Alert.ID, err)
				continue // don't ack — will be redelivered
			}
			if err := redis.Ack(ctx, rdb, d.MessageID); err != nil {
				log.Printf("worker: ack %s: %v", d.MessageID, err)
				continue
			}
			processed++
		}
		if len(deliveries) > 0 {
			log.Printf("worker: processed %d alerts (%d total)", len(deliveries), processed)
		}
	}
}
