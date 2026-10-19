// Command api serves the analyst-facing REST API (internal/api) backed by
// PostgreSQL (alert workflow state) and OpenSearch (raw event search).
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/api"
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
	ctx := context.Background()

	openSearchURL := getenv("OPENSEARCH_URL", "http://localhost:9200")
	postgresDSN := getenv("POSTGRES_DSN", "postgresql://nidr:nidr_dev_password@localhost:5432/nidr")
	listenAddr := getenv("LISTEN_ADDR", ":8080")

	osClient, err := osstore.New(openSearchURL)
	if err != nil {
		log.Fatalf("connect opensearch: %v", err)
	}
	pg, err := postgres.New(ctx, postgresDSN)
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pg.Close()

	server := api.NewServer(pg, osClient)
	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("api: listening on %s", listenAddr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("api server: %v", err)
	}
}
