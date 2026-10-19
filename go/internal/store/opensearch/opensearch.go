// Package opensearch wraps the official opensearch-go client with the small
// set of operations this platform needs: bulk-indexing normalized events,
// indexing alerts, and searching events by IP for the analyst API.
package opensearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	opensearchgo "github.com/opensearch-project/opensearch-go/v2"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

type Client struct {
	es *opensearchgo.Client
}

func New(url string) (*Client, error) {
	es, err := opensearchgo.NewClient(opensearchgo.Config{Addresses: []string{url}})
	if err != nil {
		return nil, fmt.Errorf("create opensearch client: %w", err)
	}
	return &Client{es: es}, nil
}

// BulkIndexEvents writes a batch of normalized events via the OpenSearch
// _bulk API. Each event lands in its own daily index (events-YYYY.MM.DD).
func (c *Client) BulkIndexEvents(ctx context.Context, events []models.Event) error {
	if len(events) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, e := range events {
		meta := map[string]any{"index": map[string]any{"_index": e.IndexName(), "_id": e.ID}}
		if err := writeNDJSONLine(&buf, meta); err != nil {
			return err
		}
		if err := writeNDJSONLine(&buf, e); err != nil {
			return fmt.Errorf("marshal event %s: %w", e.ID, err)
		}
	}
	res, err := c.es.Bulk(bytes.NewReader(buf.Bytes()), c.es.Bulk.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("bulk index events: %w", err)
	}
	defer res.Body.Close()
	return checkResponse(res.StatusCode, res.Body, "bulk index events")
}

// IndexAlert writes a single alert document to its daily alerts-YYYY.MM.DD
// index, keyed by alert ID so re-processing the same alert is idempotent.
func (c *Client) IndexAlert(ctx context.Context, a models.Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshal alert %s: %w", a.ID, err)
	}
	res, err := c.es.Index(
		a.IndexName(),
		bytes.NewReader(body),
		c.es.Index.WithDocumentID(a.ID),
		c.es.Index.WithContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("index alert %s: %w", a.ID, err)
	}
	defer res.Body.Close()
	return checkResponse(res.StatusCode, res.Body, "index alert "+a.ID)
}

type searchResponse struct {
	Hits struct {
		Hits []struct {
			Source models.Event `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// SearchEventsByIP returns the most recent normalized events where ip
// appears as either the source or destination address, newest first.
func (c *Client) SearchEventsByIP(ctx context.Context, ip string, limit int) ([]models.Event, error) {
	query := map[string]any{
		"size": limit,
		"sort": []map[string]any{{"timestamp": map[string]any{"order": "desc"}}},
		"query": map[string]any{
			"bool": map[string]any{
				"should": []map[string]any{
					{"term": map[string]any{"src_ip": ip}},
					{"term": map[string]any{"dst_ip": ip}},
				},
				"minimum_should_match": 1,
			},
		},
	}
	body, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("marshal query: %w", err)
	}
	res, err := c.es.Search(
		c.es.Search.WithContext(ctx),
		c.es.Search.WithIndex("events-*"),
		c.es.Search.WithBody(bytes.NewReader(body)),
	)
	if err != nil {
		return nil, fmt.Errorf("search events for ip %s: %w", ip, err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("search events for ip %s: status %d: %s", ip, res.StatusCode, string(b))
	}
	var sr searchResponse
	if err := json.NewDecoder(res.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("decode search response: %w", err)
	}
	events := make([]models.Event, 0, len(sr.Hits.Hits))
	for _, h := range sr.Hits.Hits {
		events = append(events, h.Source)
	}
	return events, nil
}

func writeNDJSONLine(buf *bytes.Buffer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	buf.Write(b)
	buf.WriteByte('\n')
	return nil
}

type bulkResponse struct {
	Errors bool `json:"errors"`
	Items  []map[string]struct {
		Status int `json:"status"`
		Error  any `json:"error,omitempty"`
	} `json:"items"`
}

func checkResponse(status int, body io.ReadCloser, action string) error {
	raw, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("%s: read response body: %w", action, err)
	}
	if status >= 300 {
		return fmt.Errorf("%s: status %d: %s", action, status, string(raw))
	}
	var br bulkResponse
	if err := json.Unmarshal(raw, &br); err == nil && br.Errors {
		return fmt.Errorf("%s: opensearch reported per-item bulk errors: %s", action, string(raw))
	}
	return nil
}
