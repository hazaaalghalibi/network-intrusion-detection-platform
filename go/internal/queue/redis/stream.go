// Package redis wraps the alert queue: a Redis Stream that decouples alert
// production (cmd/ingest, and the detection engine it drives) from alert
// persistence (cmd/worker). This is the project's "Create an alert queue
// using Redis" requirement.
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

const (
	AlertStream       = "alerts"
	AlertConsumerGrp  = "alert-workers"
	alertFieldPayload = "alert"
)

// NewClient connects to Redis at addr (host:port).
func NewClient(addr string) *redis.Client {
	return redis.NewClient(&redis.Options{Addr: addr})
}

// PublishAlert XADDs a normalized Alert onto the shared stream as JSON.
func PublishAlert(ctx context.Context, rdb *redis.Client, a models.Alert) error {
	payload, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshal alert %s: %w", a.ID, err)
	}
	if err := rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: AlertStream,
		Values: map[string]any{alertFieldPayload: payload},
	}).Err(); err != nil {
		return fmt.Errorf("xadd alert %s: %w", a.ID, err)
	}
	return nil
}

// EnsureConsumerGroup creates the worker consumer group if it doesn't exist
// yet, and creates the stream itself (MKSTREAM) if no producer has run yet.
func EnsureConsumerGroup(ctx context.Context, rdb *redis.Client) error {
	err := rdb.XGroupCreateMkStream(ctx, AlertStream, AlertConsumerGrp, "0").Err()
	if err != nil && !isBusyGroupErr(err) {
		return fmt.Errorf("create consumer group: %w", err)
	}
	return nil
}

func isBusyGroupErr(err error) bool {
	// Redis returns "BUSYGROUP Consumer Group name already exists" — not a
	// real error for our purposes, just means a previous run already set it up.
	return err != nil && len(err.Error()) >= 9 && err.Error()[:9] == "BUSYGROUP"
}

// Delivery is one message read off the stream by a consumer.
type Delivery struct {
	MessageID string
	Alert     models.Alert
}

// ReadAlerts blocks (up to blockMS) waiting for new alert deliveries for the
// given consumer name within AlertConsumerGrp.
func ReadAlerts(ctx context.Context, rdb *redis.Client, consumer string, count int64, blockMS int64) ([]Delivery, error) {
	res, err := rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    AlertConsumerGrp,
		Consumer: consumer,
		Streams:  []string{AlertStream, ">"},
		Count:    count,
		Block:    time.Duration(blockMS) * time.Millisecond,
	}).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("xreadgroup: %w", err)
	}
	var deliveries []Delivery
	for _, stream := range res {
		for _, msg := range stream.Messages {
			raw, ok := msg.Values[alertFieldPayload].(string)
			if !ok {
				continue
			}
			var a models.Alert
			if err := json.Unmarshal([]byte(raw), &a); err != nil {
				continue
			}
			deliveries = append(deliveries, Delivery{MessageID: msg.ID, Alert: a})
		}
	}
	return deliveries, nil
}

// Ack acknowledges successful processing of a delivery.
func Ack(ctx context.Context, rdb *redis.Client, messageID string) error {
	return rdb.XAck(ctx, AlertStream, AlertConsumerGrp, messageID).Err()
}
