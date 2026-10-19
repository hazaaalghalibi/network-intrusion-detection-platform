package detect

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

const (
	highVolumeWindow    = 10 * time.Minute
	highVolumeThreshold = int64(150 * 1024 * 1024) // 150MB in the window
	highVolumeCooldown  = 15 * time.Minute
)

// DetectHighVolume sums bytes transferred by a single source within a
// sliding window. A ZSET member alone can't hold a sum, so each member
// encodes "<unix_nanos>:<bytes>" and we sum the surviving members after
// trimming — see rules/sigma/high_volume_outbound.yml.
func (e *Engine) DetectHighVolume(ctx context.Context, ev models.Event) (*models.Alert, error) {
	if ev.Source != models.SourceZeekConn {
		return nil, nil
	}
	total := ev.OrigBytes + ev.RespBytes
	if total <= 0 {
		return nil, nil
	}
	key := "detect:volume:" + ev.SrcIP
	member := fmt.Sprintf("%d:%d", ev.Timestamp.UnixNano(), total)
	score := float64(ev.Timestamp.Unix())

	pipe := e.rdb.TxPipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: score, Member: member})
	pipe.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatFloat(score-highVolumeWindow.Seconds(), 'f', 0, 64))
	pipe.Expire(ctx, key, highVolumeWindow+time.Hour)
	members := pipe.ZRange(ctx, key, 0, -1)
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("volume window %s: %w", key, err)
	}

	var sum int64
	var count int
	for _, m := range members.Val() {
		parts := strings.SplitN(m, ":", 2)
		if len(parts) != 2 {
			continue
		}
		b, _ := strconv.ParseInt(parts[1], 10, 64)
		sum += b
		count++
	}
	if sum < highVolumeThreshold {
		return nil, nil
	}
	down, err := coolingDown(ctx, e.rdb, "detect:cooldown:volume:"+ev.SrcIP, ev.Timestamp, highVolumeCooldown)
	if err != nil || down {
		return nil, err
	}

	a := newAlert(ev.Timestamp, models.AlertHighVolume, models.SeverityHigh,
		fmt.Sprintf("High-volume outbound traffic from %s", ev.SrcIP),
		fmt.Sprintf("%s transferred %.1f MB across %d connections within %s (most recently to %s:%d). "+
			"This volume is well above baseline and may indicate data exfiltration.",
			ev.SrcIP, float64(sum)/1024/1024, count, highVolumeWindow, ev.DstIP, ev.DstPort))
	a.SrcIP, a.DstIP, a.DstPort = ev.SrcIP, ev.DstIP, ev.DstPort
	a.AssetHostname = e.hostnameFor(ev.SrcIP)
	a.EventCount = count
	e.enrichIP(&a, ev.SrcIP, ev.DstIP)
	return &a, nil
}
