package detect

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

const (
	beaconWindow     = 40 * time.Minute
	beaconMinSamples = 6
	beaconMaxCV      = 0.15 // coefficient of variation (stddev/mean) of intervals
	beaconMinMean    = 5 * time.Second
	beaconMaxMean    = 15 * time.Minute
	beaconCooldown   = 20 * time.Minute
)

// DetectBeaconing looks for a src->dst:port pair connecting at a
// near-constant interval — low variance in inter-connection timing is the
// classic C2 beacon signature, in contrast to human-driven traffic which is
// bursty and irregular. See rules/sigma/c2_beaconing.yml.
func (e *Engine) DetectBeaconing(ctx context.Context, ev models.Event) (*models.Alert, error) {
	if ev.Source != models.SourceZeekConn {
		return nil, nil
	}
	key := fmt.Sprintf("detect:beacon:%s->%s:%d", ev.SrcIP, ev.DstIP, ev.DstPort)
	score := float64(ev.Timestamp.Unix())

	pipe := e.rdb.TxPipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: score, Member: ev.ID})
	pipe.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatFloat(score-beaconWindow.Seconds(), 'f', 0, 64))
	pipe.Expire(ctx, key, beaconWindow+time.Hour)
	zrange := pipe.ZRangeWithScores(ctx, key, 0, -1)
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("beacon window %s: %w", key, err)
	}

	entries := zrange.Val()
	if len(entries) < beaconMinSamples {
		return nil, nil
	}
	times := make([]float64, len(entries))
	for i, z := range entries {
		times[i] = z.Score
	}
	sort.Float64s(times)
	intervals := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		intervals = append(intervals, times[i]-times[i-1])
	}
	mean, stddev := meanStddev(intervals)
	if mean < beaconMinMean.Seconds() || mean > beaconMaxMean.Seconds() || mean == 0 {
		return nil, nil
	}
	if stddev/mean > beaconMaxCV {
		return nil, nil
	}

	down, err := coolingDown(ctx, e.rdb, "detect:cooldown:beacon:"+key, ev.Timestamp, beaconCooldown)
	if err != nil || down {
		return nil, err
	}

	a := newAlert(ev.Timestamp, models.AlertBeaconing, models.SeverityHigh,
		fmt.Sprintf("Possible C2 beaconing from %s to %s:%d", ev.SrcIP, ev.DstIP, ev.DstPort),
		fmt.Sprintf("%s connected to %s:%d %d times at a near-constant interval (mean %.0fs, "+
			"coefficient of variation %.2f). This regularity is atypical of human-driven traffic and "+
			"consistent with C2 beaconing.",
			ev.SrcIP, ev.DstIP, ev.DstPort, len(entries), mean, stddev/mean))
	a.SrcIP, a.DstIP, a.DstPort = ev.SrcIP, ev.DstIP, ev.DstPort
	a.AssetHostname = e.hostnameFor(ev.SrcIP)
	a.EventCount = len(entries)
	e.enrichIP(&a, ev.SrcIP, ev.DstIP)
	return &a, nil
}

func meanStddev(xs []float64) (mean, stddev float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean = sum / float64(len(xs))
	var variance float64
	for _, x := range xs {
		variance += (x - mean) * (x - mean)
	}
	variance /= float64(len(xs))
	return mean, math.Sqrt(variance)
}
