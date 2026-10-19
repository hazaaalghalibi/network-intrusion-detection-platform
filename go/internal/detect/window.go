package detect

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// windowCount adds member to a Redis sorted set keyed by key with
// score=ts.Unix(), trims entries older than `window`, and returns the
// number of members remaining.
//
// Every detector uses the event's own timestamp as the score — not wall
// clock — so replaying a full day of historical logs in a few seconds
// still produces correct sliding-window semantics. A generous real-world
// EXPIRE is set alongside purely as hygiene for a long-running deployment;
// it is not relied on for correctness.
func windowCount(ctx context.Context, rdb *redis.Client, key, member string, ts time.Time, window time.Duration) (int64, error) {
	score := float64(ts.Unix())
	pipe := rdb.TxPipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: score, Member: member})
	pipe.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatFloat(score-window.Seconds(), 'f', 0, 64))
	pipe.Expire(ctx, key, window+time.Hour)
	card := pipe.ZCard(ctx, key)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("window count %s: %w", key, err)
	}
	return card.Val(), nil
}

// coolingDown reports whether an alert of this kind already fired within
// `cooldown` of ts, and if not, marks one as having fired now. Same
// event-time-not-wall-clock reasoning as windowCount.
func coolingDown(ctx context.Context, rdb *redis.Client, key string, ts time.Time, cooldown time.Duration) (bool, error) {
	now := ts.Unix()
	lastStr, err := rdb.Get(ctx, key).Result()
	if err == nil {
		if last, perr := strconv.ParseInt(lastStr, 10, 64); perr == nil && now-last < int64(cooldown.Seconds()) {
			return true, nil
		}
	} else if err != redis.Nil {
		return false, fmt.Errorf("cooldown get %s: %w", key, err)
	}
	if err := rdb.Set(ctx, key, now, cooldown+time.Hour).Err(); err != nil {
		return false, fmt.Errorf("cooldown set %s: %w", key, err)
	}
	return false, nil
}
