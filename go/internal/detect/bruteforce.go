package detect

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

const (
	bruteForceWindow     = 120 * time.Second
	bruteForceThreshold  = 6
	bruteForceCooldown   = 5 * time.Minute
	bruteForceSuccessMin = 4 // min recent failures to treat a success as suspicious
)

// DetectBruteForce watches ssh.log auth events. Repeated failures from one
// source to one destination within a short window is a brute-force
// signature; a success shortly after such a burst is treated as a likely
// compromise. See rules/sigma/ssh_brute_force.yml.
func (e *Engine) DetectBruteForce(ctx context.Context, ev models.Event) (*models.Alert, error) {
	if ev.Source != models.SourceZeekSSH || ev.SSHAuthSuccess == nil {
		return nil, nil
	}
	pairKey := "detect:bf:" + ev.SrcIP + "->" + ev.DstIP

	if !*ev.SSHAuthSuccess {
		member := strconv.FormatInt(ev.Timestamp.UnixNano(), 10)
		count, err := windowCount(ctx, e.rdb, pairKey, member, ev.Timestamp, bruteForceWindow)
		if err != nil {
			return nil, err
		}
		if count < bruteForceThreshold {
			return nil, nil
		}
		down, err := coolingDown(ctx, e.rdb, "detect:cooldown:bf:"+pairKey, ev.Timestamp, bruteForceCooldown)
		if err != nil || down {
			return nil, err
		}
		a := newAlert(ev.Timestamp, models.AlertBruteForce, models.SeverityHigh,
			fmt.Sprintf("SSH brute force from %s against %s", ev.SrcIP, ev.DstIP),
			fmt.Sprintf("%d failed SSH authentication attempts from %s to %s within %s.",
				count, ev.SrcIP, ev.DstIP, bruteForceWindow))
		a.SrcIP, a.DstIP, a.DstPort = ev.SrcIP, ev.DstIP, ev.DstPort
		a.AssetHostname = e.hostnameFor(ev.DstIP)
		a.EventCount = int(count)
		e.enrichIP(&a, ev.SrcIP, ev.DstIP)
		return &a, nil
	}

	// Successful auth — check for a recent burst of failures on the same pair.
	recentFailures, err := e.rdb.ZCount(ctx, pairKey,
		strconv.FormatInt(ev.Timestamp.Add(-bruteForceWindow).Unix(), 10),
		strconv.FormatInt(ev.Timestamp.Unix(), 10)).Result()
	if err != nil {
		return nil, fmt.Errorf("zcount recent ssh failures %s: %w", pairKey, err)
	}
	if recentFailures < bruteForceSuccessMin {
		return nil, nil
	}
	a := newAlert(ev.Timestamp, models.AlertBruteForce, models.SeverityCritical,
		fmt.Sprintf("Possible compromise: SSH login succeeded on %s after brute force from %s", ev.DstIP, ev.SrcIP),
		fmt.Sprintf("%s successfully authenticated to %s via SSH immediately after %d failed attempts in the "+
			"preceding %s. Treat the account and host as potentially compromised.",
			ev.SrcIP, ev.DstIP, recentFailures, bruteForceWindow))
	a.SrcIP, a.DstIP, a.DstPort = ev.SrcIP, ev.DstIP, ev.DstPort
	a.AssetHostname = e.hostnameFor(ev.DstIP)
	a.EventCount = int(recentFailures) + 1
	e.enrichIP(&a, ev.SrcIP, ev.DstIP)
	return &a, nil
}
