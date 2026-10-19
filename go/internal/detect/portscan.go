package detect

import (
	"context"
	"fmt"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

const (
	portScanWindow    = 60 * time.Second
	portScanThreshold = 12
	portScanCooldown  = 5 * time.Minute
)

// DetectPortScan flags a single source touching many distinct
// dst_ip:dst_port pairs in a short window. Zeek marks unanswered SYNs as
// conn_state S0 (or REJ for actively refused), which is what a scan
// typically looks like on the wire — see rules/sigma/port_scan.yml.
func (e *Engine) DetectPortScan(ctx context.Context, ev models.Event) (*models.Alert, error) {
	if ev.Source != models.SourceZeekConn || (ev.ConnState != "S0" && ev.ConnState != "REJ") {
		return nil, nil
	}
	key := "detect:portscan:" + ev.SrcIP
	member := fmt.Sprintf("%s:%d", ev.DstIP, ev.DstPort)
	count, err := windowCount(ctx, e.rdb, key, member, ev.Timestamp, portScanWindow)
	if err != nil {
		return nil, err
	}
	if count < portScanThreshold {
		return nil, nil
	}
	down, err := coolingDown(ctx, e.rdb, "detect:cooldown:portscan:"+ev.SrcIP, ev.Timestamp, portScanCooldown)
	if err != nil || down {
		return nil, err
	}

	a := newAlert(ev.Timestamp, models.AlertPortScan, models.SeverityMedium,
		fmt.Sprintf("Port scan from %s", ev.SrcIP),
		fmt.Sprintf("%s contacted %d distinct destination ports within %s (most recently %s:%d). "+
			"This pattern is consistent with network reconnaissance / port scanning.",
			ev.SrcIP, count, portScanWindow, ev.DstIP, ev.DstPort))
	a.SrcIP, a.DstIP, a.DstPort = ev.SrcIP, ev.DstIP, ev.DstPort
	a.AssetHostname = e.hostnameFor(ev.SrcIP)
	a.EventCount = int(count)
	e.enrichIP(&a, ev.SrcIP, ev.DstIP)
	return &a, nil
}
