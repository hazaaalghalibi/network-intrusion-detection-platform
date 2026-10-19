package detect

import (
	"context"
	"fmt"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

const suricataCooldown = 5 * time.Minute

// ProcessSuricataAlert converts every ingested Suricata eve.json alert into
// a NIDR alert, re-scored through the same threat-intel enrichment as every
// other detector. Suricata already decided the event is alert-worthy; this
// step is about normalization and severity re-scoring, not re-detection.
func (e *Engine) ProcessSuricataAlert(ctx context.Context, ev models.Event) (*models.Alert, error) {
	if ev.Source != models.SourceSuricata {
		return nil, nil
	}
	cdKey := "detect:cooldown:suricata:" + ev.SuricataSignature + ":" + ev.SrcIP + "->" + ev.DstIP
	down, err := coolingDown(ctx, e.rdb, cdKey, ev.Timestamp, suricataCooldown)
	if err != nil || down {
		return nil, err
	}

	a := newAlert(ev.Timestamp, models.AlertSuricataIDS, suricataSeverity(ev.SuricataSeverity),
		ev.SuricataSignature,
		fmt.Sprintf("Suricata IDS alert: %s -> %s:%d. Category: %s.",
			ev.SrcIP, ev.DstIP, ev.DstPort, ev.SuricataCategory))
	a.SrcIP, a.DstIP, a.DstPort = ev.SrcIP, ev.DstIP, ev.DstPort
	a.AssetHostname = e.hostnameFor(ev.SrcIP)
	if a.AssetHostname == "" {
		a.AssetHostname = e.hostnameFor(ev.DstIP)
	}
	e.enrichIP(&a, ev.SrcIP, ev.DstIP)
	return &a, nil
}

// suricataSeverity maps Suricata's native 1(highest)-3(lowest) severity
// scale onto this platform's Low/Medium/High/Critical scale.
func suricataSeverity(s int) models.Severity {
	switch s {
	case 1:
		return models.SeverityCritical
	case 2:
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}
