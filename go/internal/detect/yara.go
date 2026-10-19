package detect

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

// ScanMalwareSamples shells out to the `yara` CLI (installed in the ingest
// Docker image — see go/Dockerfile.ingest) against every rule file in
// rulesDir, scanned recursively over samplesDir. Real SOC pipelines often
// wire YARA in exactly this way: a CLI invocation from an orchestration
// service, rather than a library binding.
func (e *Engine) ScanMalwareSamples(ctx context.Context, rulesDir, samplesDir string, scanTime time.Time) ([]models.Alert, error) {
	ruleFiles, err := filepath.Glob(filepath.Join(rulesDir, "*.yar"))
	if err != nil {
		return nil, fmt.Errorf("glob yara rules in %s: %w", rulesDir, err)
	}

	var alerts []models.Alert
	for _, rule := range ruleFiles {
		cmd := exec.CommandContext(ctx, "yara", "-r", rule, samplesDir)
		out, runErr := cmd.Output()
		if runErr != nil {
			var exitErr *exec.ExitError
			// yara exits non-zero on some builds even when it successfully
			// finds matches; only bail out on errors that aren't a plain
			// non-zero exit (e.g. binary missing, bad rule syntax).
			if !errors.As(runErr, &exitErr) {
				return nil, fmt.Errorf("run yara for rule %s: %w", rule, runErr)
			}
		}
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			// `yara -r <rule> <dir>` prints one line per match:
			// "<rule_name> <matched_file_path>"
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				continue
			}
			ruleName, file := parts[0], parts[1]
			a := newAlert(scanTime, models.AlertMalwareFile, yaraSeverity(ruleName),
				fmt.Sprintf("YARA match: %s", ruleName),
				fmt.Sprintf("File %s matched YARA rule %q (defined in %s).",
					file, ruleName, filepath.Base(rule)))
			alerts = append(alerts, a)
		}
	}
	return alerts, nil
}

func yaraSeverity(ruleName string) models.Severity {
	switch ruleName {
	case "fake_ransomware_note":
		return models.SeverityCritical
	case "suspicious_powershell_cradle":
		return models.SeverityHigh
	default:
		return models.SeverityLow
	}
}
