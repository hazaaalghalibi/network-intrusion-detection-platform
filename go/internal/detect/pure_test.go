package detect

import (
	"testing"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		name    string
		s       string
		wantLow bool // true if this should be well below the tunneling threshold
	}{
		{"empty", "", true},
		{"repeated char", "aaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"english word", "administrator", true},
		{"random looking", "k3f9zq2mx7vb1jd8wne0plrt", false},
	}
	for _, c := range cases {
		got := shannonEntropy(c.s)
		isLow := got < highEntropyBits
		if isLow != c.wantLow {
			t.Errorf("shannonEntropy(%q) = %.2f, wantLow=%v (threshold %.2f)", c.s, got, c.wantLow, highEntropyBits)
		}
	}
}

func TestMeanStddev(t *testing.T) {
	mean, stddev := meanStddev([]float64{90, 90, 90, 90})
	if mean != 90 || stddev != 0 {
		t.Errorf("constant series: mean=%.2f stddev=%.2f, want 90/0", mean, stddev)
	}

	mean, stddev = meanStddev([]float64{10, 100, 10, 100})
	if mean != 55 {
		t.Errorf("mean = %.2f, want 55", mean)
	}
	if stddev < 40 {
		t.Errorf("stddev = %.2f, want a large value for a high-variance series", stddev)
	}

	if mean, stddev := meanStddev(nil); mean != 0 || stddev != 0 {
		t.Errorf("empty series: mean=%.2f stddev=%.2f, want 0/0", mean, stddev)
	}
}

func TestConfidenceSeverity(t *testing.T) {
	cases := map[string]models.Severity{
		"high":    models.SeverityCritical,
		"medium":  models.SeverityHigh,
		"low":     models.SeverityMedium,
		"unknown": models.SeverityMedium,
	}
	for confidence, want := range cases {
		if got := confidenceSeverity(confidence); got != want {
			t.Errorf("confidenceSeverity(%q) = %q, want %q", confidence, got, want)
		}
	}
}

func TestSeverityMax(t *testing.T) {
	if got := models.SeverityLow.Max(models.SeverityCritical); got != models.SeverityCritical {
		t.Errorf("Low.Max(Critical) = %q, want critical", got)
	}
	if got := models.SeverityHigh.Max(models.SeverityLow); got != models.SeverityHigh {
		t.Errorf("High.Max(Low) = %q, want high", got)
	}
}

func TestYaraSeverity(t *testing.T) {
	if got := yaraSeverity("fake_ransomware_note"); got != models.SeverityCritical {
		t.Errorf("yaraSeverity(fake_ransomware_note) = %q, want critical", got)
	}
	if got := yaraSeverity("eicar_test_string"); got != models.SeverityLow {
		t.Errorf("yaraSeverity(eicar_test_string) = %q, want low", got)
	}
}

func TestSuricataSeverity(t *testing.T) {
	if got := suricataSeverity(1); got != models.SeverityCritical {
		t.Errorf("suricataSeverity(1) = %q, want critical", got)
	}
	if got := suricataSeverity(3); got != models.SeverityLow {
		t.Errorf("suricataSeverity(3) = %q, want low", got)
	}
}
