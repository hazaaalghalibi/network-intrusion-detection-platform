package threatintel

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestBlocklists(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ips := "ip,category,source,confidence,first_seen,description\n" +
		"203.0.113.66,c2,test-feed,high,2026-06-20,test entry\n"
	domains := "domain,category,source,confidence,first_seen,description\n" +
		"badc2exfil.test,c2,test-feed,high,2026-06-15,test entry\n"
	if err := os.WriteFile(filepath.Join(dir, "malicious_ips.csv"), []byte(ips), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "malicious_domains.csv"), []byte(domains), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestMatchIP(t *testing.T) {
	bl, err := Load(writeTestBlocklists(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := bl.MatchIP("203.0.113.66"); !ok {
		t.Error("expected match for blocklisted IP")
	}
	if _, ok := bl.MatchIP("10.0.0.10"); ok {
		t.Error("expected no match for internal IP")
	}
}

func TestMatchDomainIncludesSubdomains(t *testing.T) {
	bl, err := Load(writeTestBlocklists(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cases := []struct {
		domain string
		want   bool
	}{
		{"badc2exfil.test", true},
		{"abc123xyz.badc2exfil.test", true}, // subdomain of a flagged domain
		{"example.com", false},
	}
	for _, c := range cases {
		_, got := bl.MatchDomain(c.domain)
		if got != c.want {
			t.Errorf("MatchDomain(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
}
