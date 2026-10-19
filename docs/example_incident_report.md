# Incident Report: INC-2026-0630-01 — SSH Bastion Compromise, Lateral Movement, and C2 Beaconing

**All indicators below are synthetic** — RFC 5737 documentation IP ranges
(`198.51.100.0/24`, `203.0.113.0/24`) and RFC 2606 `.test` domains, generated
by `scripts/generate_logs.py` for this demo. This report demonstrates the
platform's detection coverage and the analyst workflow (`/api/alerts/{id}/report`
generates this same document shape automatically from live alert + note data).

| Field | Value |
|---|---|
| Severity | **Critical** |
| Status | Resolved |
| Detected | 2026-06-30 14:05 UTC (automated, real-time) |
| Reported by | NIDR platform (automated detection) |
| Analyst | J. Rivera (SOC Tier 2) |
| Affected assets | `srv-jump-01` (10.0.0.10), `srv-db-01` (10.0.0.12), `ws-eng-02` (10.0.0.24) |

## Executive Summary

Between 14:00 and 14:51 UTC on 2026-06-30, an external host (`198.51.100.23`)
scanned and then brute-forced SSH on the internet-facing bastion host
`srv-jump-01`, succeeding after 24 failed attempts. From the compromised
bastion, the attacker performed an internal port-scan of the LAN, established
periodic C2 beaconing to `203.0.113.66`, and exfiltrated approximately
359 MB from the database server `srv-db-01` to the same C2 address.
Independently, a separate workstation (`ws-eng-02`) was found running a DNS
tunneling channel against `badc2exfil.test`. All activity was detected in
real time by the platform's detection engine, and the affected hosts were
isolated within the same operational window.

## Timeline (UTC, 2026-06-30)

| Time | Event | Alert type | Severity |
|---|---|---|---|
| 14:00:00–14:00:26 | `198.51.100.23` scans 26 ports on `srv-jump-01` | `port_scan` | Medium |
| 14:03:00–14:05:29 | 24 failed SSH auth attempts, `198.51.100.23` → `srv-jump-01` | `brute_force` | High |
| 14:05:29 | SSH auth **succeeds** immediately after the failure burst | `brute_force` (compromise) | **Critical** |
| 14:10:29–14:11:00 | `srv-jump-01` probes 105 dst_ip:port combinations across 15 internal hosts | `port_scan` | Medium |
| 14:10:34 | `srv-jump-01` → `srv-db-01`:5432 (staging/lateral touch) | — | — |
| 14:20:29–14:48:57 | `srv-jump-01` beacons to `203.0.113.66`:443 every ~90s (20x) | `beaconing`, `known_bad_ip` | High / Critical |
| 14:40:00–14:50:30 | `ws-eng-02` issues 55 high-entropy DNS queries to `*.badc2exfil.test` | `dns_anomaly`, `known_bad_domain` | High / Critical |
| 14:45:29–14:47:49 | `srv-db-01` sends 359MB to `203.0.113.66`:8443 in 8 bursts | `high_volume_traffic`, `known_bad_ip` | High / Critical |
| 15:30 (approx.) | IR sweep recovers `suspicious_script_sample.txt` referencing `198.51.100.77` (known exfil drop, per threat intel) | `malware_file_match` (YARA: `suspicious_powershell_cradle`) | High |
| 15:32 (approx.) | `eicar_test_file.txt` flagged by YARA — confirmed AV test artifact | `malware_file_match` (YARA: `eicar_test_string`) | Low — marked **false positive** |
| 16:00 | `srv-jump-01` and `srv-db-01` isolated from the network | — | — |
| 17:15 | Incident marked **Resolved** after credential rotation and host rebuild | — | — |

## Indicators of Compromise

| Indicator | Type | Category | Confidence |
|---|---|---|---|
| `198.51.100.23` | IP | scanner / brute-force source | High |
| `203.0.113.66` | IP | C2 / beaconing endpoint | High |
| `198.51.100.77` | IP | exfil drop (referenced in dropped file only) | High |
| `badc2exfil.test` | Domain | DNS tunneling / C2 | High |

## Affected Assets

| Hostname | IP | Role | Criticality | Impact |
|---|---|---|---|---|
| `srv-jump-01` | 10.0.0.10 | Internet-facing SSH bastion | High | Compromised, used for recon + C2 beaconing |
| `srv-db-01` | 10.0.0.12 | Primary database server | Critical | Data exfiltrated (~370MB) |
| `ws-eng-02` | 10.0.0.24 | Engineering workstation | Medium | Separate DNS tunneling infection |

## Detection Details

Every alert in this incident was raised automatically by
`go/internal/detect/`, with the corresponding vendor-neutral logic
documented under `rules/sigma/`:

- Port scans: `internal/detect/portscan.go` / `rules/sigma/port_scan.yml`
- SSH brute force + compromise: `internal/detect/bruteforce.go` /
  `rules/sigma/ssh_brute_force.yml`
- C2 beaconing: `internal/detect/beacon.go` / `rules/sigma/c2_beaconing.yml`
- DNS tunneling: `internal/detect/dns.go` / `rules/sigma/dns_tunneling.yml`
- Known-bad IP/domain: `internal/detect/badip.go` + `internal/detect/dns.go`
  / `rules/sigma/known_bad_indicator.yml`
- High-volume outbound: `internal/detect/volume.go` /
  `rules/sigma/high_volume_outbound.yml`
- File-based indicators: `internal/detect/yara.go` against
  `rules/yara/*.yar`

## Response Actions Taken

1. Isolated `srv-jump-01` and `srv-db-01` from the network at 16:00 UTC.
2. Rotated SSH credentials for all bastion accounts; enforced key-only auth
   going forward (password auth had been enabled for `srv-jump-01`).
3. Blocked `198.51.100.23`, `203.0.113.66`, `198.51.100.77`, and
   `badc2exfil.test` at the perimeter firewall / DNS resolver.
4. Rebuilt `srv-jump-01` from a known-good image; restored `srv-db-01` from
   the last verified pre-incident backup snapshot.
5. Re-imaged `ws-eng-02` after confirming the DNS tunneling implant via
   forensic review.
6. Reviewed `eicar_test_file.txt` and confirmed it was a routine AV test
   artifact left by a prior tooling evaluation — closed as **false
   positive** rather than deleted, to demonstrate the triage workflow.

## Recommendations

1. Disable password authentication on all internet-facing SSH hosts; require
   key-based auth + MFA.
2. Add rate-limiting / fail2ban-equivalent throttling on `srv-jump-01`.
3. Segment the bastion host from direct access to `srv-db-01`; require a
   jump through a monitored, logged intermediary for database
   administration.
4. Add the confirmed IOCs to the persistent threat-intel blocklist (already
   done in `data/threat_intel/` for this demo).
5. Review DNS logs for other hosts querying `.test`-pattern high-entropy
   subdomains to rule out additional tunneling infections.

## Analyst Notes (from `alert_notes`)

> **J. Rivera** (2026-06-30 16:05): Confirmed `srv-jump-01` was running
> password-auth SSH exposed directly to the internet — that's how the
> brute force succeeded. Filing a follow-up ticket to enforce key-only auth
> fleet-wide.

> **J. Rivera** (2026-06-30 17:10): DB backup verified clean; exfiltrated
> data appears limited to the `orders` and `customers` tables based on
> query patterns in the touch event at 14:10:34. Legal/compliance notified
> per data-breach playbook.
