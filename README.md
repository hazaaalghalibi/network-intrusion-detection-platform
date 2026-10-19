# Network Intrusion Detection & Threat Intelligence Platform

A mini Network Detection & Response (NDR) platform: it ingests Zeek
connection/DNS/SSH logs and Suricata IDS alerts, normalizes them into a
common event schema, runs a custom detection engine (port scanning, SSH
brute force, DNS tunneling, C2 beaconing, data exfiltration, known-bad
indicators, YARA file matches), enriches everything against a local threat
intel blocklist, and gives an analyst a Grafana dashboard plus a REST API
for triage — status, notes, and one-click incident report export.

Built as a defensive-security / blue-team portfolio project. See
[Ethics & safety](#ethics--safety) before assuming any of the "attacker" IPs
or domains below are real.

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full diagram.
Short version:

```
Zeek/Suricata sample logs
        |
        v
cmd/ingest (Go) --parse+normalize--> OpenSearch (events-*)
        |
        +--detection engine (Redis-backed sliding windows)
        |    port scan | brute force | DNS tunneling | beaconing
        |    high-volume traffic | known-bad IP/domain | YARA file match
        |
        +--threat intel enrichment + severity scoring
        |
        v
   Redis Stream "alerts"
        |
        v
cmd/worker (Go) --> OpenSearch (alerts-*) + PostgreSQL (alerts, notes, assets)
        |
        v
cmd/api (Go REST API) <--- Nginx <--- Analyst browser
        |
   Grafana dashboards (Postgres + OpenSearch datasources)
```

## Why sample data, not live packet capture

This repo ships pre-generated Zeek/Suricata logs in their real on-disk
formats (`scripts/generate_logs.py`) instead of running Zeek/Suricata
containers against PCAPs. That keeps the stack fast to build and run
locally, and avoids the two heaviest, most fragile pieces of a real NDR
deployment. The parsing and detection code is real and works against real
Zeek/Suricata output — point `SAMPLE_LOGS_DIR` at genuine Zeek/Suricata logs
and it runs unmodified.

## Ethics & safety

- Every "malicious" IP in this repo is drawn from **RFC 5737** documentation
  ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) — reserved by
  IANA for exactly this purpose, never assigned to real hosts.
- Every "malicious" domain uses the **`.test`** TLD (RFC 2606), which is
  guaranteed to never resolve on the real internet.
- `data/malware_samples/` contains **inert text only** — the industry
  standard EICAR AV test string, and plain-text files containing strings a
  YARA rule can match (a fake PowerShell cradle, a fake ransom note). Nothing
  in this repo executes, scans, or contacts a real host. See
  [`data/malware_samples/README.md`](data/malware_samples/README.md).
- Nothing in this repo performs network scanning, exploitation, or traffic
  generation against any real system.

## Quickstart

Prerequisites: Docker + Docker Compose v2, ~4GB RAM free for OpenSearch,
internet access on first boot (Grafana downloads the OpenSearch datasource
plugin, and image pulls need to happen at least once).

```bash
git clone <this-repo> && cd Network-Intrusion-Detection-Platform
docker compose up -d --build
```

This starts OpenSearch, PostgreSQL, Redis, Grafana, Nginx, and three Go
services (`ingest`, `worker`, `api`). `ingest` parses the sample logs, runs
detection, and exits after publishing alerts; `worker` and `api` keep
running. `seed-assets` loads the asset inventory + threat intel into
Postgres.

Then:

- **Grafana dashboards**: http://localhost/grafana/ (login `admin` / `admin`)
  — "NIDR - SOC Overview" is pre-provisioned and should already show data
    (the dashboard's time range is fixed to the sample data's window).
- **Analyst API**: http://localhost/api/alerts
- **OpenSearch**: http://localhost:9200 (security plugin disabled — local
  demo only, see [Security notes](#security-notes))

Regenerate the sample data (deterministic, seeded) at any time:

```bash
python3 scripts/generate_logs.py
```

### Troubleshooting: OpenSearch won't start (`max virtual memory areas too low`)

OpenSearch (like Elasticsearch) needs the host's `vm.max_map_count` set to
at least `262144`. Most Docker Desktop installs already set this inside
their VM; on native Linux hosts you may need to run once:

```bash
sudo sysctl -w vm.max_map_count=262144
```

(`terraform/user_data.sh.tpl` sets this automatically for the optional EC2
deploy path.)

## Project layout

```
docker-compose.yml        Full local stack: opensearch, postgres, redis,
                           grafana, nginx, + 3 Go services
go/                        Go module (module github.com/hazaaalghalibi/network-intrusion-detection-platform)
  cmd/ingest/               Parses sample logs, runs detection, publishes alerts
  cmd/worker/               Redis Stream consumer -> OpenSearch + PostgreSQL
  cmd/api/                  Analyst REST API (net/http, no router dependency)
  internal/models/          Event, Alert, Asset, AlertNote types
  internal/parse/           Zeek TSV + Suricata eve.json -> normalized Event
  internal/detect/          Detection engine: one file per technique
  internal/threatintel/     Local blocklist loader + matcher
  internal/store/opensearch/  OpenSearch client (bulk index, search)
  internal/store/postgres/    pgx-based alert/asset/note repository
  internal/queue/redis/     Redis Streams producer/consumer wrapper
  internal/api/             HTTP handlers
  internal/report/          Incident report Markdown generator
data/
  assets.json                Asset inventory (single source of truth)
  sample_logs/                Generated conn.log, dns.log, ssh.log, eve.json
  malware_samples/            Synthetic files for the YARA scanner (see Ethics)
  threat_intel/                malicious_ips.csv, malicious_domains.csv (RFC 5737)
scripts/
  generate_logs.py           Synthetic Zeek + Suricata generator with attack scenarios
  seed_assets.py              Seeds PostgreSQL from data/assets.json + threat_intel/*.csv
rules/
  sigma/                      Sigma rules documenting each detector's logic
  yara/                       YARA rules matched against data/malware_samples
opensearch/
  mappings/                   Index templates (events-*, alerts-*)
  init.sh                     Applies the templates on stack startup
sql/schema.sql               PostgreSQL schema
grafana/
  provisioning/                Datasource + dashboard-provider config
  dashboards/soc-overview.json  The 6-panel SOC dashboard (+ 4 stat tiles)
nginx/nginx.conf             Reverse proxy: /api -> api, /grafana -> grafana
docs/
  architecture.md             Full Mermaid architecture diagram + design rationale
  example_incident_report.md  A filled-out IR report for the sample dataset's scenario
  RESUME_BULLETS.md           Resume bullet points for this project
.github/workflows/ci.yml     Go build/vet/test, sample data regen, compose smoke test
terraform/                   Optional: single-EC2 docker-compose deploy path (not required for local use)
```

## Detection coverage

| Technique | Detector | Sigma doc |
|---|---|---|
| Port scanning | `internal/detect/portscan.go` | `rules/sigma/port_scan.yml` |
| SSH brute force + compromise | `internal/detect/bruteforce.go` | `rules/sigma/ssh_brute_force.yml` |
| DNS tunneling / high-entropy queries | `internal/detect/dns.go` | `rules/sigma/dns_tunneling.yml` |
| Known-bad IP / domain | `internal/detect/badip.go`, `internal/detect/dns.go` | `rules/sigma/known_bad_indicator.yml` |
| High-volume outbound (exfiltration) | `internal/detect/volume.go` | `rules/sigma/high_volume_outbound.yml` |
| C2 beaconing (regular-interval connections) | `internal/detect/beacon.go` | `rules/sigma/c2_beaconing.yml` |
| Suricata alert passthrough | `internal/detect/suricata.go` | — (Suricata already decided alert-worthiness; this re-scores severity/enrichment) |
| Malicious file patterns | `internal/detect/yara.go` (shells out to the `yara` CLI) | `rules/yara/*.yar` |

Every detector uses **Redis-backed sliding windows scored by the event's own
timestamp**, not wall-clock time — see
[`docs/architecture.md`](docs/architecture.md#why-this-shape) for why that
matters when replaying a full day of logs in a few seconds. All detectors
enrich against the local threat-intel blocklist and escalate severity
(Low/Medium/High/Critical) by indicator confidence.

## Analyst workflow (REST API)

| Method | Path | Description |
|---|---|---|
| GET | `/api/alerts` | List alerts. Filters: `?status=`, `?severity=`, `?alert_type=`, `?limit=`, `?offset=` |
| GET | `/api/alerts/{id}` | Get one alert |
| PATCH | `/api/alerts/{id}` | Update status: `{"status": "investigating"}` (`open`/`investigating`/`resolved`/`false_positive`) |
| GET | `/api/alerts/{id}/notes` | List analyst notes |
| POST | `/api/alerts/{id}/notes` | Add a note: `{"author": "...", "note": "..."}` |
| GET | `/api/alerts/{id}/report` | Export a Markdown incident report (see `docs/example_incident_report.md` for the shape) |
| GET | `/api/assets` | List the asset inventory |
| GET | `/api/events/search?ip=` | Search raw normalized events (OpenSearch) by source/destination IP |

Example:

```bash
curl http://localhost/api/alerts?severity=critical
curl -X PATCH http://localhost/api/alerts/<id> -d '{"status":"investigating"}'
curl -X POST http://localhost/api/alerts/<id>/notes -d '{"author":"analyst1","note":"Confirmed compromise, isolating host."}'
curl http://localhost/api/alerts/<id>/report
```

## Dashboards

`grafana/dashboards/soc-overview.json` is pre-provisioned and covers all six
required analyst views: alerts over time (by severity), top suspicious IPs,
affected internal hosts, most common alert types, severity breakdown, and
threat-intelligence matches — plus 4 summary stat tiles. It's built entirely
against PostgreSQL (every field needed is on the `alerts` table); a second
OpenSearch datasource is also provisioned for ad-hoc raw-event queries. See
[`docs/architecture.md`](docs/architecture.md#why-this-shape) for why the
dashboard is Postgres-backed rather than hand-written OpenSearch aggregation
DSL.

Screenshots: this environment couldn't run Docker to capture live
screenshots (no daemon access in the sandbox this was built in) — run
`docker compose up -d --build` and open http://localhost/grafana/ to see it
populated with the sample incident.

## Security notes (this is a demo, not a hardened deployment)

- OpenSearch runs with its security plugin disabled and no auth — fine for
  a local demo, not for anything internet-facing.
- Postgres/Grafana credentials in `docker-compose.yml` are placeholder dev
  credentials, not secrets — rotate before deploying anywhere real.
- Nginx terminates plain HTTP; add TLS before exposing this beyond
  localhost.

## Optional: cloud deployment

`terraform/` provisions a single EC2 instance that runs the exact same
`docker compose up` — not a production reference architecture, just an
optional way to demo this from a public URL instead of localhost. See
[`terraform/README.md`](terraform/README.md).

## CI

`.github/workflows/ci.yml` runs on every push/PR: Go build/vet/test/gofmt,
regenerates and sanity-checks the sample dataset, validates
`docker-compose.yml`, and — the real end-to-end check — brings up the full
stack with `docker compose up`, waits for it to become healthy, and asserts
that alerts actually made it through Redis → OpenSearch → PostgreSQL → the
API.

## Further reading

- [`docs/architecture.md`](docs/architecture.md) — full diagram + design rationale
- [`docs/example_incident_report.md`](docs/example_incident_report.md) — a filled-out IR report for the sample dataset's simulated incident
- [`docs/RESUME_BULLETS.md`](docs/RESUME_BULLETS.md) — resume bullet points for this project
- [`rules/sigma/`](rules/sigma/) — detection logic documented as Sigma rules
