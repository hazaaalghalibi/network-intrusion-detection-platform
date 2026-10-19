# Resume bullet points

Pick 3-5 relevant to the role you're applying for — don't paste all of them.

## Security / SOC / Detection Engineering focused

- Designed and built a mini Network Detection & Response (NDR) platform in Go
  that ingests Zeek connection/DNS/SSH logs and Suricata IDS alerts,
  normalizes them into a common event schema, and runs a custom detection
  engine covering port scanning, SSH brute force, DNS tunneling, C2
  beaconing, and data exfiltration.
- Wrote detection logic for 7 distinct attack techniques (port scanning,
  credential brute force, DNS tunneling, C2 beaconing, known-bad-indicator
  matching, high-volume exfiltration, malicious file patterns) and documented
  each as a vendor-neutral Sigma rule, mapped 1:1 to MITRE ATT&CK techniques.
- Built a threat-intelligence enrichment pipeline that scores alert severity
  (Low/Medium/High/Critical) against a local IOC blocklist, and integrated
  YARA-based file scanning via CLI shell-out for malware pattern matching.
- Implemented an event-driven alert pipeline using Redis Streams as a message
  queue between a Go detection service and a Go persistence worker,
  decoupling detection throughput from storage writes.
- Built a REST API (Go, stdlib `net/http`) supporting the full SOC analyst
  triage workflow: alert status transitions (open/investigating/
  resolved/false positive), analyst notes, and on-demand Markdown incident
  report generation.
- Modeled and implemented a PostgreSQL schema for alert workflow state and
  asset inventory, and OpenSearch index templates for searchable
  event/alert storage at scale.
- Authored 6 Grafana dashboard panels (alert volume over time by severity,
  top suspicious IPs, affected internal hosts, alert-type breakdown,
  severity breakdown, threat-intel match table) driven entirely by
  parameterized SQL against the live alert data.
- Containerized a 9-service security stack (OpenSearch, PostgreSQL, Redis,
  Grafana, Nginx, and 3 Go microservices) with Docker Compose and a
  GitHub Actions CI pipeline that builds, tests, and smoke-tests the full
  stack end-to-end on every push.

## Backend / Platform Engineering focused

- Designed a multi-service Go backend (3 independent binaries sharing common
  internal packages) around an event-sourcing pattern: a producer service
  publishes normalized domain events to a Redis Streams queue, a consumer
  group persists them idempotently to both a search index and a relational
  store.
- Built a normalization layer that ingests two structurally different log
  formats (Zeek's self-describing TSV and Suricata's line-delimited JSON)
  into one common Go struct, using each format's own schema metadata rather
  than hardcoded field positions.
- Implemented sliding-window stream analytics (rate limiting-style counters,
  time-series aggregation, statistical anomaly detection) using Redis sorted
  sets, correctly handling both live and fast-forward batch-replay execution
  by scoring on event time rather than wall-clock time.
- Wrote a REST API with Go's standard library (`net/http`, 1.22+ method/path
  routing) with zero third-party router dependency, backed by `pgx` for
  PostgreSQL and the official OpenSearch Go client.
- Set up a CI pipeline (GitHub Actions) that builds and vets the Go module,
  regenerates and validates sample data, validates Docker Compose config,
  and runs a full end-to-end smoke test against a live `docker compose up`
  stack before merge.

## Data / Dashboarding focused

- Authored parameterized SQL queries (including `LATERAL` joins over JSONB
  arrays) powering a full Grafana analytics dashboard: time-series alert
  volume, ranked bar-gauge breakdowns, pie charts, and enrichment tables.
- Applied a semantic color system (severity mapped to fixed status colors
  across every panel; magnitude-ranked panels on single-hue gradients rather
  than arbitrary categorical color) for a dashboard that reads consistently
  at a glance.
