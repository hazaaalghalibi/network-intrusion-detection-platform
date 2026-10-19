-- NIDR platform schema. Applied automatically on first container start via
-- postgres's /docker-entrypoint-initdb.d mechanism (see docker-compose.yml).
--
-- IP columns are TEXT rather than INET: this platform never does CIDR
-- arithmetic in SQL, and TEXT keeps the Go driver code trivial. Alerts and
-- events are correlated with assets by exact string match on IP.

CREATE TABLE IF NOT EXISTS assets (
    ip              TEXT PRIMARY KEY,
    hostname        TEXT NOT NULL,
    asset_type      TEXT NOT NULL,
    role            TEXT,
    criticality     TEXT NOT NULL DEFAULT 'medium',
    owner           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS threat_intel_indicators (
    indicator       TEXT NOT NULL,
    indicator_type  TEXT NOT NULL CHECK (indicator_type IN ('ip', 'domain')),
    category        TEXT NOT NULL,
    source          TEXT,
    confidence      TEXT NOT NULL DEFAULT 'medium',
    description     TEXT,
    first_seen      DATE,
    PRIMARY KEY (indicator, indicator_type)
);

CREATE TABLE IF NOT EXISTS alerts (
    id              UUID PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL,
    alert_type      TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    src_ip          TEXT,
    dst_ip          TEXT,
    dst_port        INTEGER,
    asset_hostname  TEXT,
    event_count     INTEGER NOT NULL DEFAULT 1,
    threat_intel    JSONB NOT NULL DEFAULT '[]'::jsonb,
    source_refs     JSONB NOT NULL DEFAULT '[]'::jsonb,
    status          TEXT NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_alert_type ON alerts (alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip     ON alerts (src_ip);

CREATE TABLE IF NOT EXISTS alert_notes (
    id              BIGSERIAL PRIMARY KEY,
    alert_id        UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    author          TEXT NOT NULL DEFAULT 'analyst',
    note            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alert_notes_alert_id ON alert_notes (alert_id);
