#!/usr/bin/env python3
"""
Seeds PostgreSQL with the asset inventory (data/assets.json) and the local
threat intel blocklists (data/threat_intel/*.csv), so the analyst API and
Grafana dashboards can join alerts against known hosts/indicators.

Runs once as the `seed-assets` service in docker-compose.yml, after
Postgres's schema.sql init script has already created the tables.

Usage: POSTGRES_DSN=postgresql://... python3 scripts/seed_assets.py
"""
import csv
import json
import os
import sys
import time

import psycopg2

DATA_DIR = "/data" if os.path.isdir("/data") else os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"
)


def wait_for_postgres(dsn, attempts=20, delay=2):
    for i in range(attempts):
        try:
            conn = psycopg2.connect(dsn)
            return conn
        except psycopg2.OperationalError as e:
            print(f"postgres not ready ({e}); retrying ({i+1}/{attempts})", file=sys.stderr)
            time.sleep(delay)
    raise SystemExit("could not connect to postgres")


def seed_assets(cur):
    with open(os.path.join(DATA_DIR, "assets.json")) as f:
        assets = json.load(f)
    for a in assets:
        cur.execute(
            """
            INSERT INTO assets (ip, hostname, asset_type, role, criticality, owner)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (ip) DO UPDATE SET
                hostname = EXCLUDED.hostname, asset_type = EXCLUDED.asset_type,
                role = EXCLUDED.role, criticality = EXCLUDED.criticality, owner = EXCLUDED.owner
            """,
            (a["ip"], a["hostname"], a["asset_type"], a["role"], a["criticality"], a["owner"]),
        )
    print(f"seeded {len(assets)} assets")


def seed_threat_intel(cur):
    total = 0
    for filename, indicator_type, key_col in (
        ("malicious_ips.csv", "ip", "ip"),
        ("malicious_domains.csv", "domain", "domain"),
    ):
        path = os.path.join(DATA_DIR, "threat_intel", filename)
        with open(path) as f:
            rows = [line for line in f if not line.startswith("#")]
        for row in csv.DictReader(rows):
            cur.execute(
                """
                INSERT INTO threat_intel_indicators
                    (indicator, indicator_type, category, source, confidence, description, first_seen)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (indicator, indicator_type) DO UPDATE SET
                    category = EXCLUDED.category, source = EXCLUDED.source,
                    confidence = EXCLUDED.confidence, description = EXCLUDED.description,
                    first_seen = EXCLUDED.first_seen
                """,
                (
                    row[key_col], indicator_type, row["category"], row["source"],
                    row["confidence"], row["description"], row["first_seen"],
                ),
            )
            total += 1
    print(f"seeded {total} threat intel indicators")


def main():
    dsn = os.environ.get(
        "POSTGRES_DSN", "postgresql://nidr:nidr_dev_password@localhost:5432/nidr"
    )
    conn = wait_for_postgres(dsn)
    conn.autocommit = True
    with conn.cursor() as cur:
        seed_assets(cur)
        seed_threat_intel(cur)
    conn.close()


if __name__ == "__main__":
    main()
