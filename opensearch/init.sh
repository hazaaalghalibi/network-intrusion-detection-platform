#!/bin/sh
# Applies index templates so the events-* and alerts-* daily indices get the
# right field types (ip, date, keyword, nested threat_intel) from the first
# document onward, instead of relying on dynamic mapping guesses.
set -eu

OS_URL="${OPENSEARCH_URL:-http://opensearch:9200}"

echo "Waiting for OpenSearch at $OS_URL..."
until curl -sf "$OS_URL/_cluster/health" >/dev/null; do
  sleep 2
done

echo "Applying events-template..."
curl -sf -X PUT "$OS_URL/_index_template/events-template" \
  -H 'Content-Type: application/json' \
  --data-binary @/mappings/events-template.json

echo "Applying alerts-template..."
curl -sf -X PUT "$OS_URL/_index_template/alerts-template" \
  -H 'Content-Type: application/json' \
  --data-binary @/mappings/alerts-template.json

echo "OpenSearch index templates applied."
