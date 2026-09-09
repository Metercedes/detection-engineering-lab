#!/usr/bin/env bash
# Bring up the lab cluster and install the detection rules.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/elastic"

if [[ ! -f .env ]]; then
  echo "elastic/.env is missing. Copy elastic/.env.example and fill it in." >&2
  exit 1
fi

docker compose up -d
echo "waiting for Kibana"
until curl -sf http://localhost:5601/api/status >/dev/null; do sleep 5; done

cd "$root"
python scripts/export_elastic_rules.py
set -a; source elastic/.env; set +a
ELASTIC_USERNAME=elastic ELASTIC_PASSWORD="$ELASTIC_PASSWORD" python scripts/deploy_to_kibana.py

echo "Kibana: http://localhost:5601 (user: elastic)"
