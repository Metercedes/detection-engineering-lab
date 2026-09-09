#!/usr/bin/env python3
"""Install the exported detection rules into a running Kibana.

Credentials come from the environment, never from a file in the repository:

    export KIBANA_URL=http://localhost:5601
    export ELASTIC_USERNAME=elastic
    export ELASTIC_PASSWORD=...
    python scripts/deploy_to_kibana.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "elastic" / "rules"


def _auth_header() -> str:
    api_key = os.environ.get("ELASTIC_API_KEY")
    if api_key:
        return f"ApiKey {api_key}"
    username = os.environ.get("ELASTIC_USERNAME")
    password = os.environ.get("ELASTIC_PASSWORD")
    if not (username and password):
        raise SystemExit("set ELASTIC_API_KEY, or ELASTIC_USERNAME and ELASTIC_PASSWORD")
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def request(method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    base = os.environ.get("KIBANA_URL", "http://localhost:5601")
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        base + path,
        data=body,
        method=method,
        headers={
            "Authorization": _auth_header(),
            "Content-Type": "application/json",
            "kbn-xsrf": "detection-engineering-lab",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            text = response.read().decode()
            return response.status, json.loads(text) if text else {}
    except urllib.error.HTTPError as error:
        text = error.read().decode(errors="replace")
        try:
            return error.code, json.loads(text) if text else {}
        except json.JSONDecodeError:
            return error.code, {"message": text}


def main() -> int:
    files = sorted(RULES.glob("*.json"))
    if not files:
        raise SystemExit("no exported rules; run scripts/export_elastic_rules.py first")

    installed = updated = failed = 0
    for path in files:
        rule = json.loads(path.read_text(encoding="utf-8"))
        status, body = request("POST", "/api/detection_engine/rules", rule)
        if status in (200, 201):
            installed += 1
        elif status == 409:
            status, body = request("PUT", "/api/detection_engine/rules", rule)
            if status in (200, 201):
                updated += 1
            else:
                failed += 1
                print(f"  {path.name}: {status} {body.get('message')}", file=sys.stderr)
        else:
            failed += 1
            print(f"  {path.name}: {status} {body.get('message')}", file=sys.stderr)

    print(f"installed {installed}, updated {updated}, failed {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
