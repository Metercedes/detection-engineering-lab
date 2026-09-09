from __future__ import annotations

import json
from pathlib import Path


def load_events(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def load_corpus(root: Path) -> list[dict]:
    return [event for path in sorted(root.rglob("*.jsonl")) for event in load_events(path)]
