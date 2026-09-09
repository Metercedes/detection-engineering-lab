#!/usr/bin/env python3
"""Translate every Sigma rule into an Elastic Security detection rule under elastic/rules/."""

from __future__ import annotations

import json
from pathlib import Path

from sigmatch.elastic import to_elastic_rule
from sigmatch.rule import load_rules

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "elastic" / "rules"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for existing in OUT.glob("*.json"):
        existing.unlink()

    rules = load_rules(ROOT / "detections")
    languages: dict[str, int] = {}
    for rule in rules:
        exported = to_elastic_rule(rule)
        languages[exported["language"]] = languages.get(exported["language"], 0) + 1
        (OUT / f"{rule.path.stem}.json").write_text(
            json.dumps(exported, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    ndjson = OUT / "all-rules.ndjson"
    with ndjson.open("w", encoding="utf-8") as handle:
        for rule in rules:
            handle.write(json.dumps(to_elastic_rule(rule), sort_keys=True) + "\n")

    summary = ", ".join(f"{count} {language}" for language, count in sorted(languages.items()))
    print(f"exported {len(rules)} rules ({summary}) to {OUT}")
    print(f"import with: kibana Detection Rules > Import, using {ndjson.name}")


if __name__ == "__main__":
    main()
