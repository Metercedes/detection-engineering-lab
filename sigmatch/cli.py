"""Command line entry point.

sigmatch validate                 check rules parse and carry required metadata
sigmatch coverage                 print the ATT&CK coverage table
sigmatch hunt EVENTS.jsonl        report which rules match which events
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sigmatch.attack import render_markdown
from sigmatch.corpus import load_events
from sigmatch.correlation import evaluate_correlation, load_correlations
from sigmatch.errors import SigmaError
from sigmatch.matcher import matches
from sigmatch.rule import load_rules

DEFAULT_DETECTIONS = Path("detections")


def _load(detections: Path):
    return load_rules(detections), load_correlations(detections)


def cmd_validate(args: argparse.Namespace) -> int:
    rules, correlations = _load(args.detections)
    print(f"{len(rules)} detection rules and {len(correlations)} correlation rules parsed")
    problems = []
    for rule in rules:
        if not rule.falsepositives:
            problems.append(f"{rule.path.name}: no documented false positives")
        if not (rule.attack_techniques or rule.attack_tactics):
            problems.append(f"{rule.path.name}: no ATT&CK tags")
    for problem in problems:
        print(f"  problem: {problem}", file=sys.stderr)
    return 1 if problems else 0


def cmd_coverage(args: argparse.Namespace) -> int:
    rules, correlations = _load(args.detections)
    print(render_markdown(rules, correlations))
    return 0


def cmd_hunt(args: argparse.Namespace) -> int:
    rules, correlations = _load(args.detections)
    events = load_events(args.events)
    findings = []

    for rule in rules:
        hits = [e for e in events if matches(rule, e)]
        for event in hits:
            findings.append(
                {
                    "rule": rule.title,
                    "rule_id": rule.id,
                    "level": rule.level,
                    "techniques": rule.attack_techniques,
                    "timestamp": event.get("@timestamp"),
                    "host": event.get("host", {}).get("name"),
                    "user": event.get("user", {}).get("name"),
                    "evidence": event.get("process", {}).get("command_line")
                    or event.get("registry", {}).get("path")
                    or event.get("service", {}).get("name"),
                }
            )

    base = {r.id: r for r in rules}
    for correlation in correlations:
        for hit in evaluate_correlation(correlation, base, events):
            findings.append(
                {
                    "rule": correlation.title,
                    "rule_id": correlation.id,
                    "level": correlation.level,
                    "techniques": sorted(
                        t.split(".", 1)[1].upper()
                        for t in correlation.tags
                        if t.lower().startswith("attack.t")
                    ),
                    "timestamp": hit.window_end.isoformat(),
                    "group": list(hit.group),
                    "observed": hit.observed,
                }
            )

    findings.sort(key=lambda f: (str(f.get("timestamp")), f["rule"]))
    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        if not findings:
            print("no rule matched any event")
        for finding in findings:
            detail = finding.get("evidence") or f"{finding.get('group')} x{finding.get('observed')}"
            print(f"[{finding['level']:>13}] {finding['timestamp']}  {finding['rule']}")
            print(f"{'':16}  {detail}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sigmatch", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--detections",
        type=Path,
        default=DEFAULT_DETECTIONS,
        help="directory of Sigma rules (default: detections)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="check rules parse and carry required metadata")
    validate.set_defaults(func=cmd_validate)

    coverage = sub.add_parser("coverage", help="print the ATT&CK coverage table")
    coverage.set_defaults(func=cmd_coverage)

    hunt = sub.add_parser("hunt", help="report which rules match events in a JSONL file")
    hunt.add_argument("events", type=Path)
    hunt.add_argument("--json", action="store_true", help="emit findings as JSON")
    hunt.set_defaults(func=cmd_hunt)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SigmaError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
