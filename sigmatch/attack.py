"""ATT&CK coverage summary across the rule set."""

from __future__ import annotations

from collections import defaultdict

from sigmatch.correlation import CorrelationRule
from sigmatch.rule import SigmaRule

TACTIC_ORDER = [
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]


def _techniques(tags: list[str]) -> list[str]:
    return sorted({t.split(".", 1)[1].upper() for t in tags if t.lower().startswith("attack.t")})


def _tactics(tags: list[str]) -> list[str]:
    known = set(TACTIC_ORDER)
    return sorted(
        {
            t.split(".", 1)[1]
            for t in tags
            if t.lower().startswith("attack.") and t.split(".", 1)[1].lower() in known
        }
    )


def coverage(rules: list[SigmaRule], correlations: list[CorrelationRule]) -> dict[str, list[str]]:
    by_tactic: dict[str, set[str]] = defaultdict(set)
    for item in [*rules, *correlations]:
        tags = item.tags
        for tactic in _tactics(tags):
            by_tactic[tactic].update(_techniques(tags))
    return {t: sorted(by_tactic[t]) for t in TACTIC_ORDER if t in by_tactic}


def render_markdown(rules: list[SigmaRule], correlations: list[CorrelationRule]) -> str:
    rows = coverage(rules, correlations)
    lines = ["| Tactic | Techniques | Rules |", "| --- | --- | --- |"]
    for tactic, techniques in rows.items():
        names = [item.title for item in [*rules, *correlations] if tactic in _tactics(item.tags)]
        lines.append(
            f"| {tactic.replace('_', ' ').title()} | {', '.join(techniques)} | {len(names)} |"
        )
    total = sorted({t for ts in rows.values() for t in ts})
    lines.append("")
    lines.append(
        f"{len(rules) + len(correlations)} rules covering {len(total)} techniques "
        f"across {len(rows)} tactics."
    )
    return "\n".join(lines)
