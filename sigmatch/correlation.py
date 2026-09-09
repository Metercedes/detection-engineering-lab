"""Evaluation of Sigma correlation rules.

A single-event rule cannot express "ten failures within five minutes", so the Sigma correlation
types are handled here. A correlation rule names one or more base rules by id, groups their
matching events, and applies a threshold over a sliding time window.

Windows slide rather than tumble: for every matching event the window is the ``timespan`` ending
at that event. A tumbling window would let an attacker straddle a boundary and stay under the
threshold in both halves.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from sigmatch.errors import RuleParseError
from sigmatch.matcher import matches, resolve
from sigmatch.rule import SigmaRule

SUPPORTED_TYPES = ("event_count", "value_count")

_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_timespan(value: str) -> timedelta:
    text = str(value).strip()
    unit = text[-1].lower()
    if unit not in _UNITS:
        raise RuleParseError(f"unsupported timespan unit in {value!r}")
    try:
        amount = int(text[:-1])
    except ValueError as exc:
        raise RuleParseError(f"malformed timespan {value!r}") from exc
    return timedelta(**{_UNITS[unit]: amount})


def parse_timestamp(value: object) -> datetime:
    text = str(value).replace("Z", "+00:00")
    return datetime.fromisoformat(text)


@dataclass
class CorrelationRule:
    path: Path
    raw: dict

    @property
    def title(self) -> str:
        return self.raw["title"]

    @property
    def id(self) -> str:
        return self.raw["id"]

    @property
    def spec(self) -> dict:
        return self.raw["correlation"]

    @property
    def type(self) -> str:
        return self.spec["type"]

    @property
    def rules(self) -> list[str]:
        value = self.spec["rules"]
        return value if isinstance(value, list) else [value]

    @property
    def group_by(self) -> list[str]:
        return self.spec.get("group-by", []) or []

    @property
    def timespan(self) -> timedelta:
        return parse_timespan(self.spec["timespan"])

    @property
    def threshold(self) -> tuple[str, int]:
        condition = self.spec["condition"]
        for operator in ("gte", "gt", "lte", "lt", "eq"):
            if operator in condition:
                return operator, int(condition[operator])
        raise RuleParseError(f"{self.path.name}: correlation condition has no supported operator")

    @property
    def count_field(self) -> str | None:
        return self.spec.get("condition", {}).get("field") or self.spec.get("field")

    @property
    def tags(self) -> list[str]:
        return self.raw.get("tags", [])

    @property
    def level(self) -> str:
        return self.raw.get("level", "medium")


def load_correlations(root: Path) -> list[CorrelationRule]:
    found = []
    for path in sorted(root.rglob("*.yml")):
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if document and "correlation" in document:
                rule = CorrelationRule(path=path, raw=document)
                if rule.type not in SUPPORTED_TYPES:
                    raise RuleParseError(f"{path.name}: unsupported correlation type {rule.type!r}")
                found.append(rule)
    return found


def _compare(operator: str, observed: int, threshold: int) -> bool:
    return {
        "gte": observed >= threshold,
        "gt": observed > threshold,
        "lte": observed <= threshold,
        "lt": observed < threshold,
        "eq": observed == threshold,
    }[operator]


def _group_key(event: dict, fields: list[str]) -> tuple:
    return tuple(resolve(event, f) for f in fields)


@dataclass
class CorrelationHit:
    group: tuple
    observed: int
    window_end: datetime
    events: list[dict]


def evaluate_correlation(
    rule: CorrelationRule, base_rules: dict[str, SigmaRule], events: list[dict]
) -> list[CorrelationHit]:
    missing = [rid for rid in rule.rules if rid not in base_rules]
    if missing:
        raise RuleParseError(f"{rule.path.name}: references unknown base rule id(s) {missing}")

    candidates = [
        event for event in events if any(matches(base_rules[rid], event) for rid in rule.rules)
    ]
    candidates.sort(key=lambda e: parse_timestamp(e["@timestamp"]))

    operator, threshold = rule.threshold
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for event in candidates:
        grouped[_group_key(event, rule.group_by)].append(event)

    hits: list[CorrelationHit] = []
    span = rule.timespan
    for group, group_events in grouped.items():
        for index, event in enumerate(group_events):
            end = parse_timestamp(event["@timestamp"])
            window = [
                e
                for e in group_events[: index + 1]
                if end - parse_timestamp(e["@timestamp"]) <= span
            ]
            observed = (
                len(window)
                if rule.type == "event_count"
                else len({resolve(e, rule.count_field) for e in window})
            )
            if _compare(operator, observed, threshold):
                hits.append(CorrelationHit(group, observed, end, window))
                break
    return hits
