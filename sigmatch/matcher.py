"""Evaluate a Sigma rule against a single event.

Events are flat or nested dictionaries. Field names are resolved dot-first against the nested
structure and then against the flat key, so both ``{"process": {"name": "x"}}`` and
``{"process.name": "x"}`` work. That matters because ECS documents are nested in Elasticsearch
but usually flat once exported to NDJSON.
"""

from __future__ import annotations

from typing import Any

from sigmatch.condition import evaluate, parse
from sigmatch.errors import RuleParseError
from sigmatch.fieldmatch import match_field, parse_field
from sigmatch.rule import SigmaRule

_MISSING = object()


def resolve(event: dict, field: str) -> Any:
    if field in event:
        return event[field]
    current: Any = event
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _match_map(event: dict, criteria: dict) -> bool:
    for spec, expected in criteria.items():
        name, modifiers = parse_field(spec)
        if not match_field(resolve(event, name), expected, modifiers):
            return False
    return True


def _match_search(event: dict, search: Any) -> bool:
    """A map is an AND over its keys. A list of maps is an OR over the maps."""
    if isinstance(search, dict):
        return _match_map(event, search)
    if isinstance(search, list):
        if all(isinstance(item, dict) for item in search):
            return any(_match_map(event, item) for item in search)
        # A bare list of scalars is a keyword search over every value in the event.
        haystack = " ".join(str(v) for v in _flatten_values(event)).lower()
        return any(str(item).lower() in haystack for item in search)
    raise RuleParseError(f"unsupported search block of type {type(search).__name__}")


def _flatten_values(value: Any) -> list:
    if isinstance(value, dict):
        return [v for item in value.values() for v in _flatten_values(item)]
    if isinstance(value, list):
        return [v for item in value for v in _flatten_values(item)]
    return [value]


def matches(rule: SigmaRule, event: dict) -> bool:
    results = {name: _match_search(event, search) for name, search in rule.searches.items()}
    return evaluate(parse(rule.condition), results)


def matching_events(rule: SigmaRule, events: list[dict]) -> list[dict]:
    return [event for event in events if matches(rule, event)]
