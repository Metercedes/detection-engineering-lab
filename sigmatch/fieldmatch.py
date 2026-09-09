"""Value comparison for a single Sigma field, including the modifier chain.

Sigma writes modifiers into the field name, as in ``CommandLine|base64offset|contains``.
Each modifier either transforms the expected value into a set of candidate values or changes
how the comparison is performed, so the chain is applied left to right.
"""

from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from collections.abc import Iterable

from sigmatch.errors import UnsupportedFeatureError

COMPARISON_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "re",
    "cidr",
    "gt",
    "gte",
    "lt",
    "lte",
}
QUANTIFIER_MODIFIERS = {"all"}
TRANSFORM_MODIFIERS = {"base64", "base64offset", "windash"}

# Base64 encodes three input bytes into four output characters, so where a plaintext substring
# begins relative to that 3-byte grouping changes its encoding. Shifting the string by 0, 1 and 2
# bytes covers every alignment; the slice then drops the characters contaminated by the padding.
# Offsets follow the pySigma reference implementation so rules behave the same here as in Elastic.
_BASE64_START_OFFSETS = (0, 2, 3)

_WINDASH_VARIANTS = ("-", "/", "\u2013", "\u2014", "\u2015")


def parse_field(spec: str) -> tuple[str, list[str]]:
    field, *modifiers = spec.split("|")
    unknown = set(modifiers) - COMPARISON_MODIFIERS - QUANTIFIER_MODIFIERS - TRANSFORM_MODIFIERS
    if unknown:
        raise UnsupportedFeatureError(f"unsupported modifier(s) {sorted(unknown)} in {spec!r}")
    return field, modifiers


def _as_list(value: object) -> list:
    return list(value) if isinstance(value, list) else [value]


def _stringify(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _base64_candidates(text: str, offsets: bool) -> list[str]:
    raw = text.encode()
    if not offsets:
        return [base64.b64encode(raw).decode()]

    candidates = []
    for shift in range(3):
        encoded = base64.b64encode(b" " * shift + raw).decode().rstrip("=")
        # Characters fully or partly determined by the injected prefix carry no information
        # about the plaintext, and the final character is contaminated by whatever follows the
        # substring in the real stream, so both ends are trimmed back to reliable characters.
        trailing = 0 if (shift + len(raw)) % 3 == 0 else 1
        candidates.append(encoded[_BASE64_START_OFFSETS[shift] : len(encoded) - trailing])
    return candidates


def _windash_candidates(text: str) -> list[str]:
    if not text or text[0] not in "-/\u2013\u2014\u2015":
        return [text]
    stripped = text.lstrip("-/\u2013\u2014\u2015")
    return [f"{dash}{stripped}" for dash in _WINDASH_VARIANTS]


def _expand(expected: object, modifiers: list[str]) -> list[str]:
    text = _stringify(expected)
    if text is None:
        return []
    values = [text]
    if "base64offset" in modifiers:
        values = [c for v in values for c in _base64_candidates(v, offsets=True)]
    elif "base64" in modifiers:
        values = [c for v in values for c in _base64_candidates(v, offsets=False)]
    if "windash" in modifiers:
        values = [c for v in values for c in _windash_candidates(v)]
    return values


def _compare_one(actual: object, expected: str, modifiers: list[str]) -> bool:
    if "re" in modifiers:
        return actual is not None and re.search(expected, str(actual), re.IGNORECASE) is not None
    if "cidr" in modifiers:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(expected, strict=False)
        except ValueError:
            return False
    if any(m in modifiers for m in ("gt", "gte", "lt", "lte")):
        try:
            left, right = float(actual), float(expected)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        modifier = next(m for m in modifiers if m in ("gt", "gte", "lt", "lte"))
        return {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[
            modifier
        ]

    text = _stringify(actual)
    if text is None:
        return False
    haystack, needle = text.lower(), expected.lower()
    if "contains" in modifiers:
        pattern = f"*{needle}*"
    elif "startswith" in modifiers:
        pattern = f"{needle}*"
    elif "endswith" in modifiers:
        pattern = f"*{needle}"
    else:
        pattern = needle
    return fnmatch.fnmatchcase(haystack, pattern)


def match_field(event_value: object, expected: object, modifiers: list[str]) -> bool:
    """Return True when the event value satisfies the expected value under the modifier chain.

    A Sigma list is an OR by default. The ``all`` modifier turns it into an AND. When the event
    field itself holds a list (common in ECS, where ``event.category`` is an array) any element
    may satisfy the comparison.
    """
    expected_values = _as_list(expected)
    if expected_values == [None]:
        return event_value is None

    actual_values: Iterable = event_value if isinstance(event_value, list) else [event_value]
    actual_values = list(actual_values)

    def one_expected(candidate: object) -> bool:
        candidates = _expand(candidate, modifiers)
        if not candidates:
            return any(a is None for a in actual_values)
        return any(_compare_one(a, c, modifiers) for a in actual_values for c in candidates)

    if "all" in modifiers:
        return all(one_expected(v) for v in expected_values)
    return any(one_expected(v) for v in expected_values)
