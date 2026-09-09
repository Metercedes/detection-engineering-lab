"""Convert Sigma rules into Elastic Security detection rules.

Only the subset of Sigma used by this repository is translated. Anything unsupported raises
rather than emitting a query that silently means something different from the rule, because a
detection that quietly changes meaning in translation is worse than one that fails to deploy.
"""

from __future__ import annotations

import re

from sigmatch.errors import UnsupportedFeatureError
from sigmatch.fieldmatch import parse_field
from sigmatch.rule import SigmaRule

TACTIC_IDS = {
    "initial_access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege_escalation": ("TA0004", "Privilege Escalation"),
    "defense_evasion": ("TA0005", "Defense Evasion"),
    "credential_access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral_movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "command_and_control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
}

SEVERITY_RISK = {"informational": 1, "low": 21, "medium": 47, "high": 73, "critical": 99}

_KQL_SPECIAL = re.compile(r'(["\\])')


def _quote(value: str) -> str:
    return '"' + _KQL_SPECIAL.sub(r"\\\1", value) + '"'


def uses_regex(rule: SigmaRule) -> bool:
    """KQL has no regular-expression operator, so a rule using |re must be emitted as Lucene."""
    for search in rule.searches.values():
        blocks = search if isinstance(search, list) else [search]
        for block in blocks:
            if isinstance(block, dict) and any("re" in parse_field(k)[1] for k in block):
                return True
    return False


def _lucene_leaf(field: str, modifiers: list[str], value: object) -> str:
    if "re" in modifiers:
        # Lucene regexp is anchored, so a Sigma |re (which searches anywhere) is wrapped.
        pattern = str(value).replace("/", "\\/")
        return f"{field}:/.*{pattern}.*/"
    if value is None:
        return f"(NOT _exists_:{field})"
    text = str(value)
    if "contains" in modifiers:
        text = f"*{text}*"
    elif "startswith" in modifiers:
        text = f"{text}*"
    elif "endswith" in modifiers:
        text = f"*{text}"
    escaped = re.sub(r'([+\-!(){}\[\]^"~:\\/])', r"\\\1", text).replace("*", "*")
    return f"{field}:{escaped}" if "*" in text else f'{field}:"{text}"'


def _leaf(field: str, modifiers: list[str], value: object) -> str:
    if "re" in modifiers:
        raise UnsupportedFeatureError(
            f"{field}: KQL has no regular-expression operator; this rule is emitted as Lucene"
        )
    if "cidr" in modifiers:
        return f"{field} : {_quote(str(value))}"
    if any(m in modifiers for m in ("gt", "gte", "lt", "lte")):
        operator = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[
            next(m for m in modifiers if m in ("gt", "gte", "lt", "lte"))
        ]
        return f"{field} {operator} {value}"
    if value is None:
        return f"not {field} : *"

    text = str(value)
    if "contains" in modifiers:
        text = f"*{text}*"
    elif "startswith" in modifiers:
        text = f"{text}*"
    elif "endswith" in modifiers:
        text = f"*{text}"
    return f"{field} : {_quote(text)}"


def _criteria_to_query(criteria: dict, lucene: bool) -> str:
    leaf = _lucene_leaf if lucene else _leaf
    and_op, or_op = ("AND", "OR") if lucene else ("and", "or")
    clauses = []
    for spec, expected in criteria.items():
        field, modifiers = parse_field(spec)
        values = expected if isinstance(expected, list) else [expected]
        joiner = f" {and_op} " if "all" in modifiers else f" {or_op} "
        leaves = [leaf(field, modifiers, v) for v in values]
        clause = leaves[0] if len(leaves) == 1 else "(" + joiner.join(leaves) + ")"
        clauses.append(clause)
    return clauses[0] if len(clauses) == 1 else "(" + f" {and_op} ".join(clauses) + ")"


def _search_to_query(search: object, lucene: bool) -> str:
    or_op = "OR" if lucene else "or"
    if isinstance(search, dict):
        return _criteria_to_query(search, lucene)
    if isinstance(search, list) and all(isinstance(i, dict) for i in search):
        parts = [_criteria_to_query(i, lucene) for i in search]
        return "(" + f" {or_op} ".join(parts) + ")"
    raise UnsupportedFeatureError("keyword-list searches are not translated")


def _condition_to_query(node: object, searches: dict[str, str], lucene: bool) -> str:
    from sigmatch.condition import And, Identifier, Not, Or, Quantifier

    and_op, or_op, not_op = ("AND", "OR", "NOT") if lucene else ("and", "or", "not")
    match node:
        case Identifier(name):
            return searches[name]
        case Not(operand):
            return f"{not_op} {_condition_to_query(operand, searches, lucene)}"
        case And(operands):
            joined = f" {and_op} ".join(_condition_to_query(o, searches, lucene) for o in operands)
            return f"({joined})"
        case Or(operands):
            joined = f" {or_op} ".join(_condition_to_query(o, searches, lucene) for o in operands)
            return f"({joined})"
        case Quantifier(mode, pattern):
            import fnmatch

            selected = (
                list(searches.values())
                if pattern.lower() == "them"
                else [v for k, v in searches.items() if fnmatch.fnmatchcase(k, pattern)]
            )
            joiner = f" {and_op} " if mode == "all" else f" {or_op} "
            return "(" + joiner.join(selected) + ")"
    raise UnsupportedFeatureError(f"cannot translate condition node {node!r}")


def to_query(rule: SigmaRule) -> tuple[str, str]:
    """Return the query and the Elastic query language it is written in."""
    from sigmatch.condition import parse

    lucene = uses_regex(rule)
    searches = {name: _search_to_query(body, lucene) for name, body in rule.searches.items()}
    query = _condition_to_query(parse(rule.condition), searches, lucene)
    return query, "lucene" if lucene else "kuery"


def to_kql(rule: SigmaRule) -> str:
    query, language = to_query(rule)
    if language != "kuery":
        raise UnsupportedFeatureError(f"{rule.path.name} requires the {language} language")
    return query


def _threat(rule: SigmaRule) -> list[dict]:
    techniques = [
        {
            "id": technique,
            "name": technique,
            "reference": "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/",
        }
        for technique in rule.attack_techniques
    ]
    entries = []
    for tactic in rule.attack_tactics:
        if tactic not in TACTIC_IDS:
            continue
        tactic_id, tactic_name = TACTIC_IDS[tactic]
        entries.append(
            {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": tactic_id,
                    "name": tactic_name,
                    "reference": f"https://attack.mitre.org/tactics/{tactic_id}/",
                },
                "technique": techniques,
            }
        )
    return entries


def to_elastic_rule(rule: SigmaRule, index: list[str] | None = None) -> dict:
    query, language = to_query(rule)
    return {
        "rule_id": rule.id,
        "name": rule.title,
        "description": " ".join(rule.description.split()) or rule.title,
        "type": "query",
        "language": language,
        "query": query,
        "index": index or ["logs-*", "winlogbeat-*"],
        "enabled": True,
        "interval": "5m",
        "from": "now-10m",
        "severity": rule.level if rule.level != "informational" else "low",
        "risk_score": SEVERITY_RISK.get(rule.level, 47),
        "tags": [f"sigma:{rule.path.stem}", *rule.tags],
        "author": [rule.raw.get("author", "unknown")],
        "references": rule.references,
        "false_positives": rule.falsepositives,
        "note": "Investigation fields: " + ", ".join(rule.fields) if rule.fields else "",
        "threat": _threat(rule),
    }
