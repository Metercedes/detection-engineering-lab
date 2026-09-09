from __future__ import annotations

from pathlib import Path

import pytest

from sigmatch.elastic import TACTIC_IDS, to_elastic_rule, to_query, uses_regex
from sigmatch.rule import load_rules

RULES = load_rules(Path(__file__).resolve().parents[1] / "detections")


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_every_rule_translates(rule):
    query, language = to_query(rule)
    assert query
    assert language in ("kuery", "lucene")


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_regex_rules_are_emitted_as_lucene(rule):
    _, language = to_query(rule)
    assert language == ("lucene" if uses_regex(rule) else "kuery")


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_elastic_rule_shape(rule):
    exported = to_elastic_rule(rule)
    assert exported["rule_id"] == rule.id
    assert exported["type"] == "query"
    assert exported["severity"] in ("low", "medium", "high", "critical")
    assert 1 <= exported["risk_score"] <= 100
    for entry in exported["threat"]:
        assert entry["tactic"]["id"].startswith("TA")
        assert entry["framework"] == "MITRE ATT&CK"


def test_tactic_table_covers_every_tactic_used_by_the_rules():
    used = {t for rule in RULES for t in rule.attack_tactics}
    assert used <= set(TACTIC_IDS)
