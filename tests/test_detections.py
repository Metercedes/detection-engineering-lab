"""Validation of every detection against the telemetry corpus.

Two properties are asserted for each rule:

1. It matches the events that were written to demonstrate the technique.
2. It matches none of the benign baseline events.

The second is the one that keeps the rule honest. A rule that alerts on everything satisfies the
first property trivially, so a broad rule fails here rather than in production.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sigmatch.corpus import load_events
from sigmatch.correlation import evaluate_correlation, load_correlations
from sigmatch.matcher import matches
from sigmatch.rule import load_rules

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS = ROOT / "detections"
TELEMETRY = ROOT / "telemetry"

RULES = load_rules(DETECTIONS)
CORRELATIONS = load_correlations(DETECTIONS)
BENIGN = load_events(TELEMETRY / "benign" / "workstation_and_server_baseline.jsonl")

# A base rule exists only to feed a correlation. It is expected to match single events, including
# benign ones, because the threshold that makes the signal meaningful lives in the correlation.
BASE_ONLY_RULE_IDS = {"1a7b3c5d-9e02-4f68-b134-8c50a2d97e6b"}

ALERTING_RULES = [r for r in RULES if r.id not in BASE_ONLY_RULE_IDS]


def rule_id(rule) -> str:
    return rule.path.stem


@pytest.mark.parametrize("rule", ALERTING_RULES, ids=rule_id)
def test_rule_matches_its_true_positives(rule):
    fixture = TELEMETRY / "true_positive" / f"{rule.path.stem}.jsonl"
    assert fixture.exists(), f"{rule.path.name} has no true-positive fixture"

    events = load_events(fixture)
    assert events, f"{fixture.name} is empty"

    unmatched = [e for e in events if not matches(rule, e)]
    assert not unmatched, (
        f"{rule.title} failed to match {len(unmatched)} of its own fixtures: "
        f"{[e.get('process', {}).get('command_line') or e for e in unmatched]}"
    )


@pytest.mark.parametrize("rule", ALERTING_RULES, ids=rule_id)
def test_rule_does_not_match_benign_baseline(rule):
    false_positives = [e for e in BENIGN if matches(rule, e)]
    assert not false_positives, (
        f"{rule.title} matched {len(false_positives)} benign event(s): "
        f"{[e.get('process', {}).get('command_line') or e.get('service') for e in false_positives]}"
    )


@pytest.mark.parametrize("rule", RULES, ids=rule_id)
def test_rule_metadata_is_complete(rule):
    assert rule.attack_techniques or rule.attack_tactics, f"{rule.title} has no ATT&CK tags"
    assert rule.falsepositives, f"{rule.title} documents no false positives"
    assert rule.level in {"informational", "low", "medium", "high", "critical"}
    assert rule.fields, f"{rule.title} lists no investigation fields"
    assert len(rule.id) == 36, f"{rule.title} has a malformed id"


def test_base_rules_are_informational_and_match_single_events():
    """A base rule must not carry an alerting level, or it would page on one failed password."""
    for rule in RULES:
        if rule.id in BASE_ONLY_RULE_IDS:
            assert rule.level == "informational"
            assert any(matches(rule, e) for e in BENIGN), (
                f"{rule.title} matches nothing in the baseline, so its correlation cannot fire"
            )


def test_rule_ids_are_unique():
    ids = [r.id for r in RULES] + [c.id for c in CORRELATIONS]
    assert len(ids) == len(set(ids)), "duplicate rule ids"


class TestCorrelations:
    BASE = {r.id: r for r in RULES}
    EVENTS = load_events(TELEMETRY / "true_positive" / "authentication_bursts.jsonl")

    @pytest.mark.parametrize("correlation", CORRELATIONS, ids=lambda c: c.id[:8])
    def test_correlation_fires(self, correlation):
        hits = evaluate_correlation(correlation, self.BASE, self.EVENTS)
        assert hits, f"{correlation.title} produced no hit on the burst corpus"

    @pytest.mark.parametrize("correlation", CORRELATIONS, ids=lambda c: c.id[:8])
    def test_correlation_silent_on_baseline(self, correlation):
        hits = evaluate_correlation(correlation, self.BASE, BENIGN)
        assert not hits, f"{correlation.title} fired on the benign baseline"

    def test_single_account_burst_identifies_the_account(self):
        burst = next(c for c in CORRELATIONS if c.type == "event_count")
        hits = evaluate_correlation(burst, self.BASE, self.EVENTS)
        assert {h.group for h in hits} == {("mrossi",)}
        assert all(h.observed >= 10 for h in hits)

    def test_spray_identifies_the_source_address(self):
        spray = next(c for c in CORRELATIONS if c.type == "value_count")
        hits = evaluate_correlation(spray, self.BASE, self.EVENTS)
        assert {h.group for h in hits} == {("203.0.113.99",)}
        assert all(h.observed >= 10 for h in hits)

    def test_burst_below_threshold_does_not_fire(self):
        burst = next(c for c in CORRELATIONS if c.type == "event_count")
        nine = [e for e in self.EVENTS if e["user"]["name"] == "mrossi"][:9]
        assert not evaluate_correlation(burst, self.BASE, nine)

    def test_events_spread_beyond_the_window_do_not_fire(self):
        burst = next(c for c in CORRELATIONS if c.type == "event_count")
        spread = []
        for index, event in enumerate(e for e in self.EVENTS if e["user"]["name"] == "mrossi"):
            copy = dict(event)
            copy["@timestamp"] = f"2026-03-02T{9 + index:02d}:20:00Z"
            spread.append(copy)
        assert not evaluate_correlation(burst, self.BASE, spread)


def test_readme_example_matches_real_output(capsys):
    """The README quotes CLI output, so the quote has to stay true."""
    from sigmatch.cli import main

    # Only the severity-prefixed hunt lines, not markdown links.
    severity_line = re.compile(r"^\[\s*(informational|low|medium|high|critical)\]")
    readme = (ROOT / "README.md").read_text()
    quoted = [line.strip() for line in readme.splitlines() if severity_line.match(line.strip())]
    assert quoted, "README no longer shows example hunt output"

    main(
        [
            "--detections",
            str(DETECTIONS),
            "hunt",
            str(TELEMETRY / "true_positive" / "powershell_encoded_command.jsonl"),
        ]
    )
    produced = capsys.readouterr().out

    position = -1
    for line in quoted:
        found = produced.find(line)
        assert found != -1, f"README line absent from real output: {line}"
        assert found > position, f"README line out of order: {line}"
        position = found
