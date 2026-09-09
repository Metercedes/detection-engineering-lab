"""Unit tests for the matching engine itself, independent of the shipped rules."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
import yaml

from sigmatch.condition import evaluate, parse
from sigmatch.errors import RuleParseError, UnsupportedFeatureError
from sigmatch.fieldmatch import _base64_candidates, match_field, parse_field
from sigmatch.matcher import matches, resolve
from sigmatch.rule import SigmaRule


def rule_from(detection: dict) -> SigmaRule:
    raw = {
        "title": "test",
        "id": "0" * 36,
        "status": "test",
        "level": "low",
        "logsource": {"product": "windows"},
        "detection": detection,
    }
    return SigmaRule(path=Path("test.yml"), raw=raw)


class TestFieldResolution:
    def test_nested_lookup(self):
        assert resolve({"process": {"name": "cmd.exe"}}, "process.name") == "cmd.exe"

    def test_flat_key_lookup(self):
        assert resolve({"process.name": "cmd.exe"}, "process.name") == "cmd.exe"

    def test_missing_field_is_none(self):
        assert resolve({"process": {}}, "process.name") is None


class TestModifiers:
    def test_plain_match_is_case_insensitive(self):
        assert match_field("CMD.EXE", "cmd.exe", [])

    def test_contains(self):
        assert match_field("a -enc b", "-enc", ["contains"])
        assert not match_field("a -encoding b", "-enc ", ["contains"])

    def test_startswith_and_endswith(self):
        assert match_field("C:\\Windows\\cmd.exe", "\\cmd.exe", ["endswith"])
        assert match_field("C:\\Windows\\cmd.exe", "C:\\Windows", ["startswith"])

    def test_wildcards_in_plain_values(self):
        assert match_field("svc_backup$", "*$", [])

    def test_list_is_or_by_default(self):
        assert match_field("cmd.exe", ["powershell.exe", "cmd.exe"], [])

    def test_all_modifier_makes_list_an_and(self):
        assert match_field("a b", ["a", "b"], ["contains", "all"])
        assert not match_field("a c", ["a", "b"], ["contains", "all"])

    def test_event_field_that_is_a_list_matches_any_element(self):
        assert match_field(["process", "start"], "process", [])

    def test_regex(self):
        assert match_field("curl x | bash", r"\|\s*bash", ["re"])
        assert not match_field("curl x > bash.txt", r"\|\s*bash", ["re"])

    def test_cidr(self):
        assert match_field("10.20.1.5", "10.20.0.0/16", ["cidr"])
        assert not match_field("192.0.2.5", "10.20.0.0/16", ["cidr"])
        assert not match_field("not-an-ip", "10.20.0.0/16", ["cidr"])

    def test_numeric_comparison(self):
        assert match_field(4625, "4000", ["gt"])
        assert not match_field(3000, "4000", ["gt"])

    def test_null_matches_absent_field(self):
        assert match_field(None, None, [])
        assert not match_field("x", None, [])

    def test_unknown_modifier_is_rejected(self):
        with pytest.raises(UnsupportedFeatureError):
            parse_field("CommandLine|nonsense")


class TestBase64Offset:
    @pytest.mark.parametrize("needle", ["whoami", "New-Object", "DownloadString", "a", "ab"])
    @pytest.mark.parametrize("offset", range(4))
    def test_candidate_appears_in_encoded_stream_at_every_alignment(self, needle, offset):
        blob = base64.b64encode(("X" * offset + needle + "TRAILING").encode()).decode()
        assert any(c in blob for c in _base64_candidates(needle, True))

    def test_matches_through_the_modifier_chain(self):
        blob = base64.b64encode(b"prefix IEX(New-Object Net.WebClient) suffix").decode()
        assert match_field(blob, "New-Object", ["base64offset", "contains"])

    def test_does_not_match_unrelated_content(self):
        blob = base64.b64encode(b"an entirely ordinary configuration string").decode()
        assert not match_field(blob, "New-Object", ["base64offset", "contains"])


class TestCondition:
    def test_and_binds_tighter_than_or(self):
        node = parse("a or b and c")
        assert evaluate(node, {"a": False, "b": True, "c": False}) is False
        assert evaluate(node, {"a": True, "b": True, "c": False}) is True

    def test_not_binds_tighter_than_and(self):
        assert evaluate(parse("not a and b"), {"a": False, "b": True}) is True

    def test_parentheses(self):
        assert evaluate(parse("(a or b) and c"), {"a": True, "b": False, "c": False}) is False

    def test_one_of_wildcard(self):
        assert evaluate(parse("1 of sel_*"), {"sel_a": False, "sel_b": True}) is True

    def test_all_of_them(self):
        assert evaluate(parse("all of them"), {"a": True, "b": True}) is True
        assert evaluate(parse("all of them"), {"a": True, "b": False}) is False

    def test_unknown_identifier_is_an_error(self):
        with pytest.raises(RuleParseError):
            evaluate(parse("missing"), {"a": True})

    def test_quantifier_matching_nothing_is_an_error(self):
        with pytest.raises(RuleParseError):
            evaluate(parse("1 of nomatch_*"), {"a": True})

    def test_malformed_condition_is_rejected(self):
        with pytest.raises(RuleParseError):
            parse("a and")


class TestSearchSemantics:
    def test_map_keys_are_anded(self):
        rule = rule_from(
            {
                "selection": {"process.name": "cmd.exe", "user.name": "jdoe"},
                "condition": "selection",
            }
        )
        assert matches(rule, {"process": {"name": "cmd.exe"}, "user": {"name": "jdoe"}})
        assert not matches(rule, {"process": {"name": "cmd.exe"}, "user": {"name": "other"}})

    def test_list_of_maps_is_ored(self):
        rule = rule_from(
            {
                "selection": [{"process.name": "cmd.exe"}, {"process.name": "sh"}],
                "condition": "selection",
            }
        )
        assert matches(rule, {"process": {"name": "sh"}})

    def test_filter_excludes(self):
        rule = rule_from(
            {
                "selection": {"process.name": "schtasks.exe"},
                "filter": {"user.name|endswith": "$"},
                "condition": "selection and not filter",
            }
        )
        assert matches(rule, {"process": {"name": "schtasks.exe"}, "user": {"name": "jdoe"}})
        assert not matches(rule, {"process": {"name": "schtasks.exe"}, "user": {"name": "SYSTEM$"}})


class TestRuleValidation:
    def test_missing_required_field_is_rejected(self):
        with pytest.raises(RuleParseError):
            SigmaRule(path=Path("x.yml"), raw={"title": "t"})

    def test_detection_without_condition_is_rejected(self):
        with pytest.raises(RuleParseError):
            SigmaRule(
                path=Path("x.yml"),
                raw={
                    "title": "t",
                    "id": "i",
                    "status": "s",
                    "level": "low",
                    "logsource": {},
                    "detection": {"selection": {}},
                },
            )

    def test_yaml_in_shipped_rules_is_well_formed(self):
        for path in (Path(__file__).resolve().parents[1] / "detections").rglob("*.yml"):
            list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
