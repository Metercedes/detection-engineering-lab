from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from sigmatch.errors import RuleParseError

REQUIRED_FIELDS = ("title", "id", "status", "logsource", "detection", "level")


@dataclass
class SigmaRule:
    path: Path
    raw: dict

    title: str = ""
    id: str = ""
    status: str = ""
    description: str = ""
    level: str = ""
    logsource: dict = field(default_factory=dict)
    detection: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        missing = [f for f in REQUIRED_FIELDS if f not in self.raw]
        if missing:
            raise RuleParseError(f"{self.path.name}: missing required field(s) {missing}")
        self.title = self.raw["title"]
        self.id = self.raw["id"]
        self.status = self.raw["status"]
        self.description = self.raw.get("description", "")
        self.level = self.raw["level"]
        self.logsource = self.raw["logsource"]
        self.detection = self.raw["detection"]
        self.tags = self.raw.get("tags", [])
        self.falsepositives = self.raw.get("falsepositives", [])
        self.references = self.raw.get("references", [])
        self.fields = self.raw.get("fields", [])
        if "condition" not in self.detection:
            raise RuleParseError(f"{self.path.name}: detection has no condition")

    @property
    def condition(self) -> str:
        return self.detection["condition"]

    @property
    def searches(self) -> dict:
        return {k: v for k, v in self.detection.items() if k not in ("condition", "timeframe")}

    @property
    def attack_techniques(self) -> list[str]:
        return sorted(
            tag.split(".", 1)[1].upper() for tag in self.tags if tag.lower().startswith("attack.t")
        )

    @property
    def attack_tactics(self) -> list[str]:
        known = {
            "reconnaissance",
            "resource_development",
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
        }
        return sorted(
            tag.split(".", 1)[1]
            for tag in self.tags
            if tag.lower().startswith("attack.") and tag.split(".", 1)[1].lower() in known
        )


def load_rule(path: Path) -> SigmaRule:
    """Load the single detection rule in a file, rejecting files that hold more than one."""
    rules = load_rules_from_file(path)
    if len(rules) != 1:
        raise RuleParseError(f"{path.name}: expected one detection rule, found {len(rules)}")
    return rules[0]


def load_rules_from_file(path: Path) -> list[SigmaRule]:
    """Sigma permits several documents per file, typically a base rule and the correlations that
    build on it. Correlation documents have no ``detection`` block and are handled elsewhere."""
    return [
        SigmaRule(path=path, raw=document)
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if document and "correlation" not in document
    ]


def load_rules(root: Path) -> list[SigmaRule]:
    return [rule for path in sorted(root.rglob("*.yml")) for rule in load_rules_from_file(path)]
