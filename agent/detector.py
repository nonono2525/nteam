from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from agent.collector import Event

try:
    import yaml
except ModuleNotFoundError:
    yaml = None


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    pattern: str
    response: str


@dataclass(frozen=True)
class Finding:
    rule: Rule
    event: Event


def load_rules(path: Path) -> list[Rule]:
    if not path.exists():
        raise FileNotFoundError(f"Rules file not found: {path}")

    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) if yaml else _load_simple_rules(text)
    data = data or {}
    rules = []
    for item in data.get("rules", []):
        rules.append(
            Rule(
                id=str(item["id"]),
                name=str(item["name"]),
                severity=str(item["severity"]),
                pattern=str(item["pattern"]),
                response=str(item["response"]),
            )
        )
    return rules


def _load_simple_rules(text: str) -> dict[str, list[dict[str, str]]]:
    rules: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line == "rules:":
            continue
        if line.startswith("- "):
            if current:
                rules.append(current)
            current = {}
            line = line[2:]
        if ":" not in line or current is None:
            continue
        key, value = line.split(":", 1)
        current[key.strip()] = value.strip().strip('"')

    if current:
        rules.append(current)
    return {"rules": rules}


def detect(events: list[Event], rules: list[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        for rule in rules:
            if re.search(rule.pattern, event.raw, flags=re.IGNORECASE):
                findings.append(Finding(rule=rule, event=event))
    return findings
