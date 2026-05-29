from __future__ import annotations

from dataclasses import dataclass

from agent.detector import Finding


@dataclass(frozen=True)
class Response:
    finding: Finding
    action: str


def build_responses(findings: list[Finding]) -> list[Response]:
    return [Response(finding=finding, action=finding.rule.response) for finding in findings]
