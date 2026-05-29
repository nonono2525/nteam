from __future__ import annotations

from agent.detector import Finding
from agent.responder import Response


def print_report(findings: list[Finding], responses: list[Response]) -> None:
    print("A&D Defense Agent Report")
    print("=" * 28)
    print(f"Findings: {len(findings)}")

    if not findings:
        print("No suspicious events detected.")
        return

    for response in responses:
        finding = response.finding
        print()
        print(f"[{finding.rule.severity.upper()}] {finding.rule.name}")
        print(f"Rule: {finding.rule.id}")
        print(f"Line: {finding.event.line_no}")
        print(f"Event: {finding.event.raw}")
        print(f"Action: {response.action}")
