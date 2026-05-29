from __future__ import annotations

import argparse
from pathlib import Path

from agent.collector import collect_events
from agent.detector import load_rules, detect
from agent.reporter import print_report
from agent.responder import build_responses


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="A&D defensive log analysis agent")
    parser.add_argument("--log", required=True, help="Path to log file")
    parser.add_argument("--rules", required=True, help="Path to YAML rules file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    events = collect_events(Path(args.log))
    rules = load_rules(Path(args.rules))
    findings = detect(events, rules)
    responses = build_responses(findings)
    print_report(findings, responses)


if __name__ == "__main__":
    main()
