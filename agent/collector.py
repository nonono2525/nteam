from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Event:
    line_no: int
    raw: str


def collect_events(path: Path) -> list[Event]:
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    events: list[Event] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        text = line.strip()
        if text:
            events.append(Event(line_no=line_no, raw=text))
    return events
