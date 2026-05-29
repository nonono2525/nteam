from __future__ import annotations

import runpy
import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    attack_main = root / "attack" / "main (7).py"
    if not attack_main.exists():
        raise SystemExit(f"attack entrypoint not found: {attack_main}")
    sys.path.insert(0, str(root))
    runpy.run_path(str(attack_main), run_name="__main__")


if __name__ == "__main__":
    main()
