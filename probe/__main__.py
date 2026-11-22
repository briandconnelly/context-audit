"""Run probe scenarios: ``uv run python -m probe [--only NAME ...] [--out DIR]``."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from probe.runner import run_scenario
from probe.scenario import Result
from probe.scenarios import ALL_SCENARIOS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="probe")
    parser.add_argument("--only", action="append", default=[], metavar="NAME")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    known = {s.name for s in ALL_SCENARIOS}
    unknown = [name for name in args.only if name not in known]
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")
    out = args.out or Path("runs") / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    results: list[Result] = []
    for scenario in ALL_SCENARIOS:
        if args.only and scenario.name not in args.only:
            continue
        result = run_scenario(scenario, out / scenario.name)
        results.append(result)
        print(f"{result.name}: {result.outcome} - {result.reason}", flush=True)
    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
