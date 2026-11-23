"""Run probe scenarios: ``uv run python -m probe [--only NAME ...] [--out DIR]``."""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from probe.pty_runner import run_interactive
from probe.report import write_report
from probe.runner import CLAUDE_ARGV0, run_scenario
from probe.scenario import Result
from probe.scenarios import ALL_SCENARIOS
from probe.scenarios.interactive import DRIVE

RESEARCH = Path(__file__).resolve().parent.parent / "docs" / "research"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="probe")
    parser.add_argument("--only", action="append", default=[], metavar="NAME")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--report", action="store_true", help="write docs/research results")
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
        if scenario.interactive:
            steps, until = DRIVE[scenario.name]
            result = run_interactive(scenario, steps, out / scenario.name, until=until, timeout=90)
        else:
            result = run_scenario(scenario, out / scenario.name)
        results.append(result)
        print(f"{result.name}: {result.outcome} - {result.reason}", flush=True)
    if args.report:
        version = (
            subprocess.run([CLAUDE_ARGV0, "--version"], capture_output=True, text=True, check=False)
            .stdout.strip()
            .removesuffix(" (Claude Code)")
        )
        write_report(
            results,
            claude_version=version or "unknown",
            out_md=RESEARCH / "2026-11-22-probe-results.md",
            out_json=RESEARCH / "2026-11-22-probe-results.json",
        )
    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
