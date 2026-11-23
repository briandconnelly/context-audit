"""Run probe scenarios: ``uv run python -m probe [--only NAME ...] [--out DIR]``."""

from __future__ import annotations

import argparse
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from probe.pty_runner import run_interactive
from probe.report import write_report
from probe.runner import CLAUDE_ARGV0, run_scenario
from probe.sandbox import Sandbox
from probe.scenario import Result
from probe.scenarios import ALL_SCENARIOS
from probe.scenarios.interactive import DRIVE

RESEARCH = Path(__file__).resolve().parent.parent / "docs" / "research"


def claude_version() -> str:
    """The installed version, asked for inside the sandbox like every other run of the CLI."""
    with tempfile.TemporaryDirectory(prefix="ctxa-version-") as tmp:
        done = Sandbox(Path(tmp)).run([CLAUDE_ARGV0, "--version"], cwd=Path(tmp), timeout=30)
    return done.stdout.strip().removesuffix(" (Claude Code)") or "unknown"


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
    if args.report and args.only:
        parser.error("--report needs the full run; it cannot be combined with --only")
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
        if scenario.name == "routing" and result.outcome != "shown":
            # Nothing else means anything if the CLI is not talking to the stub alone.
            print("stopping: routing was not shown; ask the owner before going further", flush=True)
            return 2
    if args.report:
        write_report(
            results,
            claude_version=claude_version(),
            out_md=RESEARCH / "2026-11-22-probe-results.md",
            out_json=RESEARCH / "2026-11-22-probe-results.json",
        )
    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
