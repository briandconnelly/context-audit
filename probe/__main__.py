"""Run probe scenarios: ``uv run python -m probe [--only NAME ...] [--out DIR]``."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from context_audit import __version__ as PLUGIN_VERSION
from context_audit.receipts import read_receipts, write_receipts
from probe.pty_runner import run_interactive
from probe.report import write_report
from probe.runner import CLAUDE_ARGV0, run_scenario
from probe.sandbox import Sandbox
from probe.scenario import Result, Scenario
from probe.scenarios import ALL_SCENARIOS
from probe.scenarios.interactive import DRIVE, START
from probe.scenarios.packaged import apply_baseline, to_receipts

RESEARCH = Path(__file__).resolve().parent.parent / "docs" / "research"


def claude_version() -> str:
    """The installed version, asked for inside the sandbox like every other run of the CLI."""
    with tempfile.TemporaryDirectory(prefix="ctxa-version-") as tmp:
        done = Sandbox(Path(tmp)).run([CLAUDE_ARGV0, "--version"], cwd=Path(tmp), timeout=30)
    return done.stdout.strip().removesuffix(" (Claude Code)") or "unknown"


def _run(scenario: Scenario, out: Path) -> Result:
    if scenario.interactive:
        steps, until = DRIVE.get(scenario.name, ([START], None))
        return run_interactive(scenario, steps, out / scenario.name, until=until, timeout=90)
    return run_scenario(scenario, out / scenario.name)


def _save_receipts(home: Path, results: list[Result]) -> Path:
    """Merge this run's receipts into home/receipts.json, replacing older ones it re-probed."""
    new = to_receipts(results, claude_version=claude_version(), plugin_version=PLUGIN_VERSION)
    redone = {(r.behaviour, r.claude_version, r.plugin_version, r.build) for r in new}
    kept = [
        r
        for r in read_receipts(home)
        if (r.behaviour, r.claude_version, r.plugin_version, r.build) not in redone
    ]
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_receipts(home, [*kept, *new])
    return home / "receipts.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="probe")
    parser.add_argument("--only", action="append", default=[], metavar="NAME")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--report", action="store_true", help="write docs/research results")
    parser.add_argument(
        "--receipts",
        action="store_true",
        help="write receipts.json for the packaged scenarios into $CONTEXT_AUDIT_HOME",
    )
    args = parser.parse_args(argv)
    known = {s.name for s in ALL_SCENARIOS}
    unknown = [name for name in args.only if name not in known]
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")
    if args.report and args.only:
        parser.error("--report needs the full run; it cannot be combined with --only")
    receipts_home: Path | None = None
    if args.receipts:
        if not os.environ.get("CONTEXT_AUDIT_HOME"):
            parser.error(
                "--receipts writes into the state directory named by CONTEXT_AUDIT_HOME, "
                "which is not set; set it to the directory to write receipts.json into"
            )
        receipts_home = Path(os.environ["CONTEXT_AUDIT_HOME"])
    out = args.out or Path("runs") / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    # Receipts count only when routing to the stub was shown in the same invocation.
    wanted = set(args.only) | ({"routing"} if args.receipts and args.only else set())
    results: list[Result] = []
    for scenario in ALL_SCENARIOS:
        if wanted and scenario.name not in wanted:
            continue
        if scenario.baseline is not None:
            baseline = _run(scenario.baseline, out)
            print(f"{baseline.name}: {baseline.outcome} - {baseline.reason}", flush=True)
            result = apply_baseline(_run(scenario, out), baseline)
        else:
            result = _run(scenario, out)
        results.append(result)
        print(f"{result.name}: {result.outcome} - {result.reason}", flush=True)
        if scenario.name == "routing" and result.outcome != "shown":
            # Nothing else means anything if the CLI is not talking to the stub alone.
            print("stopping: routing was not shown; ask the owner before going further", flush=True)
            return 2
    if receipts_home is not None:
        print(f"receipts written to {_save_receipts(receipts_home, results)}", flush=True)
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
