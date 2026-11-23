"""Scenario, evidence, and outcome types."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from probe.sandbox import Completed
from probe.stub import Reply

Outcome = Literal["shown", "not_shown", "inconclusive"]


@dataclass(frozen=True)
class HookSpec:
    event: str
    matcher: str | None
    mode: str  # record | message | replace | ask
    label: str
    # The hook program; None means the recording hook, probe/hooks/record.py.
    script: Path | None = None


@dataclass(frozen=True)
class Evidence:
    run_dir: Path
    completed: Completed
    requests: list[dict[str, Any]]
    hook_events: list[dict[str, Any]]
    calls: list[str]
    transcript: Path | None
    screen: str = ""
    steps_seen: tuple[bool, ...] = ()
    raw: bytes = b""  # the terminal's raw output, escape sequences included


Check = Callable[[Evidence], tuple[Outcome, str]]


def _no_check(ev: Evidence) -> tuple[Outcome, str]:
    return "inconclusive", "scenario has no check"


@dataclass(frozen=True)
class Scenario:
    name: str
    claim: str
    script: list[Reply]
    hooks: list[HookSpec]
    allowed_tools: tuple[str, ...] = ("mcp__probe__*",)
    check: Check = _no_check
    followups: tuple[Scenario, ...] = field(default=())
    interactive: bool = False
    # Files written to an ancestor of the working directory before the run: name -> content.
    planted: dict[str, str] = field(default_factory=dict)
    # Let the CLI read user, project, and local settings and instruction files, as it does by
    # default. Only the isolation canary wants this.
    load_outside_settings: bool = False
    # Passed as --plugin-dir: a plugin to load for this run.
    plugin_dir: Path | None = None
    # Extra environment for the CLI and its hooks; "{run_dir}" in a value becomes the run directory.
    env: dict[str, str] = field(default_factory=dict)
    # Run first; unless its check reports "shown", this scenario's outcome is inconclusive.
    baseline: Scenario | None = None
    # Called with the evidence after the run and before the check, to gather more of it.
    after: Callable[[Evidence], None] | None = None


@dataclass(frozen=True)
class Result:
    name: str
    claim: str
    outcome: Outcome
    reason: str
    run_dir: Path
