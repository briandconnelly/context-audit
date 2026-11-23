"""Run one scenario: Claude Code in a sandbox, against the stub, with the fake server and hooks."""

from __future__ import annotations

import json
import shlex
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from probe import checks
from probe.sandbox import Completed, Sandbox
from probe.scenario import Evidence, Outcome, Result, Scenario
from probe.stub import Stub

CLAUDE_ARGV0 = "claude"
PROMPT = "run the probe"
ROOT = Path(__file__).resolve().parent
HOOK = ROOT / "hooks" / "record.py"
SERVER = ROOT / "fake_mcp.py"


@dataclass(frozen=True)
class Prepared:
    argv: list[str]
    extra_env: dict[str, str]
    hook_log: Path
    counter: Path


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def prepare(
    s: Scenario,
    run_dir: Path,
    stub_url: str,
    *,
    interactive: bool = False,
    resume: str | None = None,
) -> Prepared:
    """Write the settings and MCP config for ``s`` and return the command to run."""
    hook_log = run_dir / "hooks.jsonl"
    counter = run_dir / "calls.jsonl"
    hooks: dict[str, list[dict[str, Any]]] = {}
    for spec in s.hooks:
        env = {
            "PROBE_HOOK_LOG": str(hook_log),
            "PROBE_HOOK_MODE": spec.mode,
            "PROBE_HOOK_LABEL": spec.label,
        }
        assigns = " ".join(f"{k}={shlex.quote(v)}" for k, v in env.items())
        script = spec.script or HOOK
        command = f"{assigns} {shlex.quote(sys.executable)} -I {shlex.quote(str(script))}"
        group: dict[str, Any] = {"hooks": [{"type": "command", "command": command}]}
        if spec.matcher is not None:
            group["matcher"] = spec.matcher
        hooks.setdefault(spec.event, []).append(group)
    settings = run_dir / "settings.json"
    settings.write_text(json.dumps({"hooks": hooks}, indent=1), encoding="utf-8")
    mcp = run_dir / "mcp.json"
    server = {"command": sys.executable, "args": ["-I", str(SERVER), "--counter", str(counter)]}
    mcp.write_text(json.dumps({"mcpServers": {"probe": server}}, indent=1), encoding="utf-8")
    argv = [CLAUDE_ARGV0]
    if not interactive:
        argv += ["-p", PROMPT, "--output-format", "stream-json", "--verbose"]
        argv += ["--include-hook-events"]
    else:
        argv += ["--permission-mode", "default"]
    if resume:
        argv += ["--resume", resume]
    if not s.load_outside_settings:
        # No user, project, or local settings or instruction files: only the --settings file.
        argv += ["--setting-sources", ""]
    argv += ["--settings", str(settings), "--mcp-config", str(mcp), "--strict-mcp-config"]
    argv += ["--debug-file", str(run_dir / "debug.log")]
    if s.plugin_dir is not None:
        argv += ["--plugin-dir", str(s.plugin_dir)]
    if s.allowed_tools:
        argv += ["--allowedTools", *s.allowed_tools]
    env = {k: v.replace("{run_dir}", str(run_dir)) for k, v in s.env.items()}
    return Prepared(argv, {**env, "ANTHROPIC_BASE_URL": stub_url}, hook_log, counter)


def collect(
    run_dir: Path, prepared: Prepared, completed: Completed, stub: Stub, screen: str = ""
) -> Evidence:
    events = _read_jsonl(prepared.hook_log)
    transcript = None
    for event in events:
        candidate = event.get("input", {}).get("transcript_path")
        if isinstance(candidate, str) and Path(candidate).is_file():
            transcript = Path(candidate)
            break
    calls = [str(line.get("tool")) for line in _read_jsonl(prepared.counter)]
    return Evidence(run_dir, completed, stub.requests(), events, calls, transcript, screen)


def judge(s: Scenario, ev: Evidence) -> tuple[Outcome, str]:
    """Apply the setup gates, then the scenario's own check."""
    if ev.completed.timed_out:
        return "inconclusive", "claude timed out"
    if not ev.requests:
        return "inconclusive", f"no request reached the stub (exit {ev.completed.exit})"
    real = checks.real_credentials(ev)
    if real:
        return "inconclusive", f"requests carried credentials of kind {real}"
    if not s.planted and checks.instruction_file_loaded(ev):
        return "inconclusive", "an instruction file from outside the run was loaded"
    try:
        return s.check(ev)
    except Exception as exc:  # noqa: BLE001 - a broken check must not look like a finding
        return "inconclusive", f"check failed: {type(exc).__name__}: {exc}"


def gather(s: Scenario, ev: Evidence) -> None:
    """Run the scenario's after-step; a failure there is left for the check to find."""
    if s.after is None:
        return
    try:
        s.after(ev)
    except Exception as exc:  # noqa: BLE001 - the check reports the missing evidence
        (ev.run_dir / "after-error.txt").write_text(f"{type(exc).__name__}: {exc}\n")


def fresh_dir(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    if any(run_dir.iterdir()):
        raise ValueError(f"run directory is not empty: {run_dir}")


def session_id(ev: Evidence) -> str | None:
    for event in ev.hook_events:
        sid = event.get("input", {}).get("session_id")
        if isinstance(sid, str):
            return sid
    return None


def isolated_workdir(planted: dict[str, str] | None = None) -> Path:
    """A fresh working directory with no CLAUDE.md or .claude in any ancestor.

    ``planted`` files are written two levels above it, to test ancestor loading on purpose.

    Claude Code reads instructions and skills from every ancestor of its working directory, so a
    directory under the owner's home would put their real configuration into the run.
    """
    root = Path(tempfile.mkdtemp(prefix="ctxa-probe-")).resolve()
    work = root / "nested" / "cwd"
    work.mkdir(parents=True)
    for ancestor in [work, *work.parents]:
        if (ancestor / "CLAUDE.md").exists() or (ancestor / ".claude").exists():
            raise RuntimeError(f"working directory is not isolated: {ancestor} has Claude files")
    if work.is_relative_to(Path.home().resolve()):
        raise RuntimeError(f"working directory is under the home directory: {work}")
    for name, content in (planted or {}).items():
        (root / name).write_text(content, encoding="utf-8")
    return work


def run_scenario(s: Scenario, run_dir: Path, *, timeout: float = 120) -> Result:
    run_dir = run_dir.resolve()
    fresh_dir(run_dir)
    sandbox = Sandbox(run_dir / "profile")
    work = isolated_workdir(s.planted)
    (run_dir / "workdir.txt").write_text(str(work), encoding="utf-8")
    script = [*s.script]
    for follow in s.followups:
        script += follow.script
    with Stub(script, run_dir / "requests.jsonl") as stub:
        prepared = prepare(s, run_dir, stub.url)
        completed = sandbox.run(
            prepared.argv, cwd=work, timeout=timeout, extra_env=prepared.extra_env
        )
        ev = collect(run_dir, prepared, completed, stub)
        for follow in s.followups:
            sid = session_id(ev)
            if sid is None or completed.timed_out:
                break
            again = prepare(follow, run_dir, stub.url, resume=sid)
            completed = sandbox.run(
                again.argv, cwd=work, timeout=timeout, extra_env=again.extra_env
            )
            ev = collect(run_dir, again, completed, stub)
    (run_dir / "stdout.txt").write_text(ev.completed.stdout, encoding="utf-8")
    (run_dir / "stderr.txt").write_text(ev.completed.stderr, encoding="utf-8")
    gather(s, ev)
    outcome, reason = judge(s, ev)
    return Result(s.name, s.claim, outcome, reason, run_dir)
