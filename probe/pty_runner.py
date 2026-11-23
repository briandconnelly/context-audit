"""Drive an interactive program on a pseudo-terminal: wait for text, send keys, capture it."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import pty
import re
import select
import signal
import struct
import subprocess
import termios
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from probe.runner import collect, fresh_dir, gather, isolated_workdir, judge, prepare
from probe.sandbox import SYNTHETIC_KEY, Completed, Sandbox
from probe.scenario import Result, Scenario
from probe.stub import Stub

ANSI = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC ... BEL or ST
    r"|\x1b\[[0-9;?<=>]*[ -/]*[@-~]"  # CSI
    r"|\x1b[@-Z\\-_]"  # two-character escapes
)


@dataclass(frozen=True)
class Step:
    wait_for: str | None
    send: str
    timeout: float = 30
    optional: bool = False


def strip_ansi(raw: str) -> str:
    return ANSI.sub("", raw)


def _squash(text: str) -> str:
    """Compare without whitespace: a terminal UI may place words with cursor moves, not spaces."""
    return re.sub(r"\s+", "", text)


def _finish(proc: subprocess.Popen[bytes]) -> int | None:
    """Give the program a moment to exit by itself, then stop its process group."""
    for sig, grace in ((None, 2), (signal.SIGTERM, 5), (signal.SIGKILL, 5)):
        if sig is not None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, sig)
        try:
            return proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            continue
    return None


def drive(
    argv: list[str],
    steps: list[Step],
    *,
    cwd: Path,
    env: dict[str, str],
    until: str | Callable[[str], bool] | None = None,
    timeout: float = 180,
    settle: float = 1.0,
    raw_path: Path | None = None,
) -> tuple[str, str | None, int | None, list[bool]]:
    """Run ``argv`` on a pty.

    Returns the screen text, the awaited text that never came (or None), the exit code, and
    whether each step's text was seen. Each wait looks only at output since the last send.
    With ``raw_path``, the unfiltered bytes the program wrote are saved there.
    """
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 200, 0, 0))
    full_env = {**{k: v for k, v in os.environ.items() if k in ("PATH", "LANG")}, **env}
    full_env.setdefault("TERM", "xterm-256color")
    proc = subprocess.Popen(
        argv,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        cwd=cwd,
        env=full_env,
        start_new_session=True,
        close_fds=True,
    )
    os.close(slave)
    raw = bytearray()
    deadline = time.monotonic() + timeout

    def screen() -> str:
        return strip_ansi(raw.decode("utf-8", errors="replace"))

    def pump(seconds: float) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            ready, _, _ = select.select([master], [], [], 0.1)
            if not ready:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return
            if not chunk:
                return
            raw.extend(chunk)

    mark = 0

    def fresh() -> str:
        return _squash(screen())[mark:]

    def wait_for(text: str, seconds: float) -> bool:
        end = min(time.monotonic() + seconds, deadline)
        want = _squash(text)
        while time.monotonic() < end:
            if want in fresh():
                return True
            if proc.poll() is not None:
                pump(0.3)
                return want in fresh()
            pump(0.2)
        return want in fresh()

    exit_code: int | None = None
    try:
        missing: str | None = None
        seen: list[bool] = []
        for step in steps:
            found = step.wait_for is None or wait_for(step.wait_for, step.timeout)
            seen.append(found)
            if not found:
                if step.optional:
                    continue
                missing = step.wait_for
                break
            pump(settle)
            mark = len(_squash(screen()))
            with contextlib.suppress(OSError):
                os.write(master, step.send.encode())
        if missing is None and isinstance(until, str) and not wait_for(until, timeout):
            missing = until
        if missing is None and callable(until):
            while not until(fresh()) and time.monotonic() < deadline and proc.poll() is None:
                pump(0.2)
            if not until(fresh()):
                missing = "the end condition"
        pump(settle)
    finally:
        # Never leave the program running, even when a check raises.
        exit_code = _finish(proc)
        pump(0.3)
        os.close(master)
        if raw_path is not None:
            raw_path.write_bytes(bytes(raw))
    return screen(), missing, exit_code, seen


def _script_used_up(stub: Stub, replies: int) -> bool:
    return sum(1 for r in stub.requests() if r["scripted"]) >= replies


def seed_profile(sandbox: Sandbox, work: Path) -> None:
    """Mark first-run steps done, so an interactive session starts without reaching the network.

    A fresh profile runs onboarding, which checks connectivity to the real API host directly and
    stops when the sandbox refuses it. These keys are the profile's own record of having finished
    onboarding, trusted the working directory, and approved the (synthetic) API key.
    """
    config = {
        "hasCompletedOnboarding": True,
        "theme": "dark",
        "customApiKeyResponses": {"approved": [SYNTHETIC_KEY[-20:]], "rejected": []},
        "projects": {
            str(work): {"hasTrustDialogAccepted": True, "hasCompletedProjectOnboarding": True}
        },
    }
    path = Path(sandbox.env["CLAUDE_CONFIG_DIR"]) / ".claude.json"
    path.write_text(json.dumps(config, indent=1), encoding="utf-8")


def run_interactive(
    s: Scenario,
    steps: list[Step],
    run_dir: Path,
    *,
    until: str | None = None,
    timeout: float = 180,
) -> Result:
    """Drive ``s`` on a terminal until the script is used up or the ``until`` text appears."""
    run_dir = run_dir.resolve()
    fresh_dir(run_dir)
    sandbox = Sandbox(run_dir / "profile")
    work = isolated_workdir()
    (run_dir / "workdir.txt").write_text(str(work), encoding="utf-8")
    seed_profile(sandbox, work)
    with Stub(list(s.script), run_dir / "requests.jsonl") as stub:
        prepared = prepare(s, run_dir, stub.url, interactive=True)
        screen, missing, exit_code, seen = drive(
            sandbox.wrap(prepared.argv),
            steps,
            cwd=work,
            env={**sandbox.env, **prepared.extra_env},
            until=lambda fresh: (
                _script_used_up(stub, len(s.script))
                or (until is not None and _squash(until) in fresh)
            ),
            timeout=timeout,
            settle=1.5,
            raw_path=run_dir / "raw.bin",
        )
        completed = Completed(exit_code, "", "", False)
        ev = replace(
            collect(run_dir, prepared, completed, stub, screen),
            steps_seen=tuple(seen),
            raw=(run_dir / "raw.bin").read_bytes(),
        )
    (run_dir / "screen.txt").write_text(screen, encoding="utf-8")
    if missing is not None:
        tail = screen[-400:]
        return Result(
            s.name, s.claim, "inconclusive", f"never saw {missing!r}; screen tail: {tail}", run_dir
        )
    gather(s, ev)
    outcome, reason = judge(s, ev)
    return Result(s.name, s.claim, outcome, reason, run_dir)
