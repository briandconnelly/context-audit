"""Run a command in a disposable profile with outbound network denied except loopback."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

SYNTHETIC_KEY = "sk-ant-probe-synthetic"
MACOS_PROFILE = (
    "(version 1)(allow default)"
    "(deny network-outbound (remote ip))"
    '(allow network-outbound (remote ip "localhost:*"))'
)
KEEP = ("PATH", "LANG", "LC_ALL", "TERM")
DIRS = ("home", "xdg", "cache", "tmp", "claude")


@dataclass(frozen=True)
class Completed:
    exit: int | None
    stdout: str
    stderr: str
    timed_out: bool


def network_denial() -> list[str] | None:
    """The argv prefix that denies non-loopback outbound traffic, or None when unavailable."""
    if platform.system() == "Darwin" and shutil.which("sandbox-exec"):
        return ["sandbox-exec", "-p", MACOS_PROFILE]
    return None


class Sandbox:
    """Throwaway home and Claude Code profile under ``root``."""

    def __init__(self, root: Path) -> None:
        self.root = root
        for name in DIRS:
            (root / name).mkdir(parents=True, exist_ok=True)

    @property
    def env(self) -> dict[str, str]:
        kept = {k: v for k, v in os.environ.items() if k in KEEP}
        r = self.root
        return {
            **kept,
            "HOME": str(r / "home"),
            "XDG_CONFIG_HOME": str(r / "xdg"),
            "XDG_CACHE_HOME": str(r / "cache"),
            "TMPDIR": str(r / "tmp"),
            "CLAUDE_CONFIG_DIR": str(r / "claude"),
            "ANTHROPIC_API_KEY": SYNTHETIC_KEY,
            "NO_COLOR": "1",
        }

    def wrap(self, argv: list[str]) -> list[str]:
        denial = network_denial()
        if denial is None:
            raise RuntimeError("no network denial available; refusing to run unsandboxed")
        return [*denial, *argv]

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path,
        timeout: float,
        stdin: str | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> Completed:
        try:
            done = subprocess.run(
                self.wrap(argv),
                cwd=cwd,
                env={**self.env, **(extra_env or {})},
                input=stdin if stdin is not None else "",
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return Completed(None, out, err, True)
        return Completed(done.returncode, done.stdout, done.stderr, False)
