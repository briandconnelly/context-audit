"""The `sh` launchers in bin/: pick the newest Python 3 on PATH and exec the hook or the CLI."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_hook import CANARY, OLD_PYTHON, event, needs_old

ROOT = Path(__file__).resolve().parent.parent
HOOK_LAUNCHER = ROOT / "bin" / "context-audit-hook"
CLI_LAUNCHER = ROOT / "bin" / "context-audit"
SH = "/bin/sh"


def fake_interpreter(directory: Path, name: str) -> None:
    """An executable that prints its own name, its arguments, and its stdin."""
    path = directory / name
    path.write_text(f'#!/bin/sh\nprintf "%s\\n" {name} "$@"\n/bin/cat\n')
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def link(directory: Path, name: str, target: str) -> None:
    (directory / name).symlink_to(target)


def launch(launcher: Path, path_dir: Path, stdin: str = "", **env: str):
    return subprocess.run(
        [SH, str(launcher)],
        input=stdin,
        capture_output=True,
        text=True,
        env={"PATH": str(path_dir), **env},
        cwd=path_dir,
        timeout=30,
    )


@pytest.mark.parametrize("launcher", [HOOK_LAUNCHER, CLI_LAUNCHER])
def test_launcher_prefers_the_newest_interpreter(tmp_path, launcher):
    for name in ("python3", "python3.13", "python3.14"):
        fake_interpreter(tmp_path, name)
    p = launch(launcher, tmp_path, stdin="payload")
    target = "hook.py" if launcher == HOOK_LAUNCHER else "cli.py"
    lines = p.stdout.splitlines()
    assert lines[:2] == ["python3.14", "-I"]
    assert Path(lines[2]).resolve() == ROOT / "context_audit" / target
    assert lines[3:] == ["payload"]


@pytest.mark.parametrize(
    ("offered", "chosen"),
    [(["python3", "python3.15"], "python3.15"), (["python3"], "python3")],
)
def test_launcher_falls_through_the_list(tmp_path, offered, chosen):
    for name in offered:
        fake_interpreter(tmp_path, name)
    assert launch(HOOK_LAUNCHER, tmp_path).stdout.splitlines()[0] == chosen


def test_cli_launcher_passes_its_arguments(tmp_path):
    fake_interpreter(tmp_path, "python3.13")
    p = subprocess.run(
        [SH, str(CLI_LAUNCHER), "scan", "--json"],
        capture_output=True,
        text=True,
        env={"PATH": str(tmp_path)},
        timeout=30,
    )
    assert p.stdout.splitlines()[-2:] == ["scan", "--json"]


def test_launcher_works_from_a_path_with_spaces_and_no_plugin_root(tmp_path):
    plugin = tmp_path / "a plugin dir"
    shutil.copytree(ROOT / "bin", plugin / "bin")
    fake_interpreter(tmp_path, "python3.13")
    p = launch(plugin / "bin" / "context-audit-hook", tmp_path)
    assert p.stdout.splitlines()[2] == str(plugin / "bin" / ".." / "context_audit" / "hook.py")


def test_hook_launcher_with_no_python_exits_zero_silently(tmp_path):
    p = launch(HOOK_LAUNCHER, tmp_path, stdin=json.dumps(event()))
    assert (p.returncode, p.stdout, p.stderr) == (0, "", "")


def test_cli_launcher_with_no_python_says_so_and_fails(tmp_path):
    p = launch(CLI_LAUNCHER, tmp_path)
    assert p.returncode == 127
    assert p.stdout == ""
    assert "no python3" in p.stderr


def test_hook_launcher_runs_the_real_hook(tmp_path):
    link(tmp_path, "python3.13", sys.executable)
    home = tmp_path / "state"
    p = launch(HOOK_LAUNCHER, tmp_path, stdin=json.dumps(event()), CONTEXT_AUDIT_HOME=str(home))
    assert (p.returncode, p.stdout, p.stderr) == (0, "", "")
    assert json.loads((home / "counters.json").read_text()) == {
        "results_delivered": 1,
        "fully_scanned": 1,
    }


def test_hook_launcher_passes_a_finding_through(tmp_path):
    link(tmp_path, "python3.13", sys.executable)
    home = tmp_path / "state"
    p = launch(
        HOOK_LAUNCHER, tmp_path, stdin=json.dumps(event(text=CANARY)), CONTEXT_AUDIT_HOME=str(home)
    )
    assert p.returncode == 0
    assert "systemMessage" in json.loads(p.stdout)


def test_cli_launcher_runs_the_real_cli(tmp_path):
    link(tmp_path, "python3", sys.executable)
    p = subprocess.run(
        [SH, str(CLI_LAUNCHER), "--help"],
        capture_output=True,
        text=True,
        env={"PATH": str(tmp_path)},
        timeout=30,
    )
    assert p.returncode == 0
    assert "usage: context-audit" in p.stdout


@needs_old
def test_hook_launcher_on_an_old_interpreter_warns(tmp_path):
    assert OLD_PYTHON
    link(tmp_path, "python3", OLD_PYTHON)
    home = tmp_path / "state"
    p = launch(
        HOOK_LAUNCHER, tmp_path, stdin=json.dumps(event(text=CANARY)), CONTEXT_AUDIT_HOME=str(home)
    )
    assert (p.returncode, p.stderr) == (0, "")
    assert "needs Python 3.13 or newer" in json.loads(p.stdout)["systemMessage"]
    assert not home.exists()


@pytest.mark.parametrize("launcher", [HOOK_LAUNCHER, CLI_LAUNCHER])
def test_launchers_are_executable(launcher):
    assert os.access(launcher, os.X_OK)
