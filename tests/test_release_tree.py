"""The release tree built for `main` runs on its own and carries nothing dev-only."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from context_audit.receipts import build_digest
from context_audit.state import read_counters

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "build_release_tree", REPO / "scripts" / "build-release-tree.py"
)
assert _spec and _spec.loader
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)

DEV_ONLY = ("evaluation/", "tests/", "probe/", "docs/research/", "runs/", "scripts/")
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
# A bare `research/...` or `evaluation/...` path in shipped prose names a file the tree lacks.
DEV_PATH = re.compile(r"`((?:docs/)?research/[^`]*|evaluation/[^`]*|probe/[^`]*|tests/[^`]*)`")


@pytest.fixture(scope="module")
def tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("release") / "tree"
    builder.build(out)
    return out


def _files(tree: Path) -> list[str]:
    return sorted(p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file())


def test_no_dev_only_paths(tree: Path) -> None:
    leaked = [f for f in _files(tree) if f.startswith(DEV_ONLY)]
    assert leaked == []


def test_no_caches(tree: Path) -> None:
    assert [f for f in _files(tree) if "__pycache__" in f or f.endswith(".pyc")] == []


def test_build_digest_matches_source(tree: Path) -> None:
    # A receipt taken on dev must describe the same runtime an install of main runs.
    assert build_digest(tree) == build_digest(REPO)


def test_relative_links_resolve(tree: Path) -> None:
    broken = []
    for md in tree.rglob("*.md"):
        for target in LINK.findall(md.read_text(encoding="utf-8")):
            if "://" in target or target.startswith("mailto:"):
                continue
            if not (md.parent / target).exists():
                broken.append(f"{md.relative_to(tree)} -> {target}")
        broken += [f"{md.relative_to(tree)} -> `{m}`" for m in DEV_PATH.findall(md.read_text())]
    assert broken == []


def test_cli_runs_from_tree(tree: Path) -> None:
    r = subprocess.run(
        ["sh", str(tree / "bin" / "context-audit"), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stderr


def test_hook_runs_from_tree(tree: Path, tmp_path: Path) -> None:
    # The hook fails open (exit 0, no output), so its exit code proves nothing; a
    # PreToolUse event must bump the call counter in an isolated state directory.
    home = tmp_path / "state"
    r = subprocess.run(
        ["sh", str(tree / "bin" / "context-audit-hook")],
        input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "mcp__x__y"}),
        capture_output=True,
        text=True,
        timeout=60,
        env={
            "PATH": str(Path(sys.executable).parent) + ":/usr/bin:/bin",
            "HOME": str(tmp_path),
            "CONTEXT_AUDIT_HOME": str(home),
        },
    )
    assert r.returncode == 0, r.stderr
    assert read_counters(home).get("calls_requested") == 1


def test_package_installs_from_tree(tree: Path) -> None:
    # README tells users to `uv tool install` the plugin directory, so the tree must
    # carry the packaging metadata and the files the wheel force-includes.
    with (tree / "pyproject.toml").open("rb") as f:
        meta = tomllib.load(f)
    includes = meta["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert [src for src in includes if not (tree / src).is_file()] == []


def test_refuses_unmarked_directory(tmp_path: Path) -> None:
    (tmp_path / "keep.txt").write_text("x")
    with pytest.raises(SystemExit):
        builder.build(tmp_path)
    assert (tmp_path / "keep.txt").exists()
