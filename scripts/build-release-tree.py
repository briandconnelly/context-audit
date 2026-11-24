#!/usr/bin/env python3
"""Copy the plugin's runtime files into a clean directory.

The release tree is what an install fetches from `main`: the plugin manifest, hooks,
launchers, the `context_audit` package and its packaging metadata (README tells users
to `uv tool install` the plugin directory), the audit skill, and the user-facing docs.
Tests, the evaluation corpus (held-out text above all), the probe, and research notes
stay on `dev`. `.github/dependabot.yml` ships because Dependabot reads its config only
from the default branch; it targets `dev`. Workflows cannot ship: the publish job's
token may not push `.github/workflows/`.

Only files git tracks are copied, so local caches and untracked scratch never ship.
The output directory is created fresh; an existing directory is rebuilt only when it
carries this builder's marker.
"""

import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MARKER = ".context-audit-release"
FILES = [
    "LICENSE",
    "README.md",
    "docs/reference.md",
    ".claude-plugin/plugin.json",
    "hooks/hooks.json",
    "pyproject.toml",
    "uv.lock",
    ".github/dependabot.yml",
]
TREES = ["bin", "context_audit", "skills"]


def tracked(prefix: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "-z", "--", prefix],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [p for p in out.split("\0") if p]


def release_paths() -> list[str]:
    paths = []
    for rel in FILES:
        if not tracked(rel):
            sys.exit(f"runtime file {rel} is not tracked")
        paths.append(rel)
    for tree in TREES:
        found = tracked(tree)
        if not found:
            sys.exit(f"runtime tree {tree}/ has no tracked files")
        paths += found
    return sorted(paths)


def prepare_output(out: Path) -> None:
    if out.exists():
        if not (out / MARKER).is_file():
            sys.exit(f"refusing to replace {out}: it exists and was not built by this script")
        shutil.rmtree(out)
    out.mkdir(parents=True)
    (out / MARKER).write_text("built by scripts/build-release-tree.py; safe to delete\n")


def build(out: Path) -> None:
    prepare_output(out)
    for rel in release_paths():
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, dst)


if __name__ == "__main__":
    if len(sys.argv) != 2:  # noqa: PLR2004
        sys.exit("usage: build-release-tree.py OUTPUT_DIR")
    build(Path(sys.argv[1]).resolve())
