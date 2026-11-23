"""Coverage receipts: what the probe showed the packaged hooks doing on one harness build.

The probe writes ``receipts.json`` into the state directory; `status` and `scan` read it.
A receipt counts only when it matches both the installed Claude Code version and this
plugin's version; every other behaviour is reported ``unverified``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from context_audit.report import CAPABILITY_BEHAVIOURS

RECEIPT_STATUSES = ("shown", "not_shown", "inconclusive")
NO_RECEIPT = "No receipt matches this Claude Code version and plugin version."
VERSION_UNKNOWN = "The installed Claude Code version is unknown, so no receipt can match."
_VERSION = re.compile(r"^(\d+(?:\.\d+)+)(?: \(Claude Code\))?$")
VERSION_TIMEOUT = 5.0


@dataclass(frozen=True)
class Receipt:
    behaviour: str  # one of CAPABILITY_BEHAVIOURS
    status: str  # one of RECEIPT_STATUSES
    claude_version: str
    plugin_version: str
    frontend: str  # "terminal" | "headless"
    permission_mode: str


_KEYS = tuple(f.name for f in fields(Receipt))


def _valid(r: Receipt) -> bool:
    return (
        r.behaviour in CAPABILITY_BEHAVIOURS
        and r.status in RECEIPT_STATUSES
        and all(isinstance(getattr(r, k), str) for k in _KEYS)
    )


def write_receipts(root: Path, receipts: list[Receipt]) -> None:
    """Replace root/receipts.json, owner-only."""
    bad = [r for r in receipts if not _valid(r)]
    if bad:
        raise ValueError(f"invalid receipt(s): {bad}")
    path = root / "receipts.json"
    tmp = root / "receipts.json.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"receipts": [asdict(r) for r in receipts]}, f, indent=1)
    os.replace(tmp, path)


def read_receipts(root: Path) -> list[Receipt]:
    """Every well-formed receipt in root/receipts.json; anything else is ignored."""
    try:
        data = json.loads((root / "receipts.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    items = data.get("receipts") if isinstance(data, dict) else None
    out = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict) or set(item) != set(_KEYS):
            continue
        r = Receipt(**{k: item[k] for k in _KEYS})
        if _valid(r):
            out.append(r)
    return out


def capability(root: Path, claude_version: str | None, plugin_version: str) -> list[dict]:
    """Per behaviour, the status from a receipt matching both versions, else unverified."""
    if claude_version is None:
        return [
            {"behaviour": b, "status": "unverified", "reason": VERSION_UNKNOWN}
            for b in CAPABILITY_BEHAVIOURS
        ]
    found = {
        r.behaviour: r.status
        for r in read_receipts(root)
        if r.claude_version == claude_version and r.plugin_version == plugin_version
    }
    return [
        {"behaviour": b, "status": found[b]}
        if b in found
        else {"behaviour": b, "status": "unverified", "reason": NO_RECEIPT}
        for b in CAPABILITY_BEHAVIOURS
    ]


def parse_claude_version(stdout: str) -> str | None:
    m = _VERSION.match(stdout.strip())
    return m.group(1) if m else None


def installed_claude_version() -> str | None:
    """`claude --version`, or None on any failure. For the CLI only, never the hook."""
    try:
        done = subprocess.run(
            ["claude", "--version"],
            capture_output=True,
            text=True,
            timeout=VERSION_TIMEOUT,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return parse_claude_version(done.stdout) if done.returncode == 0 else None
