"""Coverage receipts: what the probe showed the packaged hooks doing on one harness build.

The probe writes ``receipts.json`` into the state directory; `status` and `scan` read it.
A receipt counts only when it matches the installed Claude Code version, this plugin's
version, and the digest of this build's runtime files (`build_digest`), and only for the
frontend and permission mode it was taken in; every other behaviour, including one whose
receipt came from another build, is reported ``unverified``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import select
import signal
import stat
import subprocess
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from context_audit.report import (
    CAPABILITY_BEHAVIOURS,
    FRONTENDS,
    PERMISSION_MODES,
    VERSION_UNKNOWN,
    unverified_entry,
)

__all__ = [
    "VERSION_UNKNOWN", "Receipt", "build_digest", "capability", "read_receipts", "write_receipts",
]  # fmt: skip

RECEIPT_STATUSES = ("shown", "not_shown", "inconclusive")
# When receipts for one behaviour, frontend and mode disagree, the least favourable wins.
_WORST_FIRST = ("not_shown", "inconclusive", "shown")
MAX_BYTES = 1024 * 1024
_VERSION = re.compile(r"^(\d+(?:\.\d+)+)(?: \(Claude Code\))?$")
VERSION_TIMEOUT = 2.0
VERSION_MAX_BYTES = 200


@dataclass(frozen=True)
class Receipt:
    behaviour: str  # one of CAPABILITY_BEHAVIOURS
    status: str  # one of RECEIPT_STATUSES
    claude_version: str
    plugin_version: str
    frontend: str  # one of FRONTENDS
    permission_mode: str  # one of PERMISSION_MODES
    build: str  # build_digest() of the plugin the receipt was taken on


# The plugin's runtime files, which a receipt's build digest covers. In a repository or
# plugin directory they sit beside the package; a wheel carries hooks/ and bin/ inside the
# package under _runtime/ (see pyproject.toml).
_PACKAGE = Path(__file__).resolve().parent


def _runtime_files(top: Path) -> list[tuple[str, Path]]:
    package = top / "context_audit"
    extra = top if (top / "hooks" / "hooks.json").is_file() else package / "_runtime"
    files = [(f"context_audit/{p.name}", p) for p in package.glob("*.py")]
    files.append(("hooks/hooks.json", extra / "hooks" / "hooks.json"))
    bin_dir = extra / "bin"
    if bin_dir.is_dir():
        files += [(f"bin/{p.name}", p) for p in bin_dir.iterdir() if p.is_file()]
    return sorted(files)


def build_digest(top: Path | None = None) -> str:
    """SHA-256 (first 16 hex characters) over the runtime files' names and contents:
    context_audit/*.py, hooks/hooks.json, and bin/*. A missing file is hashed as missing."""
    h = hashlib.sha256()
    for name, path in _runtime_files(top or _PACKAGE.parent):
        try:
            data = path.read_bytes()
        except OSError:
            data = None
        h.update(name.encode() + b"\0")
        h.update(b"-\0" if data is None else str(len(data)).encode() + b"\0" + data)
    return h.hexdigest()[:16]


_KEYS = tuple(f.name for f in fields(Receipt))


def _valid(r: Receipt) -> bool:
    return (
        all(isinstance(getattr(r, k), str) for k in _KEYS)
        and r.behaviour in CAPABILITY_BEHAVIOURS
        and r.status in RECEIPT_STATUSES
        and r.frontend in FRONTENDS
        and r.permission_mode in PERMISSION_MODES
    )


def write_receipts(root: Path, receipts: list[Receipt]) -> None:
    """Replace root/receipts.json, owner-only."""
    bad = [r for r in receipts if not _valid(r)]
    if bad:
        raise ValueError(f"invalid receipt(s): {bad}")
    path = root / "receipts.json"
    tmp = root / f"receipts.json.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"receipts": [asdict(r) for r in receipts]}, f, indent=1)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _read_bytes(path: Path) -> bytes | None:
    """A regular, non-symlinked file of at most MAX_BYTES, else None."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            return None
        data = os.read(fd, MAX_BYTES + 1)
    finally:
        os.close(fd)
    return data if len(data) <= MAX_BYTES else None


def read_receipts(root: Path) -> list[Receipt]:
    """Every well-formed receipt in root/receipts.json; any failure reads as none."""
    try:
        raw = _read_bytes(root / "receipts.json")
        if raw is None:
            return []
        data = json.loads(raw.decode("utf-8"))
        items = data.get("receipts") if isinstance(data, dict) else None
        out = []
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict) or set(item) != set(_KEYS):
                continue
            r = Receipt(**{k: item[k] for k in _KEYS})
            if _valid(r):
                out.append(r)
        return out
    except Exception:  # noqa: BLE001 - a hostile or broken file reads as no receipts
        return []


def capability(
    root: Path, claude_version: str | None, plugin_version: str, build: str | None = None
) -> list[dict]:
    """One entry per behaviour and (frontend, permission mode) with a matching receipt,
    and an unverified entry for each behaviour with none. `build` defaults to this build's
    digest."""
    build = build_digest() if build is None else build
    found: dict[tuple[str, str, str], str] = {}
    if claude_version is not None:
        for r in read_receipts(root):
            if r.claude_version != claude_version or r.plugin_version != plugin_version:
                continue
            if r.build != build:
                continue
            key = (r.behaviour, r.frontend, r.permission_mode)
            found[key] = min(found.get(key, "shown"), r.status, key=_WORST_FIRST.index)
    out: list[dict] = []
    for b in CAPABILITY_BEHAVIOURS:
        here = sorted(k for k in found if k[0] == b)
        if not here:
            out.append(unverified_entry(b))
        for key in here:
            out.append(
                {
                    "behaviour": b,
                    "status": found[key],
                    "frontend": key[1],
                    "permission_mode": key[2],
                }  # fmt: skip
            )
    return out


def parse_claude_version(stdout: str) -> str | None:
    m = _VERSION.match(stdout.strip())
    return m.group(1) if m else None


def _read_capped(proc: subprocess.Popen[bytes], deadline: float) -> bytes | None:
    """Standard output up to EOF, or None past the deadline or VERSION_MAX_BYTES."""
    assert proc.stdout is not None
    fd = proc.stdout.fileno()
    out = b""
    while True:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            return None
        chunk = os.read(fd, VERSION_MAX_BYTES + 1 - len(out))
        if not chunk:
            return out
        out += chunk
        if len(out) > VERSION_MAX_BYTES:
            return None


def installed_claude_version() -> str | None:
    """`claude --version`, or None on any failure. For the CLI only, never the hook.

    Reads at most VERSION_MAX_BYTES of standard output within VERSION_TIMEOUT seconds."""
    deadline = time.monotonic() + VERSION_TIMEOUT
    try:
        proc = subprocess.Popen(
            ["claude", "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    try:
        out = _read_capped(proc, deadline)
        code = None
        if out is not None:
            code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    finally:
        if proc.poll() is None:
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.SubprocessError):
                proc.wait(timeout=1)
        if proc.stdout is not None:
            proc.stdout.close()
    if out is None or code != 0:
        return None
    return parse_claude_version(out.decode("utf-8", "replace"))
