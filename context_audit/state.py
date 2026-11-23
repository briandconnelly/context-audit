"""Owner-only state directory: keyed digests, a locked event log, and counters."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

COUNTER_NAMES = (
    "calls_requested",
    "results_delivered",
    "fully_scanned",
    "partly_scanned",
    "not_scanned",
)
EVENTS_CAP_BYTES = 5 * 1024 * 1024
DIGEST_LEN = 16


class StateError(Exception):
    """The state directory cannot be created, read, or written."""


def state_dir(env: Mapping[str, str] | None = None) -> Path:
    """Resolve the state directory without creating it."""
    env = os.environ if env is None else env
    if home := env.get("CONTEXT_AUDIT_HOME"):
        return Path(home)
    if xdg := env.get("XDG_STATE_HOME"):
        return Path(xdg) / "context-audit"
    base = Path(env["HOME"]) if env.get("HOME") else Path.home()
    return base / ".local" / "state" / "context-audit"


def ensure_state(root: Path) -> Path:
    """Create root with mode 0700 (parents too) and return it."""
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.chmod(0o700)
    except OSError as e:
        raise StateError(f"cannot create state directory {root}: {e.strerror}") from e
    return root


@contextmanager
def _locked(root: Path) -> Generator[None]:
    try:
        fd = os.open(root / "lock", os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError as e:
        raise StateError(f"cannot write state directory {root}: {e.strerror}") from e
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    except OSError as e:
        raise StateError(f"cannot write state directory {root}: {e.strerror}") from e
    finally:
        os.close(fd)


def _key(root: Path) -> bytes:
    path = root / "key"
    try:
        key = path.read_bytes()
    except FileNotFoundError:
        with _locked(root):
            for stale in root.glob("key.*.tmp"):
                stale.unlink(missing_ok=True)
            if not path.exists():
                # Write the whole key under a temporary name, then rename it into place
                # (no hard links needed), so a reader outside the lock never sees an
                # empty or partial key. Creators are serialized by the lock.
                tmp = root / f"key.{os.getpid()}.tmp"
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(secrets.token_bytes(32))
                    os.replace(tmp, path)
                finally:
                    tmp.unlink(missing_ok=True)
            key = path.read_bytes()
    except OSError as e:
        raise StateError(f"cannot read key in {root}: {e.strerror}") from e
    if len(key) != 32:
        raise StateError(f"key in {root} is not 32 bytes")
    return key


def span_digest(root: Path, text: str) -> str:
    """Keyed digest of text: HMAC-SHA256 hex, first 16 characters."""
    mac = hmac.new(_key(root), text.encode("utf-8", "surrogatepass"), hashlib.sha256)
    return mac.hexdigest()[:DIGEST_LEN]


def _trim(path: Path, root: Path) -> None:
    data = path.read_bytes()
    keep = data[len(data) - EVENTS_CAP_BYTES // 2 :]
    nl = keep.find(b"\n")
    keep = keep[nl + 1 :] if nl != -1 else b""
    tmp = root / "events.jsonl.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(keep)
    os.replace(tmp, path)
    (root / "trimmed").write_text(datetime.now(UTC).isoformat() + "\n")


def append_event(root: Path, record: dict) -> None:
    """Append one JSON line to events.jsonl under the lock; trim at the size cap."""
    line = (json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    path = root / "events.jsonl"
    with _locked(root):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as f:
            f.write(line)
            size = f.tell()
        if size >= EVENTS_CAP_BYTES:
            _trim(path, root)


def bump(root: Path, **counts: int) -> None:
    """Add counts to counters.json under the lock."""
    unknown = set(counts) - set(COUNTER_NAMES)
    if unknown:
        raise ValueError(f"unknown counter(s): {', '.join(sorted(unknown))}")
    path = root / "counters.json"
    with _locked(root):
        current = read_counters(root)
        for name, n in counts.items():
            current[name] = current.get(name, 0) + n
        tmp = root / "counters.json.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(current, f)
        os.replace(tmp, path)


def read_events(root: Path) -> list[dict]:
    """Return every whole JSON object line; skip lines that do not parse."""
    try:
        raw = (root / "events.jsonl").read_bytes()
    except FileNotFoundError:
        return []
    except OSError as e:
        raise StateError(f"cannot read events in {root}: {e.strerror}") from e
    events = []
    for line in raw.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def read_counters(root: Path) -> dict[str, int]:
    """Return the counters; an absent or unreadable file reads as empty."""
    try:
        data = json.loads((root / "counters.json").read_text())
    except FileNotFoundError:
        return {}
    except ValueError:
        return {}
    except OSError as e:
        raise StateError(f"cannot read counters in {root}: {e.strerror}") from e
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if k in COUNTER_NAMES and isinstance(v, int)}
