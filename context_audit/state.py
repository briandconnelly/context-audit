"""Owner-only state directory: keyed digests, a locked event log, and counters.

The directory must be a real directory owned by the user, not a symlink. Every file in it
is opened with O_NOFOLLOW and O_NONBLOCK and checked as a regular file on the open
descriptor, and temporary files are created exclusively under unique names, so a link or
special file planted in the directory is refused, never followed or blocked on.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
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
    """Create root with mode 0700 (parents too) and return it. Raises StateError when root
    is a symlink, not a directory, or not owned by the user."""
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(root)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise StateError(f"state directory {root} is not a directory (or is a symlink)")
        if info.st_uid != os.getuid():
            raise StateError(f"state directory {root} is not owned by this user")
        if stat.S_IMODE(info.st_mode) != 0o700:
            os.chmod(root, 0o700, follow_symlinks=False)
    except OSError as e:
        raise StateError(f"cannot create state directory {root}: {e.strerror}") from e
    return root


def _open(path: Path, flags: int, mode: int = 0o600) -> int:
    """Open a state file without following a symlink or blocking on a special file;
    raises OSError, or StateError when it is not a regular file."""
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, mode)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise StateError(f"{path} is not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_bytes(path: Path) -> bytes:
    fd = _open(path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as f:
        return f.read()


def _write_new(root: Path, stem: str, data: bytes, target: Path) -> None:
    """Write data to an exclusively created, uniquely named file, then rename it over
    target."""
    tmp = root / f"{stem}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)


@contextmanager
def _locked(root: Path) -> Generator[None]:
    try:
        fd = _open(root / "lock", os.O_WRONLY | os.O_CREAT)
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
        key = _read_bytes(path)
    except FileNotFoundError:
        with _locked(root):
            for stale in root.glob("key.*.tmp"):
                stale.unlink(missing_ok=True)
            if not os.path.lexists(path):
                # Write the whole key under a temporary name, then rename it into place
                # (no hard links needed), so a reader outside the lock never sees an
                # empty or partial key. Creators are serialized by the lock.
                _write_new(root, "key", secrets.token_bytes(32), path)
            key = _read_bytes(path)
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
    data = _read_bytes(path)
    keep = data[len(data) - EVENTS_CAP_BYTES // 2 :]
    nl = keep.find(b"\n")
    keep = keep[nl + 1 :] if nl != -1 else b""
    _write_new(root, "events.jsonl", keep, path)
    stamp = (datetime.now(UTC).isoformat() + "\n").encode()
    _write_new(root, "trimmed", stamp, root / "trimmed")


def append_event(root: Path, record: dict) -> None:
    """Append one JSON line to events.jsonl under the lock; trim at the size cap."""
    line = (json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    path = root / "events.jsonl"
    with _locked(root):
        try:
            fd = _open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
            with os.fdopen(fd, "ab") as f:
                f.write(line)
                size = f.tell()
            if size >= EVENTS_CAP_BYTES:
                _trim(path, root)
        except OSError as e:
            raise StateError(f"cannot write events in {root}: {e.strerror}") from e


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
        try:
            _write_new(root, "counters.json", json.dumps(current).encode(), path)
        except OSError as e:
            raise StateError(f"cannot write counters in {root}: {e.strerror}") from e


def read_events(root: Path) -> list[dict]:
    """Return every whole JSON object line; skip lines that do not parse."""
    try:
        raw = _read_bytes(root / "events.jsonl")
    except FileNotFoundError:
        return []
    except OSError as e:
        raise StateError(f"cannot read events in {root}: {e.strerror}") from e
    events = []
    for line in raw.splitlines():
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def read_counters(root: Path) -> dict[str, int]:
    """Return the counters; an absent or unreadable file reads as empty."""
    try:
        data = json.loads(_read_bytes(root / "counters.json").decode("utf-8", "replace"))
    except FileNotFoundError:
        return {}
    except ValueError:
        return {}
    except OSError as e:
        raise StateError(f"cannot read counters in {root}: {e.strerror}") from e
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if k in COUNTER_NAMES and isinstance(v, int)}
