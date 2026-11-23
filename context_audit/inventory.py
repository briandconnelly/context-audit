"""Inventory of third-party content a Claude Code installation holds on disk.

Nothing is started and no command is run: skills, plugin files, and MCP server
configuration are enumerated from disk, and the readable parts become `Field`s.
Every file is opened relative to a directory handle on its trusted root, one path
component at a time with O_NOFOLLOW, and checked as a regular file on the open handle.
MCP server entries contribute only a name, a transport, and an executable base name or
a URL's scheme and host; arguments, environment values, headers, and URL paths are
never copied into a `Source` or a `Field`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from context_audit.text import Field

MAX_SOURCES = 2_000
MAX_FILES = 5_000
DEFAULT_MAX_BYTES = 1_000_000

SKIP_REASONS = frozenset(
    {"symlink-escape", "not-regular", "too-large", "malformed", "outside-root", "too-many"}
)

_BODY_SURFACE = {"skill": "skill", "command": "command", "agent": "agent"}
_KEY = re.compile(r"^([A-Za-z0-9_-]+):[ \t]*(.*?)[ \t]*$")
_BLOCK = re.compile(r"^([|>])([+-]?)\d?$")


@dataclass(frozen=True)
class Source:
    source_id: str
    kind: str  # "skill" | "command" | "agent" | "hook_prompt" | "plugin_file" | "mcp_server"
    name: str  # as found on disk; third-party text
    path: Path | None
    label: str  # "discovered" | "configured"
    skipped: str  # "" or a member of SKIP_REASONS
    transport: str = ""  # mcp_server only: "stdio" | "http" | "sse"
    endpoint: str = ""  # mcp_server only: executable base name, or URL scheme and host
    root: Path | None = None  # trusted top root (claude_dir, project, or claude_json's parent)


@dataclass(frozen=True)
class Roots:
    claude_dir: Path
    claude_json: Path
    project: Path | None


def default_roots(project: Path | None) -> Roots:
    home = Path.home()
    return Roots(home / ".claude", home / ".claude.json", project)


def _source_id(*parts: str) -> str:
    return (
        "src-" + hashlib.sha256("\0".join(parts).encode("utf-8", "surrogatepass")).hexdigest()[:8]
    )


class _Full(Exception):
    pass


class _Absent(Exception):
    pass


def _open_component(name: str, flags: int, dir_fd: int) -> int:
    """Open one path component without following a symlink; raise _Skip with the reason."""
    try:
        return os.open(name, flags | os.O_NOFOLLOW, dir_fd=dir_fd)
    except FileNotFoundError:
        raise _Absent from None
    except OSError:
        try:
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            raise _Absent from None
        except OSError:
            raise _Skip("not-regular") from None
        raise _Skip("symlink-escape" if stat.S_ISLNK(info.st_mode) else "not-regular") from None


class _Skip(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _open_dir(root: Path, rel: Path) -> int:
    """A directory handle on root/rel, walked from root one component at a time."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    for part in rel.parts:
        try:
            nxt = _open_component(part, os.O_RDONLY | os.O_DIRECTORY, fd)
        finally:
            os.close(fd)
        fd = nxt
    return fd


def _read(root: Path, rel: Path, max_bytes: int) -> tuple[bytes, str]:
    """Read root/rel without following any symlink below root.

    Returns (data, "") or (b"", skip reason); raises _Absent if the file does not exist.
    """
    try:
        parent = _open_dir(root, rel.parent)
    except _Skip as e:
        return b"", e.reason
    except FileNotFoundError:
        raise _Absent from None
    try:
        fd = _open_component(rel.name, os.O_RDONLY | os.O_NONBLOCK, parent)
    except _Skip as e:
        return b"", e.reason
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return b"", "not-regular"
        if info.st_size > max_bytes:
            return b"", "too-large"
        chunks, remaining = [], max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 16))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            return b"", "too-large"
        return data, ""
    finally:
        os.close(fd)


def _json(data: bytes) -> object:
    try:
        return json.loads(data.decode("utf-8", errors="replace"))
    except ValueError:
        return None


class _Walk:
    """Enumeration state. Every path is relative to a trusted top root."""

    def __init__(self) -> None:
        self.sources: list[Source] = []
        self.files = 0

    def add(self, source: Source) -> None:
        if len(self.sources) >= MAX_SOURCES:
            raise _Full
        self.sources.append(source)

    def skip(self, kind: str, name: str, path: Path | None, reason: str, *extra: str) -> None:
        sid = _source_id(kind, str(path), reason, *extra)
        self.add(Source(sid, kind, name, path, "discovered", reason))

    def read(self, root: Path, rel: Path) -> tuple[bytes, str]:
        """Read a file for enumeration; raises _Absent when it does not exist."""
        self.files += 1
        if self.files > MAX_FILES:
            raise _Full
        return _read(root, rel, DEFAULT_MAX_BYTES)

    def file(self, kind: str, name: str, root: Path, rel: Path) -> None:
        try:
            _, skipped = self.read(root, rel)
        except _Absent:
            return
        path = root / rel
        sid = _source_id(kind, str(path))
        self.add(Source(sid, kind, name, path, "discovered", skipped, root=root))

    def entries(self, root: Path, rel: Path) -> list[os.DirEntry[str]]:
        """Entries of root/rel, listed from a handle walked without following symlinks.

        A container reached through a symlink is recorded as skipped.
        """
        try:
            fd = _open_dir(root, rel)
        except (_Absent, FileNotFoundError):
            return []
        except _Skip as e:
            self.skip("plugin_file", str(rel), root / rel, e.reason)
            return []
        try:
            with os.scandir(fd) as it:
                return sorted(it, key=lambda e: e.name)
        except OSError:
            return []
        finally:
            os.close(fd)

    def subdirs(self, root: Path, rel: Path) -> list[str]:
        names = []
        for entry in self.entries(root, rel):
            if entry.is_symlink():
                self.skip("plugin_file", entry.name, root / rel / entry.name, "symlink-escape")
            elif entry.is_dir(follow_symlinks=False):
                names.append(entry.name)
        return names


def _skills(walk: _Walk, root: Path, rel: Path) -> None:
    for name in walk.subdirs(root, rel):
        walk.file("skill", name, root, rel / name / "SKILL.md")


def _endpoint(server: dict) -> tuple[str, str]:
    kind = server.get("type")
    url = server.get("url")
    if isinstance(url, str) and kind != "stdio":
        transport = "sse" if kind == "sse" else "http"
        try:
            parts = urlsplit(url)
            host = parts.hostname or ""
            port = parts.port
        except ValueError:
            return transport, ""
        if not parts.scheme or not host:
            return transport, ""
        return transport, f"{parts.scheme}://{host}" + (f":{port}" if port else "")
    command = server.get("command")
    if isinstance(command, str):
        tokens = command.split()
        return "stdio", os.path.basename(tokens[0]) if tokens else ""
    return "", ""


def _servers(walk: _Walk, servers: object, scope: str, path: Path) -> bool:
    if servers is None:
        return True
    if not isinstance(servers, dict):
        return False
    for name, server in servers.items():
        sid = _source_id("mcp_server", scope, str(name))
        if not isinstance(server, dict):
            walk.add(Source(sid, "mcp_server", str(name), path, "configured", "malformed"))
            continue
        transport, endpoint = _endpoint(server)
        walk.add(Source(sid, "mcp_server", str(name), path, "configured", "", transport, endpoint))
    return True


def _mcp_file(walk: _Walk, root: Path, rel: Path, scope: str, projects: bool = False) -> None:
    try:
        data, skipped = walk.read(root, rel)
    except _Absent:
        return
    path = root / rel
    doc = _json(data) if not skipped else None
    ok = isinstance(doc, dict) and _servers(walk, doc.get("mcpServers"), scope, path)
    if ok and projects and isinstance(doc, dict):
        entries = doc.get("projects")
        if isinstance(entries, dict):
            for proj, conf in entries.items():
                if isinstance(conf, dict):
                    ok = _servers(walk, conf.get("mcpServers"), f"local:{proj}", path) and ok
        elif entries is not None:
            ok = False
    if skipped or not ok:
        sid = _source_id("mcp_server", str(path))
        walk.add(Source(sid, "mcp_server", "", path, "configured", skipped or "malformed"))


def _hook_entries(doc: object) -> tuple[list[tuple[str, str]] | None, bool]:
    """(locator, prompt) pairs and whether any command hook exists; None when wrong-shaped."""
    if not isinstance(doc, dict) or not isinstance(doc.get("hooks"), dict):
        return None, False
    prompts: list[tuple[str, str]] = []
    commands = False
    for event, groups in doc["hooks"].items():
        if not isinstance(groups, list):
            return None, False
        for i, group in enumerate(groups):
            hooks = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(hooks, list):
                return None, False
            for j, hook in enumerate(hooks):
                if not isinstance(hook, dict):
                    return None, False
                if hook.get("type") == "prompt":
                    if not isinstance(hook.get("prompt"), str):
                        return None, False
                    prompts.append((f"hooks.{event}[{i}].hooks[{j}].prompt", hook["prompt"]))
                elif hook.get("type") == "command":
                    commands = True
    return prompts, commands


def _hooks(walk: _Walk, root: Path, prel: Path, name: str) -> None:
    rel = prel / "hooks" / "hooks.json"
    try:
        data, skipped = walk.read(root, rel)
    except _Absent:
        return
    path = root / rel
    prompts, commands = _hook_entries(_json(data)) if not skipped else (None, False)
    if prompts is None:
        walk.skip("hook_prompt", name, path, skipped or "malformed")
        return
    if prompts:
        sid = _source_id("hook_prompt", str(path))
        walk.add(Source(sid, "hook_prompt", name, path, "discovered", "", root=root))
    if commands:
        sid = _source_id("plugin_file", str(path))
        walk.add(Source(sid, "plugin_file", name, path, "discovered", ""))


def _plugin(walk: _Walk, key: str, root: Path, prel: Path) -> None:
    walk.file("plugin_file", key, root, prel / ".claude-plugin" / "plugin.json")
    _skills(walk, root, prel / "skills")
    for kind, folder in (("command", "commands"), ("agent", "agents")):
        for entry in walk.entries(root, prel / folder):
            if entry.name.endswith(".md"):
                walk.file(kind, entry.name.removesuffix(".md"), root, prel / folder / entry.name)
    _hooks(walk, root, prel, key)
    _mcp_file(walk, root, prel / ".mcp.json", f"plugin:{key}")
    for fname in ("CLAUDE.md", "AGENTS.md"):
        walk.file("skill", f"{key}/{fname}", root, prel / fname)


def _plugin_rel(install: str, claude_dir: Path) -> Path | None:
    """installPath relative to claude_dir, or None when it is not absolute or lies outside.

    The relative path is only ever opened by walking from claude_dir with O_NOFOLLOW,
    so a symlink swapped in later is refused rather than followed.
    """
    path = Path(install)
    if not path.is_absolute():
        return None
    real, top = path.resolve(), claude_dir.resolve()
    if not real.is_relative_to(top) or real == top:
        return None
    return real.relative_to(top)


def _plugins(walk: _Walk, claude_dir: Path) -> None:
    rel = Path("plugins", "installed_plugins.json")
    try:
        data, skipped = walk.read(claude_dir, rel)
    except _Absent:
        return
    path = claude_dir / rel
    doc = _json(data) if not skipped else None
    plugins = doc.get("plugins") if isinstance(doc, dict) else None
    if not isinstance(plugins, dict):
        walk.skip("plugin_file", "", path, skipped or "malformed")
        return
    for key, entries in plugins.items():
        key = str(key)
        for index, entry in enumerate(entries if isinstance(entries, list) else [entries]):
            install = entry.get("installPath") if isinstance(entry, dict) else None
            if not isinstance(install, str) or not install:
                walk.skip("plugin_file", key, None, "malformed", key, str(index))
                continue
            prel = _plugin_rel(install, claude_dir)
            if prel is None:
                walk.skip("plugin_file", key, None, "outside-root", key, str(index))
                continue
            try:
                os.close(_open_dir(claude_dir, prel))
            except (_Absent, FileNotFoundError):
                continue
            except _Skip as e:
                walk.skip("plugin_file", key, claude_dir / prel, e.reason)
                continue
            _plugin(walk, key, claude_dir, prel)


def enumerate_sources(roots: Roots) -> list[Source]:
    walk = _Walk()
    try:
        if roots.claude_dir.is_dir():
            _skills(walk, roots.claude_dir, Path("skills"))
            _plugins(walk, roots.claude_dir)
        _mcp_file(
            walk, roots.claude_json.parent, Path(roots.claude_json.name), "user", projects=True
        )
        if roots.project is not None and roots.project.is_dir():
            _skills(walk, roots.project, Path(".claude", "skills"))
            _mcp_file(walk, roots.project, Path(".mcp.json"), "project")
    except _Full:
        sid = _source_id("plugin_file", "too-many")
        walk.sources.append(Source(sid, "plugin_file", "", None, "discovered", "too-many"))
    return walk.sources


def _fold(lines: list[str]) -> str:
    """Fold lines as YAML does: single newlines become spaces, blank lines newlines."""
    text, prev_blank = "", True
    for line in lines:
        if not line.strip():
            text += "\n"
            prev_blank = True
        else:
            text += ("" if prev_blank else " ") + line
            prev_blank = False
    return text


def _block_scalar(lines: list[str], style: str, chomp: str) -> str:
    while lines and not lines[-1].strip():
        lines.pop()
    indents = [len(x) - len(x.lstrip()) for x in lines if x.strip()]
    cut = min(indents) if indents else 0
    lines = [x[cut:] for x in lines]
    text = "\n".join(lines) if style == "|" else _fold(lines)
    return text if chomp == "-" else text + "\n"


def _continuation(header: list[str], start: int) -> int:
    """Index after the indented or blank lines that continue the value begun before start."""
    end = start
    while end < len(header) and (not header[end].strip() or header[end][:1].isspace()):
        end += 1
    while end > start and not header[end - 1].strip():
        end -= 1
    return end


def _description(header: list[str]) -> tuple[str, set[int]]:
    """The description value and the header line indices it consumed."""
    for i, line in enumerate(header):
        m = _KEY.match(line)
        if not m or m.group(1) != "description":
            continue
        value = m.group(2)
        block = _BLOCK.match(value)
        if block:
            end = _continuation(header, i + 1)
            text = _block_scalar(header[i + 1 : end], block.group(1), block.group(2))
            return text, set(range(i, end))
        quote = value[:1]
        if quote in ("'", '"'):
            parts, end = [value[1:]], i + 1
            while not parts[-1].rstrip().endswith(quote) and end < len(header):
                parts.append(header[end].strip())
                end += 1
            parts[-1] = parts[-1].rstrip().removesuffix(quote)
            return _fold(parts), set(range(i, end))
        end = _continuation(header, i + 1)
        parts = [value] + [x.strip() for x in header[i + 1 : end]]
        return _fold(parts).strip(), set(range(i, end))
    return "", set()


def _split_frontmatter(text: str) -> tuple[str, str, str]:
    """(description, unparsed header text, body) of Markdown with optional frontmatter."""
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        return "", "", text
    for k in range(1, len(lines)):
        if lines[k].rstrip("\r\n") == "---":
            header = [x.rstrip("\r\n") for x in lines[1:k]]
            description, used = _description(header)
            rest = [x for n, x in enumerate(header) if n not in used and x.strip()]
            return description, "\n".join(rest), "".join(lines[k + 1 :])
    return "", "", text


def read_fields(source: Source, *, max_bytes: int = DEFAULT_MAX_BYTES) -> list[Field]:
    return read_source(source, max_bytes=max_bytes)[0]


def read_source(source: Source, *, max_bytes: int = DEFAULT_MAX_BYTES) -> tuple[list[Field], bool]:
    """The source's fields, and whether it could be read now (False when it vanished,
    changed type, or grew past the limit since enumeration)."""
    if source.skipped or source.root is None or source.path is None:
        return [], False
    if source.kind not in _BODY_SURFACE and source.kind != "hook_prompt":
        return [], False
    try:
        data, skipped = _read(source.root, source.path.relative_to(source.root), max_bytes)
    except (_Absent, ValueError, OSError):
        return [], False
    if skipped:
        return [], False
    sid = source.source_id
    if source.kind == "hook_prompt":
        prompts, _ = _hook_entries(_json(data))
        return [
            Field(sid, "hook_prompt", loc, p, i) for i, (loc, p) in enumerate(prompts or [])
        ], True
    description, unparsed, body = _split_frontmatter(data.decode("utf-8", errors="replace"))
    fields: list[Field] = []
    for surface, locator, text in (
        ("frontmatter", "frontmatter.description", description),
        ("frontmatter", "frontmatter.unparsed", unparsed),
        (_BODY_SURFACE[source.kind], "body", body),
    ):
        if text:
            fields.append(Field(sid, surface, locator, text, len(fields)))
    return fields, True
