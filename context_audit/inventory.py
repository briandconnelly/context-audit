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

import errno
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
    root: Path | None = None  # the trusted directory `path` is opened relative to


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


def _read(root: Path, rel: Path, max_bytes: int) -> tuple[bytes, str]:
    """Read root/rel without following any symlink below root.

    Returns (data, "") or (b"", skip reason); raises _Absent if the file does not exist.
    """
    fds: list[int] = []
    try:
        try:
            fds.append(os.open(root, os.O_RDONLY | os.O_DIRECTORY))
            for part in rel.parts[:-1]:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                fds.append(os.open(part, flags, dir_fd=fds[-1]))
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            fds.append(os.open(rel.parts[-1], flags, dir_fd=fds[-1]))
        except FileNotFoundError:
            raise _Absent from None
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                return b"", "symlink-escape"
            return b"", "not-regular"
        info = os.fstat(fds[-1])
        if not stat.S_ISREG(info.st_mode):
            return b"", "not-regular"
        if info.st_size > max_bytes:
            return b"", "too-large"
        chunks, remaining = [], max_bytes + 1
        while remaining > 0:
            chunk = os.read(fds[-1], min(remaining, 1 << 16))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            return b"", "too-large"
        return data, ""
    finally:
        for fd in reversed(fds):
            os.close(fd)


def _json(data: bytes) -> object:
    try:
        return json.loads(data.decode("utf-8", errors="replace"))
    except ValueError:
        return None


class _Walk:
    def __init__(self) -> None:
        self.sources: list[Source] = []
        self.files = 0

    def add(self, source: Source) -> None:
        if len(self.sources) >= MAX_SOURCES:
            raise _Full
        self.sources.append(source)

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
        self.add(
            Source(_source_id(kind, str(path)), kind, name, path, "discovered", skipped, root=root)
        )

    def subdirs(self, root: Path, rel: Path) -> list[str]:
        """Names of real subdirectories of root/rel; a symlinked one leaving root is recorded."""
        here = root
        for part in rel.parts:
            here = here / part
            if here.is_symlink():
                return []
        try:
            entries = sorted(os.scandir(here), key=lambda e: e.name)
        except OSError:
            return []
        names = []
        real_root = root.resolve()
        for entry in entries:
            if entry.is_symlink():
                target = Path(entry.path).resolve()
                if not target.is_relative_to(real_root):
                    path = Path(entry.path)
                    sid = _source_id("plugin_file", str(path))
                    self.add(
                        Source(sid, "plugin_file", entry.name, path, "discovered", "symlink-escape")
                    )
            elif entry.is_dir(follow_symlinks=False):
                names.append(entry.name)
        return names

    def files_in(self, root: Path, rel: Path, suffix: str) -> list[str]:
        here = root / rel
        if any((root / Path(*rel.parts[: i + 1])).is_symlink() for i in range(len(rel.parts))):
            return []
        try:
            return sorted(e.name for e in os.scandir(here) if e.name.endswith(suffix))
        except OSError:
            return []


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
        token = command.split()[0] if command.split() else ""
        return "stdio", os.path.basename(token)
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
        walk.add(
            Source(
                _source_id("mcp_server", str(path)),
                "mcp_server",
                "",
                path,
                "configured",
                skipped or "malformed",
            )
        )


def _hooks(walk: _Walk, root: Path, name: str) -> None:
    rel = Path("hooks", "hooks.json")
    try:
        data, skipped = walk.read(root, rel)
    except _Absent:
        return
    path = root / rel
    prompts, commands = _hook_entries(_json(data)) if not skipped else (None, False)
    if prompts is None:
        sid = _source_id("hook_prompt", str(path))
        walk.add(
            Source(sid, "hook_prompt", name, path, "discovered", skipped or "malformed", root=root)
        )
        return
    if prompts:
        walk.add(
            Source(
                _source_id("hook_prompt", str(path)),
                "hook_prompt",
                name,
                path,
                "discovered",
                "",
                root=root,
            )
        )
    if commands:
        walk.add(
            Source(
                _source_id("plugin_file", str(path)), "plugin_file", name, path, "discovered", ""
            )
        )


def _hook_entries(doc: object) -> tuple[list[tuple[str, str]] | None, bool]:
    """(locator, prompt) pairs and whether any command hook exists; None when malformed."""
    if not isinstance(doc, dict) or not isinstance(doc.get("hooks"), dict):
        return None, False
    prompts: list[tuple[str, str]] = []
    commands = False
    for groups in doc["hooks"].values():
        if not isinstance(groups, list):
            continue
        for i, group in enumerate(groups):
            hooks = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(hooks, list):
                continue
            for j, hook in enumerate(hooks):
                if not isinstance(hook, dict):
                    continue
                if hook.get("type") == "prompt" and isinstance(hook.get("prompt"), str):
                    prompts.append((f"hooks[{i}].hooks[{j}].prompt", hook["prompt"]))
                elif hook.get("type") == "command":
                    commands = True
    return prompts, commands


def _plugin(walk: _Walk, key: str, root: Path) -> None:
    walk.file("plugin_file", key, root, Path(".claude-plugin", "plugin.json"))
    _skills(walk, root, Path("skills"))
    for kind, folder in (("command", "commands"), ("agent", "agents")):
        for fname in walk.files_in(root, Path(folder), ".md"):
            walk.file(kind, fname.removesuffix(".md"), root, Path(folder, fname))
    _hooks(walk, root, key)
    _mcp_file(walk, root, Path(".mcp.json"), f"plugin:{key}")
    for fname in ("CLAUDE.md", "AGENTS.md"):
        walk.file("skill", f"{key}/{fname}", root, Path(fname))


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
        walk.add(
            Source(
                _source_id("plugin_file", str(path)),
                "plugin_file",
                "",
                path,
                "discovered",
                skipped or "malformed",
            )
        )
        return
    real_claude = claude_dir.resolve()
    for key, entries in plugins.items():
        key = str(key)
        for entry in entries if isinstance(entries, list) else [entries]:
            install = entry.get("installPath") if isinstance(entry, dict) else None
            if not isinstance(install, str) or not install:
                walk.add(
                    Source(
                        _source_id("plugin_file", key),
                        "plugin_file",
                        key,
                        None,
                        "discovered",
                        "malformed",
                    )
                )
                continue
            root = Path(install).resolve()
            if not root.is_relative_to(real_claude):
                sid = _source_id("plugin_file", str(root))
                walk.add(Source(sid, "plugin_file", key, None, "discovered", "outside-root"))
                continue
            if root.is_dir():
                _plugin(walk, key, root)


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


def _block_scalar(lines: list[str], style: str, chomp: str) -> str:
    while lines and not lines[-1].strip():
        lines.pop()
    indents = [len(x) - len(x.lstrip()) for x in lines if x.strip()]
    cut = min(indents) if indents else 0
    lines = [x[cut:] for x in lines]
    if style == "|":
        text = "\n".join(lines)
    else:
        text, prev_blank = "", True
        for line in lines:
            if not line.strip():
                text += "\n"
                prev_blank = True
            else:
                text += ("" if prev_blank else " ") + line
                prev_blank = False
    return text if chomp == "-" else text + "\n"


def _description(header: list[str]) -> str:
    for i, line in enumerate(header):
        m = _KEY.match(line)
        if not m or m.group(1) != "description":
            continue
        value = m.group(2)
        block = _BLOCK.match(value)
        if block:
            body = []
            for nxt in header[i + 1 :]:
                if nxt.strip() and not nxt[:1].isspace():
                    break
                body.append(nxt)
            return _block_scalar(body, block.group(1), block.group(2))
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        return value
    return ""


def _split_frontmatter(text: str) -> tuple[str, str]:
    """(description, body) of a Markdown file with optional YAML frontmatter."""
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        return "", text
    for k in range(1, len(lines)):
        if lines[k].rstrip("\r\n") == "---":
            header = [x.rstrip("\r\n") for x in lines[1:k]]
            return _description(header), "".join(lines[k + 1 :])
    return "", text


def read_fields(source: Source, *, max_bytes: int = DEFAULT_MAX_BYTES) -> list[Field]:
    if source.skipped or source.root is None or source.path is None:
        return []
    if source.kind not in _BODY_SURFACE and source.kind != "hook_prompt":
        return []
    try:
        data, skipped = _read(source.root, source.path.relative_to(source.root), max_bytes)
    except (_Absent, ValueError):
        return []
    if skipped:
        return []
    text = data.decode("utf-8", errors="replace")
    sid = source.source_id
    if source.kind == "hook_prompt":
        prompts, _ = _hook_entries(_json(data))
        return [Field(sid, "hook_prompt", loc, p, i) for i, (loc, p) in enumerate(prompts or [])]
    description, body = _split_frontmatter(text)
    fields = []
    if description:
        fields.append(Field(sid, "frontmatter", "frontmatter.description", description, 0))
    if body:
        fields.append(Field(sid, _BODY_SURFACE[source.kind], "body", body, len(fields)))
    return fields
