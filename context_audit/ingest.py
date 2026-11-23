"""Turn the JSON a Claude Code hook receives into the `Field`s that `scan_fields` scans.

Shapes follow the probe (docs/research/2026-11-22-probe-observations.md): a result is a
list of content blocks or, with `structuredContent`, a string of JSON; a failure carries a
top-level `error` string. Text that parses as a JSON object or array is expanded into one
field per string value, so a directive inside JSON is read as prose, not as a quotation.
Keys are not scanned. Nesting past `Budget.max_depth` and fields past `Budget.max_fields`
are dropped and reported as `partial`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from context_audit.scan import Budget
from context_audit.text import Field

PREVIEW_LIMIT = 2_000  # characters the model is shown of a large result, per the probe


@dataclass(frozen=True)
class Ingested:
    fields: list[Field]
    outcome: str  # "complete" | "partial" | "not_scanned"
    reason: str  # "", "depth", "field-budget", "undecodable"
    tool: str
    tool_use_id: str
    oversized: bool  # total text over PREVIEW_LIMIT


def source_id_for(tool: str, server: str | None) -> str:
    """A stable ID for a tool's results; names are not secret, so a plain hash suffices."""
    key = f"{server or ''}\x00{tool}".encode("utf-8", "surrogatepass")
    return "src-" + hashlib.sha256(key).hexdigest()[:8]


class _Collector:
    def __init__(self, source_id: str, surface: str, budget: Budget) -> None:
        self.source_id = source_id
        self.surface = surface
        self.budget = budget
        self.fields: list[Field] = []
        self.reason = ""
        self.chars = 0
        self.leaves = 0

    def full(self) -> bool:
        if len(self.fields) >= self.budget.max_fields:
            self.reason = self.reason or "field-budget"
            return True
        return False

    def add(self, source_id: str, locator: str, text: str, block: int) -> None:
        if not self.full():
            self.fields.append(Field(source_id, self.surface, locator, text, block))

    def text(self, locator: str, text: str, block: int, json_prefix: str) -> None:
        """One text: expanded into its string leaves when it is a JSON object or array,
        each located by `json_prefix` followed by its JSON path."""
        self.chars += len(text)
        parsed = self._parse(text)
        if parsed is _UNPARSEABLE:
            self.reason = self.reason or "depth"
        elif isinstance(parsed, (dict, list)):
            self._walk(parsed, json_prefix, block)
        else:
            self.add(self.source_id, locator, text, block)

    def _parse(self, text: str) -> object:
        stripped = text.lstrip()
        if not stripped.startswith(("{", "[")) or len(text) > self.budget.max_bytes * 4:
            return None
        try:
            return json.loads(text)
        except RecursionError:
            return _UNPARSEABLE
        except ValueError:
            return None

    def _walk(self, root: object, prefix: str, block: int) -> None:
        # Iterative, depth-first in document order; depth counts enclosing containers.
        stack: list[tuple[object, str, int]] = [(root, "$", 1)]
        while stack:
            node, path, depth = stack.pop()
            if isinstance(node, str):
                if self.full():
                    return
                # Each leaf is its own statement: its own source_id, so leaves never join.
                self.leaves += 1
                self.add(f"{self.source_id}.j{self.leaves}", prefix + path, node, block)
            elif isinstance(node, (dict, list)):
                if depth > self.budget.max_depth:
                    self.reason = self.reason or "depth"
                    continue
                if isinstance(node, dict):
                    items = [(f"{path}.{k}", v) for k, v in node.items()]
                else:
                    items = [(f"{path}[{i}]", v) for i, v in enumerate(node)]
                stack.extend((v, p, depth + 1) for p, v in reversed(items))


_UNPARSEABLE = object()
_DEFAULT_BUDGET = Budget()


def from_hook_event(event: dict, budget: Budget = _DEFAULT_BUDGET) -> Ingested:
    if not isinstance(event, dict):
        return Ingested([], "not_scanned", "undecodable", "", "", False)
    tool = event.get("tool_name")
    tool = tool if isinstance(tool, str) else ""
    use_id = event.get("tool_use_id")
    use_id = use_id if isinstance(use_id, str) else ""
    server = event.get("mcp_server")
    name = server.get("name") if isinstance(server, dict) else None
    source_id = source_id_for(tool, name if isinstance(name, str) else None)

    def undecodable() -> Ingested:
        return Ingested([], "not_scanned", "undecodable", tool, use_id, False)

    kind = event.get("hook_event_name")
    if kind == "PostToolUseFailure":
        error = event.get("error")
        if not isinstance(error, str):
            return undecodable()
        c = _Collector(source_id, "tool_error", budget)
        c.add(source_id, "error", error, 0)
        c.chars = len(error)
    elif kind == "PostToolUse":
        response = event.get("tool_response")
        c = _Collector(source_id, "tool_result", budget)
        if isinstance(response, str):
            c.text("text", response, 0, "")
        elif isinstance(response, list):
            for i, block in enumerate(response):
                text = block.get("text") if isinstance(block, dict) else None
                if isinstance(text, str):
                    locator = f"content[{i}].text"
                    c.text(locator, text, i, locator)
        else:
            return undecodable()
    else:
        return undecodable()
    outcome = "partial" if c.reason else "complete"
    return Ingested(c.fields, outcome, c.reason, tool, use_id, c.chars > PREVIEW_LIMIT)
