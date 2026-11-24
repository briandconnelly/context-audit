"""Turn the JSON a Claude Code hook receives into the `Field`s that `scan_fields` scans.

Shapes follow the probe (docs/research/2026-11-22-probe-observations.md): a result is a
list of content blocks or, with `structuredContent`, a string of JSON; a failure carries a
top-level `error` string. Text that parses as a JSON object or array is expanded into one
field per string value, so a directive inside JSON is read as prose, not as a quotation.
Keys are not scanned, and never copied: an object member is located by its ordinal
(`$.#0`), so no key reaches a locator, the event log, or hook output. Nesting past
`Budget.max_depth` and fields past `Budget.max_fields` are dropped and reported as
`partial`; the walk is lazy and stops at its node cap.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass

from context_audit.scan import Budget
from context_audit.text import Field

PREVIEW_LIMIT = 2_000  # characters the model is shown of a large result, per the probe

_Item = tuple[object, str, int, tuple[str, int] | None]


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
        self.visited = 0  # JSON nodes walked, across every text of the result

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
        each located by `json_prefix` followed by its JSON path. Text the parser cannot
        nest into is kept as one plain field, so a deep sibling cannot hide it."""
        self.chars += len(text)
        parsed = self._parse(text)
        if parsed is _UNPARSEABLE:
            self.reason = self.reason or "depth"
            self.add(self.source_id, locator, text, block)
        elif isinstance(parsed, (dict, list)):
            self._walk(parsed, json_prefix, block)
        else:
            self.add(self.source_id, locator, text, block)

    def _parse(self, text: str) -> object:
        stripped = text.lstrip("\ufeff \t\r\n")
        if not stripped.startswith(("{", "[")) or len(text) > self.budget.max_bytes * 4:
            return None
        try:
            return json.loads(stripped)
        except RecursionError:
            return _UNPARSEABLE
        except ValueError:
            return None

    def _new_source(self) -> str:
        self.leaves += 1
        return f"{self.source_id}.j{self.leaves}"

    def _children(self, node: dict | list, path: str, depth: int) -> Iterator[_Item]:
        """A container's children, made one at a time. A string leaf carries its
        (source_id, block): values of different object members are separate sources;
        consecutive strings of one array share a source with consecutive blocks, so they
        join like sibling text blocks."""
        if isinstance(node, dict):
            for i, v in enumerate(node.values()):
                yield v, f"{path}.#{i}", depth + 1, None
            return
        run: str | None = None
        run_block = 0
        for i, v in enumerate(node):
            here = None
            if isinstance(v, str):
                if run is None:
                    run, run_block = self._new_source(), 0
                else:
                    run_block += 1
                here = (run, run_block)
            else:
                run = None
            yield v, f"{path}[{i}]", depth + 1, here

    def _walk(self, root: object, prefix: str, block: int) -> None:
        # Iterative, depth-first in document order; depth counts enclosing containers.
        stack: list[Iterator[_Item]] = [iter([(root, "$", 1, None)])]
        node_cap = self.budget.max_fields * 10
        while stack:
            item = next(stack[-1], None)
            if item is None:
                stack.pop()
                continue
            node, path, depth, where = item
            self.visited += 1
            if self.visited > node_cap:
                self.reason = self.reason or "field-budget"
                return
            if isinstance(node, str):
                if self.full():
                    return
                sid, blk = where or (self._new_source(), block)
                self.add(sid, prefix + path, node, blk)
            elif isinstance(node, (dict, list)):
                if depth > self.budget.max_depth:
                    self.reason = self.reason or "depth"
                    continue
                stack.append(self._children(node, path, depth))


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
                if c.full():
                    break
                if not isinstance(block, dict):
                    continue
                text, locator = block.get("text"), f"content[{i}].text"
                resource = block.get("resource")
                if not isinstance(text, str) and isinstance(resource, dict):
                    text, locator = resource.get("text"), f"content[{i}].resource.text"
                if isinstance(text, str):
                    c.text(locator, text, i, locator)
        elif isinstance(response, dict):
            # Structured content handed over already parsed: walked like parsed JSON.
            c.chars = len(json.dumps(response, ensure_ascii=False, default=str))
            c._walk(response, "response", 0)
        else:
            return undecodable()
    else:
        return undecodable()
    outcome = "partial" if c.reason else "complete"
    return Ingested(c.fields, outcome, c.reason, tool, use_id, c.chars > PREVIEW_LIMIT)
