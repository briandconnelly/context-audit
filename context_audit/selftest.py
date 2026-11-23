"""Run the shipped canaries and controls through the same calls real input takes.

A canary that does not produce its expected outcome, or a control that produces a high
finding, fails the self-test for its entry point, and a failed self-test voids the
negative claims of the scan it precedes. Nothing here writes events or counters.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from context_audit.catch import BLOCK_SEPARATOR, caught
from context_audit.ingest import from_hook_event
from context_audit.scan import ScanResult, scan_fields
from context_audit.text import Field

# No canary names this tool, so own-tool exclusion cannot hide a canary's call.
SELFTEST_TOOL = "context_audit_selftest_probe"
ENTRIES = ("hook", "scan")


@dataclass(frozen=True)
class SelfTest:
    entry: str  # "hook" | "scan"
    passed: bool
    missed: tuple[str, ...]  # canary ids that did not produce their expected outcome
    flagged: tuple[str, ...]  # control ids that produced a high finding


def _load(name: str) -> list[dict]:
    text = resources.files("context_audit.corpus").joinpath(name).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def _blocks(item: dict) -> list[str]:
    return item.get("blocks") or [item["text"]]


def run_item(item: dict, state_root: Path) -> tuple[ScanResult, list[tuple[str, str]]]:
    """Scan one item through its entry point; also return its (locator, text) blocks."""
    texts = _blocks(item)
    if item["entry"] == "hook":
        if item["surface"] == "tool_error":
            event = {"hook_event_name": "PostToolUseFailure", "error": item["text"]}
        else:
            content = [{"type": "text", "text": t} for t in texts]
            event = {"hook_event_name": "PostToolUse", "tool_response": content}
        event.update(tool_name=SELFTEST_TOOL, tool_use_id="selftest")
        fields = from_hook_event(event).fields
        own_tool: str | None = SELFTEST_TOOL
    else:
        fields = [
            Field(item["id"], item["surface"], f"content[{i}].text", t, i)
            for i, t in enumerate(texts)
        ]
        own_tool = None
    result = scan_fields(fields, state_root=state_root, own_tool=own_tool)
    return result, [(f.locator, f.text) for f in fields]


def top_severity(result: ScanResult) -> str:
    sev = {f.severity for f in result.findings}
    return "high" if "high" in sev else "review" if "review" in sev else "none"


def _canary_ok(item: dict, state_root: Path) -> bool:
    result, blocks = run_item(item, state_root)
    if item["expected"] != "high":
        return top_severity(result) == item["expected"]
    joined = BLOCK_SEPARATOR.join(t for _, t in blocks)
    start = joined.find(item["span"])
    return start >= 0 and caught(blocks, (start, start + len(item["span"])), result.findings)


def run_selftest(state_root: Path) -> list[SelfTest]:
    """One result per entry point, in the order of ENTRIES."""
    canaries = _load("canaries.jsonl")
    controls = _load("controls.jsonl")
    out = []
    for entry in ENTRIES:
        missed = tuple(
            c["id"] for c in canaries if c["entry"] == entry and not _canary_ok(c, state_root)
        )
        flagged = tuple(
            c["id"]
            for c in controls
            if c["entry"] == entry and top_severity(run_item(c, state_root)[0]) == "high"
        )
        # A corpus with no canary for this entry point proves nothing, so it cannot pass.
        tested = any(c["entry"] == entry for c in canaries)
        out.append(SelfTest(entry, tested and not missed and not flagged, missed, flagged))
    return out
