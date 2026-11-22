"""Probe hook: record the event input, then optionally emit one configured output.

Run by absolute path under ``python3 -I``, so it puts its own repository root on the path.
Field names come from docs/research/2026-11-22-hook-fields.md.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from probe import markers  # noqa: E402

FOLLOW_ON = "mcp__probe__follow_on"
OUTPUTS: dict[str, dict[str, Any]] = {
    "message": {"systemMessage": f"Probe hook message {markers.HOOK_MESSAGE}"},
    "ask": {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": "Probe gate: confirm this call",
        }
    },
}


def _swap(value: Any) -> Any:
    """Replace TEXT_RESULT in every string of a JSON value, keeping its shape."""
    if isinstance(value, str):
        return value.replace(markers.TEXT_RESULT, markers.REPLACEMENT)
    if isinstance(value, list):
        return [_swap(item) for item in value]
    if isinstance(value, dict):
        return {key: _swap(item) for key, item in value.items()}
    return value


def output_for(mode: str, event: dict[str, Any]) -> dict[str, Any] | None:
    name = event.get("hook_event_name")
    if mode == "message":
        return OUTPUTS["message"]
    if mode == "ask":
        if name == "PreToolUse" and event.get("tool_name") == FOLLOW_ON:
            return OUTPUTS["ask"]
        return None
    if mode == "replace" and name == "PostToolUse":
        original = event.get("tool_response")
        swapped = _swap(original)
        if swapped == original:
            return None
        return {
            "hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": swapped}
        }
    return None


def main() -> None:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
        if not isinstance(event, dict):
            event = {"_raw": raw}
    except ValueError:
        event = {"_raw": raw}
    log = os.environ.get("PROBE_HOOK_LOG")
    if log:
        record = {"label": os.environ.get("PROBE_HOOK_LABEL", ""), "input": event}
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    out = output_for(os.environ.get("PROBE_HOOK_MODE", "record"), event)
    if out is not None:
        sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
