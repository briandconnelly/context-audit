"""Predicates over a run's evidence. Each names which marker it looks for and where."""

from __future__ import annotations

import json
import re
from typing import Any

from probe.scenario import Evidence


def dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def hook_records(
    ev: Evidence, event: str, *, label: str | None = None, tool_use_id: str | None = None
) -> list[dict[str, Any]]:
    out = []
    for record in ev.hook_events:
        data = record.get("input", {})
        if data.get("hook_event_name") != event:
            continue
        if label is not None and record.get("label") != label:
            continue
        if tool_use_id is not None and data.get("tool_use_id") != tool_use_id:
            continue
        out.append(record)
    return out


def hook_saw(ev: Evidence, event: str, marker: str, *, label: str | None = None) -> bool:
    return any(marker in dump(r["input"]) for r in hook_records(ev, event, label=label))


def scripted_requests(ev: Evidence) -> list[dict[str, Any]]:
    return [r for r in ev.requests if r["scripted"]]


def next_request_has(ev: Evidence, marker: str) -> bool:
    """True when a model request after the first carries ``marker``."""
    return any(marker in dump(r["body"]) for r in scripted_requests(ev)[1:])


def any_request_has(ev: Evidence, marker: str) -> bool:
    return any(marker in dump(r["body"]) for r in ev.requests)


def events_seen(ev: Evidence) -> list[str]:
    return sorted({str(r.get("input", {}).get("hook_event_name")) for r in ev.hook_events})


def any_hook_event_has(ev: Evidence, marker: str) -> list[str]:
    names = set()
    for record in ev.hook_events:
        if marker in dump(record.get("input", {})):
            names.add(str(record["input"].get("hook_event_name")))
    return sorted(names)


INSTRUCTION_FILE = re.compile(r"Contents of [^\"\\\n]*CLAUDE\.md")


def instruction_file_loaded(ev: Evidence) -> bool:
    """True when a request quotes a CLAUDE.md file, or the harness reported loading one."""
    if any(INSTRUCTION_FILE.search(dump(r["body"])) for r in ev.requests):
        return True
    return bool(hook_records(ev, "InstructionsLoaded"))


def real_credentials(ev: Evidence) -> list[str]:
    return sorted({r["auth"] for r in ev.requests if r["auth"] in ("bearer", "other-key")})


def transcript_has(ev: Evidence, tool_use_id: str, marker: str) -> bool:
    if ev.transcript is None or not ev.transcript.is_file():
        return False
    text = ev.transcript.read_text(encoding="utf-8", errors="replace")
    return any(tool_use_id in line and marker in line for line in text.splitlines())
