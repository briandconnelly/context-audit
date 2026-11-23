"""The one scan entry point, shared by the hook, the CLI and the self-test.

Budgets bound the work: fields are scanned in order until the byte, field, or time
budget runs out. Nothing past the cut is scanned or reported, and the outcome is then
`partial` with the reason of the budget that ran out.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, replace
from pathlib import Path

from context_audit.features import Match, detect
from context_audit.rules import Finding, judge
from context_audit.text import Field, normalize

_SENTENCE_END = re.compile(r"[.!?](?=\s)|\n")
_WHITESPACE = re.compile(r"\s")


@dataclass(frozen=True)
class Budget:
    max_bytes: int = 150_000
    max_fields: int = 2_000
    max_depth: int = 32  # enforced by callers that walk nested content
    max_seconds: float = 0.12


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    outcome: str  # "complete" | "partial" | "not_scanned"
    reason: str  # "", "byte-budget", "field-budget", "time-budget", "undecodable", "depth"
    scanned_fields: int


def _prefix(text: str, max_bytes: int) -> str:
    """The longest prefix of text within max_bytes of UTF-8, cut at the last sentence
    boundary, else the last whitespace, else exactly at the byte limit."""
    hard = text.encode("utf-8", "surrogatepass")[:max_bytes].decode("utf-8", "ignore")
    ends = [m.end() for m in _SENTENCE_END.finditer(hard)]
    if ends:
        return hard[: ends[-1]]
    spaces = [m.start() for m in _WHITESPACE.finditer(hard)]
    return hard[: spaces[-1]] if spaces else hard


def scan_fields(
    fields: list[Field],
    *,
    state_root: Path,
    own_tool: str | None = None,
    budget: Budget = Budget(),
) -> ScanResult:
    deadline = time.monotonic() + budget.max_seconds
    remaining = budget.max_bytes
    scanned: list[Field] = []
    matches: dict[int, list[Match]] = {}
    reason = ""
    for f in fields:
        if len(scanned) >= budget.max_fields:
            reason = "field-budget"
            break
        size = len(f.text.encode("utf-8", "surrogatepass"))
        if size > remaining:
            reason = "byte-budget"
            text = _prefix(f.text, remaining)
            if not text:
                break
            f = replace(f, text=text)
            size = len(text.encode("utf-8", "surrogatepass"))
        found = detect(f, normalize(f), own_tool=own_tool, deadline=deadline)
        matches[len(scanned)] = list(found)
        scanned.append(f)
        remaining -= size
        if not found.complete:
            reason = "time-budget"
            break
        if reason:
            break
    findings = judge(scanned, matches, state_root) if any(matches.values()) else []
    outcome = "partial" if reason else "complete"
    return ScanResult(tuple(findings), outcome, reason, len(scanned))
