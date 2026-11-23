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

_SENTENCE_END = re.compile(r"[.!?](?=\s|$)|\n")
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
    # The alternate reading of escape sequences, only for fields that hold one.
    alt_fields: dict[int, Field] = {}
    alt_matches: dict[int, list[Match]] = {}
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
        n = normalize(f)
        found = detect(f, n, own_tool=own_tool, deadline=deadline)
        idx = len(scanned)
        matches[idx] = list(found)
        scanned.append(f)
        remaining -= size
        complete = found.complete
        if complete and any(kind == "control" for _, _, kind in n.hidden):
            alt = replace(f, reading="alternate")
            alt_found = detect(alt, normalize(alt), own_tool=own_tool, deadline=deadline)
            alt_fields[idx] = alt
            alt_matches[idx] = list(alt_found)
            complete = alt_found.complete
        if not complete:
            reason = "time-budget"
            break
        if reason:
            break
    findings = judge(scanned, matches, state_root) if any(matches.values()) else []
    if alt_fields:
        findings = _merge_alternate(findings, scanned, matches, alt_fields, alt_matches, state_root)
    outcome = "partial" if reason else "complete"
    return ScanResult(tuple(findings), outcome, reason, len(scanned))


_RANK = {"review": 1, "high": 2}


def _merge_alternate(
    findings: list[Finding],
    scanned: list[Field],
    matches: dict[int, list[Match]],
    alt_fields: dict[int, Field],
    alt_matches: dict[int, list[Match]],
    state_root: Path,
) -> list[Finding]:
    """Primary findings, plus each alternate-reading finding whose severity is higher than
    everything the primary reading produced for the fields it touches. Both readings map
    back to original code points, so their ranges are directly comparable."""
    fields = [alt_fields.get(i, f) for i, f in enumerate(scanned)]
    merged = {i: alt_matches.get(i, m) for i, m in matches.items()}
    if not any(merged.values()):
        return findings
    best: dict[tuple[str, str], int] = {}
    for f in findings:
        for locator, _, _ in f.ranges:
            key = (f.source_id, locator)
            best[key] = max(best.get(key, 0), _RANK[f.severity])
    seen = {f.finding_id for f in findings}
    out = list(findings)
    for f in judge(fields, merged, state_root):
        top = max(best.get((f.source_id, loc), 0) for loc, _, _ in f.ranges)
        if _RANK[f.severity] > top and f.finding_id not in seen:
            out.append(f)
            seen.add(f.finding_id)
    out.sort(key=lambda f: (f.source_id, f.ranges))
    return out
