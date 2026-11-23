"""The one scan entry point, shared by the hook, the CLI and the self-test.

Budgets bound the work: fields are scanned in order until the byte, field, or time
budget runs out. Nothing past the cut is scanned or reported, and the outcome is then
`partial` with the reason of the budget that ran out. Findings made before a cut are kept:
judging has its own allowance (`judge_seconds`), so a detection overrun never leaves it
without time.
"""

from __future__ import annotations

import re
import time
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, replace
from pathlib import Path

from context_audit.features import Match, detect
from context_audit.rules import HIGH_TABLE, Finding, judge_until
from context_audit.text import Field, has_second_reading, normalize

_SENTENCE_END = re.compile(r"[.!?](?=\s|$)|\n")
_WHITESPACE = re.compile(r"\s")


@dataclass(frozen=True)
class Budget:
    max_bytes: int = 150_000
    max_fields: int = 2_000
    max_depth: int = 32  # enforced by callers that walk nested content
    max_seconds: float = 0.12  # detection
    # Judging, after detection; it is linear in the matches. None: a quarter of max_seconds.
    judge_seconds: float | None = None

    @property
    def judge_allowance(self) -> float:
        return self.max_seconds / 4 if self.judge_seconds is None else self.judge_seconds


# The static scan (CLI `scan`) has no latency constraint: a larger time budget per source,
# the same byte rule.
STATIC_BUDGET = Budget(max_seconds=2.0, judge_seconds=1.0)


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
    # The alternate reading, only for fields whose text can be read a second way.
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
        if complete and has_second_reading(n):
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
    if not reason and time.monotonic() > deadline:
        reason = "time-budget"
    # Judging gets its own deadline, so what detection found before a cut is still judged.
    judge_deadline = time.monotonic() + budget.judge_allowance
    findings: list[Finding] = []
    judged = True
    if any(matches.values()):
        findings, judged = judge_until(scanned, matches, state_root, judge_deadline)
    if alt_fields and judged:
        fields = [alt_fields.get(i, f) for i, f in enumerate(scanned)]
        merged = {i: alt_matches.get(i, m) for i, m in matches.items()}
        if any(merged.values()):
            alt, judged = judge_until(fields, merged, state_root, judge_deadline)
            findings = _merge_alternate(findings, alt)
    # A scan whose judging overran is never reported complete; its findings so far stand.
    if not reason and (not judged or time.monotonic() > judge_deadline):
        reason = "time-budget"
    outcome = "partial" if reason else "complete"
    return ScanResult(tuple(findings), outcome, reason, len(scanned))


_RANK = {"review": 1, "high": 2}
# Features a high finding is joined from. A lone finding of one of these is redundant once
# the other reading reports a high finding over the same text.
_JOINABLE = frozenset().union(*HIGH_TABLE)
_Key = tuple[str, str]  # source_id, locator: one field
_Cover = dict[_Key, tuple[list[int], list[int]]]  # starts, and the furthest end so far


def _cover(findings: list[Finding], min_rank: int) -> _Cover:
    """The ranges of findings at or above a severity, indexed per field for range queries:
    sorted starts, and beside each the furthest end among ranges up to it."""
    spans: dict[_Key, list[tuple[int, int]]] = {}
    for f in findings:
        if _RANK[f.severity] >= min_rank:
            for locator, start, end in f.ranges:
                spans.setdefault((f.source_id, locator), []).append((start, end))
    cover: _Cover = {}
    for key, ranges in spans.items():
        ranges.sort()
        reach: list[int] = []
        for _, end in ranges:
            reach.append(max(end, reach[-1]) if reach else end)
        cover[key] = ([start for start, _ in ranges], reach)
    return cover


def _overlaps(cover: _Cover, f: Finding) -> bool:
    """Whether any range of f overlaps a covered range in the same field."""
    for locator, start, end in f.ranges:
        starts, reach = cover.get((f.source_id, locator), ((), ()))
        k = bisect_left(starts, end) - 1  # the last covered range starting before `end`
        if k >= 0 and reach[k] > start:
            return True
    return False


def _inside(cover: _Cover, f: Finding) -> bool:
    """Whether every range of f lies inside a covered range in the same field."""
    for locator, start, end in f.ranges:
        starts, reach = cover.get((f.source_id, locator), ((), ()))
        k = bisect_right(starts, start) - 1  # the last covered range starting at or before
        if k < 0 or reach[k] < end:
            return False
    return True


def _is_hidden(f: Finding) -> bool:
    return f.features == ("hidden",)


def _merge_alternate(primary: list[Finding], alternate: list[Finding]) -> list[Finding]:
    """Primary findings, plus each alternate-reading finding that no primary finding of equal
    or higher severity overlaps. Both readings report original code points, so their ranges
    compare directly, field by field. Hidden runs are compared only with hidden runs: the
    run that makes the readings differ always touches the words it was placed against, and
    must not mask them. A primary finding of lower severity that lies inside an added
    finding, and has only features a high finding is joined from, is dropped: the added
    finding already reports it."""
    at_least = {
        (kind, rank): _cover([f for f in primary if _is_hidden(f) == kind], rank)
        for kind in (False, True)
        for rank in set(_RANK.values())
    }
    added = [f for f in alternate if not _overlaps(at_least[_is_hidden(f), _RANK[f.severity]], f)]
    if not added:
        return primary
    above = {rank: _cover(added, rank + 1) for rank in set(_RANK.values())}
    out = [
        f
        for f in primary
        if not (_JOINABLE.issuperset(f.features) and _inside(above[_RANK[f.severity]], f))
    ]
    out.extend(added)
    out.sort(key=lambda f: (f.source_id, f.ranges))
    return out
