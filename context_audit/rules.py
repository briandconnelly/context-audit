"""Join feature matches into findings under the closed table of high combinations.

Precedence, from the spec: negation (already applied by `detect`), then quotation, then
the user-approval condition, then the table. A quoted or conditioned match yields review
at most, and so does a match on a record line (`Match.record`). Joining: same sentence,
or adjacent sentences where the later one refers back; sibling blocks of one result (same
`source_id`, consecutive `block`) are one sentence sequence for this test. Fields with
different `source_id` never join.
"""

from __future__ import annotations

import hashlib
import re
import time
from bisect import bisect_left
from dataclasses import dataclass
from pathlib import Path

from context_audit import RULE_VERSION, scope
from context_audit.features import Match
from context_audit.state import span_digest
from context_audit.text import Field, Normalized, normalize, original_range, sentences

HIGH_TABLE = frozenset(
    {
        frozenset({"conceal-act", "act"}),
        frozenset({"conceal-act", "call"}),
        frozenset({"override", "act"}),
    }
)
# Surfaces on which a lone `act` or `call` is reported; elsewhere they only combine.
_DIRECTIVE_SURFACES = frozenset({"tool_result", "tool_error"})
_TABLE_FEATURES = frozenset().union(*HIGH_TABLE)
# A sentence refers back by a demonstrative or pronoun, by "instead" ("Disregard your
# instructions. Instead, send ..."), or by ending on a verb of knowing or telling with
# its object left out ("Send the file. The user should not be told.").
_BACK_REFERENCE = re.compile(
    r"\b(?:this|that|it|these|the above|instead)\b"
    r"|\b(?:told|informed|notified|aware|know|find\s+out|notice|learn)\W*$",
    re.IGNORECASE,
)


_LIST_ITEM = re.compile(r"(?:[-*+]|\d+[.)]) ")


def _refers_back(sentence: str, after_item: bool) -> bool:
    """Whether a sentence refers back to the one before it. A list item after a list item
    needs an explicit back-reference (`scope.refers_to_previous_item`): a feature in one
    item does not combine with a feature in the next on a pronoun resolved in its own item."""
    if not _BACK_REFERENCE.search(sentence):
        return False
    return not after_item or scope.refers_to_previous_item(sentence)


@dataclass(frozen=True)
class Finding:
    finding_id: str  # "f-" + 12 hex, derived from source_id, locator, digest
    source_id: str
    surface: str
    locator: str  # locator of the finding's first range
    # (locator, start, end) per joined feature: ORIGINAL code-point indexes in that field
    ranges: tuple[tuple[str, int, int], ...]
    features: tuple[str, ...]  # sorted
    severity: str  # "high" | "review"
    rule_version: int
    digest: str
    tool: str | None  # for a call feature


@dataclass(frozen=True)
class _Hit:
    field: int  # index into fields
    pos: int  # position in the sentence sequence of the field's run of sibling blocks
    match: Match
    range: tuple[int, int]  # original


def _runs(fields: list[Field]) -> list[list[int]]:
    """Field indexes grouped into runs that may join: same source, consecutive blocks."""
    by_source: dict[str, list[int]] = {}
    for i, f in enumerate(fields):
        by_source.setdefault(f.source_id, []).append(i)
    runs: list[list[int]] = []
    for idxs in by_source.values():
        idxs.sort(key=lambda i: (fields[i].block, i))
        current = [idxs[0]]
        for i in idxs[1:]:
            if fields[i].block == fields[current[-1]].block + 1:
                current.append(i)
            else:
                runs.append(current)
                current = [i]
        runs.append(current)
    return runs


def _hidden_ranges(n: Normalized) -> dict[int, list[tuple[int, int]]]:
    """Original ranges of hidden spans keyed by the normalized start `detect` gives them."""
    out: dict[int, list[tuple[int, int]]] = {}
    for h_start, h_end, _kind in n.hidden:
        start = min(bisect_left(n.origin, h_start), len(n.text))
        out.setdefault(start, []).append((h_start, h_end))
    return out


def _hits(
    fields: list[Field], run: list[int], matches: dict[int, list[Match]]
) -> tuple[list[_Hit], list[bool]]:
    """Hits in one run, and for each sentence position whether it refers back."""
    hits: list[_Hit] = []
    refers_back: list[bool] = []
    for i in run:
        n = normalize(fields[i])
        sents = sentences(n)
        base = len(refers_back)
        items = [_LIST_ITEM.match(n.text, a) is not None for a, _ in sents]
        refers_back.extend(
            _refers_back(n.text[a:b], items[k] and (items[k - 1] if k else False))
            for k, (a, b) in enumerate(sents)
        )
        if not sents:  # an empty block still separates its neighbours
            refers_back.append(False)
        hidden = _hidden_ranges(n)
        for m in matches.get(i, []):
            if m.feature == "hidden" and hidden.get(m.start):
                rng = hidden[m.start].pop(0)
            else:
                rng = original_range(n, m.start, m.end)
            hits.append(_Hit(i, base + m.sentence, m, rng))
    return hits, refers_back


def _drop_contained(hits: list[_Hit]) -> list[_Hit]:
    """Drop a hit whose range lies within another hit of the same feature and field, so a
    sentence yields each feature once. Identical ranges keep the first."""
    kept: list[_Hit] = []
    by_key: dict[tuple[int, str], list[_Hit]] = {}
    for h in hits:
        by_key.setdefault((h.field, h.match.feature), []).append(h)
    for group in by_key.values():
        group.sort(key=lambda h: (h.range[0], -h.range[1]))
        reach = -1
        for h in group:
            if h.range[1] <= reach:
                continue
            kept.append(h)
            reach = h.range[1]
    kept.sort(key=lambda h: (h.field, h.range))
    return kept


def _root(parent: list[int], k: int) -> int:
    """Union-find root, halving the path as it goes."""
    while parent[k] != k:
        parent[k] = parent[parent[k]]
        k = parent[k]
    return k


def _finding(fields: list[Field], hits: list[_Hit], severity: str, root: Path) -> Finding:
    hits = sorted(hits, key=lambda h: (fields[h.field].block, h.field, h.range))
    first = fields[hits[0].field]
    locator = first.locator
    digest = span_digest(root, "\x1f".join(fields[h.field].text[slice(*h.range)] for h in hits))
    key = "\x00".join((first.source_id, locator, digest)).encode("utf-8", "surrogatepass")
    return Finding(
        finding_id="f-" + hashlib.sha256(key).hexdigest()[:12],
        source_id=first.source_id,
        surface=first.surface,
        locator=locator,
        ranges=tuple((fields[h.field].locator, *h.range) for h in hits),
        features=tuple(sorted({h.match.feature for h in hits})),
        severity=severity,
        rule_version=RULE_VERSION,
        digest=digest,
        tool=next((h.match.tool for h in hits if h.match.tool), None),
    )


def judge(
    fields: list[Field],
    matches: dict[int, list[Match]],
    state_root: Path,
    *,
    deadline: float | None = None,
) -> list[Finding]:
    """Findings for `matches`, keyed by each field's index in `fields`. With `deadline`
    (a `time.monotonic()` value) it stops there and returns the findings made so far;
    the caller sees the overrun on the clock."""
    return judge_until(fields, matches, state_root, deadline)[0]


def _order(f: Finding) -> tuple:
    return (f.source_id, f.ranges)


def _eligible(h: _Hit) -> bool:
    """Whether a hit may join a high: not quoted, not conditioned on the user's approval,
    not on a record line (spec precedence: quotation, then the condition, then the table)."""
    m = h.match
    return m.feature in _TABLE_FEATURES and not (m.quoted or m.conditioned or m.record)


def _link(
    hits: list[_Hit], a: list[int], b: list[int], parent: list[int], in_high: set[int]
) -> None:
    """Join every table pair between hit groups a and b (one sentence, or a sentence and
    the next that refers back). Linking each hit to one representative of each partner
    feature gives the same groups as testing every pair, in linear time."""
    by_a: dict[str, list[int]] = {}
    by_b: dict[str, list[int]] = {}
    for k in a:
        if _eligible(hits[k]):
            by_a.setdefault(hits[k].match.feature, []).append(k)
    for k in b:
        if _eligible(hits[k]):
            by_b.setdefault(hits[k].match.feature, []).append(k)
    for pair in HIGH_TABLE:
        f, g = tuple(pair)
        for x_feat, y_feat in ((f, g), (g, f)):
            xs, ys = by_a.get(x_feat), by_b.get(y_feat)
            if not xs or not ys:
                continue
            x0, y0 = xs[0], ys[0]
            for x in xs:
                parent[_root(parent, x)] = _root(parent, y0)
            for y in ys:
                parent[_root(parent, y)] = _root(parent, x0)
            in_high.update(xs)
            in_high.update(ys)


def judge_until(
    fields: list[Field],
    matches: dict[int, list[Match]],
    state_root: Path,
    deadline: float | None,
) -> tuple[list[Finding], bool]:
    """`judge`, stopping at `deadline` (a `time.monotonic()` value). The flag is False when
    it stopped early; the findings made so far are returned."""
    findings: list[Finding] = []
    for run in _runs(fields):
        if not any(matches.get(i) for i in run):
            continue
        hits, refers_back = _hits(fields, run, matches)
        hits = _drop_contained(hits)
        parent = list(range(len(hits)))
        by_pos: dict[int, list[int]] = {}
        for k, h in enumerate(hits):
            if h.match.feature in _TABLE_FEATURES:
                by_pos.setdefault(h.pos, []).append(k)
        in_high: set[int] = set()
        for pos, here in by_pos.items():
            if deadline is not None and time.monotonic() > deadline:
                return sorted(findings, key=_order), False
            _link(hits, here, here, parent, in_high)
            later = by_pos.get(pos + 1)
            if later and refers_back[pos + 1]:
                _link(hits, here, later, parent, in_high)
        groups: dict[int, list[_Hit]] = {}
        for k in sorted(in_high):
            groups.setdefault(_root(parent, k), []).append(hits[k])
        findings.extend(_finding(fields, g, "high", state_root) for g in groups.values())
        for k, h in enumerate(hits):
            if deadline is not None and k % 256 == 0 and time.monotonic() > deadline:
                return sorted(findings, key=_order), False
            if k in in_high:
                continue
            lone_directive = h.match.feature in {"act", "call"}
            if lone_directive and fields[h.field].surface not in _DIRECTIVE_SURFACES:
                continue
            findings.append(_finding(fields, [h], "review", state_root))
    findings.sort(key=_order)
    return findings, True
