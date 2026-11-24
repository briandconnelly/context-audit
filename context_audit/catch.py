"""When an expected-high corpus item counts as caught. Shared by the self-test, tests, and gates.

Corpus spans label one sentence of a joined pair, so a high finding is credited when one
of its ranges overlaps the span and every range lies within the span's own sentences or a
sentence adjacent to them, adjacency running across sibling blocks.
"""

from __future__ import annotations

from collections.abc import Iterable

from context_audit.rules import Finding
from context_audit.text import Field, normalize, original_range, sentences

BLOCK_SEPARATOR = "\n\n"


def _sentence_spans(blocks: list[tuple[str, str]]) -> tuple[list[tuple[int, int]], dict[str, int]]:
    """Sentences of all blocks in order, in joined-text coordinates, and block offsets."""
    spans: list[tuple[int, int]] = []
    offsets: dict[str, int] = {}
    off = 0
    for locator, text in blocks:
        offsets[locator] = off
        n = normalize(Field("x", "tool_result", locator, text))
        spans.extend((off + a, off + b) for a, b in (original_range(n, *s) for s in sentences(n)))
        off += len(text) + len(BLOCK_SEPARATOR)
    return spans, offsets


def caught(
    blocks: list[tuple[str, str]], span: tuple[int, int], findings: Iterable[Finding]
) -> bool:
    """True when some high finding locates `span`, given as joined-text indexes.

    `blocks` are (locator, text) in block order; texts join with a blank line.
    """
    sents, offsets = _sentence_spans(blocks)
    start, end = span
    hit = [i for i, (a, b) in enumerate(sents) if a < end and start < b]
    if not hit:
        return False
    lo = sents[max(hit[0] - 1, 0)][0]
    hi = sents[min(hit[-1] + 1, len(sents) - 1)][1]
    for f in findings:
        if f.severity != "high":
            continue
        placed = [(offsets[loc] + a, offsets[loc] + b) for loc, a, b in f.ranges]
        if any(a < end and start < b for a, b in placed) and all(
            lo <= a and b <= hi for a, b in placed
        ):
            return True
    return False
