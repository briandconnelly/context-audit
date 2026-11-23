"""Text fields, normalization, and the map from normalized text back to the original.

Detectors work on normalized text; findings are reported as ranges in the original
`Field.text`, so every normalized character carries the index it came from.
Hidden payloads are located and reported, never decoded.
"""

from __future__ import annotations

import re
import unicodedata
from bisect import bisect_left
from dataclasses import dataclass

SURFACES = frozenset(
    {
        "tool_result",
        "tool_error",
        "tool_description",
        "param_description",
        "server_instructions",
        "skill",
        "command",
        "agent",
        "hook_prompt",
        "frontmatter",
    }
)

_ZERO_WIDTH = frozenset("​‌‍⁠﻿")
_BIDI = frozenset("‎‏؜‪‫‬‭‮⁦⁧⁨⁩")
_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
_ENCODED = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
_FENCE = re.compile(r"^[ \t]*```.*?(?:^[ \t]*```[^\n]*|\Z)", re.DOTALL | re.MULTILINE)
_BLOCKQUOTE = re.compile(r"^[ \t]*>[^\n]*", re.MULTILINE)
_STRAIGHT_QUOTE = re.compile(r'"[^"\n]*"')
_BACKTICKS = re.compile(r"`+")
_HAS_SPACE = re.compile(r"\s")


@dataclass(frozen=True)
class Field:
    source_id: str
    surface: str
    locator: str
    text: str
    block: int = 0


@dataclass(frozen=True)
class Normalized:
    text: str
    origin: tuple[int, ...]
    hidden: tuple[tuple[int, int, str], ...]
    source: str = ""  # the original Field.text, for line structure lost by collapsing


def _removed_kind(c: str) -> str | None:
    if c in _ZERO_WIDTH:
        return "zero-width"
    if c in _BIDI:
        return "bidi"
    if 0xE0000 <= ord(c) <= 0xE007F:
        return "tag"
    return None


def normalize(field: Field) -> Normalized:
    src = field.text
    out: list[str] = []
    origin: list[int] = []
    hidden: list[tuple[int, int, str]] = []
    i, size = 0, len(src)
    while i < size:
        kind = _removed_kind(src[i])
        if kind is not None:
            if hidden and hidden[-1][1] == i and hidden[-1][2] == kind:
                hidden[-1] = (hidden[-1][0], i + 1, kind)
            else:
                hidden.append((i, i + 1, kind))
            i += 1
            continue
        j = i + 1
        while j < size and unicodedata.combining(src[j]) and _removed_kind(src[j]) is None:
            j += 1
        for ch in unicodedata.normalize("NFKC", src[i:j]):
            if ch.isspace():
                if out and out[-1] == " ":
                    continue
                ch = " "
            out.append(ch)
            origin.append(i)
        i = j
    hidden.extend((m.start(), m.end(), "comment") for m in _COMMENT.finditer(src))
    hidden.extend((m.start(), m.end(), "encoded") for m in _ENCODED.finditer(src))
    hidden.sort()
    return Normalized("".join(out), tuple(origin), tuple(hidden), src)


def original_range(n: Normalized, start: int, end: int) -> tuple[int, int]:
    """Map a normalized span [start, end) to the original span it came from."""
    if start >= end:
        point = n.origin[start] if start < len(n.origin) else len(n.source)
        return (point, point)
    stop, src = n.origin[end - 1] + 1, n.source
    # A normalized character may come from a base character plus combining marks.
    while stop < len(src) and unicodedata.combining(src[stop]) and _removed_kind(src[stop]) is None:
        stop += 1
    return (n.origin[start], stop)


def _to_normalized(n: Normalized, start: int, end: int) -> tuple[int, int] | None:
    ns, ne = bisect_left(n.origin, start), bisect_left(n.origin, end)
    while ns < ne and n.text[ns] == " ":
        ns += 1
    while ne > ns and n.text[ne - 1] == " ":
        ne -= 1
    return (ns, ne) if ns < ne else None


def _is_line_break(n: Normalized, i: int) -> bool:
    stop = n.origin[i + 1] if i + 1 < len(n.origin) else len(n.source)
    return "\n" in n.source[n.origin[i] : stop]


def sentences(n: Normalized) -> list[tuple[int, int]]:
    """Spans of sentences in normalized text, split at terminal punctuation and newlines."""
    spans: list[tuple[int, int]] = []
    text, size = n.text, len(n.text)
    start = 0

    def close(begin: int, end: int) -> None:
        while begin < end and text[begin] == " ":
            begin += 1
        while begin < end and text[end - 1] == " ":
            end -= 1
        if begin < end:
            spans.append((begin, end))

    for i, c in enumerate(text):
        if c == " " and _is_line_break(n, i):
            close(start, i)
            start = i + 1
        elif c in ".!?" and (i + 1 == size or text[i + 1] == " "):
            close(start, i + 1)
            start = i + 1
    close(start, size)
    return spans


def _curly_quotes(src: str) -> list[tuple[int, int]]:
    """Pair each opening curly quote with the next closing one in a single pass.

    A regex here backtracks quadratically on many unclosed opening quotes.
    """
    spans: list[tuple[int, int]] = []
    opened = -1
    for i, c in enumerate(src):
        if c == "\u201c" and opened < 0:
            opened = i
        elif c == "\u201d" and opened >= 0:
            spans.append((opened, i + 1))
            opened = -1
    return spans


def _inline_code(src: str) -> list[tuple[int, int]]:
    """Inline code spans: a run of one to three backticks closed by the next equal run on
    the same line. Only spans containing whitespace count as quotation; a span that is just
    an identifier, such as `submit_feedback`, is how a tool is named, not quoted text.

    Linear: each run is paired through a precomputed next-run-of-equal-length index.
    """
    spans: list[tuple[int, int]] = []
    for line_match in re.finditer(r"[^\n]+", src):
        lo, hi = line_match.span()
        runs = [(m.start(), m.end()) for m in _BACKTICKS.finditer(src, lo, hi)]
        nxt = [-1] * len(runs)
        last: dict[int, int] = {}
        for k in range(len(runs) - 1, -1, -1):
            width = runs[k][1] - runs[k][0]
            nxt[k] = last.get(width, -1)
            last[width] = k
        k = 0
        while k < len(runs):
            width, j = runs[k][1] - runs[k][0], nxt[k]
            if width <= 3 and j >= 0:
                start, end = runs[k][0], runs[j][1]
                if _HAS_SPACE.search(src, runs[k][1], runs[j][0]):
                    spans.append((start, end))
                k = j + 1
            else:
                k += 1
    return spans


def fenced(n: Normalized) -> list[tuple[int, int]]:
    """Normalized spans of quoted material: code fences, inline code, block quotes, quotations."""
    src = n.source
    found: list[tuple[int, int]] = []  # sorted, non-overlapping original spans
    groups = (
        [m.span() for m in _FENCE.finditer(src)],
        _inline_code(src),
        [m.span() for m in _BLOCKQUOTE.finditer(src)],
        sorted([m.span() for m in _STRAIGHT_QUOTE.finditer(src)] + _curly_quotes(src)),
    )
    for matches in groups:
        taken = list(found)
        starts = [s for s, _ in taken]
        for m_start, m_end in matches:
            # Only the last earlier span starting before this match can overlap it.
            k = bisect_left(starts, m_end) - 1
            if k >= 0 and taken[k][1] > m_start:
                continue
            found.append((m_start, m_end))
        found.sort()
    spans = (_to_normalized(n, s, e) for s, e in found)
    return [s for s in spans if s is not None]
