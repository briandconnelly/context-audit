"""Text fields, normalization, and the map from normalized text back to the original.

Detectors work on normalized text; findings are reported as ranges in the original
`Field.text`, so every normalized character carries the index it came from.
Hidden payloads are located and reported, never decoded.
"""

from __future__ import annotations

import re
import unicodedata
from bisect import bisect_left, bisect_right
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
_KEEP_CONTROLS = frozenset("\t\n\r\x0c")
_CSI_CAP = 32  # longest CSI sequence removed whole
_OSC_CAP = 256  # a control string with no terminator within this many characters is not swallowed
_OSC_TERM = re.compile(r"[\x07\x9c\x1b]")
_STRING_C1 = frozenset("\x90\x98\x9d\x9e\x9f")  # DCS, SOS, OSC, PM, APC
_STRING_ESC = frozenset("]PX^_")  # their ESC forms
_INVISIBLE_CATEGORIES = frozenset({"Cf", "Co", "Cn", "Cs"})
_FILLERS = frozenset("\u034f\u115f\u1160\u3164\uffa0\u2800")
_ALT_SKIP = frozenset("0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
_LINE_BREAK = re.compile(r"[\n\r\u2028\u2029]")
_LIST_ITEM = re.compile(r"(?:[-*+]|\d+[.)])(?: |$)")
_BLOCK_START = re.compile(r"(?:[-*+](?: |$)|\d+[.)](?: |$)|#|>|\||```)")
_BACKTICKS = re.compile(r"`+")
_HAS_SPACE = re.compile(r"\s")


@dataclass(frozen=True)
class Field:
    source_id: str
    surface: str
    locator: str
    text: str
    block: int = 0
    # "primary" reads escape sequences by the ECMA-48 grammar; "alternate" removes only an
    # introducer and the punctuation or digits after it, keeping the letters a model reads.
    reading: str = "primary"


@dataclass(frozen=True)
class Normalized:
    text: str
    origin: tuple[int, ...]
    hidden: tuple[tuple[int, int, str], ...]
    source: str = ""  # the original Field.text, for line structure lost by collapsing


def _removed_kind(c: str) -> str | None:
    """Kind of a character removed from the text, or None. Controls are handled apart."""
    if " " <= c < "\x7f":
        return None
    if c in _ZERO_WIDTH:
        return "zero-width"
    if c in _BIDI:
        return "bidi"
    o = ord(c)
    if 0xE0000 <= o <= 0xE007F:
        return "tag"
    if (
        c in _FILLERS
        or 0xFE00 <= o <= 0xFE0F
        or 0xE0100 <= o <= 0xE01EF
        or unicodedata.category(c) in _INVISIBLE_CATEGORIES
    ):
        return "invisible"
    return None


def _is_control(c: str) -> bool:
    o = ord(c)
    return (o < 0x20 and c not in _KEEP_CONTROLS) or 0x7F <= o <= 0x9F


class _Terminators:
    """Next control-string terminator at or after a position, found without rescanning:
    a found position is reused for every later opener before it."""

    def __init__(self, src: str) -> None:
        self.src = src
        self.pos = -1  # position of the last terminator found, or len(src) for none

    def end(self, j: int) -> int:
        """End of a control string whose body starts at j, through BEL or ST; j if none."""
        src = self.src
        if j > self.pos:
            m = _OSC_TERM.search(src, j)
            self.pos = m.start() if m else len(src)
        p = self.pos
        if p >= len(src) or p - j > _OSC_CAP:
            return j
        if src[p] != "\x1b":
            return p + 1
        return p + 2 if p + 1 < len(src) and src[p + 1] == "\\" else j


def _csi_end(src: str, j: int) -> int:
    """End of a CSI sequence whose parameters start at j (ECMA-48: parameters, then
    intermediates, then one final byte). An incomplete sequence ends where it stops."""
    k, cap = j, min(len(src), j + _CSI_CAP)
    while k < cap and "\x30" <= src[k] <= "\x3f":
        k += 1
    while k < cap and "\x20" <= src[k] <= "\x2f":
        k += 1
    return k + 1 if k < cap and "\x40" <= src[k] <= "\x7e" else k


def _primary_end(src: str, i: int, terms: _Terminators) -> int:
    """End of the control character or escape sequence starting at i, read by ECMA-48."""
    c, size = src[i], len(src)
    if c == "\x9b":
        return _csi_end(src, i + 1)
    if c in _STRING_C1:
        return terms.end(i + 1)
    if c != "\x1b" or i + 1 >= size:
        return i + 1
    nxt = src[i + 1]
    if nxt == "[":
        return _csi_end(src, i + 2)
    if nxt in _STRING_ESC:
        return terms.end(i + 2)
    k, cap = i + 1, min(size, i + 1 + _CSI_CAP)
    while k < cap and "\x20" <= src[k] <= "\x2f":
        k += 1
    return k + 1 if k < cap and "\x30" <= src[k] <= "\x7e" else k


def _alternate_end(src: str, i: int) -> int:
    """End of an introducer and the ASCII punctuation or digits after it; letters stay."""
    c = src[i]
    if c != "\x1b" and not "\x80" <= c <= "\x9f":
        return i + 1
    k, cap = i + 1, min(len(src), i + 1 + _CSI_CAP)
    while k < cap and src[k] in _ALT_SKIP:
        k += 1
    return k


def normalize(field: Field) -> Normalized:
    src = field.text
    alternate = field.reading == "alternate"
    terms = _Terminators(src)
    out: list[str] = []
    origin: list[int] = []
    hidden: list[tuple[int, int, str]] = []

    def note(start: int, end: int, kind: str) -> None:
        if hidden and hidden[-1][1] == start and hidden[-1][2] == kind:
            hidden[-1] = (hidden[-1][0], end, kind)
        else:
            hidden.append((start, end, kind))

    i, size = 0, len(src)
    gap = -1  # original index of a removed control or invisible run awaiting spacing
    while i < size:
        c = src[i]
        if _is_control(c):
            j = _alternate_end(src, i) if alternate else _primary_end(src, i, terms)
            note(i, j, "control")
            if gap < 0:
                gap = i
            i = j
            continue
        kind = _removed_kind(c)
        if kind is not None:
            note(i, i + 1, kind)
            if kind == "invisible" and gap < 0:
                gap = i
            i += 1
            continue
        j = i + 1
        while j < size and unicodedata.combining(src[j]) and _removed_kind(src[j]) is None:
            j += 1
        for ch in unicodedata.normalize("NFKC", src[i:j]):
            if gap >= 0:
                # Letters or digits on both sides join; otherwise keep one space between
                # two non-space characters, so removal never glues two words.
                prev = out[-1] if out else " "
                if prev != " " and not ch.isspace() and not (prev.isalnum() and ch.isalnum()):
                    out.append(" ")
                    origin.append(gap)
                gap = -1
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


def _run(n: Normalized, i: int) -> str:
    """The original text that the collapsed whitespace at normalized index i stood for."""
    stop = n.origin[i + 1] if i + 1 < len(n.origin) else len(n.source)
    return n.source[n.origin[i] : stop]


def _break_count(run: str) -> int:
    lines = run.count("\n") + run.count("\r") - run.count("\r\n") + run.count("\u2028")
    return lines + 2 * run.count("\u2029")  # a paragraph separator is a blank line


def line_breaks(n: Normalized) -> list[int]:
    """Normalized indexes of spaces that stand for at least one line break, found from the
    line-break characters of the source rather than by inspecting every space."""
    found: list[int] = []
    for m in _LINE_BREAK.finditer(n.source):
        i = bisect_right(n.origin, m.start()) - 1
        if i >= 0 and n.text[i] == " " and (not found or found[-1] != i):
            found.append(i)
    return found


def _block_kind(text: str, at: int) -> str:
    if text.startswith(("#", "|", "```"), at):
        return "line"  # headings, table rows and fences end at their line
    if text.startswith(">", at):
        return "quote"
    if _LIST_ITEM.match(text, at):
        return "list"
    return ""


def sentences(n: Normalized) -> list[tuple[int, int]]:
    """Spans of sentences in normalized text.

    Split at terminal punctuation followed by a space, and at line breaks that end a block:
    a blank line; a line ending in a colon; a heading, table row or fence line; a block
    quote line not followed by another; a list item not followed by an indented
    continuation; or a next line that starts a list item, heading, block quote, table row,
    or fence. A single line break inside a paragraph is a space.
    """
    spans: list[tuple[int, int]] = []
    text, size = n.text, len(n.text)
    start = 0
    block = _block_kind(text, 0)

    def close(begin: int, end: int) -> None:
        while begin < end and text[begin] == " ":
            begin += 1
        while begin < end and text[end - 1] == " ":
            end -= 1
        if begin < end:
            spans.append((begin, end))

    breaks_at = set(line_breaks(n))
    for i, c in enumerate(text):
        if c == " ":
            if i not in breaks_at:
                continue
            run = _run(n, i)
            breaks = _break_count(run)
            nxt = i + 1
            if block == "quote":
                ends = not text.startswith(">", nxt)
            elif block == "list":
                tail = run[max(run.rfind("\n"), run.rfind("\r")) + 1 :]
                ends = tail[:1] not in (" ", "\t") or bool(_BLOCK_START.match(text, nxt))
            else:
                ends = block == "line" or bool(_BLOCK_START.match(text, nxt))
            if breaks > 1 or ends or (i > 0 and text[i - 1] == ":"):
                close(start, i)
                start = nxt
                block = _block_kind(text, nxt)
        elif (
            c in ".!?"
            and (i + 1 == size or text[i + 1] == " ")
            and not text[start:i].strip().isdigit()  # "1." numbers a list item
        ):
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
