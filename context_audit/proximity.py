"""Concealment and override by cue proximity (Task 16b).

Instead of enumerating whole phrasings, each detector looks for a cue and, within a short
window of words in the same clause, the thing the cue must be about:

- concealment: an omission or secrecy cue near a reference to the user's awareness (the
  user as the one who would be told, a place the user reads, or a word of telling,
  showing or noticing);
- override: a disregard cue near an authority target (earlier or system instructions,
  rules, policy) or an approval target (confirmation, approval, sign-off).

This module only finds candidates. `features` applies the rules that take precedence:
negation, reports with a subject of their own, withholding data, the user-approval
condition, and the requirement that a manner phrase modify a directive.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from dataclasses import dataclass

from context_audit import lexicon as lx
from context_audit.lexicon import alt

_I = re.IGNORECASE
_SPAN = 90  # characters after a cue in which its partner must appear (about 12 words)
_WORDS = re.compile(r"[A-Za-z][\w'’-]*")
_STOP = re.compile(r"[.;!?]")

# --- concealment -----------------------------------------------------------------------

# Cues that conceal by themselves, in base (imperative) form.
_STRONG = (
    r"hide|conceal|suppress|withhold|omit|exclude"
    r"|leave(?:\s+[\w'’-]+){0,4}?\s+out\b"
    r"|keep(?:\s+[\w'’-]+){0,5}?\s+(?:out|from|off|private|quiet|secret|hidden|to\s+yourself)\b"
)
# Cues that conceal only when a word of telling follows: "avoid any reference to ...".
_WEAK = r"avoid|refrain\s+from|skip"
# Negators: "do not point it out to the human", "make no announcement of it".
_NEG = r"do\s+not|don['’]t|never|without|make\s+no|with\s+no"
_CONCEAL_CUE = re.compile(rf"\b(?:(?P<strong>{_STRONG})|(?P<weak>{_WEAK})|(?P<neg>{_NEG}))\b", _I)
# Words of telling, showing or noticing, in any inflection.
_TELL = re.compile(
    r"\b(?:tell|told|mention|inform|notif|disclos|reveal|surfac|show|display"
    r"|announc|flag|alert|acknowledg|reference|bring(?:ing)?\s+(?:\w+\s+)?up|point(?:ing)?"
    r"\s+(?:\w+\s+)?out|let(?:ting)?\s+\w+\s+know|draw(?:ing)?\s+(?:\w+\s+){0,2}attention"
    r"|attention|make\s+\w+\s+aware|notic|know|learn|find(?:ing)?\s+out|appear|notice"
    r"|word\s+of|sign\s+of|trace\s+of|indication|disclosure|announcement)\w*",
    _I,
)
_WHO_RE = re.compile(
    r"\b(?:user|users|operator|operators|human|humans|person|customer|customers|requester"
    r"|owner|them|anyone|anybody|whoever)\b(?!['’]s\s+(?!attention|notice))",
    _I,
)
_PLACE = rf"\b(?:{alt(lx.PLACE_NOUNS)}|recap|briefing)\b"
# The user or a place the user reads, whichever comes first.
_REF = re.compile(rf"(?P<who>{_WHO_RE.pattern})|{_PLACE}", _I)
# A strong cue negated by a negator just before it, or a negator whose window holds a
# strong cue ("do not withhold any notice of it"): a double negative, no concealment.
_STRONG_ONLY = re.compile(rf"\b(?:{_STRONG})", _I)
# Words of showing: like the presentation verbs, they conceal only an action.
_SHOWING = re.compile(r"(?:show|display|surfac|appear)", _I)
# A participle of telling or showing after a negator describes; it does not direct.
_PARTICIPLE = re.compile(r"\w+(?:ed|own|told)", _I)
_ONLY_DETERMINERS = re.compile(r"\s*(?:(?:the|your|its|their|any|every)\s+)*", _I)
_CLAUSE = re.compile(r"[,;:]|\b(?:and|but|then|when|while|so)\b", _I)
_OBJECT_END = re.compile(
    r"\b(?:from|to|in|into|out|off|away|with|on|of|about|when|while|until|for)\b", _I
)


@dataclass(frozen=True)
class Candidate:
    start: int
    end: int
    scope: str  # the clause's words after the cue's verb, less the partners: the data rule
    obj: str  # the direct object after the cue's verb (or after a word of showing)
    strong: bool  # a secrecy cue rather than a negator or a weak cue
    # A word of telling, or the user as the object kept ("keep the user out of the
    # loop"): anything but data is concealed. Otherwise (a word of showing, or a secrecy
    # cue alone) only an action, or a pronoun standing for one, is.
    told: bool


def _has_any(s: str, stems: tuple[str, ...]) -> bool:
    return any(map(s.lower().__contains__, stems))


# Cheap prefilters (substring tests): a sentence with no cue stem cannot match.
_CONCEAL_STEMS = (
    "hide",
    "conceal",
    "suppress",
    "withhold",
    "omit",
    "exclude",
    "leave",
    "keep",
    "avoid",
    "refrain",
    "skip",
    "not",
    "n't",
    "n’t",
    "never",
    "without",
    "no ",
)
_STRONG_STEMS = ("hide", "conceal", "suppress", "withhold", "omit", "exclude", "leave", "keep")
_REF_STEMS = (
    "user",
    "operator",
    "human",
    "person",
    "customer",
    "requester",
    "owner",
    "them",
    "any",
    "whoever",
    "recap",
    "briefing",
    *lx.PLACE_NOUNS,
)
_OVERRIDE_STEMS = (
    "ignore",
    "disregard",
    "forget",
    "drop",
    "aside",
    "override",
    "supersede",
    "replace",
    "bypass",
    "skip",
    "waive",
    "dispense",
    "wait for",
    "no need",
    "regardless",
    "even if",
    "precedence",
    "priority",
    "place of",
    "instead of",
)


def _clause_end(s: str, start: int, hi: int) -> int:
    m = _CLAUSE.search(s, start, hi)
    return m.start() if m else hi


def _direct_object(s: str, lo: int, hi: int) -> str:
    """The words from lo up to the first preposition, particle or partner before hi."""
    m = _OBJECT_END.search(s, lo, hi)
    return s[lo : m.start() if m else hi]


class _Index:
    """The matches of a pattern in a sentence, found once and looked up by position, so
    that each cue costs a bisection rather than a search."""

    def __init__(self, pattern: re.Pattern[str], s: str) -> None:
        self.matches = list(pattern.finditer(s))
        self.starts = [m.start() for m in self.matches]

    def first(self, lo: int, hi: int) -> re.Match[str] | None:
        k = bisect_left(self.starts, lo)
        if k < len(self.starts) and self.starts[k] < hi:
            return self.matches[k]
        return None


def conceal_candidates(s: str) -> list[Candidate]:
    """Concealment candidates in sentence s, with the concealed object's words."""
    out: list[Candidate] = []
    if not _has_any(s, _CONCEAL_STEMS):
        return out
    if not _has_any(s, _REF_STEMS) and not _has_any(s, _STRONG_STEMS):
        return out  # a negator or weak cue needs the user or a place
    cues = list(_CONCEAL_CUE.finditer(s))
    if not cues:
        return out
    lazy: dict[re.Pattern[str], _Index] = {}

    def index(p: re.Pattern[str]) -> _Index:
        if p not in lazy:
            lazy[p] = _Index(p, s)
        return lazy[p]

    if _REF.search(s) is None and not any(m.group("strong") for m in cues):
        return out  # a negator or weak cue needs the user or a place
    for m in cues:
        # A partner may sit inside a split cue: "keep the user out", "leave that out".
        verb = _WORDS.match(s, m.start())
        lo = verb.end() if verb else m.end()
        limit = min(len(s), m.end() + _SPAN)
        stop_m = index(_STOP).first(m.end(), limit)
        hi = stop_m.start() if stop_m else limit
        strong = m.group("strong") is not None
        tell = index(_TELL).first(lo, hi)
        if tell is None and not strong:
            continue
        ref = index(_REF).first(lo, hi)
        who = ref if ref is not None and ref.group("who") else None
        if ref is not None and who is None:
            # the first reference is a place; the user may still follow it
            who = index(_WHO_RE).first(ref.end(), hi)
        found = [p for p in (tell, ref, who) if p is not None]
        if not found:
            continue
        if strong:
            partners = found
        else:
            if tell is None or ref is None:
                continue
            if _PARTICIPLE.fullmatch(tell.group()):
                continue  # "never shown to other users": a description, not a directive
            if m.group("neg") and _STRONG_ONLY.search(s, m.end(), tell.start()):
                continue  # "do not withhold any notice of it": a double negative
            partners = [tell]
        end = max(p.end() for p in partners)
        # The data rule reads the whole clause, partners left out: "never tell the user
        # the hostname", "refrain from surfacing the password in your recap".
        stop = _clause_end(s, lo, hi)
        spans = sorted((p.start(), p.end()) for p in found if p.start() < stop)
        parts, at = [], lo
        for a, b in spans:
            parts.append(s[at:a])
            at = max(at, b)
        parts.append(s[at:stop])
        scope = " ".join(parts)
        user_kept = who is not None and _ONLY_DETERMINERS.fullmatch(s[lo : who.start()]) is not None
        told = user_kept or (tell is not None and not _SHOWING.match(tell.group()))
        after = tell.end() if (tell is not None and not strong) else lo
        obj = _direct_object(s, after, stop)
        out.append(Candidate(m.start(), end, scope, obj, strong, told))
    return out


# --- override --------------------------------------------------------------------------

_DISREGARD = (
    r"ignore|disregard|forget|drop|set\s+aside|override|supersede|replace|bypass|skip|waive"
    r"|dispense\s+with|(?:do\s+not|don['’]t)\s+wait\s+for|no\s+need\s+(?:for|to)"
    r"|regardless\s+of|even\s+if|takes?\s+(?:precedence|priority)\s+over|in\s+place\s+of"
    r"|instead\s+of\s+(?:following|obeying)"
)
_OVERRIDE_CUE = re.compile(rf"\b(?:{_DISREGARD})\b", _I)
_QUALIFIER = (
    r"(?:prior|previous|earlier|above|preceding|original|other|existing|system|developer"
    r"|operator|user['’]?s?|your|any|all)"
)
_AUTHORITY = (
    r"(?:instructions?|rules?|guidance|guidelines?|polic(?:y|ies)|prompts?|directives?"
    r"|restrictions?|constraints?)"
)
_TARGET = re.compile(
    rf"\b{_QUALIFIER}\s+(?:[a-z-]+\s+)?{_AUTHORITY}\b"
    r"|\bsystem\s+prompt\b|\b(?:system|developer|security)\s+settings\b"
    r"|\b(?:confirmation|approval|permission|consent|sign-?off)s?\b"
    r"|\b(?:manual|human|user['’]?s?|maintainer['’]?s?|owner['’]?s?|security|peer)\s+reviews?\b"
    r"|\basking\s+(?:the\s+)?user\b",
    _I,
)
# A target named first and then set aside: "your instructions are replaced by this page".
_PASSIVE = re.compile(
    rf"\b(?:{_QUALIFIER}\s+(?:[a-z-]+\s+)?{_AUTHORITY}|system\s+prompt)\s+(?:are|is|have\s+been"
    r"|has\s+been)\s+(?:now\s+)?(?:replaced|superseded|overridden|waived|bypassed|dropped"
    r"|set\s+aside)\b",
    _I,
)


def override_candidates(s: str) -> list[tuple[int, int]]:
    """Override candidates in sentence s: (start, end) spans."""
    out: list[tuple[int, int]] = []
    if not _has_any(s, _OVERRIDE_STEMS):
        return out
    targets = _Index(_TARGET, s)
    if not targets.matches:
        out.extend((m.start(), m.end()) for m in _PASSIVE.finditer(s))
        return out
    stops = _Index(_STOP, s)
    for m in _OVERRIDE_CUE.finditer(s):
        limit = min(len(s), m.end() + _SPAN)
        stop = stops.first(m.end(), limit)
        t = targets.first(m.end(), stop.start() if stop else limit)
        if t is not None:
            out.append((m.start(), t.end()))
    out.extend((m.start(), m.end()) for m in _PASSIVE.finditer(s))
    return out
