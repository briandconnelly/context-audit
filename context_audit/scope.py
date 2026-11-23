"""Whether a cue belongs to the directive it would combine with (Task 18).

Instructional prose describes how software misbehaves ("X silently drops Y"), names
configuration ("overrides", "`confirm=true`") and lists things to look for. A cue in such
text sits near an imperative without modifying it. These tests decide, by form, whether
a cue's scope is the directive act itself:

- a manner cue (silently, without telling ...) must not be in a relative clause or modify
  a finite verb with a subject of its own (`manner_on_directive`);
- "in the background", "behind the scenes" and "under the hood" conceal only together
  with a user-awareness cue in the same clause (`background_conceals`);
- a list item that is a noun phrase with a relative clause is not an imperative
  (`noun_phrase_item`);
- an override cue must be a verb governing its target: not a noun, not separated from the
  target by a finite verb, and the target not a verb, a backticked name or a `name=value`
  (`override_governs`);
- a list item refers back to the previous item only by a pronoun with no antecedent in its
  own item, or by a demonstrative (`refers_to_previous_item`).
"""

from __future__ import annotations

import re

_I = re.IGNORECASE

# A relative pronoun, or "that" opening a clause with its own verb ("that quietly
# rewrites", "that is").
_RELATIVE = re.compile(
    r"\b(?:which|who|whom|whose)\b"
    r"|\bthat\s+(?:[a-z]+ly\s+)?(?:[a-z]+(?:s|ed)|is|are|was|were|has|have|had|can|could"
    r"|will|would|may|might|must|should|does|do|did)\b",
    _I,
)
# Words ending in "s" or "ed" that are not finite verbs after a manner adverb.
_NOT_FINITE = frozenset(
    re.findall(
        r"\S+",
        "as us this its thus plus across unless towards afterwards always perhaps less"
        " indeed instead need",
    )
)


def _finite_after(s: str, end: int) -> bool:
    m = re.match(r"\s+([A-Za-z]+)\b", s[end:])
    if m is None:
        return False
    w = m.group(1).lower()
    if w in _NOT_FINITE:
        return False
    if w in ("is", "are", "was", "were", "has", "have", "had"):
        return True
    if w.endswith("ed") and not w.endswith("eed"):
        return True
    return w.endswith("s") and not w.endswith(("ss", "us", "is"))


def manner_on_directive(s: str, pos: int, end: int | None, directives: list[int]) -> bool:
    """Whether the manner cue s[pos:end] can modify one of `directives` (sentence-relative
    starts of directive acts or calls before or in its clause): no relative pronoun
    between the nearest such directive and the cue, and the cue does not lead a finite
    verb of its own (checked when `end`, the end of an adverb, is given)."""
    if end is not None and _finite_after(s, end):
        return False
    before = [d for d in directives if d < pos]
    if not before:
        return True  # the directive follows the cue in its clause: "Quietly send ..."
    return _RELATIVE.search(s, max(before), pos) is None


_BACKGROUND = re.compile(r"in\s+the\s+background|behind\s+the\s+scenes|under\s+the\s+hood", _I)
_AWARE = re.compile(
    r"\b(?:tell|told|telling|mention\w*|inform\w*|notif\w*|alert\w*|aware|know\w*|notic\w*"
    r"|disclos\w*|reveal\w*|announc\w*)\b",
    _I,
)
_WHO = re.compile(r"\b(?:user|users|human|operator|owner|customer|anyone|anybody)\b", _I)
_CLAUSE_STOP = re.compile(r"[.;:!?]|,\s*(?:but|then|so)\b|\bthen\b", _I)


def is_background(phrase: str) -> bool:
    """Whether a manner phrase is one that by itself only says where work runs."""
    return _BACKGROUND.fullmatch(phrase) is not None


def background_conceals(s: str, pos: int, end: int) -> bool:
    """Whether "in the background" (or the like) at s[pos:end] has a user-awareness cue in
    its clause: a word of telling or knowing and the user."""
    lo = 0
    for m in _CLAUSE_STOP.finditer(s, 0, pos):
        lo = m.end()
    stop = _CLAUSE_STOP.search(s, end)
    hi = stop.start() if stop else len(s)
    return _AWARE.search(s, lo, hi) is not None and _WHO.search(s, lo, hi) is not None


# "Retry loops that ...", "code which ...": a head word, at most one bare noun, then a
# relative pronoun.
_NP_RELATIVE = re.compile(
    r"\s+(?:(?!(?:a|an|the|this|that|these|those|your|my|our|their|its|it|them)\b)"
    r"[A-Za-z][\w-]*\s+)?(?:that|which|who)\b",
    _I,
)


def noun_phrase_item(s: str, head_end: int) -> bool:
    """Whether the list item whose first word ends at `head_end` is a noun phrase with a
    relative clause ("Retry loops that give up ...", "code that quietly rewrites ...")."""
    return _NP_RELATIVE.match(s, head_end) is not None


_CUE_WORD = re.compile(r"[A-Za-z]+")
_DETERMINER_BEFORE = re.compile(
    r"\b(?:a|an|the|this|that|these|those|any|each|every|no|per|its|their|your|our|my)"
    r"(?:\s+[a-z-]+)?\s*$",
    _I,
)
_FINITE_BETWEEN = re.compile(
    r"\b(?:is|are|was|were|means|mean|counts|count|equals|has|have|had|becomes)\b", _I
)
_TARGET_WORD = re.compile(
    r"\b(?:instructions?|directions?|guidance|guidelines?|rules?|directives?|orders|polic(?:y"
    r"|ies)|constraints?|restrictions?|prompts?|requests?|approv\w*|confirm\w*|permission"
    r"|consent|sign-?off|authori[sz]ation|reviews?|asking)\b",
    _I,
)
_QUALIFIED_TARGET = re.compile(
    r"(?:your|the|all|any|my|our|their|prior|previous|earlier|above|system)\b", _I
)
_TARGET_AS_VERB = re.compile(r"\s+(?:out|it|them|that)\b", _I)


def override_governs(s: str, a: int, b: int) -> bool:
    """Whether the override s[a:b] is a cue verb governing its authority or approval
    target: the cue is not a noun or a third-person form, no finite verb stands between
    cue and target, and the target is not used as a verb, backticked, or a `name=value`."""
    cue = _CUE_WORD.match(s, a)
    if cue is None or _TARGET_WORD.match(s, a) or _QUALIFIED_TARGET.match(s, a):
        return True  # the target named first: "your instructions are outdated"
    word = cue.group().lower()
    if word.endswith("s") and word not in ("dismiss", "bypass", "regardless", "takes"):
        return False  # "Use overrides to ...", "it supersedes ...": a noun or a report
    if word not in ("without", "even", "regardless", "no", "in", "instead", "take", "takes"):
        before = _DETERMINER_BEFORE.search(s, max(0, a - 30), a)
        if before is not None:
            return False  # "an override", "per-directory overrides"
    targets = list(_TARGET_WORD.finditer(s, cue.end(), b))
    if not targets:
        return True  # a target outside this list ("set aside everything above")
    t = targets[-1]
    if _FINITE_BETWEEN.search(s, cue.end(), t.start()):
        return False  # "without asking is that consent": cue and target in two clauses
    if (t.start() > 0 and s[t.start() - 1] in "`_-") or s[t.end() : t.end() + 1] in ("=", "`", "_"):
        return False  # "`confirm=true`": a parameter, not an approval
    # "the design rules out": the target word is a verb
    as_verb = t.group().lower() in ("rules", "orders", "requests")
    return not (as_verb and _TARGET_AS_VERB.match(s, t.end()))


_ITEM_PRONOUN = re.compile(r"\b(?:it|them)\b", _I)
_ITEM_DEMONSTRATIVE = re.compile(r"\b(?:this|that|these|those|the\s+above)\b", _I)
_PERSON = re.compile(r"\b(?:user|users|human|operator|owner|customer|person|team)\b", _I)
_ITEM_DETERMINER = re.compile(
    r"\b(?:the|a|an|this|that|these|those|your|its|their|any|each|all)\s+[a-z][\w-]*", _I
)


def refers_to_previous_item(s: str) -> bool:
    """Whether list item s refers back to the previous item: a demonstrative, or "it" or
    "them" with no noun phrase other than a person before it in s."""
    if _ITEM_DEMONSTRATIVE.search(s):
        return True
    for p in _ITEM_PRONOUN.finditer(s):
        nps = _ITEM_DETERMINER.finditer(s, 0, p.start())
        if not any(not _PERSON.search(m.group()) for m in nps):
            return True
    return False
