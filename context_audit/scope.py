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

# A non-restrictive relative clause (", which ...", ", who ..."): a cue after it, before
# the next clause mark, describes its antecedent, not the directive.
_RELATIVE = re.compile(r",\s*(?:which|who|whom|whose)\b", _I)
_CLAUSE_MARK = re.compile(r"[,;:]")
# A clause of its own between the directive and an adverb: a clause mark or a relative.
_OWN_CLAUSE = re.compile(r"[,;:]|\b(?:which|who|whom|that)\b", _I)
_AUXILIARIES = frozenset(("is", "are", "was", "were", "has", "have", "had"))
# Words ending in "s" or "ed" that are neither finite verbs nor plural nouns.
_NOT_FINITE = frozenset(
    re.findall(
        r"\S+",
        "as us this its thus plus across unless towards afterwards always perhaps less"
        " indeed instead need",
    )
)
_NEXT_WORD = re.compile(r"\s+([A-Za-z]+)\b")


def _finite_after(s: str, start: int, end: int) -> bool:
    """Whether the manner adverb ending at `end` leads a finite verb of its own. An -s or
    -ed word after it is read as a finite verb only when a clause of its own (a clause
    mark or a relative pronoun) stands between the directive at `start` and the adverb
    ("..., which silently logs every request"); right after the directive it is the
    directive's plural object ("Send silently logs to the collector")."""
    m = _NEXT_WORD.match(s, end)
    if m is None:
        return False
    w = m.group(1).lower()
    if w in _NOT_FINITE:
        return False
    if w in _AUXILIARIES:
        return True
    inflected = (w.endswith("ed") and not w.endswith("eed")) or (
        w.endswith("s") and not w.endswith(("ss", "us", "is"))
    )
    return inflected and _OWN_CLAUSE.search(s, start, end) is not None


def manner_on_directive(s: str, pos: int, end: int | None, directives: list[int]) -> bool:
    """Whether the manner cue s[pos:end] can modify one of `directives` (sentence-relative
    starts of directive acts or calls before or in its clause): the cue is not inside a
    non-restrictive relative clause, and an adverb (`end` given) does not lead a finite
    verb of its own. A cue after a restrictive relative clause on the directive's object
    modifies the directive ("Delete files that match the pattern without telling the
    user")."""
    before = [d for d in directives if d < pos]
    if not before:
        return True  # the directive follows the cue in its clause: "Quietly send ..."
    start = max(before)
    if end is not None and _finite_after(s, start, end):
        return False
    ends = [m.end() for m in _RELATIVE.finditer(s, start, pos)]
    return not ends or _CLAUSE_MARK.search(s, ends[-1], pos) is not None


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


# "Retry loops that ...", "code which ...": the head word, at most one bare noun, then a
# relative pronoun.
_NP_RELATIVE = re.compile(
    r"\s+(?:(?!(?:a|an|the|this|that|these|those|your|my|our|their|its|it|them)\b)"
    r"[A-Za-z][\w-]*\s+)?(?:that|which|who)\b",
    _I,
)
# The relative clause's finite verb, after an optional adverb: "that quietly rewrites".
_REL_FINITE = re.compile(
    r"\s+(?:[a-z]+ly\s+)?(?:[a-z]+(?:s|ed)|is|are|was|were|has|have|had|can|could|will"
    r"|would|may|might|must|should|do|does|did|never|always|often)\b",
    _I,
)
# A lead-in that announces things to recognise rather than steps to take.
_ANNOUNCING = re.compile(
    r"\b(?:(?:look|watch|check|scan|listen)\s+(?:out\s+)?for|signs?\s+of|symptoms?"
    r"|examples?|e\.g\.|common\s+(?:causes|problems|issues|mistakes|pitfalls|failures)"
    r"|such\s+as|including|includes?|things\s+(?:that|which|to\s+(?:look|watch|check))"
    r"|red\s+flags|smells|anti-?patterns|pitfalls|culprits|suspects|candidates)\b",
    _I,
)


def announcing_lead(sentence: str) -> bool:
    """Whether a list's lead-in sentence announces things to recognise ("Look for:",
    "Signs of ...:", "Common causes:", "... such as:") rather than steps."""
    return sentence.rstrip().endswith(":") and _ANNOUNCING.search(sentence) is not None


def noun_phrase_item(s: str, head_end: int, listed_verb: bool, announced: bool) -> bool:
    """Whether the list item whose first word ends at `head_end` is a noun phrase with a
    relative clause rather than an imperative. Under a lead-in that announces things, any
    head followed by a relative clause is. Otherwise only a head that is not a listed act
    verb, and only when its relative clause has a finite verb ("code that quietly
    rewrites ..."); a listed act verb under a neutral or procedural lead-in is an
    imperative ("- Delete files that match the pattern ...")."""
    m = _NP_RELATIVE.match(s, head_end)
    if m is None:
        return False
    if announced:
        return True
    return not listed_verb and _REL_FINITE.match(s, m.end()) is not None


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
