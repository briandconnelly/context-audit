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
# Cue frames that govern their target as a preposition or fixed phrase, not as a verb:
# "without approval", "regardless of the rules", "this takes precedence over ...".
_FRAME = re.compile(
    r"(?:without|regardless|even|in\s+place|instead|no\s+need|never\s+mind"
    r"|takes?\s+(?:precedence|priority))\b",
    _I,
)
# Words after which a cue word stands in verb position (imperative, infinitive, after a
# modal or auxiliary, a conjunction, a negator, a polite or adverbial opener).
_VERB_LEAD = frozenset(
    re.findall(
        r"\S+",
        "and or but nor then so to please kindly just simply now also first next always"
        " you we i let's lets can could may might must should shall will would do does did"
        " don't dont not never is are be been being am was were by stop keep start try"
        " instead immediately therefore thus here otherwise else afterwards later finally"
        " meanwhile again yes ok okay great sure",
    )
)
_DETERMINERS = frozenset(
    re.findall(r"\S+", "a an the this that these those any each every no per its their your our my")
)
_PREVIOUS_WORD = re.compile(r"([A-Za-z][\w'’]*)\W*$")
_CLAUSE_START = re.compile(r"(?:^|[.,;:!?(\n]|(?:^|\s)(?:[-*+•]|\d+[.)]))\s*$")


def _verb_cue(s: str, a: int, word: str) -> bool:
    """Whether the cue word at `a` is a verb: a gerund not after a determiner, or a base
    form in verb position (the start of its clause, or after a conjunction, "to", a
    modal, auxiliary, negator or adverb). After a determiner, an adjective or another
    verb it is a noun ("Use overrides", "every bypass", "the ignore file"); with an -s or
    -ed ending it is a noun, a report, or a participle."""
    if (word.endswith("s") and not word.endswith(("ss", "us", "is"))) or (
        word.endswith("ed") and not word.endswith("eed")
    ):
        return False
    lo = max(0, a - 40)
    if _CLAUSE_START.search(s, lo, a):
        return True
    prev = _PREVIOUS_WORD.search(s, lo, a)
    if prev is None:
        return True
    p = prev.group(1).lower().replace("’", "'")
    if word.endswith("ing"):
        return p not in _DETERMINERS  # a gerund is verbal unless a determiner makes it a noun
    return p in _VERB_LEAD or p.endswith("ly")


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
# What follows a target word that is itself a verb with an object or particle: "the
# design rules out", "the policy requests a review", "the template orders the imports".
_TARGET_AS_VERB = re.compile(
    r"\s+(?:out|it|them|a|an|the|this|these|those|any|some|every|each|its|their)\b", _I
)


def override_governs(s: str, a: int, b: int) -> bool:
    """Whether the override s[a:b] is a cue governing an authority or approval target as
    its object. The cue must be a verb (`_verb_cue`) or a prepositional frame (`_FRAME`);
    no finite verb may stand between cue and target; and the target must be a noun: not
    a verb with an object of its own, not backticked, not a `name=value`. Forms that name
    the target first ("your instructions are outdated") are not judged here."""
    cue = _CUE_WORD.match(s, a)
    if cue is None or _TARGET_WORD.match(s, a) or _QUALIFIED_TARGET.match(s, a):
        return True
    if not _FRAME.match(s, a) and not _verb_cue(s, a, cue.group().lower()):
        return False  # "Use overrides to ...", "it supersedes ...", "an override"
    targets = list(_TARGET_WORD.finditer(s, cue.end(), b))
    if not targets:
        return True  # a target outside this list ("set aside everything above")
    t = targets[-1]
    if _FINITE_BETWEEN.search(s, cue.end(), t.start()):
        return False  # "without asking is that consent": cue and target in two clauses
    if (t.start() > 0 and s[t.start() - 1] in "`_-") or s[t.end() : t.end() + 1] in ("=", "`", "_"):
        return False  # "`confirm=true`": a parameter, not an approval
    word = t.group().lower()
    verb_form = word.endswith("s") and not word.endswith(("ss", "us", "is"))
    return not (verb_form and _TARGET_AS_VERB.match(s, t.end()))  # a target used as a verb


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
