"""Open-class imperatives recognised by form (Task 16b).

With no part-of-speech tagger, a word in imperative position is taken as a base-form verb
by exclusion: it is not in a closed word class, not on a stoplist of sentence-initial
nouns and adjectives, carries no finite or participle ending, and is followed by
something that can start an object or complement. The verb itself may be one no list
has seen. `features` finds the imperative position and applies its report and negation
rules; this module only judges the head word and what follows it.
"""

from __future__ import annotations

import re


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


# Closed classes: never the head of an imperative.
_CLOSED = _words(
    # determiners and quantifiers
    "a an the this that these those each every all any some no none both either neither"
    " such what which whose another other most many much more less few several enough"
    # pronouns and possessives
    " i me my mine we us our ours you your yours he him his she her hers it its they them"
    " their theirs one ones someone something anyone anything everyone everything nobody"
    " nothing somebody anybody everybody myself yourself itself themselves ourselves"
    # prepositions
    " of to in on at by for with from into onto upon about above below over under after"
    " before between through during without within across against along among around"
    " behind beside beyond near off out per since than toward towards until via like unlike"
    " despite except inside outside throughout"
    # conjunctions
    " and or but nor so yet if unless because although though while whereas whether when"
    " whenever where wherever once as"
    # auxiliaries and modals
    " is are was were be been being am has have had do does did will would shall should"
    " can could may might must ought need dare"
    # wh-words
    " who whom why how whatever whichever whoever"
    # interjections and discourse words
    " hello hi hey thanks thank please yes no ok okay oh wow sorry welcome congratulations"
    # common adverbs
    " also here there now then today tomorrow yesterday still just only even always never"
    " often sometimes usually again already soon later first next last finally instead"
    " otherwise however therefore meanwhile overall perhaps maybe very too not"
    # numbers
    " zero two three four five six seven eight nine ten hundred thousand million"
)
# Common sentence-initial nouns and adjectives that are not verbs ("Note the ...",
# "Summary of ..."). Grown from the benign generator and the controls, never from the
# development set.
STOPLIST = _words(
    "note notes warning warnings error errors result results status summary example examples"
    " version versions total totals details detail info information tip tips hint hints usage"
    " step steps source default type name description date time price size cost new old good"
    " great bad same different full partial main current final latest recent previous"
    " important optional required customer customers user team project service server"
    " access order data file files output input response request reply message issue"
    " ticket page section table list item items value values field fields key keys"
    " true false null none yes good nice cool"
    # cross-references, not actions: "See the section ...", "Refer to the guide"
    " see refer"
    # concealment and override cues: their own detectors judge them, and as a bare act
    # they would make a lone concealment refer to itself ("Keep it out of the reply")
    " keep hide conceal suppress withhold omit exclude avoid refrain skip ignore disregard"
    " forget override supersede bypass waive dispense"
)
# Irregular past forms, which carry no -ed ending: "Sent the file to ...".
_IRREGULAR_PAST = _words(
    "sent made said told found built kept held paid brought bought thought caught taught"
    " sold spent lost meant felt heard ran took went began broke wrote gave came became"
    " grew knew threw drew flew spoke chose froze woke ate saw did been gone done seen"
    " shown known given taken written got left led fed"
)
# Words that can start an object or complement of a verb. "of" is left out: a verb
# rarely takes it directly, and "Summary of", "List of", "Version of" are headings.
_DETERMINER_START = _words(
    "a an the this that these those each every all any some both either neither another"
    " my your our their his her its it them him me us everything anything something"
    " every"
)
_PREPOSITION_START = _words(
    "to into onto from with for at about through via on in over across against"
)
_PARTICLE_START = _words("up out down off back away")
_NEXT = re.compile(r"\s+(?P<next>[`\"'“‘]|[A-Za-z][\w'’-]*)")
_FINITE_IN_CLAUSE = re.compile(
    r"\b(?:is|are|was|were|has|have|had|will|would|can|could|may|might|must|should|does"
    r"|did|requires?|needs?)\b",
    re.IGNORECASE,
)
_CLAUSE_END = re.compile(r"[,;:.!?]")
_HEAD = re.compile(r"[A-Za-z][a-z]+(?:-[a-z]+)?")


def imperative_head(
    s: str, start: int, end: int, sentence_start: bool, *, strict: bool = False
) -> bool:
    """Whether the word s[start:end], in imperative position, reads as a base-form verb
    directing an action. `sentence_start` says whether the position is the start of a
    sentence or line (where any word is capitalised) rather than after a word or comma.
    `strict` (after a comma, bracket or quote, where a list of nouns is as likely) asks
    for a determiner, pronoun or backticked name after the word."""
    word = s[start:end]
    if not _HEAD.fullmatch(word):
        return False  # digits, underscores, all capitals: identifiers and acronyms
    if word[0].isupper() and not sentence_start:
        return False  # a proper noun after a comma or conjunction
    w = word.lower()
    if w in _CLOSED or w in STOPLIST or w in _IRREGULAR_PAST or len(w) < 3:
        return False
    if w.endswith(("ed", "ing", "ly")) and not w.endswith("eed"):
        return False  # past, progressive or adverb
    if w.endswith("s") and not w.endswith(("ss", "us", "is")):
        return False  # third person or plural noun
    m = _NEXT.match(s, end)
    if m is None:
        return False
    nxt = m.group("next")
    if nxt[0] == "`" or (nxt[0] in "\"'“‘" and not strict):
        return True
    n = nxt.lower()
    if n in _DETERMINER_START:
        return True
    if strict:
        return False
    if n in _PARTICLE_START:
        return True
    if n in _PREPOSITION_START:
        # "Access to the panel requires a token": a noun subject before a finite verb.
        stop = _CLAUSE_END.search(s, m.end())
        return _FINITE_IN_CLAUSE.search(s, m.end(), stop.start() if stop else len(s)) is None
    return False
