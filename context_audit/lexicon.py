"""Word families added for recall (Task 16), combined into frames by `features`.

Each family is a class of words a different author would plausibly use for the same
thing, not a list of phrasings seen in an evaluation set. `features` composes them with
its existing classes (addressee, place, approval) into regular expressions.
"""

from __future__ import annotations

# Verbs of placing, filing, recording and reserving: an action on a shared record or
# resource ("put a mark on the checklist", "file a vote", "reserve two seats").
PLACING_VERBS = (
    "put",
    "place",
    "leave",
    "enter",
    "file",
    "stamp",
    "lodge",
    "deposit",
    "stash",
    "tuck",
    "slip",
    "pin",
    "tag",
    "label",
    "tick",
    "jot",
    "queue",
    "enqueue",
    "reserve",
    "renew",
    "extend",
    "claim",
)

# Head nouns of places where the user reads what the agent did, after a determiner and up
# to two modifiers ("the completion report", "any progress messages").
PLACE_NOUNS = (
    "reply",
    "replies",
    "response",
    "responses",
    "answer",
    "answers",
    "summary",
    "summaries",
    "output",
    "message",
    "messages",
    "conversation",
    "chat",
    "transcript",
    "report",
    "reports",
    "notification",
    "notifications",
    "updates",
    "feed",
    "handoff",
    "view",
    "inbox",
    "dashboard",
    "digest",
    "recap",
)
# "user-facing messages", "user-visible logs".
USER_FACING = ("facing", "visible", "readable")
# "anything the user sees".
USER_PERCEIVES = ("sees", "reads", "receives", "gets", "hears")

# Participles of keeping something from someone, in a passive or stative frame:
# "that call should be withheld from the user".
KEPT_PARTICIPLES = ("kept", "withheld", "hidden", "concealed", "omitted", "excluded", "left out")
# Participles of telling, negated in a passive frame: "must never be disclosed to the user".
# Like the active communication verbs, they conceal anything but a plain data noun.
TOLD_PARTICIPLES = ("disclosed", "mentioned", "reported", "revealed", "communicated", "announced")
# Participles of presenting: like the active presentation verbs, they conceal only an action.
SHOWN_PARTICIPLES = ("shown", "displayed", "surfaced")
# Nouns of telling, after "no" or "without": "with no disclosure of that entry to the user".
TELLING_NOUNS = (
    "disclosure",
    "mention",
    "notice",
    "notification",
    "word",
    "indication",
    "sign",
    "trace",
    "acknowledgement",
    "acknowledgment",
)
# States of not knowing: "keep the user unaware", "the user must remain in the dark".
UNAWARE_STATES = ("unaware", "uninformed", "oblivious", "in the dark", "none the wiser")

# An approval step declared not to apply: "exempt from the approval step".
EXEMPT_WORDS = ("exempt", "exempted", "excused", "released")
# An approval step skipped after it is named: "the confirmation can be skipped".
SKIPPED_PARTICIPLES = ("skipped", "bypassed", "ignored", "omitted", "waived", "disregarded")
SKIP_VERBS = ("skip", "bypass", "ignore", "omit", "disregard", "waive")

# Openers that address an obligation to the agent: "the assistant should ...",
# "it is essential that you ...".
AGENT_NOUNS = ("assistant", "agent", "model", "ai")
OBLIGATION_MODALS = ("should", "must", "needs to", "has to", "is to", "ought to")
IMPORTANCE_ADJ = (
    "essential",
    "important",
    "critical",
    "vital",
    "necessary",
    "imperative",
    "required",
    "crucial",
    "mandatory",
)


def alt(words: tuple[str, ...]) -> str:
    """A regex alternation of the words, longest first, spaces matching any whitespace."""
    return "|".join(w.replace(" ", r"\s+") for w in sorted(words, key=len, reverse=True))
