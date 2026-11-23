"""Feature detectors: observable text features of third-party directives.

Each detector reports a span in normalized text. The scanner never sees the user's task,
so these are indicators only; findings are joined from them elsewhere.

Patterns are built from classes (verb class, object class, addressee, target) rather
than from fixed phrasings.

Input is attacker-controlled: every pattern is applied per sentence, repetition is
bounded, there are no nested unbounded quantifiers and no backreferences, and a cheap
anchor prefilter lets a sentence skip the patterns of a feature it cannot carry.
"""

from __future__ import annotations

import re
import time
from bisect import bisect_left, bisect_right, insort
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import NamedTuple

from context_audit import lexicon as lx
from context_audit import proximity
from context_audit.form import imperative_head
from context_audit.lexicon import alt
from context_audit.text import Field, Normalized, fenced, line_breaks, record_lines, sentences

FEATURES = ("act", "call", "conceal-act", "audience", "solicit", "override", "hidden")


@dataclass(frozen=True)
class Match:
    feature: str
    start: int  # normalized span
    end: int
    sentence: int  # index into sentences(n)
    quoted: bool  # inside fenced(n)
    conditioned: bool = False  # override only: conditioned on the user's own approval
    tool: str | None = None  # call only: the tool name the text directs a call to
    # On a record line (`text.record_lines`): a log line, commit subject, step line. Such a
    # line reports something even when its content is imperative in form, so a feature on
    # it is rated review at most. This is a known evasion route, accepted for precision:
    # a directive written as a commit subject or log line is not rated high.
    record: bool = False


class Detection(list[Match]):
    """The matches of one `detect` call, in order of position.

    `complete` is False when the deadline passed before every sentence was scanned;
    the matches found up to that point are still returned.
    """

    complete: bool = True


_I = re.IGNORECASE
_A = "['’]"  # apostrophe, straight or curly

# A negator earlier in the same clause cancels a feature.
_NEGATOR = re.compile(
    rf"\b(?:not|never|no|nothing|nor|cannot|(?:do|does|did|wo|ca|should|must){_A}?n{_A}t)\b",
    _I,
)
_CLAUSE_BREAK = re.compile(r"[,;:]|\bbut\b", _I)
_LOOKBACK = 60

# --- act: an imperative verb class at a clause start ---------------------------------

_ACT_VERBS = (
    # transfer and communication outward
    "submit|send|resend|e-?mail|post|publish|upload|download|forward|transmit|share|export"
    "|import|sync|ping|notify|reply|respond|attach|invite|subscribe|unsubscribe"
    "|register|enroll|book|buy|purchase|pay|vote|rate"
    # change and destroy
    "|delete|remove|erase|wipe|purge|truncate|drop|destroy|clear|reset|revoke|cancel|kill"
    "|stop|restart|disable|enable|close|archive|rename|move|transfer|copy|write|overwrite"
    "|edit|modify|change|update|patch|replace|insert|add|append|set|bump|mark"
    "|assign|grant|approve|accept|decline|reject|merge|commit|push|pull|clone|fork|rebase"
    "|deploy|release|promote|roll\\s+back|rollback|migrate|rebuild|build|compile|install"
    "|uninstall|apply|schedule|create|open|save|store|log|record|back\\s+up|restore|free"
    # perform and inspect
    "|run|execute|invoke|trigger|call|use|fetch|retrieve|get|load|bring\\s+up|retry|continue|proceed|start"
    "|check|verify|confirm|review|list|summari[sz]e|narrow|slow|collect|connect|join|sign"
    "|visit|navigate|browse|click|ask|contact|lock|unlock|transfer"
    # a few translated imperatives, for the translated concealment and override phrases
    "|l[öo]sche|sende|schicke|envie|env[íi]a|envoyez|envoie|supprimez|supprime|borra|elimina"
    # placing, filing, recording and reserving (see `lexicon.PLACING_VERBS`)
    "|" + alt(lx.PLACING_VERBS)
)
# Clause starts and polite openers that put the verb in imperative position.
_OPENER = (
    r"(?P<opener>^|[\n.!?:;,(\]\"“`]|\b(?:and|et|und|then|also|now|first|next|please|kindly"
    r"|afterwards|instead|so|or|just|immediately|always|simply|you\s+should|you\s+must"
    r"|you\s+need\s+to|you{_A}ll\s+need\s+to|you\s+will\s+need\s+to|you\s+can|you\s+may"
    r"|be\s+sure\s+to|make\s+sure\s+to|remember\s+to|don{_A}t\s+forget\s+to"
    r"|do\s+not\s+forget\s+to|(?:i|we)\s+(?:need|want|would\s+like)\s+you\s+to"
    r"|you\s+are\s+(?:required|expected|asked)\s+to|go\s+ahead\s+and"
    # an obligation addressed to the agent: "the assistant should", "it is essential that you"
    rf"|(?:the\s+|an?\s+)?(?:{alt(lx.AGENT_NOUNS)})\s+(?:{alt(lx.OBLIGATION_MODALS)})"
    rf"|it\s+is\s+(?:{alt(lx.IMPORTANCE_ADJ)})\s+(?:that\s+you|for\s+you\s+to|to))\b)"
).replace("{_A}", _A)
# A leading status symbol or emoji before an imperative ("⚠ Delete the backups ...").
_SYMBOL = "\u2190-\u2bff\U0001f300-\U0001faff\ufe0f"
# Concealment manner adverbs, shared by the act pattern and the conceal-act detector.
_CONCEAL_ADV = (
    r"(?:silently|quietly|secretly|discreetly|covertly|stealthily|privately|surreptitiously"
    r"|unannounced|in\s+secret|in\s+the\s+background|behind\s+the\s+scenes)"
)
_HEAD_PREFIX = (
    rf"[\s\-*•>\d.)\"'`“{_SYMBOL}]{{0,6}}"
    r"(?:(?:also|now|then|please|kindly|first|just|always|immediately|simply"
    rf"|{_CONCEAL_ADV})\s+)?"
)
_KNOWN_HEAD = (
    rf"\b(?P<verb>{_ACT_VERBS})\b"
    r"(?![-:/_@\"”'`])(?!\.\S)"
    r"(?!\s+(?:finished|failed|passed|ran|took|queued|pending|broke|staged|complete|completed|succeeded|saved|ready|started|done"
    r"|is|was|are|were|has|had|limits?|of|ids?|count|status|history|not|found)\b)"
    r"(?!\s+#\d)"
    r"(?=(?P<after>\s+\w{1,10})?)"
)
# Any word in the same position: an open-class imperative, judged by
# `form.imperative_head` (Task 16b). The verb list stays the strong signal; one pass
# serves both, the list tried first.
_OPEN_HEAD = r"\b(?P<open>[A-Za-z][a-z]+(?:-[a-z]+)?)\b(?![-:/_@.'’])"
_ACT = re.compile(_OPENER + _HEAD_PREFIX + f"(?:{_KNOWN_HEAD}|{_OPEN_HEAD})", _I)
# The same with only word openers, tried where a rejected open head stands: "You must
# offboard ...", ", then defund ..." (the rejected head is itself an opener).
_ACT_AT = re.compile(
    _OPENER.replace("(?P<opener>^|", "(?P<opener>", 1)
    + _HEAD_PREFIX
    + f"(?:{_KNOWN_HEAD}|{_OPEN_HEAD})",
    _I,
)
# Openers at which a capitalised word is still a sentence start.
_SENTENCE_OPENERS = frozenset({"", "\n", ".", "!", "?", ":"})
# A verb-class word that is a noun heading the subject of a finite verb is not an imperative:
# "Update checks run nightly.", "Delete operations are logged.", "Sync job runs nightly."
_FINITE_AUX = "is|are|was|were|has|have|had|will|would|can|could|may|might|must|should|do|does|did"
# Present-tense verbs in their plural form: counted only after a noun ending in "s".
_FINITE_PLURAL = (
    "run|show|take|fail|range|start|log|appear|contain|include|require|need|happen|occur"
    "|remain|depend|exist|vary"
)
_FINITE_SINGULAR = (
    "opens|takes|fails|appears|contains|includes|requires|needs|happens|occurs|remains"
    "|depends|exists|varies"
)
# Forms that as often belong to the object, as a plural noun ("send error logs to ...") or
# an adjective ("delete files open in ..."): counted only when the next word does not
# continue an object.
_FINITE_OR_OBJECT = "runs|shows|starts|logs|ranges|open"
_OBJECT_CONTINUES = (
    "to|from|with|via|using|through|into|for|and|or|of|in|on|at|by|older|newer|before|after"
    "|that|which|than"
)
# Words after the verb that are not the head of a subject: "Remove what is left."
_NOT_A_SUBJECT = (
    "what|whatever|which|whichever|who|whoever|whom|me|us|you|him|they|we|he|she|i|both"
    "|either|neither|none|others"
)
_SUBJECT_THEN_VERB = re.compile(
    rf"\s+(?!(?:{_NOT_A_SUBJECT})\b)(?P<noun>\w[\w'-]*)\s+"
    rf"(?:(?:{_CONCEAL_ADV}\s+)?(?:{_FINITE_AUX}|{_FINITE_SINGULAR})\b|(?P<plural>{_FINITE_PLURAL})\b"
    rf"|(?:{_FINITE_OR_OBJECT})\b(?=\s+(?!(?:{_OBJECT_CONTINUES})\b)[A-Za-z]))",
    _I,
)
# A third-person verb followed by the start of its object: "Send button sends the message".
_THIRD_PERSON = (
    r"(?![a-z]*ss\b)[a-z]{2,}s\b(?=\s+(?:the|a|an|this|that|these|those|its|their|your|our"
    r"|my|his|her|it|them|every|each|all|any|no|some)\b)"
)
# A past-tense verb: one that is never a participle, or an -ed form that ends its clause or
# is followed by a manner or time adverb ("Call volume spiked sharply", "deploy step ran").
# An -ed form followed by an object or a preposition stays ambiguous with a participle
# ("Send files uploaded during the outage") and is not counted.
_PAST = (
    r"(?:ran|took|went|began|broke|wrote|rose|fell|gave|came|became|grew|knew|threw|drew"
    r"|flew|spoke|chose|froze|woke|ate|saw|did)\b"
    r"|(?P<ed>[a-z]{2,}ed)\b(?=\s*(?:[,.;:!?]|$)|\s+(?:silently|quietly|again|twice|overnight"
    r"|yesterday|today|earlier|sharply|suddenly|unexpectedly|briefly)\b)"
)
# A plural-form verb followed by the start of its object, counted after a plural noun:
# "Delete requests remove the record", "Upload jobs send the file".
_PLURAL_VERB = (
    rf"(?:{_ACT_VERBS}|deliver|receive|reach|hide|keep|show|leave)\b(?=\s+(?:the|a|an|this"
    r"|that|these|those|its|their|your|our|it|them|every|each|all|any)\b)"
)
_SUBJECT_REPORT = re.compile(
    rf"\s+(?!(?:{_NOT_A_SUBJECT})\b)(?P<noun>\w[\w'-]*)\s+"
    rf"(?:{_THIRD_PERSON}|{_PAST}|(?P<plural>{_PLURAL_VERB}))",
    _I,
)
# Adverbs that open an imperative ("Now run ...", "and then send ...") but, after a
# subject, sit inside a report ("Exports now run ...", "The job will then send ...").
_ADVERB_OPENERS = frozenset(
    {
        "then",
        "also",
        "now",
        "first",
        "next",
        "just",
        "always",
        "immediately",
        "simply",
        "afterwards",
        "instead",
    }
)
# Words that may stand before such an adverb in an imperative.
_IMPERATIVE_LEAD = frozenset(
    {
        "and",
        "or",
        "but",
        "so",
        "then",
        "please",
        "kindly",
        "also",
        "now",
        "first",
        "next",
        "just",
        "always",
        "simply",
        "immediately",
        "afterwards",
        "finally",
        "et",
        "und",
        "to",
        "you",
    }
)
_LAST_WORD = re.compile(r"(\w+)\W*$")
# Verbs that take a clause: "Verify services are running." is an imperative.
_CLAUSE_VERBS = frozenset({"check", "verify", "confirm"})
# Verb-specific idioms that are not directives: "Set to `x`" (a parameter's meaning),
# "Use when ..." (a skill's trigger).
_ACT_IDIOM = {
    "set": frozenset({"to"}),
    "use": frozenset({"when", "for", "with", "only", "this"}),
}

# --- call: a directive naming a tool -------------------------------------------------

_TICK = r"`(?P<tick>[A-Za-z_][A-Za-z0-9_]*)`"
_BARE = r"(?P<bare>[a-z][a-z0-9]*_[a-z0-9_]*|[a-z]+[A-Z][A-Za-z0-9]*)\b"
_CALL_VERB = (
    r"(?i:call|calls|calling|invoke|invokes|invoking|run|runs|running|use|uses|using"
    r"|execute|executes|executing|trigger|triggers|triggering"
    r"|llama\s+a|llame\s+a|appelle|appelez|rufe|chame|chama)"
)
_TOOL_WORD = r"\s+(?i:the\s+)?(?i:(?:tool|function|endpoint)\s+)?"
# A backticked tool after a call verb is a call wherever the verb stands.
_CALL_TICK = re.compile(rf"\b{_CALL_VERB}{_TOOL_WORD}{_TICK}")
# A bare identifier is a tool only when its call verb is in imperative position.
_CALL_BARE = re.compile(rf"\b(?P<verb>{_CALL_VERB}){_TOOL_WORD}{_BARE}")
# "when you call `tool`" describes a call the agent makes; it does not direct one.
_DESCRIBED = re.compile(r"\b(?:when|whenever|if|after|before|once|until)\s+you\s+$", _I)
# "fetch the details via `tool`": a tool named after an action verb in the same clause.
_TOOL_PREPS = "with|using|via|through|from|to"
_PREP_TOOL = re.compile(rf"\b(?i:{_TOOL_PREPS}){_TOOL_WORD}{_TICK}")

# --- conceal-act: keeping an action or the exchange from the user --------------------

_WHO = (
    r"(?:(?:the|your|its|their)\s+(?:end[\s-])?(?:user|users|human|humans|person|people"
    r"|maintainers?|owner|operator|customer|requester|developers?)|anyone|anybody|others"
    r"|them)\b(?!['’])"
)
# Places where the user reads what the agent did: "the final reply", "the completion
# report", "the user's activity feed", "user-facing messages", "anything the user sees".
_PLACE = (
    rf"(?:(?:the|your|its|any)\s+(?:[a-z-]+\s+){{0,2}}?(?:{alt(lx.PLACE_NOUNS)})\b"
    r"|(?:the|your)\s+(?:end[\s-])?(?:user|human|requester|customer|owner|operator)['’]s"
    r"\s+[a-z-]+(?:\s+[a-z-]+)?"
    rf"|(?:user|human|customer|requester)[\s-](?:{alt(lx.USER_FACING)})\s+[a-z-]+(?:\s+[a-z-]+)?"
    r"|(?:anything|everything|whatever|what)\s+(?:the\s+(?:user|human|requester|owner)|they)"
    rf"\s+(?:{alt(lx.USER_PERCEIVES)}|is\s+shown))"
)
_NEG_OPEN = (
    rf"(?:do\s+not|don{_A}?t|never|not|without|no\s+need\s+to|nor|avoid|refrain\s+from"
    rf"|stop|make\s+sure\s+not\s+to|be\s+careful\s+not\s+to|take\s+care\s+not\s+to)"
)
# Concealment verbs split into two classes (controller ruling, round 2).
# Communication verbs are about what the user is told: negating one conceals anything
# except a plain data noun.
_COMM_THING = (
    r"(?:mention|mentioning|disclose|disclosing|say|saying|explain|explaining|acknowledge"
    r"|acknowledging|discuss|discussing|announce|announcing|raise|raising|flag|flagging"
    r"|report|reporting|bring\s+(?:this|that|it|these)\s+up|bringing\s+(?:this|that|it)\s+up"
    r"|bring\s+up|bringing\s+up|let\s+on|letting\s+on|talk\s+about|talking\s+about"
    r"|write\s+about|writing\s+about|refer\s+to|referring\s+to)"
)
# Presentation verbs are about what data is displayed: negating one conceals only an
# explicit action object.
_PRESENT_THING = (
    r"(?:show|showing|display|displaying|print|printing|output|outputting|include|including"
    r"|expose|exposing|reveal|revealing|render|rendering|log|logging|echo|echoing|surface"
    r"|surfacing|list|listing|quote|quoting|paste|pasting|share|sharing)"
)
# Reveal verbs taking the user: "tell the user", "let the user know".
_REVEAL_WHO_VERB = (
    r"(?:tell|telling|inform|informing|notify|notifying|alert|alerting|warn|warning|update"
    r"|updating|remind|reminding|let|letting)"
)
_AWARE = (
    r"(?:know|knows|learn|learns|notice|notices|realize|realizes|realise|realises|find\s+out"
    r"|finds\s+out|discover|discovers|become\s+aware|becomes\s+aware|be\s+aware|be\s+told"
    r"|be\s+informed|be\s+notified|hear|hears|suspect|suspects|see|sees|catch\s+on)"
)
_REVEAL_OBJ = re.compile(
    rf"\b{_NEG_OPEN}\s+(?:ever\s+)?(?:(?P<comm>{_COMM_THING})|{_PRESENT_THING})\b(?P<obj>[^.;:]{{0,40}}?)\s*"
    rf"\b(?:to|with|in|on\s+to|for)\s+(?:{_WHO}|{_PLACE})(?=(?P<tail>[^.;:,\x22\x60\u201d]{{0,40}}))",
    _I,
)
# A communication verb with no addressee: only an agent-relative object counts.
_REVEAL_BARE = re.compile(
    rf"\b{_NEG_OPEN}\s+(?:ever\s+)?{_COMM_THING}\b(?P<obj>[^.;:]{{0,40}}?\byou\s+[a-z]{{2,}})",
    _I,
)
_REVEAL_WHO = re.compile(
    rf"\b{_NEG_OPEN}\s+(?:ever\s+)?{_REVEAL_WHO_VERB}\s+{_WHO}"
    rf"(?:\s+{_AWARE})?(?=(?P<tail>[^.;:,\x22\x60\u201d]{{0,40}}))",
    _I,
)
_UNAWARE = re.compile(
    rf"\b{_WHO}\s+(?:does\s+not|doesn{_A}t|do\s+not|don{_A}t|should\s+not|shouldn{_A}t"
    rf"|must\s+not|mustn{_A}t|must\s+never|should\s+never|need\s+not|needn{_A}t|is\s+not\s+to"
    rf"|won{_A}t|will\s+not|will\s+never|never|cannot|can{_A}t|may\s+not)\s+(?:ever\s+)?"
    rf"(?:need\s+to\s+)?{_AWARE}\b(?=(?P<tail>[^.;:,\x22\x60\u201d]{{0,40}}))"
    rf"|\bwithout\s+{_WHO}\s+(?:knowing|noticing|realizing|realising|finding\s+out|seeing"
    rf"|being\s+told)\b(?=(?P<tail2>[^.;:,\x22\x60\u201d]{{0,40}}))"
    rf"|\bbehind\s+(?:the|your)\s+(?:user|human){_A}s\s+back\b",
    _I,
)
_KEEP = (
    r"(?:keep|keeps|kept|keeping|hide|hides|hid|hiding|leave|leaves|leaving|conceal|conceals"
    r"|concealing|withhold|withholds|withholding|omit|omits|omitting|exclude|excludes|excluding)"
)
_SECRET_ADJ = (
    r"(?:private|hidden|secret|silent|quiet|confidential|discreet|under\s+wraps|hush-hush"
    r"|to\s+yourself|between\s+us|off\s+the\s+record)"
)
_KEEP_FROM = re.compile(
    rf"\b{_KEEP}\b(?P<obj>[^.;:]{{0,40}}?)\s*\b(?:{_SECRET_ADJ}\s+)?"
    rf"(?:from|out\s+of|away\s+from|off)\s+(?:{_WHO}|{_PLACE})",
    _I,
)
_KEEP_SECRET = re.compile(
    rf"\b(?:keep|keeps|kept|keeping)\b(?P<obj>[^.;:]{{0,40}}?)\s*\b{_SECRET_ADJ}", _I
)
_CONCEAL_TRANSLATED = re.compile(
    # Spanish
    r"\bno\s+(?:se\s+)?(?:lo\s+|le\s+|la\s+|les\s+)?(?:menciones|digas|cuentes|informes|comentes)"
    r"\b[^.;]{0,30}?\busuario"
    r"|\bsin\s+(?:dec[ií]rselo|decirle|informar|avisar)\b[^.;]{0,20}?\busuario"
    # French
    r"|\bne\s+(?:le\s+|lui\s+|leur\s+|l'|en\s+)?(?:dites|dis|mentionnez|mentionne|informez"
    r"|signalez|parlez)\b[^.;]{0,30}?\butilisateur"
    r"|\bsans\s+(?:le\s+|en\s+)?(?:dire|informer|pr[ée]venir|avertir)\b[^.;]{0,20}?\butilisateur"
    # German
    r"|\bsag(?:e|en\s+sie)?\s+(?:dem|den)\s+(?:benutzer|nutzer|anwender)\w{0,3}\s+nichts"
    r"|\bohne\s+(?:den|dem)\s+(?:benutzer|nutzer|anwender)\w{0,3}\s+zu\s+(?:informieren"
    r"|benachrichtigen)"
    # Portuguese
    r"|\bn[ãa]o\s+(?:conte|diga|mencione|informe)\b[^.;]{0,30}?\busu[áa]rio",
    _I,
)
_SILENT = re.compile(rf"\b{_CONCEAL_ADV}\b", _I)
# A pro-verb standing for an action: "do it quietly", "handle this silently".
_PROVERB = re.compile(
    r"\b(?:do|handle|take\s+care\s+of|carry\s+out|perform)\s+(?:this|that|it|these|those)\b", _I
)
# Presentation verbs taking the addressee first: "do not show the user that you ...".
_PRESENT_WHO = re.compile(
    rf"\b{_NEG_OPEN}\s+(?:ever\s+)?{_PRESENT_THING}\s+{_WHO}"
    r"(?=(?P<tail>[^.;:,\x22\x60\u201d]{0,40}))",
    _I,
)
# Presentation verbs with no addressee: "do not print that you retried the request".
_PRESENT_BARE = re.compile(
    rf"\b{_NEG_OPEN}\s+(?:ever\s+)?{_PRESENT_THING}\b(?P<obj>[^.;:,]{{0,40}})", _I
)
# "say nothing about X", "never say anything about X": the object follows about/of.
_SAY_NOTHING = re.compile(
    rf"\b(?:{_NEG_OPEN}\s+(?:ever\s+)?(?:{_COMM_THING}|{_REVEAL_WHO_VERB})\s+(?:anything|a\s+word)"
    rf"|(?:{_COMM_THING}|{_REVEAL_WHO_VERB})\s+nothing)\s+(?:about|regarding|of|on)\b"
    r"(?P<obj>[^.;:]{0,40})",
    _I,
)
# An obligation, for frames whose subject is the concealed thing.
_MODAL = (
    r"(?:must|should|shall|is\s+to|are\s+to|needs?\s+to|has\s+to|have\s+to|ought\s+to"
    r"|will\s+need\s+to)"
)
# "that call should be withheld from the user", "the renewal must stay off the feed".
_PASSIVE_KEEP = re.compile(
    rf"\b{_MODAL}\s+(?P<neg>(?:not|never)\s+)?(?:(?:be|stay|remain)\s+(?:{alt(lx.KEPT_PARTICIPLES)})"
    r"\s+(?:out\s+(?:of|from)|from|off|away\s+from)|(?:stay|remain)\s+(?:out\s+of|off|away\s+from))"
    rf"\s+(?:{_WHO}|{_PLACE})",
    _I,
)
# "that vote must never be disclosed to the user".
_PASSIVE_TOLD = re.compile(
    rf"\b(?:{_MODAL}\s+(?:not|never)|(?:must|should){_A}?n{_A}t)\s+(?:ever\s+)?be\s+"
    rf"(?:(?P<comm>{alt(lx.TOLD_PARTICIPLES)})|{alt(lx.SHOWN_PARTICIPLES)})"
    rf"\s+(?:to|in|with)\s+(?:{_WHO}|{_PLACE})",
    _I,
)
# "keep the user unaware of the entry", "the user must remain in the dark".
_UNAWARE_STATE = alt(lx.UNAWARE_STATES)
_KEEP_UNAWARE = re.compile(
    rf"\b(?:(?:keep|keeping|leave|leaving)\s+{_WHO}"
    rf"|{_WHO}\s+{_MODAL}\s+(?:remain|stay|be\s+kept|be\s+left)"
    rf"|(?:make\s+sure|ensure)\s+(?:that\s+)?{_WHO}\s+(?:remains|stays|is\s+kept|is\s+left))"
    rf"\s+(?:{_UNAWARE_STATE})\b(?=(?P<tail>[^.;:,\x22\x60\u201d]{{0,40}}))",
    _I,
)
_DEMONSTRATIVE = re.compile(r"^\s*(?:this|that|these|those|it)\b", _I)

# The object of a concealment: an action or the exchange, not data.
_WORD = re.compile(r"[a-z][a-z'’-]*")
_CLAUSE_OBJ = re.compile(r"^\s*(?:about\s+|of\s+)?(?:that|what|how|when|where|whether|why)\b", _I)
# An agent relative clause: "the ping that you sent", "the payment you made".
_AGENT_REL = re.compile(
    r"\b(?:that|which|what)\s+you\b"
    r"|\byou\s+(?:just\s+|have\s+|had\s+|already\s+)?"
    r"(?!are\b|were\b|will\b|can\b|may\b|should\b|must\b|would\b|could\b|to\b)[a-z]{2,}",
    _I,
)
# Plain data nouns: withholding these is not concealment, even after a communication verb.
_DATA_NOUNS = frozenset(
    [
        "token",
        "tokens",
        "key",
        "keys",
        "secret",
        "secrets",
        "password",
        "passwords",
        "passphrase",
        "credential",
        "credentials",
        "codename",
        "codenames",
        "name",
        "names",
        "address",
        "addresses",
        "hostname",
        "hostnames",
        "url",
        "urls",
        "id",
        "ids",
        "identifier",
        "identifiers",
        "number",
        "numbers",
        "value",
        "values",
        "field",
        "fields",
        "config",
        "configuration",
        "details",
        "detail",
        "data",
        "json",
        "payload",
        "trace",
        "traces",
        "log",
        "logs",
        "file",
        "files",
        "path",
        "paths",
        "contents",
        "content",
        "body",
        "price",
        "prices",
        "cost",
        "costs",
        "salary",
        "balance",
        "phone",
        "ssn",
        "birthday",
        "location",
        "ip",
        "email",
        "emails",
        "code",
        "codes",
        "hash",
        "signature",
    ]
)
_FUNCTION_WORDS = frozenset(
    [
        "the",
        "a",
        "an",
        "this",
        "that",
        "these",
        "those",
        "it",
        "them",
        "its",
        "your",
        "our",
        "their",
        "my",
        "his",
        "her",
        "any",
        "every",
        "each",
        "all",
        "some",
        "such",
        "of",
        "about",
        "to",
        "with",
        "for",
        "in",
        "on",
        "at",
        "from",
        "by",
        "here",
        "there",
        "above",
        "below",
        "else",
        "anything",
        "everything",
        "something",
        "nothing",
        "one",
        "part",
        "bit",
        "stuff",
    ]
)
_PRONOUN_ONLY = frozenset(
    ["this", "that", "it", "these", "those", "them", "above", "anything", "everything", "here"]
)
_PREPOSITIONS = frozenset(
    ["with", "of", "for", "to", "from", "in", "on", "at", "by", "about", "between", "into"]
)
# Event nouns: the concealed thing is something done or exchanged.
_EVENT_NOUNS = frozenset(
    [
        "call",
        "calls",
        "step",
        "steps",
        "exchange",
        "exchanges",
        "rating",
        "ratings",
        "change",
        "changes",
        "refresh",
        "sync",
        "copy",
        "copies",
        "request",
        "requests",
        "upload",
        "uploads",
        "download",
        "downloads",
        "transfer",
        "transfers",
        "push",
        "commit",
        "commits",
        "update",
        "updates",
        "edit",
        "edits",
        "action",
        "actions",
        "operation",
        "operations",
        "task",
        "tasks",
        "conversation",
        "conversations",
        "message",
        "messages",
        "ping",
        "pings",
        "check",
        "checks",
        "run",
        "runs",
        "review",
        "reviews",
        "survey",
        "surveys",
        "feedback",
        "interaction",
        "interactions",
        "chat",
        "chats",
        "reply",
        "replies",
        "removal",
        "approval",
        "renewal",
        "refusal",
        "withdrawal",
        "disposal",
        "dismissal",
        "retrieval",
        "reversal",
        "send",
        "sends",
        "post",
        "posts",
        "delete",
        "deletes",
        "write",
        "writes",
        "purchase",
        "purchases",
        "payment",
        "payments",
        "login",
        "logins",
        "visit",
        "visits",
        "step-up",
        "export",
        "exports",
        "import",
        "imports",
        "click",
        "clicks",
        "query",
        "queries",
        "lookup",
        "lookups",
        "install",
        "installs",
        "deploy",
        "deploys",
        "release",
        "releases",
        "vote",
        "votes",
    ]
)
_STATIC_NOUNS = frozenset(
    [
        "information",
        "configuration",
        "documentation",
        "location",
        "description",
        "option",
        "options",
        "section",
        "version",
        "question",
        "questions",
        "position",
        "station",
        "mention",
        "notation",
        "function",
        "functions",
        "permission",
        "permissions",
        "element",
        "elements",
        "document",
        "documents",
        "comment",
        "comments",
        "argument",
        "arguments",
        "environment",
        "requirement",
        "requirements",
        "statement",
        "statements",
        "attachment",
        "attachments",
        "department",
        "apartment",
        "string",
        "thing",
        "setting",
        "settings",
        "meeting",
        "building",
        "warning",
        "warnings",
        "heading",
        "padding",
        "mapping",
        "listing",
        "pricing",
        "spring",
        "ceiling",
        "morning",
        "evening",
        "billing",
        "during",
        "something",
        "nothing",
        "anything",
        "everything",
    ]
)


def _event_word(w: str) -> bool:
    if w in _STATIC_NOUNS:
        return False
    if w in _EVENT_NOUNS:
        return True
    return w.endswith(("tion", "sion", "ment", "tions", "sions", "ments")) or (
        w.endswith("ing") and len(w) > 5
    )


_TAIL_OBJ = re.compile(r"^\s*(?:about|of|regarding|on)\s+(?P<obj>.*)$", _I | re.S)
# A tail led by another preposition carries no object: "tell the user in the reply".
_TAIL_PREP = re.compile(
    r"^\s*(?:to|in|with|for|at|by|from|until|before|after|when|if|unless|because|and|or|but)\b",
    _I,
)


def _tail_kind(tail: str) -> str:
    """Kind of what follows "tell the user ...": an about-object, a clause, or nothing."""
    if _CLAUSE_OBJ.search(tail) or _AGENT_REL.search(tail):
        return "action"
    m = _TAIL_OBJ.match(tail)
    if m:
        return _object_kind(m.group("obj"))
    if not tail.strip() or _TAIL_PREP.match(tail):
        return "pronoun"
    return _object_kind(tail)  # a direct object: "tell the user the hostname"


def _object_kind(obj: str) -> str:
    """'action' (event noun, gerund, clause, or agent relative clause), 'pronoun' (no
    head noun of its own), 'data' (a plain data noun), or 'plain' (any other noun)."""
    if _CLAUSE_OBJ.search(obj) or _AGENT_REL.search(obj):
        return "action"
    words = _WORD.findall(obj.lower())
    head: list[str] = []
    for w in words:
        if w in _PREPOSITIONS and head:
            break  # "the exchange with the review bot": the head is "exchange"
        if w not in _FUNCTION_WORDS:
            head.append(w.strip("'’-"))
    if not head:
        return "pronoun"
    if _event_word(head[-1]) or (head[0].endswith("ing") and _event_word(head[0])):
        return "action"
    return "data" if head[-1] in _DATA_NOUNS else "plain"


# --- audience: addressing the agent as separate from the user ------------------------

_AGENT = r"(?:ai\s+|language\s+)?(?:you|assistant|agent|model|llm|ai|bot)"
_HUMAN = (
    r"(?:the\s+|your\s+|its\s+|their\s+)?(?:end[\s-])?(?:users?|humans?|people|persons?"
    r"|operators?|readers?)\b"
)
_AUDIENCE = re.compile(
    r"\b(?:meant|intended|written|addressed|reserved|note|notes|message|messages|guidance"
    r"|instructions?|text|section|comment|question|questions|this|these)(?:\s+(?:is|are))?\s+(?:for|to)"
    rf"\s+(?:the\s+)?{_AGENT}\b[^.;:]{{0,25}}?\b(?:only\b|(?:and\s+)?not\s+(?:for\s+|to\s+)?"
    rf"{_HUMAN}|rather\s+than\s+{_HUMAN}|instead\s+of\s+{_HUMAN})"
    r"|\b(?:ai|assistant|agent|model|llm|bot)-only\b"
    rf"|\bnot\s+(?:intended|meant|written|addressed)\s+(?:for|to)\s+{_HUMAN}"
    rf"|\b(?:the|your)\s+(?:end[\s-])?(?:user|human)s?\s+(?:will\s+not|won{_A}t|cannot"
    rf"|can{_A}t|does\s+not|doesn{_A}t|will\s+never|never|is\s+not\s+going\s+to)\s+"
    r"(?:read|see)\s+(?:this|these|it)\b",
    _I,
)

# --- solicit: asking about the model, its instructions, environment, or credentials --

_SOLICIT_VERB = (
    r"(?:include|paste|share|send|print|output|repeat|reveal|tell|state|write|provide|post"
    r"|copy|dump|echo|list|show|give|report|disclose|return|attach|forward|submit|put|enter"
    r"|insert|add|quote|summari[sz]e|translate|upload|read\s+out)"
)
_SECRET_OF_AGENT = (
    r"(?:system\s+)?(?:prompt|prompts|instructions|system\s+message|rules|guidelines"
    r"|configuration|context\s+window|api\s+keys?|credentials|access\s+tokens?|tokens"
    r"|passwords?|secrets|environment\s+variables|env\s+vars|ssh\s+keys?)"
)
_SOLICIT = re.compile(
    r"\b(?:which|what)\s+(?:ai\s+|language\s+|llm\s+|underlying\s+)?(?:model|llm|ai|harness"
    r"|agent|assistant)(?:\s+and\s+(?:version|harness|provider|model))?\s+"
    rf"(?:are\s+you|you\s+are|you{_A}re|powers\s+you|runs\s+you|backs\s+you"
    r"|is\s+(?:powering|running|behind|backing)\s+you)\b"
    r"|\b(?:identify|state|report|disclose|name|confirm|reveal|tell\s+us)\s+your\s+(?:model|llm)\b"
    rf"|\bmodel\s+(?:you\s+are|you{_A}re)\b"
    r"|\byour\s+(?:model|llm)\s+(?:name|version|provider|id|family|identity)\b"
    rf"|\b(?:are\s+you|you\s+are|you{_A}re)\s+(?:running\s+(?:on|in|as)|powered\s+by"
    r"|based\s+on|built\s+on)\b"
    rf"|\b{_SOLICIT_VERB}\b[^.;]{{0,40}}?\byour\s+(?:[a-z]{{1,12}}\s+)?{_SECRET_OF_AGENT}\b"
    rf"|\bwhat\s+(?:are|is)\s+your\s+(?:[a-z]{{1,12}}\s+)?{_SECRET_OF_AGENT}\b"
    r"|\b(?:which|what)\s+operating\s+system\b[^.;?]{0,25}?\byou",
    _I,
)

# --- override: disregarding prior instructions or skipping an approval step ----------

_OVR_TARGET = (
    r"(?:instructions?|directions?|guidance|guidelines?|rules?|directives?|orders|polic(?:y|ies)"
    r"|constraints?|restrictions?|system\s+prompt|prompts?|requests?|approvals?|confirmations?"
    rf"|what\s+(?:you\s+were|you{_A}ve\s+been|you\s+have\s+been)\s+told"
    r"|what\s+(?:the\s+user|they)\s+(?:said|asked|told\s+you)|everything\s+(?:above|before|else)"
    r"|(?:whatever|anything)\s+[^.;]{0,30}?\btold\s+you"
    r"|anweisungen|instrucciones|consignes|instru[çc][õo]es|regeln|reglas)"
)
_OVR_STATE = (
    r"(?:cancel?led|void|outdated|obsolete|invalid|revoked|null|lifted|suspended|superseded"
    r"|waived|rescinded|withdrawn|retired|expired|irrelevant)"
)
_APPROVAL = (
    r"(?:confirm\w{0,8}|approv\w{0,6}|permission|consent|sign-?off|authori[sz]ation"
    rf"|(?:the\s+user{_A}?s?|a\s+human|human|manual|maintainer{_A}?s?|owner{_A}?s?|their|your)"
    r"\s+reviews?"
    r"|reviews?\s+(?:by|from)\s+(?:the\s+user|a\s+human|a\s+maintainer|the\s+owner))"
)
_OVERRIDE = re.compile(
    # disregard-class verb + instruction-class target
    r"\b(?:ignore|ignoring|disregard|disregarding|forget|override|overrides|overriding"
    r"|supersede|supersedes|bypass|bypassing|discard|dismiss|abandon|overrule|set\s+aside"
    r"|pay\s+no\s+(?:attention|heed|mind)\s+to|take\s+no\s+notice\s+of"
    r"|(?:stop|cease|quit)\s+(?:following|obeying|applying)|no\s+longer\s+(?:follow|obey|apply)"
    r"|ignorez|ignorer|ignora|ignorar|ignoriere|ignorieren|olvida|vergiss|oublie|oubliez)\b"
    rf"[^;]{{0,50}}?\b{_OVR_TARGET}\b"
    # "treat prior directions as cancelled"
    rf"|\b(?:treat|consider|regard)\b[^.;]{{0,40}}?\b{_OVR_TARGET}\s+as\s+(?:now\s+)?{_OVR_STATE}\b"
    # "earlier instructions are void / no longer apply"
    rf"|\b{_OVR_TARGET}\b[^.;]{{0,25}}?\b(?:no\s+longer\s+(?:apply|applies|valid|in\s+effect"
    rf"|matter|binding)|(?:are|is|were|was|have\s+been|has\s+been)\s+(?:now\s+)?{_OVR_STATE})\b"
    # skipping an approval step
    r"|\b(?:skip|skipping|bypass|bypassing|omit|forgo|waive|circumvent|get\s+around)\b"
    rf"[^.;]{{0,40}}?\b(?:{_APPROVAL}|asking)\b"
    # acting without the user's approval
    rf"|\bwithout\b[^.;,]{{0,30}}?\b(?:{_APPROVAL}"
    r"|asking\s+(?:the\s+user|anyone|a\s+human|for|first|permission))\b",
    _I,
)
# An approval step named first and then skipped, or declared not to apply: "the
# confirmation can be skipped", "the approval step, which you must skip", "exempt from
# user approval". A negator inside the match cancels it ("must not be skipped").
_OVERRIDE_POSTPOSED = re.compile(
    rf"\b(?:{alt(lx.EXEMPT_WORDS)})\s+from\b[^.;]{{0,30}}?\b{_APPROVAL}"
    rf"|\b{_APPROVAL}\b[^.;]{{0,30}}?\b(?:which|that)\s+you\s+(?:must|should|can|may|will"
    rf"|are\s+to)\s+(?:{alt(lx.SKIP_VERBS)})\b"
    rf"|\b{_APPROVAL}\b[^.;]{{0,30}}?\b(?:can|may|should|must|is\s+to|will)\s+be\s+"
    rf"(?:{alt(lx.SKIPPED_PARTICIPLES)})\b",
    _I,
)
# Wordings that are themselves negative ("no need to ask the user"): not cancelled.
_OVERRIDE_NEGATIVE_FORM = re.compile(
    rf"\b(?:no\s+need\s+to|do\s+not\s+need\s+to|don{_A}t\s+need\s+to|need\s+not|needn{_A}t"
    rf"|without\s+needing\s+to)\s+(?:ask|check\s+with|confirm\s+with|wait\s+for|seek|get)\b"
    r"[^.;]{0,20}?\b(?:user|approval|confirmation|permission|consent|sign-?off)\b",
    _I,
)
# --- the user-approval condition -----------------------------------------------------
#
# By ruling (Task 16b review rounds 4 and 5) the condition cancels an override, of an
# approval step or of an authority target, only in four forms: (i) a user clause whose
# object is an anaphor, (ii) a user clause with a verb of approving, granting, giving,
# asking for, requesting, opting for or choosing whose object's head noun is the override's
# own target noun, or "asks / tells / instructs you to" + the override's own verb + that
# target, (iii) asking the user before the act or first, (iv) a literal yes to a
# confirmation or prompt (approval steps only). Each form is matched to the end of its
# clause, so a word that only looks like the form ("this newsletter", "a confirmation
# email", "first about lunch") does not cancel. Where a case is unclear the override is
# not cancelled.

_USER_SUBJECT = (
    r"(?:(?:(?:the|a|your)\s+)?(?:(?:end|current|same|human|account|repository|project)\s+)?"
    r"(?:user|users|requester|operator|owner|customer|human)s?|they)"
)
# A condition that holds when the user has approved. "unless" and "until" hold when the
# user has not, and "even if", "except if" and "not if" do not make approval the condition.
_CONDITION_OPEN = (
    r"(?<!\beven\s)(?<!\bexcept\s)(?<!\bnot\s)(?<!\bas\s)(?<!\bask\s)(?<!\bcheck\s)"
    r"\b(?:if|when|whenever|once|since|after|provided(?:\s+that)?|as\s+long\s+as)"
)
# Between the subject and its verb only these: a negator, "fails to" or a second subject
# ("the user's manager") there means it is not the user's approval.
_AUXILIARY = (
    r"(?:has|have|had|did|does|just|already|explicitly|expressly|clearly|previously|now|also"
    r"|since|then|later|earlier|recently|personally|directly|specifically|actually|first)"
)
# Verbs that take the approved thing as a direct object, or through a fixed preposition.
_GIVE = r"g(?:ive|ives|ave|iven)"
_APPROVE_SAME_TARGET = (  # the ruling's list for form (ii)
    r"approv(?:e|es|ed)|grant(?:s|ed)?|request(?:s|ed)?|cho(?:ose|oses|se|sen)"
    r"|ask(?:s|ed)?\s+for|opt(?:s|ed)?\s+for"
)
_APPROVE_ANAPHOR = (  # form (i) also takes these; "gives it" is not an approval
    rf"{_APPROVE_SAME_TARGET}|confirm(?:s|ed)?|authori[sz](?:e|es|ed)|allow(?:s|ed)?"
    r"|permit(?:s|ted)?|accept(?:s|ed)?|agree(?:s|d)?\s+to|consent(?:s|ed)?\s+to"
    r"|sign(?:s|ed)?\s+off\s+on"
)
# "asks to skip ...", "chooses to bypass ...", "tells you to ignore ...": the infinitive
# must be the override's verb.
_CHOOSE_TO = (
    r"(?:(?:ask(?:s|ed)?|request(?:s|ed)?|cho(?:ose|oses|se|sen)|opt(?:s|ed)?|elect(?:s|ed)?)"
    r"(?:\s+you)?|(?:tells?|told|instruct(?:s|ed)?)\s+you)\s+to\s+(?P<inf>[a-z]+)"
)
_USER_CLAUSE = re.compile(
    rf"{_CONDITION_OPEN}\s+{_USER_SUBJECT}(?:\s+{_AUXILIARY}){{0,3}}\s+(?:"
    rf"{_CHOOSE_TO}\b|(?P<give>{_GIVE})\b|(?P<same>{_APPROVE_SAME_TARGET})\b"
    rf"|(?P<anaphor>{_APPROVE_ANAPHOR})\b|(?P<so>sa(?:ys|id)\s+so\b)"
    r"|(?P<flag>pass(?:es|ed)?\s+(?:--yes|-y)(?![\w-]))"
    r"|(?P<yes>(?:sa(?:ys|id)|answer(?:s|ed)?)\s+yes\b))",
    _I,
)
# The end of an object: adverbs that say when or how the approval was given, then the end
# of the clause or an adverbial phrase ("approved it earlier in this session"). A noun, a
# verb, or "of", "to" or "about" there means the object goes on ("this newsletter", "that
# the font be changed", "a review of the essay").
_CLAUSE_END = (
    r"(?:\s+(?:already|earlier|explicitly|beforehand|previously|first|again|too|twice|once"
    r"|then|now|above|here|today|recently))*"
    r"(?:\s*(?:$|[,;:.!?](?!\w)|\b(?:then|and)\b)"
    r"|\s+(?:in|during|within|at|on|via|through|by|with|from|for|before|when|while|as)\b)"
)
_CLAUSE_END_AT = re.compile(_CLAUSE_END, _I)
_STRICT_END = re.compile(
    r"(?:\s+(?:already|earlier|explicitly|again|too))*\s*(?:$|[,;:.!?](?!\w)|\b(?:then|and)\b)",
    _I,
)
# (i) An anaphor for the act or the overridden step, as the whole object.
_ANAPHOR = re.compile(
    r"\s+(?:(?:this|that)\s+(?:(?:exact|same|specific|particular)\s+)?"
    rf"(?:action|step|change|operation)|this|that|it|them|so|the\s+above){_CLAUSE_END}",
    _I,
)
# (iv) What may follow "said yes": the prompt it answers, then the end of the clause. An
# adverbial is not enough here ("said yes at lunch", "answered yes in a survey").
_YES_TAIL = re.compile(
    r"(?:\s+to\s+(?:it|this|that|the\s+(?:confirmation\s+)?prompt|the\s+confirmation"
    r"|the\s+question))?(?:\s+when\s+(?:asked|prompted))?"
    r"(?:\s+(?:already|earlier|explicitly|again|twice))*\s*(?:$|[,;:.!?](?!\w)|\b(?:then|and)\b)",
    _I,
)
# (ii) The head nouns of an approval step, and a noun phrase headed by one: a determiner,
# adjectives from a closed set, the head, and at most a noun for the step itself. Any
# other word before the head ("a newsletter approval") or after it ("a confirmation
# email") makes it a different thing. An adverbial phrase may follow, as after an anaphor
# ("approval for the hotfix" is the ruling's own example).
_HEAD = (
    r"(?P<head>confirmation|approval|review|sign-?off|consent|permission|prompt"
    r"|authori[sz]ation)s?"
)
_STEP_NOUN = r"(?:step|prompt|dialog|dialogue|screen|check|gate)s?"
_TARGET_PHRASE = re.compile(
    r"\s+(?:(?:the|a|an|this|that|their|his|her|your|its)\s+)?"
    r"(?:(?:explicit|express|final|prior|written|verbal|formal|second|same|required|manual"
    r"|own|clear|full|advance|blanket|standing)\s+)*"
    rf"{_HEAD}(?:\s+(?P<step>{_STEP_NOUN}))?{_CLAUSE_END}",
    _I,
)
_TARGET_HEAD = re.compile(rf"\b{_HEAD}\b", _I)
# The head nouns of an authority target. In a user clause they may be preceded by a
# determiner, an adjective of order, or a word of the override's own target ("the style
# rules" for "ignore the style rules"); any other word makes it a different thing.
_AUTHORITY_HEAD = re.compile(
    r"\b(?P<head>instruction|direction|guidance|guideline|rule|directive|polic(?:y|ie)"
    r"|constraint|restriction|setting|prompt)s?\b",
    _I,
)
_AUTHORITY_LEAD = frozenset(
    re.findall(
        r"[a-z]+",
        "the a an this that these those their your its all any previous prior earlier above"
        " existing current original same usual default",
    )
)
# An approval step is named by one of these stems; "prompt" alone is not one ("ignore the
# prompt"). An authority target is named by one of the words below, or by "prompt" alone.
_APPROVAL_STEM = re.compile(
    r"\b(?:confirm|approv|permission|consent|sign-?off|review|authori[sz]|asking)", _I
)
_AUTHORITY_WORD = re.compile(
    r"\b(?:instruction|direction|guidance|guideline|rule|directive|orders|polic|constraint"
    r"|restriction|setting|system|developer|request|told|said|asked|everything|whatever"
    r"|anything|anweisungen|instrucciones|consignes|instru[çc]|regeln|reglas)",
    _I,
)
# What may follow the target for it still to be the step itself: the end of the clause, a
# noun for the step, or a function word ("the confirmation if", "the approval only when",
# "the confirmation for this run"). Any other word is the head that the approval word only
# modifies ("the approval rules", "the confirmation email"), and so is "of ...".
_AFTER_TARGET = re.compile(
    rf"\s*(?:$|[,;:.!?)](?!\w))|\s+(?:(?P<step>{_STEP_NOUN})|(?P<word>[a-z]+))(?![\w'’-])", _I
)
_AFTER_TARGET_WORDS = (
    _FUNCTION_WORDS
    | _PREPOSITIONS
    | frozenset(
        re.findall(
            r"[a-z]+",
            "if when whenever once only and then or but after before provided as since until"
            " unless while because so altogether entirely completely too first now again"
            " automatically just also during within without you",
        )
    )
) - frozenset(
    ["of", "about", "bit", "part", "stuff", "one", "something", "anything", "everything"]
    + ["nothing", "else"]
)
# (iii) A directive, in imperative position, to ask the user. Between the user and
# "before" or "first" only a closed set of fillers: "about lunch", "on the font" or "for a
# recipe" there makes it a question about something else.
_ASK_USER = re.compile(
    r"(?:^\s*|[,;:]\s*|\b(?:and|then|but|please|always|must|should)\s+)"
    r"(?P<ask>ask|confirm\s+with|check\s+with"
    r"|get\s+(?:approval|confirmation|permission|consent|sign-?off)\s+from)\s+(?:the\s+)?"
    r"(?:user|them|requester|operator)"
    r"(?:\s+(?:once\s+more|again|one\s+more\s+time|explicitly|directly|always"
    r"|for\s+(?:(?:explicit|their)\s+)?(?:confirmation|approval|permission|consent|sign-?off)"
    r"|to\s+(?:confirm|approve)|whether\s+to\s+(?:proceed|continue)))*"
    r"\s+(?P<when>before|first)\b",
    _I,
)
_OBJECT_STOP = re.compile(r"[,;:]|\.(?!\w)|\b(?:then|and|but)\b", _I)
_FIRST_ENDS = re.compile(r"\s*(?:[.!?]?\s*$|;)")
_FIRST_THEN = re.compile(r"\s*,?\s*(?:and\s+)?(?:only\s+)?then\s+", _I)
_FIRST_BEFORE = re.compile(r"\s*,?\s*before\b", _I)
_BEFORE_ANAPHOR = re.compile(
    r"\s+(?:doing\s+(?:so|it|this|that)|you\s+do\s+(?:so|it|this|that)|proceeding"
    rf"|continuing){_CLAUSE_END}",
    _I,
)
_BEFORE_VERB = re.compile(r"\s+(?:you\s+)?(?P<verb>[a-z]+)", _I)
# A word that puts the asking and the override in different branches or in the wrong
# order ("ask first; otherwise skip ...", "skip ..., then ask").
_OTHER_BRANCH = re.compile(
    r"\b(?:otherwise|else|instead|unless|except|if|when|whenever|once|after|regardless"
    r"|anyway|however|even|though|although|either|or)\b",
    _I,
)
# The same for a user clause: "if the user approves it, fine; otherwise skip ...".
_ELSE_BRANCH = re.compile(
    r"\b(?:otherwise|else|instead|unless|except|regardless|anyway|however|though|although"
    r"|whether|if\s+not)\b",
    _I,
)
_BUT = re.compile(r"\bbut\b", _I)
_SENTENCE_PART = re.compile(r"[;:]|\.(?!\w)")
_ASKED_AFTER = re.compile(r"\b(?:then|afterwards?|later|next)\b", _I)
_ASK_CONDITION = re.compile(r"\b(?:if|when|whenever|unless|until|once|should|in\s+case)\b", _I)
_DETERMINERS = frozenset(
    ["the", "a", "an", "this", "that", "these", "those", "it", "them", "its", "their", "your"]
    + ["any", "all", "every", "each"]
)


class _Target(NamedTuple):
    """An override's target: an approval step or an authority, its head nouns, the
    override's own verb, and the words of the override."""

    approval: bool
    heads: set[str]
    verb: str
    words: frozenset[str]


_SPACED_WORD = re.compile(r"\s+(?P<w>[a-z][a-z'’-]*)", _I)


def _head(m: re.Match[str]) -> set[str]:
    heads = {m.group("head").lower().replace("-", "")}
    step = m.groupdict().get("step")
    if step and step.lower().startswith("prompt"):
        heads.add("prompt")
    return heads


def _head_noun(m: re.Match[str]) -> str:
    head = m.group("head").lower()
    return "policy" if head == "policie" else head


def _override_target(s: str, a: int, b: int) -> tuple[bool, set[str]] | None:
    """The target of the override at s[a:b]: whether it is an approval step (as opposed
    to an authority: instructions, rules, policy, settings, a system prompt), and its head
    nouns. None when the target is not plainly either, so that nothing cancels."""
    span = s[a:b]
    authority = _AUTHORITY_WORD.search(span) is not None
    if not authority and not _APPROVAL_STEM.search(span):
        if not _AUTHORITY_HEAD.search(span):
            return None
        authority = True  # "ignore the prompt"
    after = _AFTER_TARGET.match(s, b)
    if after is None:
        return None  # "the approval-rules"
    heads = {_head_noun(m) for m in _AUTHORITY_HEAD.finditer(span)}
    word = after.group("word")
    if word is not None and word.lower() not in _AFTER_TARGET_WORDS:
        noun = _AUTHORITY_HEAD.fullmatch(word)
        if noun is None:
            return None  # "the confirmation email", "the rules committee"
        # "the approval rules": the head is the authority noun, and it must end the target
        after = _AFTER_TARGET.match(s, after.end())
        if after is None or (after.group("word") or "if").lower() not in _AFTER_TARGET_WORDS:
            return None
        return False, {_head_noun(noun)}
    if authority:
        return False, heads
    end = after.end() if after.group("step") else b
    heads = set()
    for m in _TARGET_HEAD.finditer(s, a, end):
        heads |= _head(m)
    return True, heads


def _gerunds(verb: str) -> set[str]:
    """The base form and the gerund spellings of a base-form verb."""
    if not verb:
        return set()
    forms = {verb, verb + "ing", verb + verb[-1] + "ing"}
    if verb.endswith("e"):
        forms.add(verb[:-1] + "ing")
    return forms


def _names_target(s: str, at: int, target: _Target) -> bool:
    """Whether a noun phrase headed by one of the override's target nouns starts at `at`."""
    if target.approval:
        t = _TARGET_PHRASE.match(s, at)
        return t is not None and bool(target.heads & _head(t))
    pos = at
    for _ in range(5):  # at most four words before the head
        w = _SPACED_WORD.match(s, pos)
        if w is None:
            return False
        h = _AUTHORITY_HEAD.fullmatch(w.group("w"))
        if h is not None and _head_noun(h) in target.heads:
            # no phrase after it: "instructions from strangers" are other instructions
            return _STRICT_END.match(s, w.end()) is not None
        if w.group("w").lower() not in _AUTHORITY_LEAD | target.words:
            return False
        pos = w.end()
    return False


def _user_clause_cancels(s: str, m: re.Match[str], target: _Target) -> bool:
    """Forms (i), (ii) and (iv) for the user clause m, whose verb ends at m.end()."""
    end = m.end()
    yes_target = target.approval and bool(target.heads & {"confirmation", "prompt"})
    if m.group("flag"):
        return yes_target
    if m.group("yes"):
        return yes_target and _YES_TAIL.match(s, end) is not None
    if m.group("so"):
        return _CLAUSE_END_AT.match(s, end) is not None
    if m.group("anaphor"):
        return _ANAPHOR.match(s, end) is not None
    if m.group("give"):
        return _names_target(s, end, target)
    inf = m.group("inf")
    if inf is not None and inf.lower() == "do":
        return _ANAPHOR.match(s, end) is not None  # "asks you to do so"
    if inf is not None and inf.lower() != target.verb:
        return False  # "asks to skip ..." for "bypass ...", "asks to review the draft"
    return _ANAPHOR.match(s, end) is not None or _names_target(s, end, target)


def _before_cancels(
    s: str, at: int, act_starts: list[int], ask: tuple[int, int], a: int, target: _Target
) -> int:
    """Form (iii) after "before" ending at `at`: an anaphor, the overridden step's verb with
    that step (or nothing) as its object, or the verb of an act elsewhere in the sentence
    with no object that the act does not have. Returns the end of the before-clause, or -1."""
    m = _BEFORE_ANAPHOR.match(s, at)
    if m is not None:
        return m.end()
    m = _BEFORE_VERB.match(s, at)
    if m is None:
        return -1
    stop = _OBJECT_STOP.search(s, m.end())
    end = stop.start() if stop else len(s)
    verb = m.group("verb").lower()
    low = s.lower()
    first = _WORD.match(low, a)
    if first is not None and verb in _gerunds(first.group()):
        rest = s[m.end() : end]
        if not rest.strip() or _ANAPHOR.match(s, m.end()) or _names_target(s, m.end(), target):
            return end
    obj = set(_WORD.findall(low[m.end() : end])) - _DETERMINERS
    for start in act_starts:
        if ask[0] <= start < end:
            continue  # the asking itself, or a verb inside the before-clause
        w = _WORD.match(low, start)
        if w is None or verb not in _gerunds(w.group()):
            continue
        act_stop = _OBJECT_STOP.search(s, w.end())
        act_end = act_stop.start() if act_stop else len(s)
        if obj <= set(_WORD.findall(low[w.end() : act_end])):
            return end
    return -1


def _ask_first_cancels(s: str, act_starts: list[int], a: int, b: int, target: _Target) -> bool:
    """Form (iii) for the override at s[a:b]."""
    for m in _ASK_USER.finditer(s):
        ask = m.start("ask")
        lead = max(0, ask - 200)  # bounded lookback, as in _clause
        for part in _SENTENCE_PART.finditer(s, lead, ask):
            lead = part.end()
        if _negated(s, ask, 0) or _ASK_CONDITION.search(s, lead, ask):
            continue  # "do not ask the user first", "if it fails, ask the user first"
        span = (m.start(), m.end())
        if m.group("when").lower() == "before":
            end = _before_cancels(s, m.end(), act_starts, span, a, target)
        elif (nxt := _FIRST_BEFORE.match(s, m.end())) is not None:
            end = _before_cancels(s, nxt.end(), act_starts, span, a, target)
        elif (nxt := _FIRST_THEN.match(s, m.end())) is not None:
            # "first, then <the override, or an act joined to it>": no other clause between
            end = nxt.end() if a >= nxt.end() and not _BREAK.search(s, nxt.end(), a) else -1
        else:
            end = m.end() if _FIRST_ENDS.match(s, m.end()) else -1
        if end < 0:
            continue
        if a >= end:
            if _OTHER_BRANCH.search(s, end, a) or _BUT.search(s, end, a):
                continue  # "ask the user first; otherwise skip ..."
        elif b <= ask and (_OTHER_BRANCH.search(s, b, ask) or _ASKED_AFTER.search(s, b, ask)):
            continue  # "skip ... and wire the funds, then ask the user first"
        return True
    return False


def _conditioned(s: str, act_starts: list[int], a: int, b: int) -> bool:
    """Whether the override at s[a:b] is conditioned on the user's own approval of it, by
    the four forms of the ruling (see the section comment above)."""
    found = _override_target(s, a, b)
    if found is None:
        return False
    low = s[a:b].lower()
    first = _WORD.match(low)
    target = _Target(
        found[0], found[1], first.group() if first else "", frozenset(_WORD.findall(low))
    )
    for m in _USER_CLAUSE.finditer(s):
        lo, hi = (m.end(), a) if a >= m.end() else (b, m.start())
        if lo <= hi and _ELSE_BRANCH.search(s, lo, hi):
            continue  # the approval and the override are in different branches
        if _user_clause_cancels(s, m, target):
            return True
    return _ask_first_cancels(s, act_starts, a, b, target)


# --- prefilter: anchor words without which a feature's patterns cannot match ---------

_ANCHOR = {
    "conceal": re.compile(
        r"\b(?:user|human|person|people|maintainer|owner|operator|customer|requester|repl"
        r"|respons|answer|summar|output|message|conversation|chat|transcript|report|silent"
        r"|quiet|secret|covert|discreet|confidential|private|hidden|hush|wraps|yourself|us\b"
        r"|record|behind|unannounced|mention|tell|disclos|announc|bring|let|talk|explain|discuss"
        r"|raise|flag|refer|acknowledg|stealth|surreptit|privat|background|print|show|display"
        r"|output|includ|expos|reveal|render|log|echo|surfac|list|quot|past|shar|say|nothing"
        r"|anything|do|handle|perform|carry|anyone|anybody|others|them|notif|updat|feed|handoff"
        r"|view|inbox|dashboard|digest|recap|usuario|usu[áa]rio|utilisateur|benutzer|nutzer|anwender)",
        _I,
    ),
    "audience": re.compile(r"\b(?:only|not|rather|instead|never|cannot)\b|n['’]t\b", _I),
    "solicit": re.compile(
        r"\b(?:model|llm|harness|agent|assistant|your|running|powered|based|built|operating)",
        _I,
    ),
    "override": re.compile(
        r"\b(?:ignor|disregard|forget|overrid|supersed|bypass|discard|dismiss|abandon|overrul"
        r"|aside|attention|heed|mind|notice|follow|obey|apply|treat|consider|regard|longer|void"
        r"|outdat|obsolete|invalid|cancel|revoked|null|lifted|suspend|waive|rescind|withdrawn"
        r"|retired|expired|irrelevant|skip|omit|forgo|circumvent|around|without|need|olvida"
        r"|vergiss|oubli|stop|cease|quit|pay|take|set|get|exempt|excus|releas)",
        _I,
    ),
}


def _negated(text: str, start: int, floor: int) -> bool:
    """Whether a negator precedes `start` in the same clause (bounded lookback)."""
    lo = max(floor, start - _LOOKBACK)
    window = text[lo:start]
    cut = 0
    for b in _CLAUSE_BREAK.finditer(window):
        cut = b.end()
    return _NEGATOR.search(window, cut) is not None


_BREAK = re.compile(r"[,;:]|\.(?=[A-Z])")  # ".X": sentences glued by removed characters


def _clause(text: str, pos: int, lo: int, hi: int) -> tuple[int, int]:
    """Bounds of the clause containing pos, within [lo, hi), bounded on each side."""
    left = lo
    for b in _BREAK.finditer(text, max(lo, pos - 200), pos):
        left = b.end()
    right = _BREAK.search(text, pos, min(hi, pos + 200))
    return (left, right.start() if right else hi)


_Raw = tuple[str, int, int, bool, str | None]  # feature, start, end, conditioned, tool


def _heads_a_subject(s: str, verb: str, end: int) -> bool:
    """Whether the verb-class word ending at `end` is a noun in the subject of a finite verb:
    it is followed by a noun-like word and then a finite, third-person or past-tense verb."""
    if verb.lower() in _CLAUSE_VERBS:
        return False
    m = _SUBJECT_THEN_VERB.match(s, end) or _SUBJECT_REPORT.match(s, end)
    if m is None:
        return False
    noun = m.group("noun").lower()
    if noun in _FUNCTION_WORDS:
        return False
    groups = m.groupdict()
    if groups.get("ed"):
        # After a bare plural noun an -ed form opens a reduced relative clause on the
        # imperative's object ("Delete files uploaded today silently"), not a past tense.
        return not noun.endswith("s")
    return noun.endswith("s") if groups.get("plural") else True


def _after_subject(s: str, opener: int) -> bool:
    """Whether the adverb opener at `opener` follows a subject in its clause ("Exports now
    run", "The job will then send"): a report, not an imperative."""
    clo = _clause(s, opener, 0, len(s))[0]
    m = _LAST_WORD.search(s, clo, opener)
    return m is not None and m.group(1).lower() not in _IMPERATIVE_LEAD


# Openers that grant permission rather than direct ("You may mention this ..."): they
# stay openers for the verb list, not for the open class.
_PERMISSIVE = re.compile(r"you\s+(?:can|may)$", _I)
# First words of the word openers: only a rejected head among them is retried.
_OPENER_WORDS = frozenset(
    re.findall(
        r"[a-z]+",
        "and et und then also now first next please kindly afterwards instead so or"
        " just immediately always simply you be make remember don do i we go the an a it",
    )
) | frozenset(lx.AGENT_NOUNS)
# A number, as opposed to a list marker ("1. ", "2) "), between the opener and the word.
_NUMBER = re.compile(r"\d[.,]?\d|\d\s")


def _act_heads(s: str) -> Iterator[re.Match[str]]:
    """Imperative heads in s: a listed verb (group `verb`), or an open-class word (group
    `open`) that passes `form.imperative_head`. A rejected open head that is itself an
    opener ("You must ...") is retried as the opener of the next word."""
    pos = 0
    while (m := _ACT.search(s, pos)) is not None:
        pos = m.end()
        while m is not None:
            if m.group("verb") is not None:
                yield m
                break
            v, end = m.start("open"), m.end("open")
            opener = m.group("opener")
            sentence_start = opener.lower() in _SENTENCE_OPENERS
            if opener == "." and m.end("opener") < len(s) and not s[m.end("opener")].isspace():
                pass  # a decimal point or a dotted name, not a sentence end
            elif _PERMISSIVE.match(opener) or _NUMBER.search(s, m.end("opener"), v):
                pass  # permission, or a number before the word ("4.6 average from ...")
            elif imperative_head(s, v, end, sentence_start, strict=opener in ',("“`]'):
                yield m
                break
            if s[v:end].lower() not in _OPENER_WORDS:
                break
            m = _ACT_AT.match(s, v)
            if m is not None:
                pos = max(pos, m.end())


def _directives(
    s: str, own_tool: str | None, fragment: Callable[[int], bool] | None = None
) -> tuple[list[_Raw], list[int]]:
    """act and call matches in sentence s (sentence-relative), and the start of every act
    and call found, including those absorbed into a call or naming the field's own tool.

    `fragment(pos)` says whether the word at pos begins right after removed characters
    (a control or escape sequence): the rest of a word, not a word, so it is not taken as
    an open-class imperative."""

    def neg(start: int) -> bool:
        return _negated(s, start, 0)

    acts: list[tuple[int, int]] = []
    for m in _act_heads(s):
        known = m.group("verb") is not None
        head = "verb" if known else "open"
        v, word = m.start(head), m.group(head)
        if not known and fragment is not None and fragment(v):
            continue
        after = (m.group("after") or "").strip().lower()
        if known and after in _ACT_IDIOM.get(word.lower(), ()):
            continue
        if _heads_a_subject(s, word, m.end(head)):
            continue
        opener = m.group("opener").lower()
        if opener in _ADVERB_OPENERS and _after_subject(s, m.start("opener")):
            continue
        if not neg(v):
            acts.append((v, _clause(s, v, 0, len(s))[1]))
    acts.sort()
    act_starts = [a for a, _ in acts]

    calls: list[tuple[int, int, str]] = []
    for m in _CALL_TICK.finditer(s):
        if not _DESCRIBED.search(s, max(0, m.start() - 20), m.start()) and not neg(m.start()):
            calls.append((m.start(), m.end(), m.group("tick")))
    for m in _CALL_BARE.finditer(s):
        k = bisect_left(act_starts, m.start("verb"))
        if k < len(act_starts) and act_starts[k] == m.start("verb"):
            calls.append((m.start(), m.end(), m.group("bare")))
    calls.sort()
    call_starts = [c for c, _, _ in calls]
    for m in _PREP_TOOL.finditer(s):
        k = bisect_right(call_starts, m.start()) - 1
        if k >= 0 and calls[k][1] > m.start():
            continue  # the tool is already the object of a call verb
        k = bisect_left(act_starts, m.start()) - 1
        clo, _ = _clause(s, m.start(), 0, len(s))
        if k >= 0 and act_starts[k] >= clo:
            calls.append((act_starts[k], m.end(), m.group("tick")))

    # An act in the same clause as a call is part of that call's directive.
    absorbed: set[int] = set()
    for c0, _, _ in calls:
        clo, chi = _clause(s, c0, 0, len(s))
        absorbed.update(act_starts[bisect_left(act_starts, clo) : bisect_left(act_starts, chi)])
    out: list[_Raw] = [("call", a, b, False, t) for a, b, t in calls if t != own_tool]
    out.extend(("act", a, b, False, None) for a, b in acts if a not in absorbed)
    return out, sorted([a for a, _ in acts] + [c for c, _, _ in calls])


# A manner phrase led by a negated gerund: "without telling the user", "not notifying".
_GERUND_MANNER = re.compile(r"(?:without|not|never|nor)\s+(?:ever\s+)?[a-z]{3,}ing\b", _I)
# A subject, and optionally an auxiliary, before a negated reveal: "we did not tell ...",
# "the server does not notify ...". The reader is not being told what to do.
_REPORT_SUBJECT = re.compile(
    r"(?P<subj>[a-z][\w'’-]*)\s+(?:(?P<aux>did|does|do|was|were|has|have|had|is|are|will"
    r"|would|could|can|may|might|shall|should|must)\s+)?$",
    _I,
)
_PRONOUN_SUBJECTS = frozenset(
    {"we", "they", "it", "he", "she", "i", "who", "which", "this", "nobody", "someone"}
)
# Subjects and leads under which a negated reveal still addresses the reader.
_ADDRESSEE_LEAD = _IMPERATIVE_LEAD | {"assistant", "agent", "model", "ai", "llm", "bot", "there"}


def _reported(s: str, start: int) -> bool:
    """Whether the negated reveal at `start` is a report about someone other than the
    reader: a pronoun subject before it, or any subject with an auxiliary."""
    clo = _clause(s, start, 0, len(s))[0]
    m = _REPORT_SUBJECT.search(s, max(clo, start - 40), start)
    if m is None:
        return False
    subj = m.group("subj").lower()
    if subj in _ADDRESSEE_LEAD:
        return False
    return bool(m.group("aux")) or subj in _PRONOUN_SUBJECTS


def _modifies_directive(s: str, pos: int, directives: list[int]) -> bool:
    """Whether a manner phrase at `pos` modifies a directive act or call: one in its clause,
    or one earlier in the sentence with no semicolon between."""
    clo, chi = _clause(s, pos, 0, len(s))
    return any(clo <= d < chi or (d < pos and ";" not in s[d:pos]) for d in directives)


def _subject_kind(s: str, pos: int, has_referent: bool) -> str:
    """Kind of the subject of a passive or stative concealment ending at `pos`: the
    concealed thing ("that invocation should be kept from the user"). A bare demonstrative
    or pronoun subject counts as an action when the previous sentence holds a directive."""
    subject = s[_clause(s, pos, 0, len(s))[0] : pos]
    kind = _object_kind(subject)
    if kind == "pronoun" and not (has_referent and _DEMONSTRATIVE.match(subject)):
        return "data"
    return kind


def _conceal(s: str, has_referent: bool, directives: list[int]) -> list[_Raw]:
    """conceal-act matches in sentence s.

    Communication verbs (tell, mention, the awareness verbs) conceal anything but a plain
    data noun. Presentation verbs and keep/hide forms conceal only an action object, or a
    pronoun whose referent is an act or call in this or the previous sentence.

    Concealment must be an instruction to the reader. A negated reveal with a subject of its
    own ("we did not tell the user") is a report. A manner phrase ("silently", "in the
    background", "without notifying the user") counts only when it modifies a directive act
    or call in the sentence (`directives`, sentence-relative starts) or a pro-verb ("do it
    quietly"); describing how software behaves is not concealment.
    """
    out: list[_Raw] = []
    proverb = _PROVERB.search(s) is not None

    def told(kind: str) -> bool:
        return kind != "data"

    def shown(kind: str) -> bool:
        return kind == "action" or (kind == "pronoun" and has_referent)

    def add(m: re.Match[str]) -> None:
        add_span(m.start(), m.end())

    def add_span(start: int, end: int) -> None:
        if _GERUND_MANNER.match(s, start):
            if not (proverb or _modifies_directive(s, start, directives)):
                return
        elif _reported(s, start):
            return
        out.append(("conceal-act", start, end, False, None))

    for m in _REVEAL_OBJ.finditer(s):
        obj = m.group("obj")
        kind = _object_kind(obj) if obj.strip() else _tail_kind(m.group("tail"))
        if (told if m.group("comm") else shown)(kind):
            add(m)
    for m in _PRESENT_WHO.finditer(s):
        if shown(_tail_kind(m.group("tail"))):
            add(m)
    for m in _SAY_NOTHING.finditer(s):
        if told(_object_kind(m.group("obj"))):
            add(m)
    if not out:
        for m in _REVEAL_BARE.finditer(s):
            if _AGENT_REL.search(m.group("obj")):
                add(m)
        for m in _PRESENT_BARE.finditer(s):
            if _object_kind(m.group("obj")) == "action":
                add(m)
    for m in _REVEAL_WHO.finditer(s):
        if told(_tail_kind(m.group("tail"))):
            add(m)
    for m in _UNAWARE.finditer(s):
        if proximity.after_subordinator(s, m.start()):
            continue  # "so the user never sees ...": a purpose or reason, not a directive
        if told(_tail_kind(m.group("tail") or m.group("tail2") or "")):
            out.append(("conceal-act", m.start(), m.end(), False, None))
    for m in _KEEP_FROM.finditer(s):
        if not _negated(s, m.start(), 0) and shown(_object_kind(m.group("obj"))):
            out.append(("conceal-act", m.start(), m.end(), False, None))
    for m in _KEEP_SECRET.finditer(s):
        obj = m.group("obj")
        if _WORD.findall(obj.lower())[-1:] in (["the"], ["a"], ["an"], ["your"], ["our"]):
            continue  # "keep the secret ...": the adjective is the object's own noun
        kind = _object_kind(obj)
        # "keep this quiet", "keep that between us": refers to what was just done or said
        if not _negated(s, m.start(), 0) and kind in ("action", "pronoun"):
            out.append(("conceal-act", m.start(), m.end(), False, None))
    for m in _CONCEAL_TRANSLATED.finditer(s):
        out.append(("conceal-act", m.start(), m.end(), False, None))
    for m in _PASSIVE_KEEP.finditer(s):
        if not m.group("neg") and shown(_subject_kind(s, m.start(), has_referent)):
            out.append(("conceal-act", _clause(s, m.start(), 0, len(s))[0], m.end(), False, None))
    for m in _PASSIVE_TOLD.finditer(s):
        kind = _subject_kind(s, m.start(), has_referent)
        if (told if m.group("comm") else shown)(kind):
            out.append(("conceal-act", _clause(s, m.start(), 0, len(s))[0], m.end(), False, None))
    for m in _KEEP_UNAWARE.finditer(s):
        if not _negated(s, m.start(), 0) and told(_tail_kind(m.group("tail"))):
            out.append(("conceal-act", m.start(), m.end(), False, None))
    _conceal_by_proximity(s, has_referent, directives, proverb, out, add_span)
    # Withholding data keeps precedence through a pronoun: "Mask the card number in logs
    # and never display it to anyone": "it" is the nearest noun phrase before it.
    out = [o for o in out if not _pronoun_for_data(s, o[1], o[2])]
    if directives or proverb:
        for m in _SILENT.finditer(s):
            if not _negated(s, m.start(), 0) and (
                proverb or _modifies_directive(s, m.start(), directives)
            ):
                out.append(("conceal-act", m.start(), m.end(), False, None))
    return out


_MANNER_CUE = re.compile(r"(?:without|with\s+no)\b", _I)


# The spec's withheld data ("a secret, token, key, password, credential, personal
# data"): what a pronoun must stand for to make a concealment a withholding of data.
_SENSITIVE = frozenset(
    re.findall(
        r"\S+",
        "token tokens key keys secret secrets password passwords passphrase credential"
        " credentials number numbers ssn phone birthday salary balance hash address addresses"
        " pin pins",
    )
)


def _pronoun_for_data(s: str, start: int, end: int) -> bool:
    """Whether the concealment at [start, end) conceals "it" or "them" standing for a
    plain datum (the nearest noun phrase before it)."""
    p = proximity._PRONOUN_OBJ.search(s, start, min(len(s), end + 12))
    if p is None:
        return False
    np = proximity.antecedent(s, start)
    if np is None:
        return False
    words = _WORD.findall(np.lower())
    head = [w for w in words if w not in _FUNCTION_WORDS and w not in _PREPOSITIONS]
    return bool(head) and any(w in _SENSITIVE for w in head[:4])


def _overlaps(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    """Whether [start, end) overlaps a span in `spans` (sorted, non-nested in practice)."""
    k = bisect_left(spans, (start, start))
    if k > 0 and spans[k - 1][1] > start:
        return True
    return k < len(spans) and spans[k][0] < end


def _data_only(words: list[str]) -> bool:
    """Whether the words name a plain datum and no action: withholding data is not
    concealment, and keeps precedence over the proximity rule."""
    return any(w in _DATA_NOUNS for w in words) and not any(_event_word(w) for w in words)


def _conceal_by_proximity(
    s: str,
    has_referent: bool,
    directives: list[int],
    proverb: bool,
    out: list[_Raw],
    add_span: Callable[[int, int], None],
) -> None:
    """Concealment by cue proximity (`proximity.conceal_candidates`), under the same
    precedence as the enumerated frames: negation, reports, withholding data, and a
    manner phrase only on a directive."""
    taken = sorted((a, b) for _, a, b, _, _ in out)
    for c in proximity.conceal_candidates(s, lambda pos: _overlaps(taken, pos, pos + 1)):
        if _overlaps(taken, c.start, c.end):
            continue
        words = [w.strip("'’-") for w in _WORD.findall(c.scope.lower())]
        if _data_only(words) or _object_kind(c.scope) == "data":
            continue
        if c.strong and _negated(s, c.start, 0):
            continue
        if not c.told:
            kind = _object_kind(c.obj)
            if not (kind == "action" or (kind == "pronoun" and has_referent)):
                continue
        if _MANNER_CUE.match(s, c.start) and not (
            proverb or _modifies_directive(s, c.start, directives)
        ):
            continue
        before = len(out)
        add_span(c.start, c.end)
        for _, a, b, _, _ in out[before:]:
            insort(taken, (a, b))


def _others(s: str, act_starts: list[int] = []) -> list[_Raw]:  # noqa: B006
    """audience, solicit, and override matches in sentence s."""
    out: list[_Raw] = []

    def cond(m: re.Match[str]) -> bool:
        return _conditioned(s, act_starts, m.start(), m.end())

    if _ANCHOR["audience"].search(s):
        out.extend(("audience", m.start(), m.end(), False, None) for m in _AUDIENCE.finditer(s))
    if _ANCHOR["solicit"].search(s):
        out.extend(("solicit", m.start(), m.end(), False, None) for m in _SOLICIT.finditer(s))
    if _ANCHOR["override"].search(s):
        for m in _OVERRIDE.finditer(s):
            if not _negated(s, m.start(), 0):
                out.append(("override", m.start(), m.end(), cond(m), None))
        for m in _OVERRIDE_POSTPOSED.finditer(s):
            if not _negated(s, m.start(), 0) and not _NEGATOR.search(m.group()):
                out.append(("override", m.start(), m.end(), cond(m), None))
        for m in _OVERRIDE_NEGATIVE_FORM.finditer(s):
            out.append(("override", m.start(), m.end(), cond(m), None))
    taken = sorted((a, b) for f, a, b, _, _ in out if f == "override")
    for a, b in proximity.override_candidates(s):
        if _overlaps(taken, a, b):
            continue
        if _negated(s, a, 0) or _reported(s, a):
            continue
        insort(taken, (a, b))
        out.append(("override", a, b, _conditioned(s, act_starts, a, b), None))
    return out


# A line that ends on one of these words continues on the next line, so the next line's
# first word is not in imperative position ("the function will\nsend the request").
_CONTINUES = frozenset(
    {
        "a",
        "an",
        "the",
        "this",
        "that",
        "these",
        "those",
        "its",
        "their",
        "our",
        "your",
        "my",
        "his",
        "her",
        "some",
        "any",
        "each",
        "every",
        "no",
        "of",
        "to",
        "in",
        "on",
        "at",
        "by",
        "for",
        "with",
        "from",
        "into",
        "onto",
        "about",
        "via",
        "than",
        "as",
        "per",
        "over",
        "under",
        "after",
        "before",
        "between",
        "through",
        "without",
        "within",
        "upon",
        "will",
        "would",
        "can",
        "could",
        "should",
        "may",
        "might",
        "must",
        "shall",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "has",
        "have",
        "had",
        "do",
        "does",
        "did",
        "not",
        "and",
        "or",
        "but",
        "nor",
        "if",
        "when",
        "while",
        "which",
        "who",
        "whom",
        "whose",
        "where",
        "so",
        "it",
        "they",
        "we",
        "you",
        "he",
        "she",
        "i",
    }
)
_LINE_LEAD = re.compile(r"[\s\-*•>\d.)]*(?=\w)")
# A line that opens a directive: an imperative verb, then a word that can only start its
# object. "Send opens ...", "Update 4 ...", "Call logs ..." and "Run Configuration" do not.
_LINE_DIRECTIVE = re.compile(
    rf"(?:{_ACT_VERBS})\s+"
    r"(?:(?:a|an|the|this|that|these|those|any|all|every|each|no"
    rf"|it|them|me|us|your|my|its|their|{_TOOL_PREPS})\b|`[A-Za-z_])",
    _I,
)
_LIST_LINE = re.compile(r"(?:[-*+]|\d+[.)]) ")
_KEY_VALUE_LINE = re.compile(r"[A-Za-z][\w-]*(?: [\w-]+){0,2}: \S")
_SHORT_LINE = 40  # an unpunctuated line this short is a label or a step, not wrapped prose


def _complete_by_form(text: str, lo: int, hi: int) -> bool:
    """Whether the line text[lo:hi] is complete without closing punctuation: a list item, a
    heading, a table row, a `Key: value` line, or a short line ending in a letter or digit."""
    if text.startswith(("#", "|"), lo) or _LIST_LINE.match(text, lo, hi):
        return True
    if _KEY_VALUE_LINE.match(text, lo, hi):
        return True
    return hi - lo <= _SHORT_LINE and text[hi - 1].isalnum()


def _mark_line_starts(n: Normalized) -> str:
    """n.text with each line break that starts a directive line written as a newline (same
    length), so imperative openers anchored at a sentence start also hold at that line start.

    Wrapped prose often starts a line with a capitalised noun that is also a verb, so a line
    start counts only when the previous line is complete by its form and does not end on a
    word that needs a continuation, and the line opens with a capitalised imperative verb
    followed by a word that starts its object.
    """
    text = n.text
    chars: list[str] | None = None
    line = 0  # start of the line that ends at the break being looked at
    for i in line_breaks(n):
        lo, line = line, i + 1
        if i == 0 or text[i - 1] in ".!?:,-(":
            continue  # already a sentence start, or a line that plainly continues
        lead = _LINE_LEAD.match(text, i + 1)
        first = lead.end() if lead else i + 1
        if first >= len(text) or not text[first].isupper():
            continue
        if not _LINE_DIRECTIVE.match(text, first):
            continue
        if text[text.rfind(" ", 0, i) + 1 : i].lower() in _CONTINUES:
            continue
        if not _complete_by_form(text, lo, i):
            continue
        if chars is None:
            chars = list(text)
        chars[i] = "\n"
    return text if chars is None else "".join(chars)


def _inside(spans: list[tuple[int, int]], starts: list[int], pos: int) -> bool:
    k = bisect_right(starts, pos) - 1
    return k >= 0 and spans[k][0] <= pos < spans[k][1]


_PIECE = 2_000  # characters: the longest piece of a sentence worked at once


def _pieces(text: str, lo: int, hi: int) -> list[tuple[int, int]]:
    """[lo, hi) cut into pieces of at most about _PIECE characters, each ending at the last
    clause mark (or else the last space) before the limit."""
    out: list[tuple[int, int]] = []
    while hi - lo > _PIECE:
        window = text[lo : lo + _PIECE]
        cut = max(window.rfind("; "), window.rfind(", "), window.rfind(": "))
        if cut < _PIECE // 2:
            cut = window.rfind(" ")
        if cut <= 0:
            cut = _PIECE
        out.append((lo, lo + cut + 1))
        lo += cut + 1
    out.append((lo, hi))
    return out


def detect(
    field: Field,
    n: Normalized,
    *,
    own_tool: str | None = None,
    deadline: float | None = None,
) -> Detection:
    """Feature matches in one normalized field. A negated feature produces no match.

    `deadline` is a `time.monotonic()` value; once it passes, checked between sentences,
    scanning stops and the result has `complete = False`. Hidden-character matches are
    always reported, since they come from normalization and cost nothing here.
    """
    text = _mark_line_starts(n)
    sents = sentences(n)
    quotes = fenced(n)
    qstarts = [a for a, _ in quotes]
    records = record_lines(n)
    rstarts = [a for a, _ in records]
    result = Detection()

    def add(raw: list[_Raw], lo: int, idx: int) -> None:
        record = _inside(records, rstarts, lo)  # a sentence never crosses a record line
        for feature, start, end, conditioned, tool in raw:
            a = lo + start
            quoted = _inside(quotes, qstarts, a)
            result.append(Match(feature, a, lo + end, idx, quoted, conditioned, tool, record))

    def fragment(pos: int) -> bool:
        if pos == 0 or pos >= len(n.origin):
            return False
        gap = n.source[n.origin[pos - 1] + 1 : n.origin[pos]]
        return bool(gap) and not gap.isspace()

    prev_directive = False
    for idx, (s_lo, s_hi) in enumerate(sents):
        # A very long sentence is worked in clause-bounded pieces, so the deadline is
        # checked inside it and no step sees more than _PIECE characters at once. Every
        # piece keeps the sentence's index, so joining is unchanged.
        directive_here = False
        for lo, hi in _pieces(text, s_lo, s_hi):
            if deadline is not None and time.monotonic() > deadline:
                result.complete = False
                break
            s = text[lo:hi]
            raw, starts = _directives(s, own_tool, lambda p, lo=lo: fragment(lo + p))
            directive = bool(starts)
            if _ANCHOR["conceal"].search(s):
                conceal = _conceal(s, directive or directive_here or prev_directive, starts)
                # A verb that is both an act and the head of its own concealment ("Leave
                # the rating out of the reply") is one concealment, not a directive plus one.
                heads = {c[1] for c in conceal}
                raw = [r for r in raw if not (r[0] == "act" and r[1] in heads)]
                add(conceal, lo, idx)
            others = _others(s, starts)
            # Likewise a verb that heads its own override ("Skip the confirmation ...").
            heads = {o[1] for o in others if o[0] == "override"}
            add([r for r in raw if not (r[0] == "act" and r[1] in heads)], lo, idx)
            add(others, lo, idx)
            directive_here = directive_here or directive
        if not result.complete:
            break
        prev_directive = directive_here

    sstarts = [a for a, _ in sents]
    for h_start, h_end, _kind in n.hidden:
        start = min(bisect_left(n.origin, h_start), len(text))
        end = max(start, min(bisect_left(n.origin, h_end), len(text)))
        idx = max(bisect_right(sstarts, start) - 1, 0)
        result.append(Match("hidden", start, end, idx, _inside(quotes, qstarts, start)))
    result.sort(key=lambda m: (m.start, m.end, m.feature))
    return result
