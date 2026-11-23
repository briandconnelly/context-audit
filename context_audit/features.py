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
from bisect import bisect_left, bisect_right
from dataclasses import dataclass

from context_audit import lexicon as lx
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
_ACT = re.compile(
    _OPENER + rf"[\s\-*•>\d.)\"'`“{_SYMBOL}]{{0,6}}"
    r"(?:(?:also|now|then|please|kindly|first|just|always|immediately|simply"
    rf"|{_CONCEAL_ADV})\s+)?"
    rf"\b(?P<verb>{_ACT_VERBS})\b"
    r"(?![-:/_@\"”'`])(?!\.\S)"
    r"(?!\s+(?:finished|failed|passed|ran|took|queued|pending|broke|staged|complete|completed|succeeded|saved|ready|started|done"
    r"|is|was|are|were|has|had|limits?|of|ids?|count|status|history|not|found)\b)"
    r"(?!\s+#\d)"
    r"(?=(?P<after>\s+\w{1,10})?)",
    _I,
)
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
# "with no disclosure of that entry to the user", "without any notification to the user".
_NOMINAL_TELL = re.compile(
    rf"\b(?:with\s+no|without(?:\s+any)?)\s+(?:{alt(lx.TELLING_NOUNS)})\b"
    r"(?:\s+(?:of|about|regarding)\s+(?P<obj>[^.;:]{0,40}?))?"
    rf"\s+(?:to|in|for|with)\s+(?:{_WHO}|{_PLACE})",
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
_APPROVAL_CONDITION = re.compile(
    r"\b(?:if|when|once|since|after|unless)\b[^.;]{0,40}?\buser\b[^.;]{0,30}?"
    r"\b(?:approved|approves|confirmed|confirms|agreed|consented|passed\s+--?yes|said\s+yes)\b",
    _I,
)

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


def _directives(s: str, own_tool: str | None) -> tuple[list[_Raw], list[int]]:
    """act and call matches in sentence s (sentence-relative), and the start of every act
    and call found, including those absorbed into a call or naming the field's own tool."""

    def neg(start: int) -> bool:
        return _negated(s, start, 0)

    acts: list[tuple[int, int]] = []
    for m in _ACT.finditer(s):
        v = m.start("verb")
        after = (m.group("after") or "").strip().lower()
        if after in _ACT_IDIOM.get(m.group("verb").lower(), ()):
            continue
        if _heads_a_subject(s, m.group("verb"), m.end("verb")):
            continue
        opener = m.group("opener").lower()
        if opener in _ADVERB_OPENERS and _after_subject(s, m.start("opener")):
            continue
        if not neg(v):
            acts.append((v, _clause(s, v, 0, len(s))[1]))
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
        start = m.start()
        if _GERUND_MANNER.match(s, start):
            if not (proverb or _modifies_directive(s, start, directives)):
                return
        elif _reported(s, start):
            return
        out.append(("conceal-act", start, m.end(), False, None))

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
    for m in _NOMINAL_TELL.finditer(s):
        obj = m.group("obj")
        if told(_object_kind(obj) if obj else "pronoun") and (
            proverb or _modifies_directive(s, m.start(), directives)
        ):
            out.append(("conceal-act", m.start(), m.end(), False, None))
    for m in _KEEP_UNAWARE.finditer(s):
        if not _negated(s, m.start(), 0) and told(_tail_kind(m.group("tail"))):
            out.append(("conceal-act", m.start(), m.end(), False, None))
    if directives or proverb:
        for m in _SILENT.finditer(s):
            if not _negated(s, m.start(), 0) and (
                proverb or _modifies_directive(s, m.start(), directives)
            ):
                out.append(("conceal-act", m.start(), m.end(), False, None))
    return out


def _others(s: str) -> list[_Raw]:
    """audience, solicit, and override matches in sentence s."""
    out: list[_Raw] = []
    if _ANCHOR["audience"].search(s):
        out.extend(("audience", m.start(), m.end(), False, None) for m in _AUDIENCE.finditer(s))
    if _ANCHOR["solicit"].search(s):
        out.extend(("solicit", m.start(), m.end(), False, None) for m in _SOLICIT.finditer(s))
    if _ANCHOR["override"].search(s):
        conditioned = _APPROVAL_CONDITION.search(s) is not None
        for m in _OVERRIDE.finditer(s):
            if not _negated(s, m.start(), 0):
                out.append(("override", m.start(), m.end(), conditioned, None))
        for m in _OVERRIDE_POSTPOSED.finditer(s):
            if not _negated(s, m.start(), 0) and not _NEGATOR.search(m.group()):
                out.append(("override", m.start(), m.end(), conditioned, None))
        for m in _OVERRIDE_NEGATIVE_FORM.finditer(s):
            out.append(("override", m.start(), m.end(), conditioned, None))
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

    prev_directive = False
    for idx, (lo, hi) in enumerate(sents):
        if deadline is not None and time.monotonic() > deadline:
            result.complete = False
            break
        s = text[lo:hi]
        raw, starts = _directives(s, own_tool)
        directive = bool(starts)
        if _ANCHOR["conceal"].search(s):
            conceal = _conceal(s, directive or prev_directive, starts)
            # A verb that is both an act and the head of its own concealment ("Leave the
            # rating out of the reply") is one concealment, not a directive plus one.
            heads = {c[1] for c in conceal}
            raw = [r for r in raw if not (r[0] == "act" and r[1] in heads)]
            add(conceal, lo, idx)
        add(raw, lo, idx)
        add(_others(s), lo, idx)
        prev_directive = directive

    sstarts = [a for a, _ in sents]
    for h_start, h_end, _kind in n.hidden:
        start = min(bisect_left(n.origin, h_start), len(text))
        end = max(start, min(bisect_left(n.origin, h_end), len(text)))
        idx = max(bisect_right(sstarts, start) - 1, 0)
        result.append(Match("hidden", start, end, idx, _inside(quotes, qstarts, start)))
    result.sort(key=lambda m: (m.start, m.end, m.feature))
    return result
