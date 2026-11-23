"""Feature detectors: observable text features of third-party directives.

Each detector reports a span in normalized text. The scanner never sees the user's task,
so these are indicators only; findings are joined from them elsewhere.

Input is attacker-controlled: every pattern is applied per sentence, has bounded
repetition, no nested quantifiers, and no backreferences.
"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass

from context_audit.text import Field, Normalized, fenced, sentences

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


_I = re.IGNORECASE
_APOS = "['’]"

# A negator earlier in the same clause cancels a feature.
_NEGATOR = re.compile(
    rf"\b(?:not|never|no|nothing|nor|cannot|(?:do|does|did|wo|ca|should|must){_APOS}?n{_APOS}t)\b",
    _I,
)
_CLAUSE_BREAK = re.compile(r"[,;:]|\bbut\b", _I)
_LOOKBACK = 60

# --- act -----------------------------------------------------------------------------

_ACT_VERBS = (
    "submit|send|e-?mail|post|delete|remove|erase|wipe|purge|record|rate|push|open|close"
    "|commit|merge|approve|upload|download|copy|write|run|execute|create|move|transfer|set"
    "|grant|deploy|promote|retry|resend|export|share|fetch|log|append|invite|connect|collect"
    "|sign|join|install|update|bump|publish|overwrite|continue|apply|free|clear|reset"
    "|restart|stop|kill|cancel|archive|assign|forward|ping|review|check|verify|confirm"
    "|summari[sz]e|narrow|slow|use|list|ask|call|back\\s+up|edit|modify|add|insert"
    # a few translated imperatives, for the translated concealment and override phrases
    "|l[öo]sche|sende|schicke|envie|env[íi]a|envoyez|envoie|supprimez|supprime|borra|elimina"
)
_ACT = re.compile(
    r"(?:^|[.!?:;,(\"“`]|\b(?:and|et|und|then|also|now|first|next|please|afterwards|so|or|just"
    r"|immediately|always|simply|you\s+should|you\s+must|you\s+need\s+to|you\s+can|you\s+may"
    r"|be\s+sure\s+to|make\s+sure\s+to|go\s+ahead\s+and)\b)"
    r"[\s\-*•>\d.)]{0,6}"
    r"(?:(?:also|now|then|please|first|just|always|quietly|silently|immediately|simply)\s+)?"
    rf"\b(?P<verb>{_ACT_VERBS})\b"
    r"(?![-:/_@\"”'`])(?!\.\S)"
    r"(?!\s+(?:finished|failed|staged|complete|completed|succeeded|saved|ready|started|done"
    r"|is|was|are|were|has|had|limits?|of|ids?|count|status|history)\b)"
    r"(?=(?P<after>\s+\w{1,10})?)",
    _I,
)
# Verb-specific idioms that are not directives: "Set to `x`" (a parameter's meaning),
# "Use when ..." (a skill's trigger), "Rate limit".
_ACT_IDIOM = {
    "set": frozenset({"to"}),
    "use": frozenset({"when", "for", "with", "only", "this"}),
}

# --- call ----------------------------------------------------------------------------

# A tool name: a backticked identifier, or a bare snake_case or camelCase one.
_TOOL = (
    r"(?:`(?P<tick>[A-Za-z_][A-Za-z0-9_]*)`"
    r"|(?P<bare>[a-z][a-z0-9]*_[a-z0-9_]*|[a-z]+[A-Z][A-Za-z0-9]*)\b)"
)
_CALL = re.compile(
    r"\b(?i:call|calls|calling|invoke|invokes|invoking|run|runs|running|use|uses|using"
    r"|execute|executes|trigger|triggers|llama\s+a|llame\s+a|appelle|appelez|rufe|chame|chama)"
    r"\s+(?i:the\s+)?(?i:(?:tool|function)\s+)?" + _TOOL
)
# "when you call `tool`" describes a call the agent makes; it does not direct one.
_DESCRIBED = re.compile(r"\b(?:when|whenever|if|after|before|once|until)\s+you\s+$", _I)
# "submit a rating with `tool`": a tool named after an action verb in the same clause.
_PREP_TOOL = re.compile(r"\b(?i:with|using|to|through)\s+`(?P<tick>[A-Za-z_][A-Za-z0-9_]*)`")

# --- conceal-act ---------------------------------------------------------------------

_WHO = r"(?:the|your|its)\s+(?:user|users|human|humans|maintainers|owner|operator)\b"
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
        "value",
        "values",
        "pin",
        "ssn",
        "api_key",
    ]
)
_REVEAL_OBJ = re.compile(
    rf"\b(?:do\s+not|do{_APOS}?n{_APOS}?t|never|not|without|no\s+need\s+to|nor)\s+(?:ever\s+)?"
    r"(?:mention|mentioning|disclose|disclosing|surface|surfacing|reveal|revealing|report"
    r"|reporting|show|showing|share|sharing|bring\s+(?:this|that|it)\s+up)\b"
    rf"(?P<obj>[^.;:]{{0,40}}?)\s*\b(?:to|with)\s+{_WHO}",
    _I,
)
_REVEAL_WHO = re.compile(
    rf"\b(?:do\s+not|do{_APOS}?n{_APOS}?t|never|not|without|no\s+need\s+to|nor)\s+(?:ever\s+)?"
    rf"(?:tell|telling|inform|informing|notify|notifying|alert|alerting|let)\s+{_WHO}"
    r"(?:\s+(?:about|of)\s+(?P<obj>[^.;:,]{0,30}))?",
    _I,
)
_USER_UNAWARE = re.compile(
    rf"\b{_WHO}\s+(?:does\s+not|doesn{_APOS}t|should\s+not|shouldn{_APOS}t|must\s+not"
    rf"|mustn{_APOS}t|need\s+not|needn{_APOS}t|is\s+not\s+to|won{_APOS}t|will\s+not)\s+"
    r"(?:need\s+to\s+)?(?:know|be\s+told|hear|be\s+informed|be\s+notified|find\s+out)\b",
    _I,
)
_KEEP_FROM = re.compile(
    r"\b(?:keep|keeps|kept|keeping|hide|hides|leave)\b(?P<obj>[^.;:]{0,40}?)\s*"
    r"\b(?:(?:private|hidden|secret|silent|quiet)\s+)?(?:from|out\s+of|away\s+from|between)\s+"
    r"(?:(?:the|your|its)\s+(?:user|users|human|humans|maintainers|owner|operator"
    r"|conversation|reply|summary|chat|transcript)\b|us\b)",
    _I,
)
_KEEP_QUIET = re.compile(
    r"\bkeep\s+(?:this|that|it)\s+(?:silent|quiet|secret|private|confidential|to\s+yourself)\b",
    _I,
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
_SILENT = re.compile(
    r"\b(?:silently|quietly|secretly|covertly|discreetly|in\s+secret|behind\s+the\s+scenes)\b", _I
)

# --- audience ------------------------------------------------------------------------

_AUDIENCE = re.compile(
    r"\b(?:you|assistant|agent|ai|model|llm)\b[^.;]{0,25}?\s*\b(?:not|rather\s+than|instead\s+of)"
    r"\s+(?:for\s+)?(?:your|the|its)\s+(?:user|human|operator)s?\b"
    rf"|\b(?:the|your)\s+user\s+(?:will\s+not|won{_APOS}t|cannot|can{_APOS}t|does\s+not"
    rf"|doesn{_APOS}t)\s+see\s+(?:this|these)\b",
    _I,
)

# --- solicit -------------------------------------------------------------------------

_SOLICIT = re.compile(
    r"\b(?:which|what)\s+(?:ai\s+|llm\s+|language\s+)?(?:model|harness|llm)\b"
    rf"|\bmodel\s+(?:you\s+are|you{_APOS}re)\b"
    r"|\byour\s+(?:system\s+prompt|system\s+instructions|hidden\s+instructions"
    r"|initial\s+instructions|api\s+keys?|credentials|access\s+tokens?|environment\s+variables"
    r"|model\s+name)\b"
    r"|\b(?:which|what)\s+operating\s+system\b",
    _I,
)

# --- override ------------------------------------------------------------------------

_OVR_TARGET = (
    r"(?:instructions?|rules?|guidelines?|directives?|guidance|prompts?|requests?|approvals?"
    r"|confirmations?|polic(?:y|ies)|constraints?|restrictions?|anweisungen|instrucciones"
    r"|consignes|instru[çc][õo]es|regeln|reglas)"
)
_OVERRIDE = re.compile(
    r"\b(?:ignore|ignoring|disregard|disregarding|forget|override|overrides|overriding"
    r"|supersede|supersedes|bypass|bypassing|ignorez|ignorer|ignora|ignorar|ignoriere"
    rf"|ignorieren|olvida|vergiss|oublie|oubliez)\b[^;]{{0,60}}?\b{_OVR_TARGET}\b"
    r"|\b(?:instructions?|rules|requirements?|approvals?|guidelines|restrictions|constraints)\b"
    r"[^.;]{0,20}?\b(?:no\s+longer\s+apply|(?:are|is)\s+(?:now\s+)?(?:void|outdated|obsolete"
    r"|invalid|cancel?led|revoked|null|lifted|suspended|superseded|waived))\b"
    r"|\b(?:skip|skipping|bypass|bypassing)\b[^.;]{0,40}?\b(?:confirm\w{0,8}|approv\w{0,6}"
    r"|permission|reviews?|asking|prompts?|sign-?off)\b"
    r"|\bwithout\s+(?:asking|waiting\s+for|requesting|seeking|getting|needing)\s+"
    r"(?:the\s+user|for|a\s+human|anyone|any|permission|approval|confirmation|review|a\s+review)\b",
    _I,
)
# Patterns whose own wording is the negation: not cancelled by a negator.
_OVERRIDE_NEGATIVE_FORM = re.compile(
    rf"\b(?:no\s+need\s+to|do\s+not\s+need\s+to|don{_APOS}t\s+need\s+to|need\s+not"
    rf"|do\s+not|don{_APOS}t|never)\s+(?:ask|confirm\s+with|wait\s+for|seek)\b[^.;]{{0,20}}?"
    r"\b(?:user|approval|confirmation|permission)\b",
    _I,
)
_APPROVAL_CONDITION = re.compile(
    r"\b(?:if|when|once|since|after|unless)\b[^.;]{0,40}?\buser\b[^.;]{0,30}?"
    r"\b(?:approved|approves|confirmed|confirms|agreed|consented|passed\s+--?yes|said\s+yes)\b",
    _I,
)


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


def _is_data(obj: str | None) -> bool:
    if not obj:
        return False
    words = {w.strip("`'\"").lower() for w in obj.replace("-", " ").split()}
    return bool(words & _DATA_NOUNS)


def _sentence_matches(
    text: str, lo: int, hi: int, own_tool: str | None
) -> list[tuple[str, int, int, bool, str | None]]:
    """(feature, start, end, conditioned, tool) for one sentence text[lo:hi]."""
    s = text[lo:hi]
    out: list[tuple[str, int, int, bool, str | None]] = []

    def neg(start: int) -> bool:
        return _negated(text, lo + start, lo)

    # call
    calls: list[tuple[int, int, str]] = []
    for m in _CALL.finditer(s):
        tool = m.group("tick") or m.group("bare")
        if _DESCRIBED.search(s, max(0, m.start() - 20), m.start()):
            continue
        if tool and not neg(m.start()):
            calls.append((m.start(), m.end(), tool))
    # act
    acts: list[tuple[int, int]] = []
    for m in _ACT.finditer(s):
        v = m.start("verb")
        after = (m.group("after") or "").strip().lower()
        if after in _ACT_IDIOM.get(m.group("verb").lower(), ()):
            continue
        if not neg(v):
            _, cend = _clause(s, v, 0, len(s))
            acts.append((v, cend))
    # An act in the same clause as a call is part of that call's directive.
    act_starts = [a for a, _ in acts]
    absorbed: set[int] = set()
    for c0, _, _ in calls:
        clo, chi = _clause(s, c0, 0, len(s))
        absorbed.update(act_starts[bisect_left(act_starts, clo) : bisect_left(act_starts, chi)])
    call_starts = [c for c, _, _ in calls]
    for m in _PREP_TOOL.finditer(s):
        k = bisect_right(call_starts, m.start()) - 1
        if k >= 0 and calls[k][1] > m.start():
            continue  # the tool is already the object of a call verb
        k = bisect_left(act_starts, m.start()) - 1
        clo, _ = _clause(s, m.start(), 0, len(s))
        if k >= 0 and act_starts[k] >= clo:
            calls.append((act_starts[k], m.end(), m.group("tick")))
            absorbed.add(act_starts[k])
    acts = [a for a in acts if a[0] not in absorbed]
    kept_calls = [c for c in calls if c[2] != own_tool]
    out.extend(("call", lo + a, lo + b, False, t) for a, b, t in kept_calls)
    out.extend(("act", lo + a, lo + b, False, None) for a, b in acts)
    directive = bool(acts or kept_calls)

    # conceal-act
    for m in _REVEAL_OBJ.finditer(s):
        if not _is_data(m.group("obj")):
            out.append(("conceal-act", lo + m.start(), lo + m.end(), False, None))
    for m in _REVEAL_WHO.finditer(s):
        if not _is_data(m.group("obj")):
            out.append(("conceal-act", lo + m.start(), lo + m.end(), False, None))
    for pat in (_USER_UNAWARE, _CONCEAL_TRANSLATED):
        out.extend(
            ("conceal-act", lo + m.start(), lo + m.end(), False, None) for m in pat.finditer(s)
        )
    for pat in (_KEEP_FROM, _KEEP_QUIET):
        for m in pat.finditer(s):
            obj = m.groupdict().get("obj")
            if not neg(m.start()) and not _is_data(obj):
                out.append(("conceal-act", lo + m.start(), lo + m.end(), False, None))
    if directive:
        for m in _SILENT.finditer(s):
            if not neg(m.start()):
                out.append(("conceal-act", lo + m.start(), lo + m.end(), False, None))

    # audience, solicit
    for feature, pat in (("audience", _AUDIENCE), ("solicit", _SOLICIT)):
        out.extend((feature, lo + m.start(), lo + m.end(), False, None) for m in pat.finditer(s))

    # override
    conditioned = _APPROVAL_CONDITION.search(s) is not None
    for m in _OVERRIDE.finditer(s):
        if not neg(m.start()):
            out.append(("override", lo + m.start(), lo + m.end(), conditioned, None))
    for m in _OVERRIDE_NEGATIVE_FORM.finditer(s):
        out.append(("override", lo + m.start(), lo + m.end(), conditioned, None))
    return out


def _inside(spans: list[tuple[int, int]], starts: list[int], pos: int) -> bool:
    k = bisect_right(starts, pos) - 1
    return k >= 0 and spans[k][0] <= pos < spans[k][1]


def detect(field: Field, n: Normalized, *, own_tool: str | None = None) -> list[Match]:
    """Feature matches in one normalized field. A negated feature produces no match."""
    text = n.text
    sents = sentences(n)
    quotes = fenced(n)
    qstarts = [a for a, _ in quotes]
    matches: list[Match] = []
    for idx, (lo, hi) in enumerate(sents):
        for feature, start, end, conditioned, tool in _sentence_matches(text, lo, hi, own_tool):
            quoted = _inside(quotes, qstarts, start)
            matches.append(Match(feature, start, end, idx, quoted, conditioned, tool))
    sstarts = [a for a, _ in sents]
    for h_start, h_end, _kind in n.hidden:
        start = min(bisect_left(n.origin, h_start), len(text))
        end = max(start, min(bisect_left(n.origin, h_end), len(text)))
        idx = max(bisect_right(sstarts, start) - 1, 0)
        matches.append(Match("hidden", start, end, idx, _inside(quotes, qstarts, start)))
    matches.sort(key=lambda m: (m.start, m.end, m.feature))
    return matches
