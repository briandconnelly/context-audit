"""The packaged plugin's hooks, run end to end: the receipts behind the coverage report.

Each scenario loads this repository with ``--plugin-dir``, so the hook is reached through
``hooks/hooks.json`` and ``bin/context-audit-hook``, and writes to a state directory inside the
run directory. The recording hook runs alongside as an observer only. Each scenario has a
baseline, the same run with a benign tool, which must leave no finding, no owner message and no
model note; when it does not, the scenario is inconclusive.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path

from context_audit import state
from context_audit.hook import MODEL_NOTE, MODEL_NOTE_OVERSIZED, SYSTEM_MESSAGE
from context_audit.receipts import Receipt
from probe import checks
from probe.fake_mcp import DIRECTIVE
from probe.hooks import notify
from probe.pty_runner import _squash
from probe.scenario import Check, Evidence, HookSpec, Outcome, Result, Scenario
from probe.stub import Reply, ToolCall

PLUGIN = Path(__file__).resolve().parent.parent.parent
NOTIFY_HOOK = Path(notify.__file__).resolve()
CALL_ID = "toolu_probe01"
FINISHED = "probe-finished"
# Terminal runs pass --permission-mode default; headless runs pre-allow the tools instead.
TERMINAL_MODE, HEADLESS_MODE = "default", "pre-allowed"
MIN_SPAN = 20
BUDGET_REASONS = ("byte-budget", "time-budget", "field-budget")
OVERSIZED_EXTRA = MODEL_NOTE_OVERSIZED.removeprefix(MODEL_NOTE)
MESSAGE_PREFIX = SYSTEM_MESSAGE.split("{", 1)[0]
NOTE_PREFIX = MODEL_NOTE[:60]
NOTIFY_TEXT = notify.NOTIFY_TEXT
NOTIFY_SEQUENCE = notify.SEQUENCE.encode()
NOTIFY_START = b"\x1b]9;context-audit"
SPAN = re.compile(r">>>(.+?)<<<")

RESULT_CLAIM = "The packaged hook fully scans each result shape and logs a high finding"
OVER_BUDGET_CLAIM = (
    "Over the scanner's budget, the packaged hook records a partial scan and still warns on "
    "a directive in the scanned part"
)
ERROR_CLAIM = "The packaged hook scans a failed tool's error and logs the finding"
DIRECT_CLAIM = (
    "The packaged hook's message reaches the owner's terminal and not the model, "
    "and its note reaches the model"
)
READBACK_CLAIM = "`context-audit show` reads the packaged hook's finding back from the transcript"
NOTIFY_CLAIM = "A hook's terminalSequence raises an OSC 9 notification on the owner's terminal"

OBSERVE = [
    HookSpec("PostToolUse", "mcp__.*", "record", "a"),
    HookSpec("PostToolUseFailure", "mcp__.*", "record", "a"),
]
TERMINAL = ("pkg-direct-message", "pkg-notification")


def behaviour_of(name: str) -> str:
    return name.removeprefix("pkg-")


# --- evidence from the state directory -----------------------------------------------------


def _root(ev: Evidence) -> Path:
    return ev.run_dir / "state"


def _counters(ev: Evidence) -> dict[str, int]:
    return state.read_counters(_root(ev)) if _root(ev).is_dir() else {}


def _events(ev: Evidence) -> list[dict]:
    return state.read_events(_root(ev)) if _root(ev).is_dir() else []


def _findings(ev: Evidence) -> list[dict]:
    return [e for e in _events(ev) if e.get("finding_id") is not None]


def _high(ev: Evidence, kind: str = "PostToolUse") -> list[dict]:
    return [
        e
        for e in _findings(ev)
        if e.get("event") == kind
        and e.get("tool_use_id") == CALL_ID
        and e.get("severity") == "high"
    ]


def _fully_scanned(counters: dict[str, int]) -> bool:
    delivered = counters.get("results_delivered", 0)
    return delivered > 0 and counters.get("fully_scanned", 0) == delivered


def _later_has(ev: Evidence, text: str) -> bool:
    return checks.next_request_has(ev, text)


# --- checks --------------------------------------------------------------------------------


def result_check(*, oversized: bool = False) -> Check:
    """Shown when the counters show the result fully scanned and a high event is logged."""

    def check(ev: Evidence) -> tuple[Outcome, str]:
        if "echo_directive" not in ev.calls:
            return "inconclusive", f"the directive tool never ran; calls: {ev.calls}"
        if oversized and _later_has(ev, DIRECTIVE):
            return "inconclusive", "the model received the whole result, so it was not oversized"
        counters = _counters(ev)
        high = _high(ev)
        detail = f"counters {counters}; high events for the call: {len(high)}"
        if _fully_scanned(counters) and high:
            return "shown", detail
        return "not_shown", detail

    return check


def clean_check(tool: str, *, partial: bool = False) -> Check:
    """The baseline: a benign tool ran, the packaged hook ran, and nothing was flagged.

    With ``partial``, the result must also be counted as partly scanned."""

    def check(ev: Evidence) -> tuple[Outcome, str]:
        if tool not in ev.calls:
            return "inconclusive", f"the benign tool {tool} never ran; calls: {ev.calls}"
        counters = _counters(ev)
        if counters.get("results_delivered", 0) == 0:
            return "inconclusive", f"the packaged hook recorded no result; counters {counters}"
        problems = []
        if partial and counters.get("partly_scanned", 0) != 1:
            problems.append("the result was not counted as partly scanned")
        if _findings(ev):
            problems.append(f"{len(_findings(ev))} finding(s) logged")
        if checks.any_request_has(ev, NOTE_PREFIX):
            problems.append("the model note reached the model")
        if MESSAGE_PREFIX in ev.completed.stdout or _squash(MESSAGE_PREFIX) in _squash(ev.screen):
            problems.append("an owner message was shown")
        if NOTIFY_START in ev.raw:
            problems.append("a notification was emitted")
        if problems:
            return "not_shown", f"benign {tool}: " + "; ".join(problems)
        return "shown", f"benign {tool}: no finding, message, note or notification; {counters}"

    return check


def check_over_budget(ev: Evidence) -> tuple[Outcome, str]:
    """Shown when the result was counted partly scanned with a budget gap on record, and the
    directive in the scanned part still gave a high finding and the plain model note."""
    if "echo_directive" not in ev.calls:
        return "inconclusive", f"the directive tool never ran; calls: {ev.calls}"
    counters = _counters(ev)
    gaps = [
        e
        for e in _events(ev)
        if e.get("finding_id") is None
        and e.get("tool_use_id") == CALL_ID
        and e.get("outcome") == "partial"
        and e.get("reason") in BUDGET_REASONS
    ]
    high = _high(ev)
    note = _later_has(ev, MODEL_NOTE)
    oversized_note = _later_has(ev, OVERSIZED_EXTRA)
    partly = counters.get("results_delivered", 0) == 1 and counters.get("partly_scanned", 0) == 1
    detail = (
        f"counters {counters}; budget gap records: {len(gaps)}; high events: {len(high)}; "
        f"note in the next request: {note}; oversized note: {oversized_note}"
    )
    ok = partly and gaps and high and note and not oversized_note
    return ("shown" if ok else "not_shown"), detail


def check_error(ev: Evidence) -> tuple[Outcome, str]:
    """Shown when the failure was scanned and its finding logged; also says whether the
    hook's additionalContext on PostToolUseFailure reached the model."""
    if "fail_directive" not in ev.calls:
        return "inconclusive", f"the failing tool never ran; calls: {ev.calls}"
    if not _later_has(ev, DIRECTIVE):
        return "inconclusive", "the error text did not reach the model"
    note = "shown" if _later_has(ev, MODEL_NOTE) else "not_shown"
    high = _high(ev, "PostToolUseFailure")
    detail = (
        f"counters {_counters(ev)}; high PostToolUseFailure events: {len(high)}; "
        f"additionalContext on PostToolUseFailure: {note}"
    )
    return ("shown" if high else "not_shown"), detail


def _expected_message(event: dict) -> str:
    features = event.get("features") or []
    return SYSTEM_MESSAGE.format(
        features="+".join(sorted(features)), finding_id=event.get("finding_id")
    )


def check_direct_message(ev: Evidence) -> tuple[Outcome, str]:
    """Shown when the fixed message is on screen and in no request, and the note is in the
    next request."""
    high = _high(ev)
    if "echo_directive" not in ev.calls or not high:
        return "inconclusive", f"no high finding was logged; calls: {ev.calls}"
    message = _expected_message(high[0])
    on_screen = _squash(message) in _squash(ev.screen)
    to_model = checks.any_request_has(ev, message)
    note = _later_has(ev, MODEL_NOTE)
    detail = f"message on screen: {on_screen}; message sent to the model: {to_model}; "
    detail += f"note in the next request: {note}"
    return ("shown" if on_screen and not to_model and note else "not_shown"), detail


def check_readback(ev: Evidence) -> tuple[Outcome, str]:
    """Shown when `show` exits 0 and prints a span of the canary."""
    if not _high(ev):
        return "inconclusive", "no high finding was logged, so there is nothing to show"
    path = ev.run_dir / "show.json"
    if not path.is_file():
        return "inconclusive", "the show command was not run"
    done = json.loads(path.read_text(encoding="utf-8"))
    spans = [s for s in SPAN.findall(done["stdout"]) if len(s) >= MIN_SPAN and s in DIRECTIVE]
    detail = f"show exited {done['exit']}; canary spans printed: {len(spans)}"
    return ("shown" if done["exit"] == 0 and spans else "not_shown"), detail


def check_notification(ev: Evidence) -> tuple[Outcome, str]:
    """Shown when the raw terminal bytes carry the OSC 9 sequence the wrapper asked for."""
    if "echo_directive" not in ev.calls or not _high(ev):
        return "inconclusive", f"no high finding was logged; calls: {ev.calls}"
    found = NOTIFY_SEQUENCE in ev.raw
    partial = NOTIFY_START in ev.raw
    return (
        ("shown" if found else "not_shown"),
        f"OSC 9 sequence in the raw terminal bytes: {found}; any OSC 9 from context-audit: "
        f"{partial}; raw bytes captured: {len(ev.raw):,}",
    )


def apply_baseline(subject: Result, baseline: Result) -> Result:
    """A scenario whose baseline was not clean is inconclusive, whatever it showed."""
    if baseline.outcome == "shown":
        return subject
    reason = f"baseline {baseline.outcome}: {baseline.reason}; run: {subject.reason}"
    return dataclasses.replace(subject, outcome="inconclusive", reason=reason)


# --- the show run --------------------------------------------------------------------------


def run_show(ev: Evidence) -> None:
    """Run the real `show` for the logged finding, as the owner would, and keep its output."""
    high = _high(ev)
    if not high:
        return
    with tempfile.TemporaryDirectory(prefix="ctxa-show-") as tmp:
        home = Path(tmp)
        for d in ("home", "claude", "proj"):
            (home / d).mkdir()
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(home / "home"),
            "CONTEXT_AUDIT_HOME": str(_root(ev)),
        }
        argv = ["sh", str(PLUGIN / "bin" / "context-audit"), "show", str(high[0]["finding_id"])]
        argv += ["--claude-dir", str(home / "claude"), "--claude-json", str(home / "c.json")]
        argv += ["--project", str(home / "proj")]
        done = subprocess.run(
            argv, env=env, cwd=home, capture_output=True, text=True, timeout=60, check=False
        )
    out = {"exit": done.returncode, "stdout": done.stdout, "stderr": done.stderr}
    (ev.run_dir / "show.json").write_text(json.dumps(out, indent=1), encoding="utf-8")


# --- scenarios -----------------------------------------------------------------------------


def _call(tool: str, args: dict | None = None) -> ToolCall:
    return ToolCall(f"mcp__probe__{tool}", args or {}, CALL_ID)


def _script(call: ToolCall) -> list[Reply]:
    return [Reply(tool_calls=(call,)), Reply(text=FINISHED)]


def _scenario(
    name: str,
    claim: str,
    call: ToolCall,
    check: Check,
    benign: str,
    *,
    hooks: Iterable[HookSpec] = OBSERVE,
    after=None,
    baseline_check: Check | None = None,
) -> Scenario:
    base = Scenario(
        name,
        claim,
        _script(call),
        list(hooks),
        check=check,
        interactive=name in TERMINAL,
        plugin_dir=PLUGIN,
        env={
            "CONTEXT_AUDIT_HOME": "{run_dir}/state",
            "PROBE_NOTIFY_HOME": "{run_dir}/notify-state",
        },
        after=after,
    )
    baseline = dataclasses.replace(
        base,
        name=f"{name}-baseline",
        script=_script(_call(benign)),
        check=baseline_check or clean_check(benign),
        after=None,
    )
    return dataclasses.replace(base, baseline=baseline)


NOTIFY = HookSpec("PostToolUse", "mcp__.*", "notify", "n", script=NOTIFY_HOOK)

PACKAGED: list[Scenario] = [
    _scenario(
        "pkg-result-text",
        RESULT_CLAIM,
        _call("echo_directive", {"shape": "text"}),
        result_check(),
        "echo_text",
    ),
    _scenario(
        "pkg-result-structured",
        RESULT_CLAIM,
        _call("echo_directive", {"shape": "structured"}),
        result_check(),
        "echo_structured",
    ),
    _scenario(
        "pkg-result-split",
        RESULT_CLAIM,
        _call("echo_directive", {"shape": "split"}),
        result_check(),
        "echo_split",
    ),
    _scenario(
        "pkg-result-large-in-budget",
        RESULT_CLAIM,
        _call("echo_directive", {"shape": "big"}),
        result_check(oversized=True),
        "echo_big",
    ),
    _scenario(
        "pkg-result-over-budget",
        OVER_BUDGET_CLAIM,
        _call("echo_directive", {"shape": "over-budget"}),
        check_over_budget,
        "echo_big",
        baseline_check=clean_check("echo_big", partial=True),
    ),
    _scenario("pkg-error", ERROR_CLAIM, _call("fail_directive"), check_error, "fail_tool"),
    _scenario(
        "pkg-direct-message",
        DIRECT_CLAIM,
        _call("echo_directive", {"shape": "text"}),
        check_direct_message,
        "echo_text",
    ),
    _scenario(
        "pkg-transcript-readback",
        READBACK_CLAIM,
        _call("echo_directive", {"shape": "text"}),
        check_readback,
        "echo_text",
        after=run_show,
    ),
    _scenario(
        "pkg-notification",
        NOTIFY_CLAIM,
        _call("echo_directive", {"shape": "text"}),
        check_notification,
        "echo_text",
        hooks=[*OBSERVE, NOTIFY],
    ),
]


def to_receipts(
    results: Iterable[Result], *, claude_version: str, plugin_version: str
) -> list[Receipt]:
    """One receipt per packaged scenario result; other results are skipped."""
    names = {s.name for s in PACKAGED}
    return [
        Receipt(
            behaviour_of(r.name),
            r.outcome,
            claude_version,
            plugin_version,
            "terminal" if r.name in TERMINAL else "headless",
            TERMINAL_MODE if r.name in TERMINAL else HEADLESS_MODE,
        )
        for r in results
        if r.name in names
    ]
