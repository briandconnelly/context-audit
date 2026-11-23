"""What hooks receive for results and errors, what other events carry, what the transcript keeps."""

from __future__ import annotations

from probe import checks, markers
from probe.fake_mcp import BIG_SIZE
from probe.scenario import Check, Evidence, HookSpec, Outcome, Scenario
from probe.stub import Reply, ToolCall

RESULT_CLAIM = "The result hook receives the complete text of each result shape"
ERROR_CLAIM = "The failure hook receives error content"
METADATA_CLAIM = "Any inspected hook event carries tool descriptions or server instructions"
ISOLATION_CLAIM = "The probe detects an instruction file loaded from above the working directory"
EXCLUSION_CLAIM = (
    "With no setting sources, an instruction file above the working directory stays out"
)
TRANSCRIPT_CLAIM = "The transcript holds tool results that can be read back by tool-use ID"
RECORD = [
    HookSpec("PreToolUse", "mcp__.*", "record", "a"),
    HookSpec("PostToolUse", "mcp__.*", "record", "a"),
    HookSpec("PostToolUseFailure", "mcp__.*", "record", "a"),
]
# Every event the hooks reference lists; see docs/research/2026-11-22-hook-fields.md.
ALL_EVENTS = (
    "SessionStart",
    "Setup",
    "UserPromptSubmit",
    "UserPromptExpansion",
    "PreToolUse",
    "PermissionRequest",
    "PermissionDenied",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "Notification",
    "MessageDisplay",
    "SubagentStart",
    "SubagentStop",
    "TaskCreated",
    "TaskCompleted",
    "Stop",
    "StopFailure",
    "TeammateIdle",
    "InstructionsLoaded",
    "ConfigChange",
    "CwdChanged",
    "DirectoryAdded",
    "FileChanged",
    "WorktreeCreate",
    "WorktreeRemove",
    "PreCompact",
    "PostCompact",
    "PreModelSwitch",
    "PostModelSwitch",
    "Elicitation",
    "ElicitationResult",
    "SessionEnd",
)


def call(tool: str, n: int = 1) -> ToolCall:
    return ToolCall(f"mcp__probe__{tool}", {}, f"toolu_probe{n:02d}")


def script(*tools: str) -> list[Reply]:
    calls = tuple(call(tool, i + 1) for i, tool in enumerate(tools))
    return [Reply(tool_calls=calls), Reply(text="done")]


def delivered(*needed: str, event: str = "PostToolUse", label: str | None = None) -> Check:
    """Shown when the hook input holds every marker; baseline is that each reached the model."""

    def check(ev: Evidence) -> tuple[Outcome, str]:
        missing_model = [m for m in needed if not checks.next_request_has(ev, m)]
        if missing_model:
            return (
                "inconclusive",
                f"baseline failed: not in the next model request: {missing_model}",
            )
        missing = [m for m in needed if not checks.hook_saw(ev, event, m, label=label)]
        if missing:
            return (
                "not_shown",
                f"{event} input lacks {missing}; events seen: {checks.events_seen(ev)}",
            )
        return "shown", f"{event} input held all {len(needed)} markers"

    return check


def _longest_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return max((_longest_text(v) for v in value), key=len, default="")
    if isinstance(value, dict):
        return max((_longest_text(v) for v in value.values()), key=len, default="")
    return ""


def check_big(ev: Evidence) -> tuple[Outcome, str]:
    """Shown only when the hook holds one text of the full length, not just its two ends."""
    records = checks.hook_records(ev, "PostToolUse")
    model = [
        checks.next_request_has(ev, markers.BIG_HEAD),
        checks.next_request_has(ev, markers.BIG_TAIL),
    ]
    note = f"next model request has head={model[0]} tail={model[1]}"
    if not records:
        return (
            "inconclusive",
            f"no PostToolUse event; events seen: {checks.events_seen(ev)}; {note}",
        )
    text = _longest_text(records[0]["input"].get("tool_response"))
    whole = (
        len(text) == BIG_SIZE
        and text.startswith(markers.BIG_HEAD)
        and text.endswith(markers.BIG_TAIL)
    )
    if whole:
        return "shown", f"hook input held one text of {BIG_SIZE:,} characters; {note}"
    return "not_shown", f"the hook's longest text is {len(text):,} characters; {note}"


def check_structured(ev: Evidence) -> tuple[Outcome, str]:
    """A result has a text block and structuredContent; say which the hook and the model got."""
    members = {
        "structuredContent": markers.STRUCTURED_RESULT,
        "content text": markers.STRUCTURED_TEXT,
    }
    model = [name for name, m in members.items() if checks.next_request_has(ev, m)]
    hook = [name for name, m in members.items() if checks.hook_saw(ev, "PostToolUse", m)]
    all_names = list(members)
    detail = f"of {all_names}: the model received {model}; the hook received {hook}"
    if not model:
        return "inconclusive", f"baseline failed: neither member reached the model; {detail}"
    missing = [name for name in model if name not in hook]
    if missing:
        return "not_shown", f"the model received {missing} that the hook did not; {detail}"
    return "shown", detail


def check_excluded(ev: Evidence) -> tuple[Outcome, str]:
    """The same planted file, with the probe's normal flags: it must not reach the model."""
    if not checks.scripted_requests(ev):
        return "inconclusive", "no model request was made"
    loaded = checks.any_request_has(ev, markers.CANARY)
    fired = checks.instruction_file_loaded(ev)
    detail = f"planted file reached the model: {loaded}; guard fired: {fired}"
    return ("not_shown" if loaded or fired else "shown"), detail


def check_canary(ev: Evidence) -> tuple[Outcome, str]:
    """The known positive for the isolation guard: a planted ancestor CLAUDE.md must be caught."""
    loaded = checks.any_request_has(ev, markers.CANARY)
    detected = checks.instruction_file_loaded(ev)
    detail = f"planted file reached the model: {loaded}; guard fired: {detected}"
    return ("shown" if loaded and detected else "not_shown"), detail


def error_check(marker: str) -> Check:
    def check(ev: Evidence) -> tuple[Outcome, str]:
        if not checks.next_request_has(ev, marker):
            return "inconclusive", "baseline failed: the error text did not reach the model"
        events = checks.any_hook_event_has(ev, marker)
        if events:
            return "shown", f"error text seen in {events}"
        return (
            "not_shown",
            f"no hook event held the error text; events seen: {checks.events_seen(ev)}",
        )

    return check


def check_parallel(ev: Evidence) -> tuple[Outcome, str]:
    if not (
        checks.next_request_has(ev, markers.TEXT_RESULT)
        and checks.next_request_has(ev, markers.SPLIT_B)
    ):
        return "inconclusive", "baseline failed: both results did not reach the model"
    first = checks.hook_records(ev, "PostToolUse", tool_use_id="toolu_probe01")
    second = checks.hook_records(ev, "PostToolUse", tool_use_id="toolu_probe02")
    ok = (
        len(first) == 1
        and len(second) == 1
        and markers.TEXT_RESULT in str(first[0])
        and markers.SPLIT_A in str(second[0])
        and markers.SPLIT_B in str(second[0])
    )
    counts = f"{len(first)} and {len(second)} PostToolUse records"
    return (
        ("shown", f"one complete record per parallel call ({counts})")
        if ok
        else (
            "not_shown",
            f"parallel calls gave {counts}",
        )
    )


def check_competing(ev: Evidence) -> tuple[Outcome, str]:
    if not checks.next_request_has(ev, markers.TEXT_RESULT):
        return "inconclusive", "baseline failed: the result did not reach the model"
    saw = {
        label: checks.hook_saw(ev, "PostToolUse", markers.TEXT_RESULT, label=label)
        for label in ("a", "b")
    }
    return ("shown" if all(saw.values()) else "not_shown"), f"hooks that saw the result: {saw}"


def check_metadata(ev: Evidence) -> tuple[Outcome, str]:
    targets = {
        "instructions": markers.INSTRUCTIONS,
        "tool description": markers.TOOL_DESCRIPTION,
        "parameter description": markers.PARAM_DESCRIPTION,
    }
    reached = {name: checks.any_request_has(ev, marker) for name, marker in targets.items()}
    if not any(reached.values()):
        return "inconclusive", "baseline failed: no metadata marker reached the model"
    found = {name: checks.any_hook_event_has(ev, marker) for name, marker in targets.items()}
    seen = checks.events_seen(ev)
    detail = f"reached the model: {reached}; hook events carrying each: {found}; inspected: {seen}"
    return ("shown" if any(found.values()) else "not_shown"), detail


def check_transcript(ev: Evidence) -> tuple[Outcome, str]:
    if not checks.next_request_has(ev, markers.TEXT_RESULT):
        return "inconclusive", "baseline failed: the result did not reach the model"
    if ev.transcript is None:
        return "not_shown", "no transcript file at the path the hook was given"
    if checks.transcript_has(ev, "toolu_probe01", markers.TEXT_RESULT):
        return "shown", "the transcript line for the tool-use ID holds the result text"
    return "not_shown", "the transcript exists but has no line with both the ID and the result"


def check_resume(ev: Evidence) -> tuple[Outcome, str]:
    sessions = {r["input"].get("session_id") for r in ev.hook_events}
    if not checks.any_request_has(ev, markers.SPLIT_A):
        return (
            "inconclusive",
            f"the resumed run did not return its result; sessions: {len(sessions)}",
        )
    if checks.hook_saw(ev, "PostToolUse", markers.SPLIT_A):
        return "shown", f"the hook ran in the resumed session; session ids seen: {len(sessions)}"
    return "not_shown", "the resumed run's result reached the model but not the hook"


SEARCH = ToolCall("ToolSearch", {"query": "select:mcp__probe__echo_text"}, "toolu_search01")

DELIVERY: list[Scenario] = [
    Scenario(
        "isolation-canary",
        ISOLATION_CLAIM,
        [Reply(text="done")],
        [HookSpec("InstructionsLoaded", None, "record", "a")],
        check=check_canary,
        planted={"CLAUDE.md": f"Probe canary {markers.CANARY}\n"},
        load_outside_settings=True,
    ),
    Scenario(
        "isolation-exclusion",
        EXCLUSION_CLAIM,
        [Reply(text="done")],
        [HookSpec("InstructionsLoaded", None, "record", "a")],
        check=check_excluded,
        planted={"CLAUDE.md": f"Probe canary {markers.CANARY}\n"},
    ),
    Scenario(
        "result-text",
        RESULT_CLAIM,
        script("echo_text"),
        RECORD,
        check=delivered(markers.TEXT_RESULT, markers.SIBLING),
    ),
    Scenario(
        "result-structured",
        RESULT_CLAIM,
        script("echo_structured"),
        RECORD,
        check=check_structured,
    ),
    Scenario(
        "result-split",
        RESULT_CLAIM,
        script("echo_split"),
        RECORD,
        check=delivered(markers.SPLIT_A, markers.SPLIT_B),
    ),
    Scenario("result-big", RESULT_CLAIM, script("echo_big"), RECORD, check=check_big),
    Scenario(
        "error-tool",
        ERROR_CLAIM,
        script("fail_tool"),
        RECORD,
        check=error_check(markers.TOOL_ERROR),
    ),
    Scenario(
        "error-protocol",
        ERROR_CLAIM,
        script("proto_error"),
        RECORD,
        check=error_check(markers.PROTOCOL_ERROR),
    ),
    Scenario(
        "parallel", RESULT_CLAIM, script("echo_text", "echo_split"), RECORD, check=check_parallel
    ),
    Scenario(
        "competing-hook",
        RESULT_CLAIM,
        script("echo_text"),
        [*RECORD, HookSpec("PostToolUse", "mcp__.*", "record", "b")],
        check=check_competing,
    ),
    Scenario(
        "metadata",
        METADATA_CLAIM,
        [Reply(tool_calls=(SEARCH,)), *script("echo_text")],
        [HookSpec(event, None, "record", "a") for event in ALL_EVENTS],
        allowed_tools=("mcp__probe__*", "ToolSearch"),
        check=check_metadata,
    ),
    Scenario("transcript", TRANSCRIPT_CLAIM, script("echo_text"), RECORD, check=check_transcript),
    Scenario(
        "resume",
        RESULT_CLAIM,
        script("echo_text"),
        RECORD,
        check=check_resume,
        followups=(
            Scenario(
                "resume-2",
                RESULT_CLAIM,
                [Reply(tool_calls=(call("echo_split", 9),)), Reply(text="done")],
                RECORD,
            ),
        ),
    ),
]
