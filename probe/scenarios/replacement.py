"""Whether a PostToolUse hook can replace an MCP result before the model reads it."""

from __future__ import annotations

from probe import checks, markers
from probe.scenario import Evidence, HookSpec, Outcome, Scenario
from probe.scenarios.delivery import RECORD, script

CLAIM = "Replacing a result keeps the original out of the next request"
REPLACE = HookSpec("PostToolUse", "mcp__.*", "replace", "r")


def check_replacement(ev: Evidence) -> tuple[Outcome, str]:
    """The baseline (the original reaches the model when nothing replaces it) is result-text."""
    later = checks.scripted_requests(ev)[1:]
    original = [r["n"] for r in later if markers.TEXT_RESULT in checks.dump(r["body"])]
    replaced = checks.next_request_has(ev, markers.REPLACEMENT)
    sibling = checks.next_request_has(ev, markers.SIBLING)
    if not (original or replaced or sibling):
        return "inconclusive", "no tool result reached the model at all"
    if original:
        return "not_shown", f"the original marker is still in model request(s) {original}"
    if not replaced:
        return "not_shown", "neither the original nor the replacement reached the model"
    if not sibling:
        return "not_shown", "the replacement arrived but the sibling text was lost"
    return "shown", "the next request has the replacement and the sibling, and not the original"


def check_with_competitor(ev: Evidence) -> tuple[Outcome, str]:
    outcome, reason = check_replacement(ev)
    saw_original = checks.hook_saw(ev, "PostToolUse", markers.TEXT_RESULT, label="b")
    saw_replaced = checks.hook_saw(ev, "PostToolUse", markers.REPLACEMENT, label="b")
    note = f"the second hook saw original={saw_original} replacement={saw_replaced}"
    return outcome, f"{reason}; {note}"


REPLACEMENT: list[Scenario] = [
    Scenario(
        "replace-text", CLAIM, script("echo_text"), [*RECORD, REPLACE], check=check_replacement
    ),
    Scenario(
        "replace-with-competing-hook",
        CLAIM,
        script("echo_text"),
        [REPLACE, HookSpec("PostToolUse", "mcp__.*", "record", "b")],
        check=check_with_competitor,
    ),
]
