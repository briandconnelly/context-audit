"""Terminal scenarios: a hook message shown to the owner, and a hook-requested permission prompt."""

from __future__ import annotations

import re

from probe import checks, markers
from probe.pty_runner import Step
from probe.scenario import Check, Evidence, HookSpec, Outcome, Scenario
from probe.scenarios.delivery import call
from probe.stub import Reply

DIRECT_CLAIM = "A hook message appears on the owner's terminal without passing through the model"
ASK_CLAIM = "A gate's ask reaches the owner before the call runs"
FINISHED = "probe-finished"
PROMPT = "Do you want to proceed?"
HOOK_REASON = "Probe gate: confirm this call"
INTERRUPTED = "What should Claude do instead?"
DONT_ASK = "don't ask again"
START = Step("❯", "run the probe\r")
ASK = HookSpec("PreToolUse", "mcp__.*", "ask", "g")
RECORD_PRE = HookSpec("PreToolUse", "mcp__.*", "record", "a")


def _squash(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _on_screen(ev: Evidence, text: str) -> bool:
    return _squash(text) in _squash(ev.screen)


def follow_script(times: int = 1) -> list[Reply]:
    replies = [Reply(tool_calls=(call("follow_on", n + 1),)) for n in range(times)]
    return [*replies, Reply(text=FINISHED)]


def check_direct(ev: Evidence) -> tuple[Outcome, str]:
    if "echo_text" not in ev.calls:
        return "inconclusive", "the tool never ran, so the hook never fired"
    in_model = checks.any_request_has(ev, markers.HOOK_MESSAGE)
    if not _on_screen(ev, markers.HOOK_MESSAGE):
        return "not_shown", f"the hook message is not on screen; sent to the model: {in_model}"
    if in_model:
        return "not_shown", "the hook message is on screen but was also sent to the model"
    return "shown", "the hook message is on screen and in no request to the model"


def check_baseline(ev: Evidence) -> tuple[Outcome, str]:
    if ev.calls != ["follow_on"]:
        return "inconclusive", f"expected one unprompted call, got {ev.calls}"
    if _on_screen(ev, PROMPT):
        return "not_shown", "a pre-allowed tool prompted with no hook; the gate runs cannot tell"
    return "shown", "with no hook, the pre-allowed tool ran with no permission prompt"


def ask_check(expected_calls: int, prompt_steps: tuple[int, ...] = (1,)) -> Check:
    """``prompt_steps`` are the positions in the scenario's steps that wait for the prompt."""
    prompts = len(prompt_steps)

    def check(ev: Evidence) -> tuple[Outcome, str]:
        seen = sum(1 for n in prompt_steps if n < len(ev.steps_seen) and ev.steps_seen[n])
        reason_shown = _on_screen(ev, HOOK_REASON)
        detail = (
            f"prompts answered: {seen}; calls that ran: {len(ev.calls)}; "
            f"hook reason shown in the prompt: {reason_shown}"
        )
        if seen == 0:
            return "not_shown", f"no permission prompt appeared; {detail}"
        if seen == prompts and len(ev.calls) == expected_calls and reason_shown:
            return "shown", detail
        return "not_shown", detail

    return check


def check_dont_ask_again(ev: Evidence) -> tuple[Outcome, str]:
    """After the owner picks "don't ask again", does the hook's ask still prompt?

    The second prompt is declined, so a re-prompting hook leaves one call and a silenced hook
    leaves two. The call count decides; a repainted first prompt cannot fake it.
    """
    detail = f"calls that ran: {len(ev.calls)}; second prompt seen: {ev.steps_seen[2:3]}"
    if len(ev.steps_seen) < 3 or not ev.steps_seen[1]:
        return "inconclusive", f"the first prompt never appeared; {detail}"
    if not _on_screen(ev, DONT_ASK):
        return "inconclusive", f'the prompt did not offer "don\'t ask again"; {detail}'
    if len(ev.calls) >= 2:
        return "not_shown", f'the second call ran: "don\'t ask again" silenced the hook; {detail}'
    if len(ev.calls) == 1 and ev.steps_seen[2]:
        return "shown", f"the hook's ask prompted again and the declined call did not run; {detail}"
    return "inconclusive", detail


def _ask(name: str, times: int, check: Check) -> Scenario:
    return Scenario(
        name,
        ASK_CLAIM,
        follow_script(times),
        [ASK],
        check=check,
        interactive=True,
    )


INTERACTIVE: list[Scenario] = [
    Scenario(
        "direct-message",
        DIRECT_CLAIM,
        [Reply(tool_calls=(call("echo_text"),)), Reply(text=FINISHED)],
        [HookSpec("PostToolUse", "mcp__.*", "message", "m")],
        check=check_direct,
        interactive=True,
    ),
    Scenario(
        "ask-baseline",
        ASK_CLAIM,
        follow_script(),
        [RECORD_PRE],
        check=check_baseline,
        interactive=True,
    ),
    _ask("ask-accept", 1, ask_check(expected_calls=1)),
    _ask("ask-decline", 1, ask_check(expected_calls=0)),
    _ask("ask-dismiss", 1, ask_check(expected_calls=0)),
    _ask("ask-retry", 2, ask_check(expected_calls=0, prompt_steps=(1, 3))),
    _ask("ask-dont-ask-again", 2, check_dont_ask_again),
]

# name -> (steps, text that ends the run, or None to end when the script is used up)
DRIVE: dict[str, tuple[list[Step], str | None]] = {
    "direct-message": ([START], None),
    "ask-baseline": ([START], None),
    "ask-accept": ([START, Step(PROMPT, "1")], None),
    # Declining or dismissing ends the turn, so no further request is made.
    "ask-decline": ([START, Step(PROMPT, "3")], INTERRUPTED),
    "ask-dismiss": ([START, Step(PROMPT, "\x1b")], INTERRUPTED),
    "ask-retry": (
        # Declined both times: a retry that ran without a second prompt would leave a call.
        [START, Step(PROMPT, "3"), Step(INTERRUPTED, "again\r"), Step(PROMPT, "3")],
        INTERRUPTED,
    ),
    "ask-dont-ask-again": (
        [START, Step(PROMPT, "2"), Step(PROMPT, "3", timeout=15, optional=True)],
        INTERRUPTED,
    ),
}
