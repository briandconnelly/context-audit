from pathlib import Path

from probe import markers
from probe.sandbox import Completed
from probe.scenario import Evidence
from probe.scenarios import interactive as i


def evidence(screen="", calls=(), seen=(), request_text="nothing"):
    body = {"messages": [{"role": "user", "content": request_text}]}
    request = {"n": 0, "path": "/v1/messages", "auth": "synthetic", "scripted": True, "body": body}
    done = Completed(0, "", "", False)
    return Evidence(Path("."), done, [request], [], list(calls), None, screen, tuple(seen))


PROMPT_SCREEN = f"Hook says: {i.HOOK_REASON}\n Do you want  to proceed?"


def test_direct_shown_only_when_on_screen_and_not_sent_to_the_model():
    on = f"PostToolUse says: {markers.HOOK_MESSAGE}"
    assert i.check_direct(evidence(on, ["echo_text"]))[0] == "shown"
    assert i.check_direct(evidence("nothing", ["echo_text"]))[0] == "not_shown"
    leaked = evidence(on, ["echo_text"], request_text=markers.HOOK_MESSAGE)
    assert i.check_direct(leaked)[0] == "not_shown"
    assert i.check_direct(evidence(on, []))[0] == "inconclusive"


def test_baseline_requires_an_unprompted_call():
    assert i.check_baseline(evidence("ran", ["follow_on"]))[0] == "shown"
    assert i.check_baseline(evidence(PROMPT_SCREEN, ["follow_on"]))[0] == "not_shown"
    assert i.check_baseline(evidence("ran", []))[0] == "inconclusive"


def test_accept_needs_a_prompt_and_exactly_one_call():
    check = i.ask_check(expected_calls=1)
    assert check(evidence(PROMPT_SCREEN, ["follow_on"], [True, True]))[0] == "shown"
    assert check(evidence(PROMPT_SCREEN, [], [True, True]))[0] == "not_shown"
    assert check(evidence("no prompt", ["follow_on"], [True, False]))[0] == "not_shown"


def test_decline_needs_a_prompt_and_no_call():
    check = i.ask_check(expected_calls=0)
    assert check(evidence(PROMPT_SCREEN, [], [True, True]))[0] == "shown"
    assert check(evidence(PROMPT_SCREEN, ["follow_on"], [True, True]))[0] == "not_shown"


def test_prompt_without_the_hook_reason_is_not_shown():
    check = i.ask_check(expected_calls=1)
    assert check(evidence("Do you want to proceed?", ["follow_on"], [True, True]))[0] == "not_shown"


def test_dont_ask_again_reports_whether_the_second_prompt_came():
    assert i.check_dont_ask_again(evidence(seen=[True, True, True]))[0] == "shown"
    assert i.check_dont_ask_again(evidence(seen=[True, True, False]))[0] == "not_shown"
    assert i.check_dont_ask_again(evidence(seen=[True, False, False]))[0] == "inconclusive"


def test_every_interactive_scenario_has_a_drive_entry():
    assert {s.name for s in i.INTERACTIVE} == set(i.DRIVE)
    assert all(s.interactive for s in i.INTERACTIVE)


def test_retry_counts_only_the_prompt_steps():
    check = i.ask_check(expected_calls=1, prompt_steps=(1, 3))
    assert check(evidence(PROMPT_SCREEN, ["follow_on"], [True, True, True, True]))[0] == "shown"
    assert (
        check(evidence(PROMPT_SCREEN, ["follow_on"], [True, True, True, False]))[0] == "not_shown"
    )
