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


def test_every_interactive_scenario_has_a_drive_entry():
    assert {s.name for s in i.INTERACTIVE} == set(i.DRIVE)
    assert all(s.interactive for s in i.INTERACTIVE)


OPTION = "2. Yes, and don't ask again for probe"


def test_dont_ask_again_shown_when_second_prompt_declined_and_one_call_ran():
    ev = evidence(OPTION, ["follow_on"], [True, True, True])
    assert i.check_dont_ask_again(ev)[0] == "shown"


def test_dont_ask_again_not_shown_when_the_second_call_ran():
    two = ["follow_on", "follow_on"]
    assert i.check_dont_ask_again(evidence(OPTION, two, [True, True, False]))[0] == "not_shown"
    # a repaint could satisfy the wait, but then the second call still runs
    assert i.check_dont_ask_again(evidence(OPTION, two, [True, True, True]))[0] == "not_shown"


def test_dont_ask_again_inconclusive_without_the_first_prompt_or_the_option():
    assert i.check_dont_ask_again(evidence(OPTION, [], [True, False, False]))[0] == "inconclusive"
    ev = evidence("no option", ["follow_on"], [True, True, True])
    assert i.check_dont_ask_again(ev)[0] == "inconclusive"


def test_retry_needs_two_prompts_and_no_call():
    check = i.ask_check(expected_calls=0, prompt_steps=(1, 3))
    assert check(evidence(PROMPT_SCREEN, [], [True, True, True, True]))[0] == "shown"
    assert check(evidence(PROMPT_SCREEN, [], [True, True, True, False]))[0] == "not_shown"
    # a retry that ran without a second prompt must not pass
    ran = evidence(PROMPT_SCREEN, ["follow_on"], [True, True, True, True])
    assert check(ran)[0] == "not_shown"
