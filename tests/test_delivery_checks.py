from pathlib import Path

from probe import markers
from probe.sandbox import Completed
from probe.scenario import Evidence
from probe.scenarios import delivery as d


def hook(event, **fields):
    return {"label": "a", "input": {"hook_event_name": event, **fields}}


def request(content, scripted=True, path="/v1/messages"):
    body = {"messages": [{"role": "user", "content": content}]}
    return {"n": 0, "path": path, "auth": "synthetic", "scripted": scripted, "body": body}


def evidence(requests, hook_events):
    done = Completed(0, "", "", False)
    return Evidence(Path("."), done, requests, hook_events, [], None)


def test_structured_reports_which_member_reached_hook_and_model():
    ev = evidence(
        [request("first"), request(markers.STRUCTURED_RESULT)],
        [hook("PostToolUse", tool_response=markers.STRUCTURED_RESULT)],
    )
    outcome, reason = d.check_structured(ev)
    assert outcome == "shown"
    assert "structuredContent" in reason and "content text" in reason


def test_structured_not_shown_when_model_gets_text_the_hook_lacks():
    ev = evidence(
        [request("first"), request(f"{markers.STRUCTURED_RESULT} {markers.STRUCTURED_TEXT}")],
        [hook("PostToolUse", tool_response=markers.STRUCTURED_RESULT)],
    )
    outcome, reason = d.check_structured(ev)
    assert outcome == "not_shown"
    assert "content text" in reason


def test_structured_inconclusive_when_nothing_reached_the_model():
    assert d.check_structured(evidence([request("first"), request("x")], []))[0] == "inconclusive"


def big(text):
    return [hook("PostToolUse", tool_response=[{"type": "text", "text": text}])]


def test_big_requires_the_whole_length():
    whole = markers.BIG_HEAD + "." * (200_000 - 50) + markers.BIG_TAIL
    whole = whole[: 200_000 - len(markers.BIG_TAIL)] + markers.BIG_TAIL
    assert len(whole) == 200_000
    assert d.check_big(evidence([request("a"), request("b")], big(whole)))[0] == "shown"


def test_big_detects_middle_truncation():
    cut = markers.BIG_HEAD + "... [199000 characters truncated] ..." + markers.BIG_TAIL
    outcome, reason = d.check_big(evidence([request("a"), request("b")], big(cut)))
    assert outcome == "not_shown"
    assert "characters" in reason


def test_canary_shown_only_when_planted_file_is_loaded_and_detected():
    loaded = request(f"Contents of /tmp/x/CLAUDE.md: {markers.CANARY}")
    assert d.check_canary(evidence([loaded], []))[0] == "shown"
    assert d.check_canary(evidence([request("nothing")], []))[0] == "not_shown"
    undetected = request(f"something {markers.CANARY}")
    assert d.check_canary(evidence([undetected], []))[0] == "not_shown"


def test_exclusion_shown_only_when_the_planted_file_stays_out():
    assert d.check_excluded(evidence([request("nothing")], []))[0] == "shown"
    loaded = request(f"Contents of /tmp/x/CLAUDE.md: {markers.CANARY}")
    assert d.check_excluded(evidence([loaded], []))[0] == "not_shown"
    unscripted = request("nothing", scripted=False)
    assert d.check_excluded(evidence([unscripted], []))[0] == "inconclusive"
