import json
from pathlib import Path

from probe import checks, markers
from probe.sandbox import Completed
from probe.scenario import Evidence


def hook(event, label="a", **fields):
    return {"label": label, "input": {"hook_event_name": event, **fields}}


def request(text, scripted=True):
    body = {"messages": [{"role": "user", "content": text}]}
    return {"n": 0, "path": "/v1/messages", "auth": "synthetic", "scripted": scripted, "body": body}


def evidence(requests=(), hook_events=(), transcript=None):
    done = Completed(0, "", "", False)
    return Evidence(Path("."), done, list(requests), list(hook_events), [], transcript)


def test_hook_saw_matches_event_and_label():
    ev = evidence(
        hook_events=[
            hook("PostToolUse", "a", tool_response=f"x {markers.TEXT_RESULT}"),
            hook("PreToolUse", "b", tool_input={}),
        ]
    )
    assert checks.hook_saw(ev, "PostToolUse", markers.TEXT_RESULT)
    assert checks.hook_saw(ev, "PostToolUse", markers.TEXT_RESULT, label="a")
    assert not checks.hook_saw(ev, "PostToolUse", markers.TEXT_RESULT, label="b")
    assert not checks.hook_saw(ev, "PreToolUse", markers.TEXT_RESULT)


def test_next_request_ignores_the_first_request():
    ev = evidence(requests=[request(markers.TEXT_RESULT), request("nothing")])
    assert not checks.next_request_has(ev, markers.TEXT_RESULT)
    ev = evidence(requests=[request("nothing"), request(markers.TEXT_RESULT)])
    assert checks.next_request_has(ev, markers.TEXT_RESULT)


def test_next_request_ignores_unscripted_requests():
    ev = evidence(requests=[request("a"), request(markers.TEXT_RESULT, scripted=False)])
    assert not checks.next_request_has(ev, markers.TEXT_RESULT)


def test_hook_message_marker_is_not_a_result_marker():
    ev = evidence(requests=[request("a"), request(markers.HOOK_MESSAGE)])
    assert not checks.next_request_has(ev, markers.TEXT_RESULT)
    assert checks.next_request_has(ev, markers.HOOK_MESSAGE)


def test_any_hook_event_has_lists_event_names():
    ev = evidence(
        hook_events=[
            hook("PostToolUse", tool_response=markers.TOOL_DESCRIPTION),
            hook("SessionStart", note=markers.TOOL_DESCRIPTION),
            hook("PostToolUse", tool_response=markers.TOOL_DESCRIPTION),
            hook("Stop"),
        ]
    )
    assert checks.any_hook_event_has(ev, markers.TOOL_DESCRIPTION) == [
        "PostToolUse",
        "SessionStart",
    ]
    assert checks.events_seen(ev) == ["PostToolUse", "SessionStart", "Stop"]


def test_transcript_has_requires_the_tool_use_id(tmp_path):
    path = tmp_path / "t.jsonl"
    lines = [
        {"tool_use_id": "toolu_other", "content": markers.TEXT_RESULT},
        {"tool_use_id": "toolu_p1", "content": "nothing"},
    ]
    path.write_text("\n".join(json.dumps(line) for line in lines))
    ev = evidence(transcript=path)
    assert not checks.transcript_has(ev, "toolu_p1", markers.TEXT_RESULT)
    assert checks.transcript_has(ev, "toolu_other", markers.TEXT_RESULT)
    assert not checks.transcript_has(evidence(), "toolu_other", markers.TEXT_RESULT)


def test_hook_records_for_tool_use():
    ev = evidence(
        hook_events=[
            hook("PostToolUse", tool_use_id="toolu_p1"),
            hook("PostToolUse", tool_use_id="toolu_p2"),
            hook("PreToolUse", tool_use_id="toolu_p1"),
        ]
    )
    assert len(checks.hook_records(ev, "PostToolUse", tool_use_id="toolu_p1")) == 1
