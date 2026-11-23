from pathlib import Path

from probe import markers
from probe.sandbox import Completed
from probe.scenario import Evidence
from probe.scenarios.replacement import check_replacement


def evidence(*later_texts):
    def request(blocks):
        body = {"messages": [{"role": "user", "content": blocks}]}
        return {"n": 0, "path": "/v1/messages", "auth": "synthetic", "scripted": True, "body": body}

    requests = [request("first"), *[request(t) for t in later_texts]]
    return Evidence(Path("."), Completed(0, "", "", False), requests, [], [], None)


def test_shown_when_original_gone_and_sibling_kept():
    ev = evidence(f"Primary {markers.REPLACEMENT}. Secondary {markers.SIBLING}.")
    assert check_replacement(ev)[0] == "shown"


def test_not_shown_when_original_survives_anywhere():
    ev = evidence(
        [
            {"type": "text", "text": f"{markers.REPLACEMENT} {markers.SIBLING}"},
            {"type": "text", "text": f"copy {markers.TEXT_RESULT}"},
        ]
    )
    outcome, reason = check_replacement(ev)
    assert outcome == "not_shown"
    assert "original" in reason


def test_not_shown_when_original_survives_in_a_later_request():
    ev = evidence(f"{markers.REPLACEMENT} {markers.SIBLING}", f"late {markers.TEXT_RESULT}")
    assert check_replacement(ev)[0] == "not_shown"


def test_not_shown_when_sibling_lost():
    ev = evidence(f"Primary {markers.REPLACEMENT}.")
    outcome, reason = check_replacement(ev)
    assert outcome == "not_shown"
    assert "sibling" in reason


def test_not_shown_when_nothing_was_replaced():
    ev = evidence(f"Primary {markers.TEXT_RESULT}. Secondary {markers.SIBLING}.")
    assert check_replacement(ev)[0] == "not_shown"


def test_inconclusive_when_no_result_reached_the_model():
    assert check_replacement(evidence("nothing at all"))[0] == "inconclusive"


def test_not_shown_when_original_is_in_an_unscripted_request():
    ev = evidence(f"{markers.REPLACEMENT} {markers.SIBLING}")
    body = {"messages": [{"role": "user", "content": markers.TEXT_RESULT}]}
    ev.requests.append(
        {
            "n": 9,
            "path": "/v1/messages/count_tokens",
            "auth": "synthetic",
            "scripted": False,
            "body": body,
        }
    )
    assert check_replacement(ev)[0] == "not_shown"


def test_transcript_check_reports_what_the_transcript_holds(tmp_path):
    from dataclasses import replace

    from probe.scenarios.replacement import check_transcript_after_replacement

    path = tmp_path / "t.jsonl"
    base = evidence(f"{markers.REPLACEMENT} {markers.SIBLING}")
    path.write_text(f"toolu_probe01 {markers.REPLACEMENT}")
    outcome, reason = check_transcript_after_replacement(replace(base, transcript=path))
    assert outcome == "not_shown"
    assert "replacement" in reason
    path.write_text(f"toolu_probe01 {markers.TEXT_RESULT}")
    assert check_transcript_after_replacement(replace(base, transcript=path))[0] == "shown"
    assert check_transcript_after_replacement(base)[0] == "inconclusive"
    unreplaced = evidence(f"{markers.TEXT_RESULT} {markers.SIBLING}")
    assert check_transcript_after_replacement(replace(unreplaced, transcript=path))[0] == (
        "inconclusive"
    )
