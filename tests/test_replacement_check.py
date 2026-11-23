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
