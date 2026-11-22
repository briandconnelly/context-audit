from pathlib import Path

from probe.sandbox import Completed
from probe.scenario import Evidence
from probe.scenarios.routing import check_routing


def evidence(requests, exit_code=0):
    return Evidence(Path("."), Completed(exit_code, "", "", False), requests, [], [], None)


def req(path, auth, scripted):
    return {"n": 0, "path": path, "auth": auth, "scripted": scripted, "body": {}}


def test_unauthenticated_ping_plus_synthetic_message_is_shown():
    ev = evidence([req("/api/hello", "none", False), req("/v1/messages", "synthetic", True)])
    assert check_routing(ev)[0] == "shown"


def test_a_real_credential_anywhere_is_inconclusive():
    for kind in ("bearer", "other-key"):
        ev = evidence([req("/api/hello", kind, False), req("/v1/messages", "synthetic", True)])
        outcome, reason = check_routing(ev)
        assert outcome == "inconclusive"
        assert kind in reason


def test_a_message_without_the_synthetic_key_is_inconclusive():
    ev = evidence([req("/v1/messages?beta=true", "none", True)])
    assert check_routing(ev)[0] == "inconclusive"


def test_nonzero_exit_is_inconclusive():
    ev = evidence([req("/v1/messages", "synthetic", True)], exit_code=1)
    assert check_routing(ev)[0] == "inconclusive"
