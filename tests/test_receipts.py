import json

import pytest

from context_audit import receipts
from context_audit.receipts import Receipt, capability, read_receipts, write_receipts
from context_audit.report import CAPABILITY_BEHAVIOURS


def receipt(behaviour="result-text", status="shown", cv="2.1.330", pv="0.0.0") -> Receipt:
    return Receipt(behaviour, status, cv, pv, "headless", "default")


def by_name(caps):
    return {c["behaviour"]: c for c in caps}


def test_capability_is_unverified_without_a_matching_receipt(tmp_path):
    caps = capability(tmp_path, "2.1.330", "0.0.0")
    assert [c["behaviour"] for c in caps] == list(CAPABILITY_BEHAVIOURS)
    assert {c["status"] for c in caps} == {"unverified"}
    assert {c["reason"] for c in caps} == {receipts.NO_RECEIPT}
    write_receipts(tmp_path, [receipt(cv="2.1.329")])
    assert by_name(capability(tmp_path, "2.1.330", "0.0.0"))["result-text"]["status"] == (
        "unverified"
    )


def test_capability_matches_on_both_versions(tmp_path):
    write_receipts(
        tmp_path,
        [receipt(), receipt("error", "not_shown"), receipt("result-big", pv="0.0.1")],
    )
    caps = by_name(capability(tmp_path, "2.1.330", "0.0.0"))
    assert caps["result-text"] == {"behaviour": "result-text", "status": "shown"}
    assert caps["error"]["status"] == "not_shown"
    assert caps["result-big"]["status"] == "unverified"
    assert by_name(capability(tmp_path, "2.1.330", "0.0.1"))["result-big"]["status"] == "shown"


def test_unknown_claude_version_makes_everything_unverified(tmp_path):
    write_receipts(tmp_path, [receipt()])
    caps = capability(tmp_path, None, "0.0.0")
    assert {c["status"] for c in caps} == {"unverified"}
    assert {c["reason"] for c in caps} == {receipts.VERSION_UNKNOWN}


def test_write_then_read_round_trips_and_file_is_owner_only(tmp_path):
    write_receipts(tmp_path, [receipt(), receipt("notification", "inconclusive")])
    path = tmp_path / "receipts.json"
    assert path.stat().st_mode & 0o777 == 0o600
    assert read_receipts(tmp_path) == [receipt(), receipt("notification", "inconclusive")]


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        json.dumps({"receipts": [{"behaviour": "result-text"}]}),
        json.dumps({"receipts": [{**receipt().__dict__, "behaviour": "made-up"}]}),
        json.dumps({"receipts": [{**receipt().__dict__, "status": "unverified"}]}),
    ],
)
def test_malformed_receipts_are_ignored(tmp_path, content):
    (tmp_path / "receipts.json").write_text(content)
    assert {c["status"] for c in capability(tmp_path, "2.1.330", "0.0.0")} == {"unverified"}


def test_write_rejects_an_unknown_behaviour(tmp_path):
    with pytest.raises(ValueError):
        write_receipts(tmp_path, [receipt("made-up")])


@pytest.mark.parametrize(
    "stdout,expected",
    [("2.1.330 (Claude Code)\n", "2.1.330"), ("", None), ("garbage\x1b[0m", None)],
)
def test_parse_claude_version(stdout, expected):
    assert receipts.parse_claude_version(stdout) == expected


def test_installed_claude_version_is_none_when_missing(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    assert receipts.installed_claude_version() is None
