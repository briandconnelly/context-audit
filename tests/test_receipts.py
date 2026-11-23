import json

import pytest

from context_audit import receipts
from context_audit.receipts import Receipt, capability, read_receipts, write_receipts
from context_audit.report import CAPABILITY_BEHAVIOURS


def receipt(
    behaviour="result-text",
    status="shown",
    cv="2.1.330",
    pv="0.0.0",
    frontend="headless",
    mode="pre-allowed",
) -> Receipt:
    return Receipt(behaviour, status, cv, pv, frontend, mode)


def by_name(caps):
    return {c["behaviour"]: c for c in caps}


UNVERIFIED = {"status": "unverified", "frontend": "none", "permission_mode": "none"}


def test_capability_is_unverified_without_a_matching_receipt(tmp_path):
    caps = capability(tmp_path, "2.1.330", "0.0.0")
    assert [c["behaviour"] for c in caps] == list(CAPABILITY_BEHAVIOURS)
    assert all({k: c[k] for k in UNVERIFIED} == UNVERIFIED for c in caps)
    assert all(set(c) == {"behaviour", "status", "frontend", "permission_mode"} for c in caps)
    write_receipts(tmp_path, [receipt(cv="2.1.329")])
    assert by_name(capability(tmp_path, "2.1.330", "0.0.0"))["result-text"]["status"] == (
        "unverified"
    )


def test_capability_matches_on_both_versions(tmp_path):
    write_receipts(
        tmp_path,
        [receipt(), receipt("error", "not_shown"), receipt("result-over-budget", pv="0.0.1")],
    )
    caps = by_name(capability(tmp_path, "2.1.330", "0.0.0"))
    assert caps["result-text"] == {
        "behaviour": "result-text",
        "status": "shown",
        "frontend": "headless",
        "permission_mode": "pre-allowed",
    }
    assert caps["error"]["status"] == "not_shown"
    assert caps["result-over-budget"]["status"] == "unverified"
    later = by_name(capability(tmp_path, "2.1.330", "0.0.1"))
    assert later["result-over-budget"]["status"] == "shown"


def test_unknown_claude_version_makes_everything_unverified(tmp_path):
    write_receipts(tmp_path, [receipt()])
    caps = capability(tmp_path, None, "0.0.0")
    assert all({k: c[k] for k in UNVERIFIED} == UNVERIFIED for c in caps)


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


@pytest.mark.parametrize(
    "bad", [receipt("made-up"), receipt(frontend="web"), receipt(mode="auto"), receipt(mode="none")]
)
def test_write_rejects_values_outside_the_vocabularies(tmp_path, bad):
    with pytest.raises(ValueError):
        write_receipts(tmp_path, [bad])


def test_capability_has_one_entry_per_frontend_and_mode(tmp_path):
    write_receipts(
        tmp_path,
        [receipt("direct-message", frontend="terminal", mode="default"),
         receipt("direct-message", "not_shown")],
    )  # fmt: skip
    got = [
        c for c in capability(tmp_path, "2.1.330", "0.0.0") if c["behaviour"] == "direct-message"
    ]
    assert [(c["frontend"], c["permission_mode"], c["status"]) for c in got] == [
        ("headless", "pre-allowed", "not_shown"),
        ("terminal", "default", "shown"),
    ]


@pytest.mark.parametrize("other", ["not_shown", "inconclusive"])
def test_disagreeing_duplicates_never_report_shown(tmp_path, other):
    write_receipts(tmp_path, [receipt(), receipt(status=other), receipt()])
    assert by_name(capability(tmp_path, "2.1.330", "0.0.0"))["result-text"]["status"] == other


def test_stale_temporary_file_is_replaced(tmp_path):
    (tmp_path / "receipts.json.tmp").write_text("stale")
    write_receipts(tmp_path, [receipt()])
    assert read_receipts(tmp_path) == [receipt()]
    assert not (tmp_path / "receipts.json.tmp").exists()


def _all_unverified(tmp_path):
    return {c["status"] for c in capability(tmp_path, "2.1.330", "0.0.0")} == {"unverified"}


def test_deeply_nested_receipts_do_not_crash(tmp_path):
    (tmp_path / "receipts.json").write_text("[" * 100_000)
    assert _all_unverified(tmp_path)


def test_oversized_receipts_are_refused(tmp_path):
    write_receipts(tmp_path, [receipt()])
    path = tmp_path / "receipts.json"
    path.write_text(path.read_text() + " " * (receipts.MAX_BYTES + 1))
    assert _all_unverified(tmp_path)


def test_symlinked_receipts_are_refused(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    write_receipts(other, [receipt()])
    (tmp_path / "receipts.json").symlink_to(other / "receipts.json")
    assert _all_unverified(tmp_path)


def test_a_fifo_does_not_hang(tmp_path):
    import os

    os.mkfifo(tmp_path / "receipts.json")
    assert _all_unverified(tmp_path)


@pytest.mark.parametrize(
    "stdout,expected",
    [("2.1.330 (Claude Code)\n", "2.1.330"), ("", None), ("garbage\x1b[0m", None)],
)
def test_parse_claude_version(stdout, expected):
    assert receipts.parse_claude_version(stdout) == expected


def test_installed_claude_version_reads_at_most_200_bytes(tmp_path, monkeypatch):
    fake = tmp_path / "claude"
    fake.write_text("#!/bin/sh\nprintf '2.1.330 (Claude Code)'\nyes x | head -c 100000\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + ":/usr/bin:/bin")
    assert receipts.installed_claude_version() is None  # 200 bytes of noise do not parse


def test_installed_claude_version_times_out(tmp_path, monkeypatch):
    import time

    fake = tmp_path / "claude"
    fake.write_text("#!/bin/sh\nexec sleep 30\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + ":/usr/bin:/bin")
    start = time.monotonic()
    assert receipts.installed_claude_version() is None
    assert time.monotonic() - start < 5


def test_installed_claude_version_parses_a_fake(tmp_path, monkeypatch):
    fake = tmp_path / "claude"
    fake.write_text("#!/bin/sh\necho '2.1.330 (Claude Code)'\necho noise >&2\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + ":/usr/bin:/bin")
    assert receipts.installed_claude_version() == "2.1.330"


def test_installed_claude_version_is_none_when_missing(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    assert receipts.installed_claude_version() is None
