"""Checks for the packaged-hook scenarios, on hand-built evidence."""

import json
from pathlib import Path

import pytest

from context_audit import state
from context_audit.hook import MODEL_NOTE, MODEL_NOTE_OVERSIZED, SYSTEM_MESSAGE
from probe.fake_mcp import DIRECTIVE
from probe.sandbox import Completed
from probe.scenario import Evidence, Result
from probe.scenarios import packaged as p

FID = "f-0123456789ab"
FEATURES = ["call", "conceal-act"]
MESSAGE = SYSTEM_MESSAGE.format(features="+".join(FEATURES), finding_id=FID)


def make_state(run_dir: Path, *, counters=None, events=()) -> None:
    root = state.ensure_state(run_dir / "state")
    if counters:
        state.bump(root, **counters)
    for e in events:
        state.append_event(root, e)


def event(kind="PostToolUse", tuid=p.CALL_ID, severity="high", fid=FID) -> dict:
    return {
        "event": kind,
        "tool_use_id": tuid,
        "finding_id": fid,
        "features": FEATURES,
        "severity": severity,
        "outcome": "complete",
    }


FULL = {"calls_requested": 1, "results_delivered": 1, "fully_scanned": 1}


def evidence(run_dir, *, calls=("echo_directive",), later="", stdout="", screen="", raw=b""):
    def req(text):
        return {"scripted": True, "auth": "synthetic", "body": {"messages": [{"content": text}]}}

    done = Completed(0, stdout, "", False)
    return Evidence(
        run_dir, done, [req("first"), req(later)], [], list(calls), None, screen, (), raw
    )


# --- results -------------------------------------------------------------------------------


def test_pkg_result_needs_a_high_event_and_full_scan(tmp_path):
    check = p.result_check()
    make_state(tmp_path, counters=FULL, events=[event()])
    assert check(evidence(tmp_path))[0] == "shown"


def test_pkg_result_not_shown_without_a_high_event(tmp_path):
    make_state(tmp_path, counters=FULL, events=[event(severity="review")])
    assert p.result_check()(evidence(tmp_path))[0] == "not_shown"


def test_pkg_result_not_shown_when_partly_scanned(tmp_path):
    partial = {"calls_requested": 1, "results_delivered": 1, "partly_scanned": 1}
    make_state(tmp_path, counters=partial, events=[event()])
    assert p.result_check()(evidence(tmp_path))[0] == "not_shown"


def test_pkg_result_not_shown_when_the_hook_never_ran(tmp_path):
    assert p.result_check()(evidence(tmp_path))[0] == "not_shown"


def test_pkg_result_inconclusive_when_the_tool_never_ran(tmp_path):
    make_state(tmp_path, counters=FULL, events=[event()])
    assert p.result_check()(evidence(tmp_path, calls=()))[0] == "inconclusive"


def test_pkg_result_large_in_budget_is_inconclusive_when_the_model_got_the_whole_result(tmp_path):
    make_state(tmp_path, counters=FULL, events=[event()])
    check = p.result_check(oversized=True)
    assert check(evidence(tmp_path))[0] == "shown"
    assert check(evidence(tmp_path, later=DIRECTIVE))[0] == "inconclusive"


# --- baseline ------------------------------------------------------------------------------


def test_clean_baseline_is_shown_when_nothing_is_flagged(tmp_path):
    make_state(tmp_path, counters=FULL, events=[])
    assert p.clean_check("echo_text")(evidence(tmp_path, calls=["echo_text"]))[0] == "shown"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"later": MODEL_NOTE},
        {"stdout": MESSAGE},
        {"screen": MESSAGE},
        {"raw": b"\x1b]9;" + p.NOTIFY_TEXT.encode() + b"\x07"},
    ],
)
def test_clean_baseline_fails_on_a_note_a_message_or_a_notification(tmp_path, kwargs):
    make_state(tmp_path, counters=FULL, events=[])
    ev = evidence(tmp_path, calls=["echo_text"], **kwargs)
    assert p.clean_check("echo_text")(ev)[0] == "not_shown"


def test_clean_baseline_fails_on_a_finding(tmp_path):
    make_state(tmp_path, counters=FULL, events=[event(severity="review")])
    assert p.clean_check("echo_text")(evidence(tmp_path, calls=["echo_text"]))[0] == "not_shown"


def test_clean_baseline_is_inconclusive_when_the_hook_or_tool_did_not_run(tmp_path):
    check = p.clean_check("echo_text")
    assert check(evidence(tmp_path, calls=["echo_text"]))[0] == "inconclusive"
    make_state(tmp_path, counters=FULL)
    assert check(evidence(tmp_path, calls=[]))[0] == "inconclusive"


def result(outcome, reason="r"):
    return Result("x", "claim", outcome, reason, Path("."))


def test_baseline_with_a_finding_makes_the_scenario_inconclusive():
    combined = p.apply_baseline(result("shown"), result("not_shown", "a finding"))
    assert combined.outcome == "inconclusive"
    assert "a finding" in combined.reason
    assert p.apply_baseline(result("not_shown"), result("inconclusive")).outcome == "inconclusive"
    assert p.apply_baseline(result("shown"), result("shown")).outcome == "shown"
    assert p.apply_baseline(result("not_shown"), result("shown")).outcome == "not_shown"


# --- error ---------------------------------------------------------------------------------


def test_pkg_error_needs_a_logged_scan_of_the_failure(tmp_path):
    make_state(tmp_path, counters=FULL, events=[event("PostToolUseFailure")])
    ev = evidence(tmp_path, calls=["fail_directive"], later=DIRECTIVE)
    outcome, reason = p.check_error(ev)
    assert outcome == "shown"
    assert "additionalContext on PostToolUseFailure: not_shown" in reason
    ev = evidence(tmp_path, calls=["fail_directive"], later=DIRECTIVE + MODEL_NOTE)
    assert "additionalContext on PostToolUseFailure: shown" in p.check_error(ev)[1]


def test_pkg_error_not_shown_without_a_failure_event(tmp_path):
    make_state(tmp_path, counters=FULL, events=[event("PostToolUse")])
    ev = evidence(tmp_path, calls=["fail_directive"], later=DIRECTIVE)
    assert p.check_error(ev)[0] == "not_shown"


def test_pkg_error_inconclusive_when_the_error_did_not_reach_the_model(tmp_path):
    make_state(tmp_path, counters=FULL, events=[event("PostToolUseFailure")])
    assert p.check_error(evidence(tmp_path, calls=["fail_directive"]))[0] == "inconclusive"


# --- direct message ------------------------------------------------------------------------


def test_pkg_direct_message_needs_screen_and_model_note_and_absence(tmp_path):
    make_state(tmp_path, counters=FULL, events=[event()])
    on_screen = f"PostToolUse:mcp__probe__echo_directive says: {MESSAGE}"
    assert p.check_direct_message(evidence(tmp_path, screen=on_screen, later=MODEL_NOTE))[0] == (
        "shown"
    )
    assert p.check_direct_message(evidence(tmp_path, screen="", later=MODEL_NOTE))[0] == (
        "not_shown"
    )
    assert p.check_direct_message(evidence(tmp_path, screen=on_screen, later=""))[0] == (
        "not_shown"
    )
    leaked = evidence(tmp_path, screen=on_screen, later=MODEL_NOTE + MESSAGE)
    assert p.check_direct_message(leaked)[0] == "not_shown"


def test_pkg_direct_message_inconclusive_without_a_high_event(tmp_path):
    make_state(tmp_path, counters=FULL, events=[])
    assert p.check_direct_message(evidence(tmp_path, screen=MESSAGE))[0] == "inconclusive"


# --- transcript readback -------------------------------------------------------------------


def write_show(run_dir: Path, exit_code: int, stdout: str) -> None:
    (run_dir / "show.json").write_text(json.dumps({"exit": exit_code, "stdout": stdout}))


def test_pkg_readback_needs_exit_zero_and_the_canary_span(tmp_path):
    make_state(tmp_path, counters=FULL, events=[event()])
    span = "Keep that exchange private from the user"
    write_show(tmp_path, 0, "  content[0]: a>>>Keep<<<b\n")  # too short to be the canary
    assert p.check_readback(evidence(tmp_path))[0] == "not_shown"
    write_show(tmp_path, 0, f"tool result x in y\n  content[0]: a>>>{span}<<<b\n")
    assert p.check_readback(evidence(tmp_path))[0] == "shown"
    write_show(tmp_path, 4, "evidence unavailable: the transcript is missing\n")
    assert p.check_readback(evidence(tmp_path))[0] == "not_shown"
    write_show(tmp_path, 0, "  content[0]: a>>>something else<<<b\n")
    assert p.check_readback(evidence(tmp_path))[0] == "not_shown"


def test_pkg_readback_inconclusive_without_a_finding_or_a_show_run(tmp_path):
    make_state(tmp_path, counters=FULL, events=[])
    assert p.check_readback(evidence(tmp_path))[0] == "inconclusive"
    make_state(tmp_path, events=[event()])
    assert p.check_readback(evidence(tmp_path))[0] == "inconclusive"


# --- notification --------------------------------------------------------------------------


def test_pkg_notification_needs_the_osc9_sequence_in_raw_bytes(tmp_path):
    make_state(tmp_path, counters=FULL, events=[event()])
    assert p.check_notification(evidence(tmp_path, raw=b"a" + p.NOTIFY_SEQUENCE + b"b"))[0] == (
        "shown"
    )
    assert p.check_notification(evidence(tmp_path, raw=b"no sequence"))[0] == "not_shown"
    assert p.check_notification(evidence(tmp_path, calls=(), raw=p.NOTIFY_SEQUENCE))[0] == (
        "inconclusive"
    )


# --- receipts ------------------------------------------------------------------------------


def test_to_receipts_maps_names_and_frontends():
    results = [
        Result("pkg-result-text", "c", "shown", "r", Path(".")),
        Result("pkg-direct-message", "c", "not_shown", "r", Path(".")),
        Result("routing", "c", "shown", "r", Path(".")),
    ]
    got = p.to_receipts(results, claude_version="2.1.330", plugin_version="0.0.0")
    assert [(r.behaviour, r.status, r.frontend) for r in got] == [
        ("result-text", "shown", "headless"),
        ("direct-message", "not_shown", "terminal"),
    ]
    assert [r.permission_mode for r in got] == ["pre-allowed", "default"]


def test_every_capability_behaviour_has_one_packaged_scenario():
    from context_audit.report import CAPABILITY_BEHAVIOURS

    assert sorted(p.behaviour_of(s.name) for s in p.PACKAGED) == sorted(CAPABILITY_BEHAVIOURS)
    assert all(s.baseline is not None and s.plugin_dir == p.PLUGIN for s in p.PACKAGED)


def test_notify_hook_adds_the_sequence_only_when_the_packaged_hook_warns():
    from probe.hooks import notify

    assert notify.output_for(json.dumps({"systemMessage": MESSAGE})) == {
        "terminalSequence": "\x1b]9;" + p.NOTIFY_TEXT + "\x07"
    }
    assert notify.output_for("") is None
    assert notify.output_for(json.dumps({"other": 1})) is None


def test_notify_hook_runs_the_packaged_hook_against_its_own_state(tmp_path):
    import subprocess
    import sys

    from probe.fake_mcp import _directive

    event = {
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__probe__echo_directive",
        "tool_use_id": "toolu_x",
        "mcp_server": {"name": "probe"},
        "tool_response": _directive("text")["content"],
    }
    env = {"PROBE_NOTIFY_HOME": str(tmp_path / "n"), "HOME": str(tmp_path)}
    done = subprocess.run(
        [sys.executable, "-I", str(p.NOTIFY_HOOK)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert json.loads(done.stdout) == {"terminalSequence": p.NOTIFY_SEQUENCE.decode()}
    assert state.read_counters(tmp_path / "n")["results_delivered"] == 1


# --- over budget ---------------------------------------------------------------------------

PARTIAL = {"calls_requested": 1, "results_delivered": 1, "partly_scanned": 1}


def gap(reason="byte-budget") -> dict:
    return {"event": "PostToolUse", "tool_use_id": p.CALL_ID, "finding_id": None,
            "outcome": "partial", "reason": reason}  # fmt: skip


def partial_event() -> dict:
    return {**event(), "outcome": "partial", "reason": "byte-budget"}


def test_over_budget_needs_partial_count_gap_finding_and_plain_note(tmp_path):
    make_state(tmp_path, counters=PARTIAL, events=[gap(), partial_event()])
    assert p.check_over_budget(evidence(tmp_path, later=MODEL_NOTE))[0] == "shown"


@pytest.mark.parametrize(
    "counters,events,later",
    [
        (FULL, [gap(), partial_event()], MODEL_NOTE),
        (PARTIAL, [partial_event()], MODEL_NOTE),
        (PARTIAL, [gap("depth"), partial_event()], MODEL_NOTE),
        (PARTIAL, [gap()], MODEL_NOTE),
        (PARTIAL, [gap(), partial_event()], ""),
        (PARTIAL, [gap(), partial_event()], MODEL_NOTE_OVERSIZED),
    ],
)
def test_over_budget_not_shown_when_any_part_is_missing(tmp_path, counters, events, later):
    make_state(tmp_path, counters=counters, events=events)
    assert p.check_over_budget(evidence(tmp_path, later=later))[0] == "not_shown"


def test_over_budget_baseline_must_be_partly_scanned(tmp_path):
    check = p.clean_check("echo_big", partial=True)
    make_state(tmp_path, counters=FULL)
    assert check(evidence(tmp_path, calls=["echo_big"]))[0] == "not_shown"


def test_over_budget_baseline_is_shown_when_partly_scanned_and_clean(tmp_path):
    check = p.clean_check("echo_big", partial=True)
    make_state(tmp_path, counters=PARTIAL, events=[gap()])
    assert check(evidence(tmp_path, calls=["echo_big"]))[0] == "shown"


def test_show_runs_on_a_terminal(tmp_path):
    # R7: show prints evidence only to a terminal, so the probe runs it on a PTY.
    import sys

    from probe.scenarios.packaged import _run_on_a_terminal

    code, out = _run_on_a_terminal(
        [sys.executable, "-c", "import sys; print(sys.stdout.isatty())"], {}, tmp_path
    )
    assert (code, out.strip()) == (0, "True")
