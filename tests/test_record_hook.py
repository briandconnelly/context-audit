import json
import os
import subprocess
import sys
from pathlib import Path

from probe import markers
from probe.hooks.record import OUTPUTS

HOOK = Path(__file__).resolve().parent.parent / "probe" / "hooks" / "record.py"
POST = {
    "hook_event_name": "PostToolUse",
    "tool_name": "mcp__probe__echo_text",
    "tool_use_id": "toolu_01",
    "tool_response": [
        {"type": "text", "text": f"Primary {markers.TEXT_RESULT}. Secondary {markers.SIBLING}."}
    ],
}


def run(tmp_path, mode, payload, label="a"):
    log = tmp_path / "hooks.jsonl"
    env = {
        "PATH": os.environ["PATH"],
        "PROBE_HOOK_LOG": str(log),
        "PROBE_HOOK_MODE": mode,
        "PROBE_HOOK_LABEL": label,
    }
    stdin = payload if isinstance(payload, str) else json.dumps(payload)
    done = subprocess.run(
        [sys.executable, "-I", str(HOOK)], input=stdin, capture_output=True, text=True, env=env
    )
    records = [json.loads(line) for line in log.read_text().splitlines()]
    return done, records


def test_record_mode_logs_input_and_prints_nothing(tmp_path):
    done, records = run(tmp_path, "record", POST)
    assert done.returncode == 0
    assert done.stdout == ""
    assert records == [{"label": "a", "input": POST}]


def test_label_distinguishes_two_hooks(tmp_path):
    run(tmp_path, "record", POST, label="a")
    _, records = run(tmp_path, "record", POST, label="b")
    assert [r["label"] for r in records] == ["a", "b"]


def test_message_mode_emits_hook_message_marker(tmp_path):
    done, _ = run(tmp_path, "message", POST)
    out = json.loads(done.stdout)
    assert markers.HOOK_MESSAGE in out["systemMessage"]
    assert out == OUTPUTS["message"]


def test_replace_mode_swaps_only_the_marker(tmp_path):
    done, _ = run(tmp_path, "replace", POST)
    out = json.loads(done.stdout)["hookSpecificOutput"]
    assert out["hookEventName"] == "PostToolUse"
    text = out["updatedToolOutput"][0]["text"]
    assert markers.REPLACEMENT in text
    assert markers.SIBLING in text
    assert markers.TEXT_RESULT not in text
    assert out["updatedToolOutput"][0]["type"] == "text"


def test_replace_mode_is_silent_without_the_marker(tmp_path):
    done, _ = run(tmp_path, "replace", {**POST, "tool_response": "nothing here"})
    assert done.stdout == ""


def test_replace_mode_is_silent_on_other_events(tmp_path):
    done, _ = run(tmp_path, "replace", {**POST, "hook_event_name": "PreToolUse"})
    assert done.stdout == ""


def test_ask_mode_only_for_follow_on(tmp_path):
    pre = {"hook_event_name": "PreToolUse", "tool_name": "mcp__probe__follow_on"}
    done, _ = run(tmp_path, "ask", pre)
    out = json.loads(done.stdout)["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask"
    assert out["hookEventName"] == "PreToolUse"
    other, _ = run(tmp_path, "ask", {**pre, "tool_name": "mcp__probe__echo_text"})
    assert other.stdout == ""


def test_malformed_stdin_exits_zero_and_logs_raw(tmp_path):
    done, records = run(tmp_path, "record", "{not json")
    assert done.returncode == 0
    assert records == [{"label": "a", "input": {"_raw": "{not json"}}]


def test_unknown_mode_behaves_as_record(tmp_path):
    done, records = run(tmp_path, "nonsense", POST)
    assert done.returncode == 0
    assert done.stdout == ""
    assert len(records) == 1
