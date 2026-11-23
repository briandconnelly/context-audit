import json
from pathlib import Path

from probe.sandbox import Completed
from probe.scenario import Evidence
from probe.scenarios import invocation as inv

LITERAL = '"${CLAUDE_PLUGIN_ROOT}/bin/context-audit" scan --json'


def request(content):
    body = {"messages": [{"role": "user", "content": content}]}
    return {"n": 0, "path": "/v1/messages", "auth": "synthetic", "scripted": True, "body": body}


def evidence(contents, run_dir=Path("."), hook_events=()):
    done = Completed(0, "", "", False)
    reqs = [request(c) for c in contents]
    return Evidence(run_dir, done, reqs, list(hook_events), [], None)


def test_substitution_shown_with_the_path():
    ev = evidence(["first", 'sh "/plug/root/bin/context-audit" scan --json'])
    outcome, reason = inv.check_skill_substitution(ev)
    assert outcome == "shown"
    assert "/plug/root" in reason


def test_substitution_not_shown_on_the_literal_variable():
    assert inv.check_skill_substitution(evidence(["first", LITERAL]))[0] == "not_shown"


def test_substitution_inconclusive_when_the_body_never_arrives():
    outcome, reason = inv.check_skill_substitution(evidence(["first", "second"]))
    assert outcome == "inconclusive"
    assert "baseline" in reason


def test_bin_on_path_shown_when_a_plugin_bin_is_added(tmp_path, monkeypatch):
    plugin_bin = tmp_path / "bin"
    plugin_bin.mkdir()
    (plugin_bin / "context-audit").write_text("")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    out = f"CTXA-WHICH[{plugin_bin}/context-audit] CTXA-PATHVAR[{plugin_bin}:/usr/bin:/bin]"
    outcome, reason = inv.check_bin_on_path(evidence(["first", out]))
    assert outcome == "shown"
    assert str(plugin_bin) in reason


def test_bin_on_path_not_shown_when_path_is_unchanged(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    out = "CTXA-WHICH[none] CTXA-PATHVAR[/usr/bin:/bin]"
    assert inv.check_bin_on_path(evidence(["first", out]))[0] == "not_shown"


def test_bin_on_path_ignores_an_installed_copy_already_on_path(tmp_path, monkeypatch):
    installed = tmp_path / "local"
    installed.mkdir()
    (installed / "context-audit").write_text("")
    monkeypatch.setenv("PATH", f"{installed}:/bin")
    out = f"CTXA-WHICH[{installed}/context-audit] CTXA-PATHVAR[{installed}:/bin]"
    assert inv.check_bin_on_path(evidence(["first", out]))[0] == "not_shown"


def test_bin_on_path_inconclusive_without_the_tool_output():
    outcome, reason = inv.check_bin_on_path(evidence(["first", "second"]))
    assert outcome == "inconclusive"
    assert "baseline" in reason


def post(label="a"):
    return {"label": label, "input": {"hook_event_name": "PostToolUse"}}


def test_hook_root_shown_when_the_plugin_hook_wrote_state(tmp_path):
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "counters.json").write_text(json.dumps({"results_delivered": 1}))
    outcome, _ = inv.check_hook_root(evidence(["a", "b"], tmp_path, [post()]))
    assert outcome == "shown"


def test_hook_root_not_shown_when_no_state_was_written(tmp_path):
    outcome, _ = inv.check_hook_root(evidence(["a", "b"], tmp_path, [post()]))
    assert outcome == "not_shown"


def test_hook_root_inconclusive_when_no_result_hook_fired(tmp_path):
    outcome, reason = inv.check_hook_root(evidence(["a", "b"], tmp_path, []))
    assert outcome == "inconclusive"
    assert "baseline" in reason


def test_bin_on_path_reads_the_output_not_the_echoed_command(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    call = "CTXA-WHICH[%s] CTXA-PATHVAR[%s]"
    out = "CTXA-WHICH[none] CTXA-PATHVAR[/usr/bin:/bin:/added]"
    outcome, reason = inv.check_bin_on_path(evidence(["first", call + " " + out]))
    assert outcome == "not_shown"
    assert "/added" in reason and "%s" not in reason
