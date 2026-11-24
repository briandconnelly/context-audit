import json
import stat
import sys
from pathlib import Path

import pytest

from probe import runner
from probe.runner import run_scenario
from probe.scenario import HookSpec, Scenario
from probe.stub import Reply
from tests.conftest import needs_network_denial


def scenario(check=None):
    return Scenario(
        name="t",
        claim="test claim",
        script=[Reply(text="hi")],
        hooks=[HookSpec("PostToolUse", "mcp__.*", "record", "a")],
        check=check or (lambda ev: ("shown", "ok")),
    )


def fake_claude(tmp_path, body):
    path = tmp_path / "fake-claude"
    path.write_text(f"#!{sys.executable}\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def test_refuses_non_empty_run_dir(tmp_path):
    (tmp_path / "old.jsonl").write_text("x")
    with pytest.raises(ValueError):
        run_scenario(scenario(), tmp_path)


@needs_network_denial
def test_timeout_is_inconclusive(tmp_path, monkeypatch):
    fake = fake_claude(tmp_path, "import time; time.sleep(30)")
    monkeypatch.setattr(runner, "CLAUDE_ARGV0", fake)
    result = run_scenario(scenario(), tmp_path / "run", timeout=1)
    assert result.outcome == "inconclusive"
    assert "timed out" in result.reason


@needs_network_denial
def test_no_stub_request_is_inconclusive(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "CLAUDE_ARGV0", fake_claude(tmp_path, "raise SystemExit(1)"))
    result = run_scenario(scenario(), tmp_path / "run", timeout=10)
    assert result.outcome == "inconclusive"
    assert "no request reached the stub" in result.reason


@needs_network_denial
def test_check_exception_is_inconclusive(tmp_path, monkeypatch):
    post = (
        "import json,os,urllib.request\n"
        "u=os.environ['ANTHROPIC_BASE_URL']+'/v1/messages'\n"
        "d=json.dumps({'tools':[{'name':'x'}],'messages':[]}).encode()\n"
        "urllib.request.urlopen(urllib.request.Request(u,data=d,"
        "headers={'x-api-key':os.environ['ANTHROPIC_API_KEY']})).read()\n"
    )
    monkeypatch.setattr(runner, "CLAUDE_ARGV0", fake_claude(tmp_path, post))

    def boom(ev):
        raise KeyError("missing")

    result = run_scenario(scenario(boom), tmp_path / "run", timeout=20)
    assert result.outcome == "inconclusive"
    assert "check failed" in result.reason


@needs_network_denial
def test_evidence_reaches_the_check(tmp_path, monkeypatch):
    post = (
        "import json,os,urllib.request\n"
        "u=os.environ['ANTHROPIC_BASE_URL']+'/v1/messages'\n"
        "d=json.dumps({'tools':[{'name':'x'}],'messages':[]}).encode()\n"
        "urllib.request.urlopen(urllib.request.Request(u,data=d,"
        "headers={'x-api-key':os.environ['ANTHROPIC_API_KEY']})).read()\n"
    )
    monkeypatch.setattr(runner, "CLAUDE_ARGV0", fake_claude(tmp_path, post))
    seen = {}

    def check(ev):
        seen["requests"] = ev.requests
        seen["calls"] = ev.calls
        return "shown", "ok"

    result = run_scenario(scenario(check), tmp_path / "run", timeout=20)
    assert result.outcome == "shown"
    assert [r["auth"] for r in seen["requests"]] == ["synthetic"]
    assert seen["calls"] == []


def test_settings_and_mcp_config_shape(tmp_path):
    prepared = runner.prepare(scenario(), tmp_path, "http://127.0.0.1:1")
    settings = json.loads((tmp_path / "settings.json").read_text())
    (group,) = settings["hooks"]["PostToolUse"]
    assert group["matcher"] == "mcp__.*"
    (hook,) = group["hooks"]
    assert hook["type"] == "command"
    assert "PROBE_HOOK_MODE=record" in hook["command"]
    assert "PROBE_HOOK_LABEL=a" in hook["command"]
    assert "record.py" in hook["command"]
    mcp = json.loads((tmp_path / "mcp.json").read_text())
    assert list(mcp["mcpServers"]) == ["probe"]
    assert prepared.extra_env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:1"
    assert "--strict-mcp-config" in prepared.argv
    assert "-p" in prepared.argv


def test_hook_without_matcher_omits_it(tmp_path):
    s = Scenario("t", "c", [], [HookSpec("Stop", None, "record", "a")])
    runner.prepare(s, tmp_path, "http://127.0.0.1:1")
    settings = json.loads((tmp_path / "settings.json").read_text())
    assert "matcher" not in settings["hooks"]["Stop"][0]


@needs_network_denial
def test_relative_run_dir_yields_absolute_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runner, "CLAUDE_ARGV0", fake_claude(tmp_path, "raise SystemExit(1)"))
    result = run_scenario(scenario(), Path("rel/run"), timeout=10)
    assert result.run_dir.is_absolute()
    settings = json.loads((result.run_dir / "settings.json").read_text())
    command = settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    assert f"PROBE_HOOK_LOG={result.run_dir}/hooks.jsonl" in command


@needs_network_denial
def test_claude_runs_outside_the_home_tree(tmp_path, monkeypatch):
    # Claude Code reads CLAUDE.md and .claude/skills from every ancestor of its working directory,
    # so a working directory under the owner's home leaks their real instructions into the run.
    body = (
        "import os, pathlib, sys\n"
        "log = pathlib.Path(sys.argv[sys.argv.index('--debug-file') + 1])\n"
        "log.with_name('cwd.txt').write_text(os.getcwd())"
    )
    monkeypatch.setattr(runner, "CLAUDE_ARGV0", fake_claude(tmp_path, body))
    result = run_scenario(scenario(), tmp_path / "run", timeout=10)
    cwd = Path((result.run_dir / "cwd.txt").read_text()).resolve()
    assert not cwd.is_relative_to(Path.home().resolve())
    for ancestor in [cwd, *cwd.parents]:
        assert not (ancestor / "CLAUDE.md").exists()
        assert not (ancestor / ".claude").exists()


def _evidence(request):
    from probe.sandbox import Completed
    from probe.scenario import Evidence

    return Evidence(Path("."), Completed(0, "", "", False), [request], [], [], None)


def test_a_real_credential_in_any_scenario_is_inconclusive():
    for kind in ("bearer", "other-key"):
        request = {"n": 0, "path": "/v1/messages", "auth": kind, "scripted": True, "body": {}}
        outcome, reason = runner.judge(scenario(), _evidence(request))
        assert outcome == "inconclusive"
        assert kind in reason


def test_a_loaded_instruction_file_in_any_scenario_is_inconclusive():
    body = {"messages": [{"role": "user", "content": "Contents of /somewhere/CLAUDE.md (x):"}]}
    request = {"n": 0, "path": "/v1/messages", "auth": "synthetic", "scripted": True, "body": body}
    outcome, reason = runner.judge(scenario(), _evidence(request))
    assert outcome == "inconclusive"
    assert "instruction file" in reason


@needs_network_denial
def test_planted_files_are_written_two_levels_above_the_working_directory(tmp_path, monkeypatch):
    body = (
        "import os, pathlib, sys\n"
        "log = pathlib.Path(sys.argv[sys.argv.index('--debug-file') + 1])\n"
        "log.with_name('cwd.txt').write_text(os.getcwd())"
    )
    monkeypatch.setattr(runner, "CLAUDE_ARGV0", fake_claude(tmp_path, body))
    s = Scenario("t", "c", [Reply(text="x")], [], planted={"CLAUDE.md": "canary"})
    result = run_scenario(s, tmp_path / "run", timeout=10)
    cwd = Path((result.run_dir / "cwd.txt").read_text())
    assert (cwd.parent.parent / "CLAUDE.md").read_text() == "canary"
    assert not (cwd.parent / "CLAUDE.md").exists()
    assert not (cwd / "CLAUDE.md").exists()


def test_outside_settings_are_excluded_unless_a_scenario_asks(tmp_path):
    default = runner.prepare(scenario(), tmp_path, "http://127.0.0.1:1")
    assert default.argv[default.argv.index("--setting-sources") + 1] == ""
    loading = Scenario("t", "c", [], [], load_outside_settings=True)
    assert "--setting-sources" not in runner.prepare(loading, tmp_path, "http://127.0.0.1:1").argv


def test_plugin_dir_and_env_reach_the_command(tmp_path):
    from dataclasses import replace

    s = replace(scenario(), plugin_dir=Path("/plug in"), env={"A": "{run_dir}/state"})
    prepared = runner.prepare(s, tmp_path, "http://127.0.0.1:1")
    i = prepared.argv.index("--plugin-dir")
    assert prepared.argv[i + 1] == "/plug in"
    assert prepared.extra_env["A"] == f"{tmp_path}/state"
    assert prepared.extra_env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:1"


def test_no_plugin_dir_by_default(tmp_path):
    assert "--plugin-dir" not in runner.prepare(scenario(), tmp_path, "http://127.0.0.1:1").argv
