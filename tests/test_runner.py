import json
import stat
import sys
from pathlib import Path

import pytest

from probe import runner
from probe.runner import run_scenario
from probe.scenario import HookSpec, Scenario
from probe.stub import Reply


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


def test_timeout_is_inconclusive(tmp_path, monkeypatch):
    fake = fake_claude(tmp_path, "import time; time.sleep(30)")
    monkeypatch.setattr(runner, "CLAUDE_ARGV0", fake)
    result = run_scenario(scenario(), tmp_path / "run", timeout=1)
    assert result.outcome == "inconclusive"
    assert "timed out" in result.reason


def test_no_stub_request_is_inconclusive(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "CLAUDE_ARGV0", fake_claude(tmp_path, "raise SystemExit(1)"))
    result = run_scenario(scenario(), tmp_path / "run", timeout=10)
    assert result.outcome == "inconclusive"
    assert "no request reached the stub" in result.reason


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


def test_relative_run_dir_yields_absolute_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runner, "CLAUDE_ARGV0", fake_claude(tmp_path, "raise SystemExit(1)"))
    result = run_scenario(scenario(), Path("rel/run"), timeout=10)
    assert result.run_dir.is_absolute()
    settings = json.loads((result.run_dir / "settings.json").read_text())
    command = settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    assert f"PROBE_HOOK_LOG={result.run_dir}/hooks.jsonl" in command
