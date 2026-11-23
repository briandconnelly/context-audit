from pathlib import Path

import pytest

from probe import __main__ as cli
from probe.scenario import Result


def fake_run(outcomes):
    ran = []

    def run(scenario, run_dir, **kwargs):
        ran.append(scenario.name)
        return Result(
            scenario.name, scenario.claim, outcomes.get(scenario.name, "shown"), "r", run_dir
        )

    return ran, run


def patch(monkeypatch, tmp_path, outcomes):
    ran, run = fake_run(outcomes)
    monkeypatch.setattr(cli, "run_scenario", run)
    monkeypatch.setattr(cli, "run_interactive", lambda s, steps, d, **k: run(s, d))
    monkeypatch.setattr(cli, "RESEARCH", tmp_path)
    monkeypatch.setattr(cli, "claude_version", lambda: "0.0.0")
    return ran


def test_everything_stops_when_routing_is_not_shown(tmp_path, monkeypatch):
    ran = patch(monkeypatch, tmp_path, {"routing": "inconclusive"})
    code = cli.main(["--out", str(tmp_path / "runs"), "--report"])
    assert ran == ["routing"]
    assert code == 2
    assert not list(tmp_path.glob("*probe-results*"))


def test_a_full_run_writes_the_report(tmp_path, monkeypatch):
    ran = patch(monkeypatch, tmp_path, {})
    assert cli.main(["--out", str(tmp_path / "runs"), "--report"]) == 0
    assert ran[0] == "routing"
    baselines = sum(1 for s in cli.ALL_SCENARIOS if s.baseline is not None)
    assert len(ran) == len(cli.ALL_SCENARIOS) + baselines
    assert len(list(tmp_path.glob("*probe-results*"))) == 2


def test_report_refuses_a_partial_run(tmp_path, monkeypatch):
    patch(monkeypatch, tmp_path, {})
    with pytest.raises(SystemExit):
        cli.main(["--only", "result-text", "--report", "--out", str(tmp_path / "runs")])
    assert not list(Path(tmp_path).glob("*probe-results*"))


def test_receipts_refuse_without_context_audit_home(tmp_path, monkeypatch, capsys):
    patch(monkeypatch, tmp_path, {})
    monkeypatch.delenv("CONTEXT_AUDIT_HOME", raising=False)
    with pytest.raises(SystemExit):
        cli.main(["--only", "pkg-error", "--receipts", "--out", str(tmp_path / "runs")])
    assert "CONTEXT_AUDIT_HOME" in capsys.readouterr().err


def test_receipts_run_routing_first_and_write_into_the_state_directory(tmp_path, monkeypatch):
    from context_audit.receipts import read_receipts

    ran = patch(monkeypatch, tmp_path, {"pkg-error": "not_shown"})
    home = tmp_path / "state"
    monkeypatch.setenv("CONTEXT_AUDIT_HOME", str(home))
    argv = ["--only", "pkg-error", "--receipts", "--out", str(tmp_path / "runs")]
    assert cli.main(argv) == 0
    assert ran == ["routing", "pkg-error-baseline", "pkg-error"]
    (got,) = read_receipts(home)
    assert (got.behaviour, got.status, got.claude_version) == ("error", "not_shown", "0.0.0")
    argv = ["--only", "pkg-result-text", "--receipts", "--out", str(tmp_path / "runs2")]
    assert cli.main(argv) == 0
    assert sorted(r.behaviour for r in read_receipts(home)) == ["error", "result-text"]


def test_receipts_are_not_written_when_routing_fails(tmp_path, monkeypatch):
    ran = patch(monkeypatch, tmp_path, {"routing": "inconclusive"})
    home = tmp_path / "state"
    monkeypatch.setenv("CONTEXT_AUDIT_HOME", str(home))
    argv = ["--only", "pkg-error", "--receipts", "--out", str(tmp_path / "runs")]
    assert cli.main(argv) == 2
    assert ran == ["routing"]
    assert not (home / "receipts.json").exists()


def test_a_dirty_baseline_makes_the_scenario_inconclusive(tmp_path, monkeypatch):
    from context_audit.receipts import read_receipts

    patch(monkeypatch, tmp_path, {"pkg-error-baseline": "not_shown"})
    home = tmp_path / "state"
    monkeypatch.setenv("CONTEXT_AUDIT_HOME", str(home))
    cli.main(["--only", "pkg-error", "--receipts", "--out", str(tmp_path / "runs")])
    assert [r.status for r in read_receipts(home)] == ["inconclusive"]
