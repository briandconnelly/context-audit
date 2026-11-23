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
    assert len(ran) == len(cli.ALL_SCENARIOS)
    assert len(list(tmp_path.glob("*probe-results*"))) == 2


def test_report_refuses_a_partial_run(tmp_path, monkeypatch):
    patch(monkeypatch, tmp_path, {})
    with pytest.raises(SystemExit):
        cli.main(["--only", "result-text", "--report", "--out", str(tmp_path / "runs")])
    assert not list(Path(tmp_path).glob("*probe-results*"))
