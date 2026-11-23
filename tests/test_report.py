import json
import re
from pathlib import Path

from probe.report import write_report
from probe.scenario import Result

HOME = str(Path.home())
RESULTS = [
    Result("routing", "Claim R", "shown", "2 requests", Path("/x/routing")),
    Result("result-text", "Claim A", "shown", "held all markers", Path("/x/a")),
    Result(
        "result-big", "Claim A", "not_shown", f"lost the tail; see {HOME}/runs/a/b.log", Path("/x")
    ),
    Result(
        "ask-accept",
        "Claim B",
        "inconclusive",
        "never saw the prompt. Second sentence.",
        Path("/x"),
    ),
]


def write(tmp_path):
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    write_report(RESULTS, claude_version="9.9.9 (Claude Code)", out_md=md, out_json=js)
    return md.read_text(), json.loads(js.read_text())


def test_json_round_trips_outcomes(tmp_path):
    _, data = write(tmp_path)
    assert data["header"]["claude_version"] == "9.9.9 (Claude Code)"
    assert set(data["header"]) == {"claude_version", "date", "platform", "python"}
    assert [(r["name"], r["outcome"]) for r in data["results"]] == [
        ("routing", "shown"),
        ("result-text", "shown"),
        ("result-big", "not_shown"),
        ("ask-accept", "inconclusive"),
    ]
    assert set(data["results"][0]) == {"name", "claim", "outcome", "reason"}


def test_markdown_lists_every_claim_once(tmp_path):
    text, _ = write(tmp_path)
    rows = [line for line in text.splitlines() if line.startswith("| Claim ")]
    table = [line for line in rows if "| Scenarios |" not in line]
    assert len(table) == 3
    row_a = next(line for line in table if line.startswith("| Claim A"))
    assert "result-text: shown" in row_a
    assert "result-big: not_shown" in row_a


def test_each_unshown_result_gets_a_section(tmp_path):
    text, _ = write(tmp_path)
    assert "### result-big" in text
    assert "### ask-accept" in text
    assert "### result-text" not in text


def test_reason_paths_are_made_relative(tmp_path):
    text, data = write(tmp_path)
    assert HOME not in text
    assert HOME not in json.dumps(data)
    assert "~/runs/a/b.log" in text


def test_run_directories_are_not_reported(tmp_path):
    text, data = write(tmp_path)
    assert "run_dir" not in json.dumps(data)
    assert "/x/routing" not in text


def test_one_sentence_per_line(tmp_path):
    text, _ = write(tmp_path)
    prose = [
        line
        for line in text.splitlines()
        if line and not line.startswith(("|", "#", "-", ">", "    "))
    ]
    assert prose
    for line in prose:
        assert not re.search(r"[.!?] +[A-Z]", line), line


def test_says_results_are_exploratory(tmp_path):
    text, _ = write(tmp_path)
    assert "exploratory" in text.split("\n## ")[0]


def test_report_lists_what_was_not_probed(tmp_path):
    text, _ = write(tmp_path)
    section = text.split("## Not probed")[1].lower()
    assert "two gated tools" in section
    assert "parallel gated calls" in section
    assert "proceeds as written" not in text


def test_name_with_a_trailing_newline_is_not_a_safe_name():
    # Minor 1: `$` accepted "x\n"; names must match in full.
    from context_audit.report import safe_name

    assert safe_name("plain-name", "src-0123abcd") == "plain-name"
    assert safe_name("x\n", "src-0123abcd") == "src-0123abcd"
