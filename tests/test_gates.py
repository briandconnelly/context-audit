import json
from pathlib import Path

import pytest

from context_audit.scan import ScanResult
from evaluation import gates
from evaluation.gates import ItemOutcome, build_report, main, measure
from evaluation.latency import LatencyReport, measure_latency

CORPUS = Path(__file__).resolve().parent.parent / "evaluation" / "corpus"
MARKER = "Zyxqwvmarker"


def _o(
    id_: str, set_: str, expected: str, top: str, caught: bool | None = None, completed=True
) -> ItemOutcome:
    return ItemOutcome(
        id=id_,
        set=set_,
        surface="tool_result",
        family="conceal-act+call",
        provider="examplecloud",
        template="h01",
        expected=expected,
        top=top,
        caught=caught,
        high=int(top == "high"),
        review=int(top == "review"),
        retries=0,
        completed=completed,
        error=None,
    )


def _gate(report, name):
    return next(g for g in report.gates if g.name == name)


def test_gate_report_counts_a_review_as_a_miss_for_recall():
    outcomes = {
        "heldout_in_scope": [
            _o("his-001", "heldout_in_scope", "high", "review", caught=False),
            _o("his-002", "heldout_in_scope", "high", "high", caught=True),
        ]
    }
    g = _gate(build_report(outcomes), "in-scope recall")
    assert (g.numerator, g.denominator) == (1, 2)
    assert g.failing_ids == ("his-001",)
    assert g.passed is False


def test_gate_report_names_failing_ids():
    outcomes = {
        "canary": [
            _o("can-001", "canary", "high", "high", caught=True),
            _o("can-002", "canary", "high", "high", caught=False),
            _o("can-021", "canary", "review", "none"),
        ],
        "control": [
            _o("ctl-001", "control", "none", "high"),
            _o("ctl-002", "control", "none", "none"),
        ],
        "benign": [
            _o("ben-0001", "benign", "none", "high"),
            _o("ben-0002", "benign", "none", "review"),
        ],
    }
    r = build_report(outcomes)
    assert _gate(r, "canaries").failing_ids == ("can-002", "can-021")
    assert (_gate(r, "controls").numerator, _gate(r, "controls").denominator) == (1, 2)
    assert _gate(r, "controls").failing_ids == ("ctl-001",)
    assert _gate(r, "benign").failing_ids == ("ben-0001",)
    assert r.review_per_100_benign == 50.0
    assert r.benign_with_findings == 2


def test_an_item_that_never_completes_counts_as_a_failure_everywhere():
    outcomes = {
        "heldout_in_scope": [
            _o("his-001", "heldout_in_scope", "high", "none", False, completed=False)
        ],
        "control": [_o("ctl-001", "control", "none", "none", completed=False)],
    }
    r = build_report(outcomes)
    assert _gate(r, "in-scope recall").failing_ids == ("his-001",)
    assert _gate(r, "controls").failing_ids == ("ctl-001",)
    assert r.never_completed == ("ctl-001", "his-001")


def test_measure_retries_a_time_budget_partial(monkeypatch, tmp_path):
    item = json.loads((CORPUS / "controls.jsonl").read_text().splitlines()[0])
    calls = []

    def fake(it, root):
        calls.append(1)
        if len(calls) < 3:
            return ScanResult((), "partial", "time-budget", 0), [("content[0].text", "x")]
        return ScanResult((), "complete", "", 1), [("content[0].text", "x")]

    monkeypatch.setattr(gates, "run_item", fake)
    o = measure(item, tmp_path)
    assert (o.retries, o.completed) == (2, True)


def test_measure_gives_up_after_three_time_budget_runs(monkeypatch, tmp_path):
    item = json.loads((CORPUS / "controls.jsonl").read_text().splitlines()[0])
    partial = ScanResult((), "partial", "time-budget", 0), [("content[0].text", "x")]
    monkeypatch.setattr(gates, "run_item", lambda it, root: partial)
    o = measure(item, tmp_path)
    assert (o.retries, o.completed) == (2, False)


def _canary(id_: str) -> dict:
    for line in (CORPUS / "canaries.jsonl").read_text().splitlines():
        item = json.loads(line)
        if item["id"] == id_:
            return item
    raise KeyError(id_)


def _heldout_fixture(tmp_path: Path) -> Path:
    """Held-out files made from open canaries, each carrying a unique marker word."""
    d = tmp_path / "heldout"
    d.mkdir()
    high = _canary("can-001")
    review = _canary("can-021")
    in_scope = []
    for n, src in enumerate((high, review), start=1):
        text = f"{MARKER} report. {src['text']}"
        span = high["span"] if src is high else MARKER
        in_scope.append(
            {
                **{k: src[k] for k in ("surface", "entry", "family", "provider")},
                "id": f"his-00{n}",
                "set": "heldout_in_scope",
                "text": text,
                "expected": "high",
                "span": span,
                "template": "h01",
            }
        )
    open_set = [
        {**in_scope[1], "id": "hop-001", "set": "heldout_open", "expected": "review", "span": None}
    ]
    for name, items in (("in_scope.jsonl", in_scope), ("open_set.jsonl", open_set)):
        (d / name).write_text("".join(json.dumps(i) + "\n" for i in items))
    return d


def test_gate_output_and_report_contain_no_item_text(tmp_path, capsys):
    heldout = _heldout_fixture(tmp_path)
    out = tmp_path / "out"
    code = main(
        ["--heldout-dir", str(heldout), "--out", str(out), "--benign-count", "40", "--no-latency"]
    )
    printed = capsys.readouterr()
    report = (out / "gates.json").read_text()
    assert code in (0, 1)
    for blob in (printed.out, printed.err, report):
        assert MARKER not in blob
    assert "his-002" in printed.out and "his-002" in report
    data = json.loads(report)
    recall = next(g for g in data["gates"] if g["name"] == "in-scope recall")
    # The high canary is recovered; the review canary relabelled high is a miss.
    assert (recall["numerator"], recall["denominator"]) == (1, 2)
    assert recall["failing_ids"] == ["his-002"]


def test_a_broken_heldout_line_reports_no_text(tmp_path, capsys):
    heldout = _heldout_fixture(tmp_path)
    p = heldout / "in_scope.jsonl"
    p.write_text(p.read_text() + f'{{"id": "his-009", "text": "{MARKER}" broken\n')
    with pytest.raises(SystemExit) as exc:
        main(["--heldout-dir", str(heldout), "--out", str(tmp_path / "o"), "--no-latency"])
    printed = capsys.readouterr()
    assert MARKER not in printed.out + printed.err + str(exc.value)


def test_a_missing_receipt_fails_the_run():
    g = _gate(build_report({}, receipt_status=None), "seeded warning investigated end to end")
    assert g.passed is False
    assert "not measured" in g.detail


def test_a_repeated_span_is_credited_at_any_occurrence(tmp_path):
    item = dict(_canary("can-001"))
    span = item["span"]
    # The first occurrence sits inside a code fence, which the scanner treats as quoted.
    item["text"] = f"```\n{span}\n```\n\n{item['text']}"
    item.pop("blocks", None)
    o = measure(item, tmp_path)
    assert o.span_repeated is True
    assert o.caught is True
    assert build_report({"heldout_in_scope": [o]}).repeated_spans == 1


def test_latency_gate_fails_when_the_hook_does_nothing(tmp_path):
    silent = tmp_path / "silent-hook"
    silent.write_text("#!/bin/sh\ncat >/dev/null\nexit 0\n")
    r = measure_latency(samples=20, concurrency=(1,), hook=silent)
    assert r.runs[0].failures == 1  # the one canary payload produced no warning
    assert _gate(build_report({}, latency=r), "hook latency").passed is False


def test_latency_report_states_its_workload():
    r = measure_latency(samples=20, concurrency=(1, 2))
    assert isinstance(r, LatencyReport)
    assert r.machine and r.os and r.python and r.hook_python
    assert r.samples == 20
    assert r.payload_mix and r.payload_bytes["max"] >= r.payload_bytes["min"] > 0
    assert [run.concurrency for run in r.runs] == [1, 2]
    for run in r.runs:
        assert run.timeouts == 0 and run.failures == 0
        assert run.canaries == 1 and run.canaries_warned == 1
        assert run.benign_warned >= 0
        assert 0 < run.p50_ms <= run.p95_ms <= run.max_ms
