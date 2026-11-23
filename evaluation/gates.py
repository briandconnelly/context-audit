"""Slice 1 release gates: run every set through its entry point and score it.

Dev-only, standard library only. Run `python -m evaluation.gates`.

This is the only code that reads the held-out sets, and it never reports their text:
`measure` reduces each item to an `ItemOutcome`, which holds ids, labels, and counts and
no text or span, and everything printed or written is built from outcomes alone. Errors
are reported by exception type only, because a message can quote its input.

The development sets under `dev/` are the spent round-1 held-out set. Their recall is
reported ungated, split into dev-A and dev-B, and supports no recall claim.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from context_audit.catch import BLOCK_SEPARATOR, caught
from context_audit.selftest import run_item, top_severity
from evaluation import benign, planted, prose
from evaluation.latency import LatencyReport, measure_latency
from evaluation.schema import CORPUS_FILES, DEV_FILES, EVAL_DIR, HELDOUT_FILES, Item, is_dev_b

ROOT = EVAL_DIR.parent
HELDOUT_DIR = EVAL_DIR / "heldout"
DEV_DIR = EVAL_DIR / "dev"
# Written by the packaged probe run with CONTEXT_AUDIT_HOME at this directory (R5).
RECEIPTS = ROOT / "runs" / "final-wave-receipts" / "receipts.json"
DEFAULT_OUT = ROOT / "runs" / "task13-gates"
ATTEMPTS = 3
RECALL_FLOOR = 0.80
P95_LIMIT_MS = 200.0
HELDOUT_HIGH_LIMIT = 0.05  # independent authors' controls; see the spec's Evaluation


@dataclass(frozen=True)
class ItemOutcome:
    """What one item produced. Holds no text and no span, by design."""

    id: str
    set: str
    surface: str
    family: str
    provider: str
    template: str
    expected: str
    top: str  # "high" | "review" | "none"
    caught: bool | None  # expected-high items only
    high: int
    review: int
    retries: int
    completed: bool  # False when every attempt ran out of time
    error: str | None  # exception type name only
    span_repeated: bool = False  # the span occurs more than once in the text

    @property
    def ok(self) -> bool:
        """Produced its expected outcome: caught when high, else that top severity."""
        if not self.completed or self.error:
            return False
        if self.expected == "high":
            return bool(self.caught)
        return self.top == self.expected


@dataclass(frozen=True)
class GateResult:
    name: str
    passed: bool | None  # None: not measured here
    numerator: int
    denominator: int
    failing_ids: tuple[str, ...]
    detail: str = ""
    measured: bool = True  # False with passed False: a required input is missing


@dataclass(frozen=True)
class GateReport:
    gates: tuple[GateResult, ...]
    review_per_100_benign: float
    benign_with_findings: int
    benign_count: int
    retried: tuple[str, ...]
    never_completed: tuple[str, ...]
    errors: tuple[str, ...]
    repeated_spans: int = 0
    open_set: dict[str, dict[str, int]] = field(default_factory=dict)  # expected -> top -> n
    dev_open_set: dict[str, dict[str, int]] = field(default_factory=dict)
    dev_recall: dict[str, tuple[int, int, tuple[str, ...]]] = field(default_factory=dict)
    positives_recall: tuple[int, int, tuple[str, ...]] = (0, 0, ())
    by_surface: dict[str, dict[str, list[int]]] = field(default_factory=dict)  # set -> [ok, n]
    by_family: dict[str, dict[str, list[int]]] = field(default_factory=dict)
    latency: LatencyReport | None = None
    planted: dict[str, tuple[int, int]] = field(default_factory=dict)  # position -> hits, n


def _labels(item: Item) -> dict:
    keys = ("id", "set", "surface", "family", "provider", "template", "expected")
    return {k: str(item[k]) for k in keys}


def measure(item: Item, state_root: Path) -> ItemOutcome:
    """Run one item through its entry point, retrying a time-budget partial."""
    labels = _labels(item)
    try:
        retries = -1
        while True:
            retries += 1
            result, blocks = run_item(dict(item), state_root)
            completed = not (result.outcome == "partial" and result.reason == "time-budget")
            if completed or retries + 1 >= ATTEMPTS:
                break
        got = None
        repeated = False
        span = item["span"]
        if item["expected"] == "high" and span:
            joined = BLOCK_SEPARATOR.join(t for _, t in blocks)
            starts = [i for i in range(len(joined)) if joined.startswith(span, i)]
            repeated = len(starts) > 1
            got = any(caught(blocks, (a, a + len(span)), result.findings) for a in starts)
        sev = Counter(f.severity for f in result.findings)
        return ItemOutcome(
            **labels,
            top=top_severity(result),
            caught=got,
            high=sev["high"],
            review=sev["review"],
            retries=retries,
            completed=completed,
            error=None,
            span_repeated=repeated,
        )
    except Exception as exc:  # noqa: BLE001 - reported by type, never by message
        return ItemOutcome(
            **labels,
            top="none",
            caught=False if item["expected"] == "high" else None,
            high=0,
            review=0,
            retries=0,
            completed=False,
            error=type(exc).__name__,
        )


def _failed(outcomes: list[ItemOutcome], bad) -> tuple[str, ...]:
    return tuple(sorted(o.id for o in outcomes if bad(o)))


def _no_high(name: str, outcomes: list[ItemOutcome]) -> GateResult:
    fails = _failed(outcomes, lambda o: o.top == "high" or not o.completed or o.error)
    n = len(outcomes)
    return GateResult(name, n > 0 and not fails, n - len(fails), n, fails, "items with no high")


def _few_high(name: str, outcomes: list[ItemOutcome]) -> GateResult:
    """Pass when items with a high (or no complete run) are at most HELDOUT_HIGH_LIMIT."""
    fails = _failed(outcomes, lambda o: o.top == "high" or not o.completed or o.error)
    n = len(outcomes)
    detail = f"items with no high; at most {HELDOUT_HIGH_LIMIT:.0%} may have one"
    passed = n > 0 and len(fails) <= HELDOUT_HIGH_LIMIT * n
    return GateResult(name, passed, n - len(fails), n, fails, detail)


def _not_measured(name: str, what: str) -> GateResult:
    return GateResult(name, False, 0, 0, (), f"not measured: {what} missing", measured=False)


def _recall(outcomes: list[ItemOutcome]) -> tuple[int, int, tuple[str, ...]]:
    fails = _failed(outcomes, lambda o: not o.ok)
    return len(outcomes) - len(fails), len(outcomes), fails


def _open_table(outcomes: list[ItemOutcome]) -> dict[str, dict[str, int]]:
    table: dict[str, dict[str, int]] = defaultdict(lambda: {"high": 0, "review": 0, "none": 0})
    for o in outcomes:
        table[o.expected][o.top] += 1
    return dict(table)


def _breakdown(outcomes: dict[str, list[ItemOutcome]], key: str) -> dict[str, dict[str, list[int]]]:
    out: dict[str, dict[str, list[int]]] = {}
    for set_name, items in outcomes.items():
        table: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for o in items:
            table[getattr(o, key)][0] += o.ok
            table[getattr(o, key)][1] += 1
        out[set_name] = dict(sorted(table.items()))
    return out


def build_report(
    outcomes: dict[str, list[ItemOutcome]],
    *,
    latency: LatencyReport | None = None,
    receipt_status: str | None = None,
) -> GateReport:
    get = lambda name: outcomes.get(name, [])  # noqa: E731
    canaries = get("canary")
    cfail = _failed(canaries, lambda o: not o.ok)
    gates = [
        GateResult(
            "canaries",
            bool(canaries) and not cfail,
            len(canaries) - len(cfail),
            len(canaries),
            cfail,
            "canaries with their expected outcome through their entry point",
        )
    ]
    if "heldout_in_scope" in outcomes:
        recalled, n, hfail = _recall(outcomes["heldout_in_scope"])
        gates.append(
            GateResult(
                "in-scope recall",
                bool(n) and recalled / n >= RECALL_FLOOR,
                recalled,
                n,
                hfail,
                f"high finding locating the span; floor {RECALL_FLOOR:.0%}",
            )
        )
    else:
        gates.append(_not_measured("in-scope recall", "heldout/in_scope.jsonl"))
    gates.append(_no_high("controls", get("control")))
    if "heldout_control" in outcomes:
        gates.append(_few_high("held-out controls", outcomes["heldout_control"]))
    else:
        gates.append(_not_measured("held-out controls", "heldout/controls.jsonl"))
    gates.append(_no_high("benign", get("benign")))
    if "prose" in outcomes:
        gates.append(_no_high("instructional prose", outcomes["prose"]))
    gates.append(_latency_gate(latency))
    gates.append(
        GateResult(
            "seeded warning investigated end to end",
            receipt_status == "shown",
            int(receipt_status == "shown"),
            0 if receipt_status is None else 1,
            (),
            "not measured: transcript-readback receipt missing or unreadable"
            if receipt_status is None
            else f"transcript-readback receipt for this build: {receipt_status}",
        )
    )
    ben = get("benign")
    dev = get("dev_in_scope")
    pos = [o for o in get("positive") if o.expected == "high"]
    pfail = _failed(pos, lambda o: not o.ok)
    every = [o for items in outcomes.values() for o in items]
    return GateReport(
        gates=tuple(gates),
        review_per_100_benign=round(100 * sum(o.review for o in ben) / len(ben), 2) if ben else 0.0,
        benign_with_findings=sum(1 for o in ben if o.high or o.review),
        benign_count=len(ben),
        retried=_failed(every, lambda o: o.retries > 0),
        never_completed=_failed(every, lambda o: not o.completed and not o.error),
        errors=_failed(every, lambda o: o.error is not None),
        repeated_spans=sum(1 for o in every if o.span_repeated),
        open_set=_open_table(get("heldout_open")),
        dev_open_set=_open_table(get("dev_open")),
        dev_recall={
            "dev-A": _recall([o for o in dev if not is_dev_b(o.id)]),
            "dev-B": _recall([o for o in dev if is_dev_b(o.id)]),
        },
        positives_recall=(len(pos) - len(pfail), len(pos), pfail),
        by_surface=_breakdown(outcomes, "surface"),
        by_family=_breakdown(outcomes, "family"),
        latency=latency,
    )


def _latency_gate(latency: LatencyReport | None) -> GateResult:
    if latency is None:
        return GateResult("hook latency", None, 0, 0, (), "not measured in this run")
    bad = [r for r in latency.runs if r.p95_ms > P95_LIMIT_MS or r.timeouts or r.failures]
    total = sum(latency.samples for _ in latency.runs)
    clean = total - sum(r.timeouts + r.failures for r in latency.runs)
    detail = "; ".join(
        f"{r.concurrency}-way p95 {r.p95_ms:.1f} ms, {r.timeouts} timeouts, {r.failures} failures"
        f" (canaries warned {r.canaries_warned}/{r.canaries}, benign warned {r.benign_warned})"
        for r in latency.runs
    )
    return GateResult("hook latency", not bad, clean, total, (), detail)


def _load_jsonl(path: Path) -> list[Item]:
    """Load a set; a parse error names the file and line, never the line's content."""
    items = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            items.append(json.loads(line))
        except ValueError:
            raise SystemExit(f"{path.name}: line {n} is not valid JSON") from None
    return items


def _receipt_status(path: Path) -> str | None:
    """The transcript-readback receipt's status, or "other build" when every such receipt
    was taken on another build of the plugin (R5); None when there is none."""
    from context_audit import __version__
    from context_audit.receipts import build_digest

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    found = None
    for r in data.get("receipts", []):
        if r.get("behaviour") != "transcript-readback":
            continue
        if r.get("build") == build_digest() and r.get("plugin_version") == __version__:
            return str(r.get("status"))
        found = "other build"
    return found


def run_gates(
    *,
    heldout_dir: Path = HELDOUT_DIR,
    dev_dir: Path = DEV_DIR,
    benign_seed: int = benign.DEFAULT_SEED,
    benign_count: int = benign.DEFAULT_COUNT,
    prose_seed: int = prose.DEFAULT_SEED,
    prose_count: int = prose.DEFAULT_COUNT,
    receipts: Path = RECEIPTS,
    latency: LatencyReport | None = None,
) -> GateReport:
    sources: dict[str, list[Item]] = {k: _load_jsonl(p) for k, p in CORPUS_FILES.items()}
    for k, p in DEV_FILES.items():
        sources[k] = _load_jsonl(dev_dir / p.name)
    for k, p in HELDOUT_FILES.items():
        if (heldout_dir / p.name).exists():
            sources[k] = _load_jsonl(heldout_dir / p.name)
    sources["benign"] = benign.generate(benign_seed, benign_count)
    sources["prose"] = prose.generate(prose_seed, prose_count)
    with tempfile.TemporaryDirectory(prefix="ca-gates-") as tmp:
        outcomes = {k: [measure(i, Path(tmp)) for i in items] for k, items in sources.items()}
        planted_counts = planted.measure(Path(tmp))
    report = build_report(outcomes, latency=latency, receipt_status=_receipt_status(receipts))
    return dataclasses.replace(report, planted=planted_counts)


def render(report: GateReport) -> str:
    """Plain-text summary built from outcomes only."""
    lines = ["gate | passed | n/d | failing ids"]
    for g in report.gates:
        if not g.measured:
            mark = "not measured (fails the run)"
        else:
            mark = "not measured" if g.passed is None else "PASS" if g.passed else "FAIL"
        ids = ", ".join(g.failing_ids) or "-"
        lines.append(f"{g.name} | {mark} | {g.numerator}/{g.denominator} | {ids}")
        if g.detail:
            lines.append(f"  ({g.detail})")
    p = report.positives_recall
    lines += [
        "",
        f"review findings per 100 benign results: {report.review_per_100_benign}",
        f"benign results with any finding: {report.benign_with_findings}/{report.benign_count}",
        "planted positives (ungated): "
        f"{sum(h for h, _ in report.planted.values())} high of"
        f" {sum(n for _, n in report.planted.values())}; by position: "
        + (", ".join(f"{k} {h}/{n}" for k, (h, n) in report.planted.items()) or "-"),
        f"open positives recall: {p[0]}/{p[1]}; missed: {', '.join(p[2]) or '-'}",
        f"held-out open set (expected -> produced): {json.dumps(report.open_set, sort_keys=True)}",
        f"dev open set (expected -> produced): {json.dumps(report.dev_open_set, sort_keys=True)}",
        *(
            f"{name} recall (development, ungated, no claim): {r[0]}/{r[1]};"
            f" missed: {', '.join(r[2]) or '-'}"
            for name, r in report.dev_recall.items()
        ),
        f"items retried for time budget: {len(report.retried)} {list(report.retried)}",
        f"items never completed: {len(report.never_completed)} {list(report.never_completed)}",
        f"items that raised: {len(report.errors)} {list(report.errors)}",
        f"expected-high items whose span occurs more than once: {report.repeated_spans}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m evaluation.gates")
    parser.add_argument("--heldout-dir", type=Path, default=HELDOUT_DIR)
    parser.add_argument("--dev-dir", type=Path, default=DEV_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--benign-seed", type=int, default=benign.DEFAULT_SEED)
    parser.add_argument("--benign-count", type=int, default=benign.DEFAULT_COUNT)
    parser.add_argument("--prose-seed", type=int, default=prose.DEFAULT_SEED)
    parser.add_argument("--prose-count", type=int, default=prose.DEFAULT_COUNT)
    parser.add_argument("--receipts", type=Path, default=RECEIPTS)
    parser.add_argument("--no-latency", action="store_true")
    args = parser.parse_args(argv)
    latency = None if args.no_latency else measure_latency()
    report = run_gates(
        heldout_dir=args.heldout_dir,
        dev_dir=args.dev_dir,
        benign_seed=args.benign_seed,
        benign_count=args.benign_count,
        prose_seed=args.prose_seed,
        prose_count=args.prose_count,
        receipts=args.receipts,
        latency=latency,
    )
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "gates.json").write_text(json.dumps(asdict(report), indent=2) + "\n")
    print(render(report))
    return 0 if all(g.passed is not False for g in report.gates) else 1


if __name__ == "__main__":
    sys.exit(main())
