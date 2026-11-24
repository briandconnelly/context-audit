"""Experiment v2: Jev asked per sentence window, so the spec's joining rule lives in code.

Dev-only. `uv run python -m evaluation.jev_windows --sets corpus,dev_a --cap N`.
Text is split with the scanner's own sentence splitter. Each single sentence and each adjacent
pair (within a block, and across adjacent blocks) becomes its own pair of Noul questions; all
of an item's questions go in one request. Sentences wholly inside quoted material (code fences,
block quotes) are dropped in code. Item-level questions from v1 still decide `review`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from context_audit import decider
from evaluation import jev_compare as v1

OUT = v1.OUT.parent / "jev-windows"
CACHE = OUT / "cache"


def _blocks(item: dict) -> list[str]:
    return item["blocks"] if item.get("blocks") else [item["text"]]


def windows(item: dict) -> list[str]:
    return decider.windows(_blocks(item), item["surface"], item["id"])


def payload(item: dict) -> dict:
    return decider.request(_blocks(item), item["surface"], v1.MODEL, item["id"])


def ask(item: dict, budget: v1.Budget) -> dict:
    body = payload(item)
    key = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:24]
    path = CACHE / f"{key}.json"
    if path.exists():
        return json.loads(path.read_text())["answers"]
    if budget.cap == 0:
        return {}
    budget.take()
    req = urllib.request.Request(
        v1.API,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {os.environ['TYPESAFE_API_KEY']}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=90) as r:
        resp = json.load(r)
    path.write_text(json.dumps({"item": item["id"], "request": body, **resp}))
    return resp["answers"]


def decide(item: dict, ans: dict) -> tuple[str, float]:
    win = max(
        (a["noul"] for k, a in ans.items() if k.startswith(("hide_", "override_"))), default=0.0
    )
    return decider.verdict(ans, item["surface"], item["text"]), win


def combos(scan: str, jev: str) -> dict:
    return {
        "scanner": scan,
        "jev": jev,
        # optional verifier: Jev may only downgrade a scanner high to review
        "verify": "review" if scan == "high" and jev != "high" else scan,
        # optional second opinion: Jev may also raise any scanner flag to high
        "escalate": "high" if scan != "none" and jev == "high" else scan,
        "union": "high"
        if "high" in (scan, jev)
        else ("review" if "review" in (scan, jev) else "none"),
    }


ARMS = ("scanner", "jev", "verify", "escalate", "union")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sets", default="corpus,dev_a")
    ap.add_argument("--cap", type=int, default=0)
    ap.add_argument("--ids", default="", help="comma-separated subset")
    ap.add_argument("--show-errors", action="store_true")
    a = ap.parse_args(argv)
    CACHE.mkdir(parents=True, exist_ok=True)
    items = v1.items_for(a.sets.split(","))
    if a.ids:
        want = set(a.ids.split(","))
        items = [i for i in items if i["id"] in want]
    budget = v1.Budget(a.cap)
    with ThreadPoolExecutor(8) as ex:
        answers = list(ex.map(lambda i: ask(i, budget), items))
    rows = []
    for it, ans in zip(items, answers, strict=True):
        if not ans:
            continue
        jev, win = decide(it, ans)
        rows.append(
            {
                "id": it["id"],
                "set": it["set"],
                "family": it["family"],
                "expected": it["expected"],
                "win": round(win, 3),
                "n_windows": len(windows(it)),
                **combos(v1.scanner(it), jev),
            }
        )
    (OUT / f"rows-{a.sets.replace(',', '+')}.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows)
    )
    print(f"items={len(rows)} new_requests={budget.used}")
    for s in sorted({str(r["set"]) for r in rows}) + ["ALL"]:
        sub = rows if s == "ALL" else [r for r in rows if r["set"] == s]
        for arm in ARMS:
            print(f"{s if arm == 'scanner' else '':18} {arm:9} {v1.score(sub, arm)}")
    print("scanner->jev:", Counter((r["scanner"], r["jev"]) for r in rows).most_common())
    if a.show_errors:
        text = {i["id"]: i["text"] for i in items}
        for r in rows:
            if r["jev"] != r["expected"]:
                shown = (
                    "<held-out>" if "heldout" in a.sets else text[r["id"]][:240].replace("\n", " ")
                )
                print(
                    f"\n{r['id']} exp={r['expected']} jev={r['jev']} scan={r['scanner']}"
                    f" win={r['win']}\n   {shown}"
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())
