"""Expected-high texts planted into generated instructional prose: an ungated measurement.

Dev-only, standard library only. Every expected-high text in the corpus positives and
canaries (hook and scan entries alike, text only) and in dev-A is planted into a
generated skill body (`prose`, fixed seed) in four positions: as a numbered step, as a
bullet under a procedural lead-in, mid-paragraph, and on its own line after a heading.
The body is scanned as one skill-surface field; a hit is a high finding overlapping the
planted text. Nothing here reports item text.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from context_audit.scan import scan_fields
from context_audit.text import Field
from evaluation import prose
from evaluation.schema import CORPUS_FILES, load_dev_a

SEED = 20261124
POSITIONS = ("step", "bullet", "paragraph", "heading")
_SPACE = re.compile(r"\s+")


def texts() -> list[str]:
    """Expected-high texts, in file order, duplicates kept once."""
    out: list[str] = []
    for key in ("positive", "canary"):
        for line in CORPUS_FILES[key].read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            if item["expected"] == "high":
                out.append("\n\n".join(item.get("blocks") or [item["text"]]))
    out.extend(i["text"] for i in load_dev_a() if i["expected"] == "high")
    return list(dict.fromkeys(out))


def plant(host: str, text: str, position: str) -> tuple[str, int, int]:
    """host with `text` planted after its second section; the planted range."""
    flat = _SPACE.sub(" ", text).strip()
    if position == "step":
        head, body, tail = (
            "## Steps\n\n1. Read the current configuration.\n2. ",
            flat,
            ("\n3. Run the tests and read the whole output."),
        )
    elif position == "bullet":
        head, body, tail = (
            "## Before you start\n\nDo these in order:\n\n- Pull the latest main.\n- ",
            flat,
            ("\n- Run the linter."),
        )
    elif position == "paragraph":
        head, body, tail = (
            "## Notes\n\nThe job runs nightly and keeps its log for a week. ",
            flat,
            (" Questions about the schedule go to the owning team."),
        )
    else:
        head, body, tail = "## Note\n\n", text.strip(), ""
    parts = host.split("\n\n## ")
    k = min(2, len(parts))
    before = "\n\n## ".join(parts[:k]) + "\n\n"
    after = ("\n\n## " + "\n\n## ".join(parts[k:])) if parts[k:] else ""
    start = len(before) + len(head)
    return before + head + body + tail + after, start, start + len(body)


def measure(state_root: Path) -> dict[str, tuple[int, int]]:
    """position -> (hits, planted)."""
    items = texts()
    hosts = [i["text"] for i in prose.generate(SEED, len(items))]
    out: dict[str, tuple[int, int]] = {}
    for position in POSITIONS:
        hits = 0
        for n, (text, host) in enumerate(zip(items, hosts, strict=True)):
            body, a, b = plant(host, text, position)
            field = Field(f"planted-{n}", "skill", "body", body, 0)
            result = scan_fields([field], state_root=state_root)
            hits += any(
                f.severity == "high" and any(x < b and a < y for _, x, y in f.ranges)
                for f in result.findings
            )
        out[position] = (hits, len(items))
    return out
