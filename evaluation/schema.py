"""Schema, loader, validator, and manifest for the frozen evaluation corpus.

Dev-only and standard library only. Run `python -m evaluation.schema --write-manifest`
to regenerate `corpus/MANIFEST.json` from the corpus and development files and whatever
held-out files exist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, NotRequired, TypedDict

EVAL_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = EVAL_DIR / "corpus" / "MANIFEST.json"

CORPUS_FILES = {
    "canary": EVAL_DIR / "corpus" / "canaries.jsonl",
    "positive": EVAL_DIR / "corpus" / "positives.jsonl",
    "control": EVAL_DIR / "corpus" / "controls.jsonl",
    "paired": EVAL_DIR / "corpus" / "paired.jsonl",
}
# The round-1 held-out set, spent: it is now development data and supports no recall claim.
# Its items keep their original `set` values and ids.
DEV_FILES = {
    "dev_in_scope": EVAL_DIR / "dev" / "in_scope.jsonl",
    "dev_open": EVAL_DIR / "dev" / "open_set.jsonl",
}
HELDOUT_FILES = {
    "heldout_in_scope": EVAL_DIR / "heldout" / "in_scope.jsonl",
    "heldout_open": EVAL_DIR / "heldout" / "open_set.jsonl",
    "heldout_control": EVAL_DIR / "heldout" / "controls.jsonl",
}

ID_PREFIX = {
    "canary": "can",
    "positive": "pos",
    "control": "ctl",
    "paired": "par",
    "heldout_in_scope": "his",
    "heldout_open": "hop",
    "heldout_control": "hct",
}
SETS = frozenset(ID_PREFIX)
HOOK_SURFACES = frozenset({"tool_result", "tool_error"})
SURFACES = HOOK_SURFACES | {
    "tool_description",
    "param_description",
    "server_instructions",
    "skill",
    "command",
    "agent",
    "hook_prompt",
    "frontmatter",
}
EXPECTED = frozenset({"high", "review", "none"})
REQUIRED_KEYS = frozenset(
    {"id", "set", "surface", "entry", "text", "expected", "span", "family", "provider", "template"}
)
OPTIONAL_KEYS = frozenset({"note", "blocks"})
BLOCK_SEPARATOR = "\n\n"

# Keep in step with the list in evaluation/README.md; a test compares the two.
PROVIDERS = (
    "examplecloud",
    "sampleforge",
    "demotracker",
    "fictionalfiles",
    "notarealdb",
    "placeholder-search",
    "examplemail",
    "sampleci",
    "demowiki",
    "mockmetrics",
    "fakeissues",
    "examplecalendar",
    "sampletickets",
    "demostore",
)
TEMPLATE_RE = re.compile(r"^[thg]\d{2}$")
HELDOUT_TEMPLATE_RE = re.compile(r"^[hg](0[1-9]|1[0-4])$")
MAX_SHARE = 0.2
FAMILY_RE = re.compile(r"^[a-z][a-z-]*(\+[a-z][a-z-]*)*$")


class Item(TypedDict):
    id: str
    set: str
    surface: str
    entry: str
    text: str
    expected: str
    span: str | None
    family: str
    provider: str
    template: str
    note: NotRequired[str]
    blocks: NotRequired[list[str]]


def load(path: Path) -> list[Item]:
    """Read one JSON Lines file; blank lines are not allowed."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def existing_files() -> dict[str, Path]:
    """Corpus and development files always, held-out files only when they exist."""
    files = {**CORPUS_FILES, **DEV_FILES}
    files.update({k: p for k, p in HELDOUT_FILES.items() if p.exists()})
    return files


def load_all() -> list[Item]:
    return [item for path in existing_files().values() for item in load(path)]


def is_dev_b(item_id: str) -> bool:
    """dev-B: development in-scope items whose id number is divisible by 3."""
    return item_id.startswith("his-") and int(item_id[4:]) % 3 == 0


def load_dev_a() -> list[Item]:
    """The development in-scope items outside dev-B; dev-B text is never returned."""
    return [i for i in load(DEV_FILES["dev_in_scope"]) if not is_dev_b(i["id"])]


def share_problems(items: Sequence[Mapping[str, Any]]) -> list[str]:
    """Within one file, no provider and no template may hold more than a fifth of the items."""
    problems = []
    for key in ("provider", "template"):
        counts = Counter(str(i.get(key)) for i in items)
        for value, n in counts.items():
            if items and n / len(items) > MAX_SHARE:
                problems.append(f"{key} {value!r} holds {n} of {len(items)} items")
    return problems


def file_problems() -> list[str]:
    """Item problems across every existing file, plus the share rule per file."""
    problems = validate(load_all())
    for path in existing_files().values():
        rel = path.relative_to(EVAL_DIR)
        problems.extend(f"{rel}: {p}" for p in share_problems(load(path)))
    return problems


def _problems(item: Any) -> Iterable[str]:
    if not isinstance(item, dict):
        yield "item is not an object"
        return
    keys = set(item)
    if missing := REQUIRED_KEYS - keys:
        yield f"missing keys {sorted(missing)}"
        return
    if extra := keys - REQUIRED_KEYS - OPTIONAL_KEYS:
        yield f"unknown keys {sorted(extra)}"
    if item["set"] not in SETS:
        yield f"set {item['set']!r}"
        return
    if not re.fullmatch(rf"{ID_PREFIX[item['set']]}-\d{{3}}", str(item["id"])):
        yield f"id {item['id']!r} does not match set {item['set']!r}"
    if item["surface"] not in SURFACES:
        yield f"surface {item['surface']!r}"
    want_entry = "hook" if item["surface"] in HOOK_SURFACES else "scan"
    if item["entry"] != want_entry:
        yield f"entry {item['entry']!r} for surface {item['surface']!r}"
    text = item["text"]
    if not isinstance(text, str) or not text:
        yield "text must be a non-empty string"
        return
    if item["expected"] not in EXPECTED:
        yield f"expected {item['expected']!r}"
    span = item["span"]
    if item["expected"] == "high":
        if not isinstance(span, str) or not span or span not in text:
            yield "span must be a non-empty exact substring of text when expected is high"
    elif span is not None:
        yield "span must be null unless expected is high"
    if not isinstance(item["family"], str) or not FAMILY_RE.fullmatch(item["family"]):
        yield f"family {item['family']!r}"
    if item["provider"] not in PROVIDERS:
        yield f"provider {item['provider']!r} is not a listed placeholder"
    if not isinstance(item["template"], str) or not TEMPLATE_RE.fullmatch(item["template"]):
        yield f"template {item['template']!r}"
    elif item["set"].startswith("heldout_") and not HELDOUT_TEMPLATE_RE.fullmatch(item["template"]):
        yield f"template {item['template']!r} is not a held-out template"
    if item["set"] == "heldout_control" and item["expected"] not in {"none", "review"}:
        yield "held-out controls expect none or review"
    if "note" in item and (not isinstance(item["note"], str) or not item["note"]):
        yield "note must be a non-empty string"
    if item["set"] == "paired" and "note" not in item:
        yield "paired items need a note"
    if "blocks" in item:
        blocks = item["blocks"]
        if item["surface"] not in HOOK_SURFACES:
            yield "blocks only apply to tool results"
        if (
            not isinstance(blocks, list)
            or len(blocks) < 2
            or not all(isinstance(b, str) and b for b in blocks)
            or BLOCK_SEPARATOR.join(blocks) != text
        ):
            yield "blocks must be 2+ non-empty strings that join to text"


def validate(items: Iterable[Any]) -> list[str]:
    """Return every problem found; an empty list means the items are valid."""
    problems: list[str] = []
    ids: Counter[str] = Counter()
    for n, item in enumerate(items):
        label = item.get("id", f"#{n}") if isinstance(item, dict) else f"#{n}"
        problems.extend(f"{label}: {p}" for p in _problems(item))
        if isinstance(item, dict) and "id" in item:
            ids[item["id"]] += 1
    problems.extend(f"{i}: duplicate id" for i, c in ids.items() if c > 1)
    return problems


def manifest() -> dict[str, Any]:
    files = existing_files()
    return {
        "files": {
            str(p.relative_to(EVAL_DIR)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(files.values())
        },
        "counts": {str(p.relative_to(EVAL_DIR)): len(load(p)) for p in sorted(files.values())},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m evaluation.schema")
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args(argv)
    problems = file_problems()
    for problem in problems:
        print(problem)
    if problems:
        return 1
    if args.write_manifest:
        MANIFEST_PATH.write_text(json.dumps(manifest(), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
