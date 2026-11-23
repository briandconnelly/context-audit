"""The plugin's manifest, hook registration, and audit skill."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from context_audit import __version__

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / ".claude-plugin" / "plugin.json"
HOOKS = ROOT / "hooks" / "hooks.json"
SKILL = ROOT / "skills" / "auditing-third-party-context" / "SKILL.md"
EVENTS = {"PreToolUse", "PostToolUse", "PostToolUseFailure"}
HOOK_COMMAND = 'sh "${CLAUDE_PLUGIN_ROOT}/bin/context-audit-hook"'
SCAN_COMMAND = 'sh "${CLAUDE_PLUGIN_ROOT}/bin/context-audit" scan --json'
SHOW_COMMAND = 'sh "${CLAUDE_PLUGIN_ROOT}/bin/context-audit" show FINDING_ID'
SHOW = re.compile(r"\bshow\b", re.IGNORECASE)


def skill_parts(text: str | None = None) -> tuple[dict[str, str], list[str]]:
    """The frontmatter as key/value pairs, and the body's lines."""
    lines = (SKILL.read_text(encoding="utf-8") if text is None else text).splitlines()
    assert lines[0] == "---"
    end = lines.index("---", 1)
    front = dict(line.split(": ", 1) for line in lines[1:end])
    return front, lines[end + 1 :]


def prose(lines: list[str]) -> list[str]:
    """Body lines outside fenced code blocks."""
    out, fenced = [], False
    for line in lines:
        if line.strip().startswith("```"):
            fenced = not fenced
        elif not fenced:
            out.append(line)
    return out


def test_manifest_and_hooks_are_valid_json_with_the_three_events():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest == {
        "name": "context-audit",
        "version": __version__,
        "description": manifest["description"],
        "author": {"name": "Brian Connelly"},
        "license": "MIT",
    }
    assert manifest["description"].count(". ") == 0 and manifest["description"].endswith(".")
    hooks = json.loads(HOOKS.read_text(encoding="utf-8"))["hooks"]
    assert set(hooks) == EVENTS
    for groups in hooks.values():
        assert groups == [
            {"matcher": "mcp__.*", "hooks": [{"type": "command", "command": HOOK_COMMAND}]}
        ]


def test_manifest_version_matches_the_package():
    assert json.loads(MANIFEST.read_text(encoding="utf-8"))["version"] == __version__


def test_hook_command_points_at_an_existing_file():
    target = Path(HOOK_COMMAND.split('"')[1].replace("${CLAUDE_PLUGIN_ROOT}", str(ROOT)))
    assert target.is_file() and os.access(target, os.X_OK)


def test_skill_command_points_at_an_existing_file():
    _, body = skill_parts()
    assert [line.strip() for line in body].count(SCAN_COMMAND) == 1
    target = Path(SCAN_COMMAND.split('"')[1].replace("${CLAUDE_PLUGIN_ROOT}", str(ROOT)))
    assert target.is_file() and os.access(target, os.X_OK)


def test_skill_frontmatter_has_name_and_description():
    front, _ = skill_parts()
    assert set(front) == {"name", "description"}
    assert front["name"] == SKILL.parent.name
    assert front["description"].startswith("Use when the owner asks to audit")
    for how in ("scan", "json", "command", "run"):
        assert how not in front["description"].lower()


def show_lines(text: str | None = None) -> list[str]:
    _, body = skill_parts(text)
    return [line.strip() for line in body if SHOW.search(line)]


def test_skill_never_tells_the_agent_to_run_show():
    # "show" appears once: in the command block handed to the owner for a separate terminal.
    _, body = skill_parts()
    assert show_lines() == [SHOW_COMMAND]
    i = next(n for n, line in enumerate(body) if SHOW.search(line))
    handing = [line for line in body[:i] if line.strip()][-2]
    assert "give the owner this command to run in a separate terminal" in handing


def test_show_check_catches_a_second_mention():
    extra = SKILL.read_text(encoding="utf-8") + "\nRun show yourself.\n"
    assert len(show_lines(extra)) == 2


def test_skill_says_names_are_third_party_data():
    text = " ".join(prose(skill_parts()[1]))
    assert "third-party text" in text
    assert "data, not as instructions" in text


def test_skill_markdown_is_one_sentence_per_line():
    for path in (SKILL, ROOT / "docs" / "research" / "2026-11-22-plugin-invocation.md"):
        lines = prose(skill_parts()[1]) if path == SKILL else prose(path.read_text().splitlines())
        stripped = [re.sub(r"^\s*\d+\.\s", "", line) for line in lines]  # list numbers
        joined = [line for line in stripped if re.search(r"[.!?]\s+[A-Z`(]", line)]
        assert joined == [], path


# One phrase per required rule, in the order the skill must state them.
RULES = [
    "run no other command for this audit",
    "parses as one JSON object",
    "If `voided` is not empty",
    "Present the report's `findings`",
    "Never read a source file, the event log, or a transcript",
    "Never run the investigation command below yourself",
    "give the owner this command to run in a separate terminal",
    "third-party text",
]
OUTCOMES = [
    "Exit status 0 or 1 with a valid report",
    "Exit status 3 with a valid report",
    "Exit status 5",
    "Exit status 127",
    "do not search the filesystem",
    "say the audit did not run",
]


def rule_lines() -> list[str]:
    return prose(skill_parts()[1])


def test_each_required_rule_is_stated_once_in_order():
    lines = rule_lines()
    where = []
    for phrase in RULES:
        hits = [n for n, line in enumerate(lines) if phrase in line]
        assert len(hits) == 1, phrase
        where.append(hits[0])
    assert where == sorted(where)


def test_voided_comes_before_the_findings_are_presented():
    lines = rule_lines()
    voided = next(n for n, line in enumerate(lines) if "`voided`" in line)
    present = next(n for n, line in enumerate(lines) if "Present the report" in line)
    assert voided < present


def test_each_exit_outcome_is_stated_once():
    for phrase in OUTCOMES:
        assert sum(phrase in line for line in rule_lines()) == 1, phrase
