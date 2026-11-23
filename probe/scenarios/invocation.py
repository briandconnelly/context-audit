"""How a skill can reach the CLI when this repository is loaded as a plugin with --plugin-dir.

Three claims, one run each: whether `${CLAUDE_PLUGIN_ROOT}` in a skill body is replaced before
the body reaches the model, whether the plugin's `bin/` is on the Bash tool's PATH, and whether
the packaged hook command's `${CLAUDE_PLUGIN_ROOT}` resolves so that the hook runs.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from probe import checks
from probe.scenario import Evidence, HookSpec, Outcome, Scenario
from probe.stub import Reply, ToolCall

PLUGIN = Path(__file__).resolve().parent.parent.parent
SKILL = "context-audit:auditing-third-party-context"
VARIABLE = "${CLAUDE_PLUGIN_ROOT}"
COMMAND_TAIL = '/bin/context-audit\\" scan --json'  # as it appears in a JSON-dumped request
WHICH = re.compile(r"CTXA-WHICH\[([^\]]*)\]")
PATHVAR = re.compile(r"CTXA-PATHVAR\[([^\]]*)\]")

SKILL_CALL = ToolCall("Skill", {"skill": SKILL}, "toolu_skill01")
BASH_CALL = ToolCall(
    "Bash",
    {
        "command": 'printf "CTXA-WHICH[%s] CTXA-PATHVAR[%s]\\n" '
        '"$(command -v context-audit || echo none)" "$PATH"',
        "description": "Report where context-audit is and the PATH",
    },
    "toolu_bash01",
)
MCP_CALL = ToolCall("mcp__probe__echo_text", {}, "toolu_probe01")


def _later_requests(ev: Evidence) -> list[str]:
    return [checks.dump(r["body"]) for r in checks.scripted_requests(ev)[1:]]


def check_skill_substitution(ev: Evidence) -> tuple[Outcome, str]:
    """Shown when the skill body reached the model with a path in place of the variable."""
    bodies = [text for text in _later_requests(ev) if COMMAND_TAIL in text]
    if not bodies:
        return "inconclusive", "baseline failed: the skill's command never reached the model"
    text = bodies[0]
    if VARIABLE + COMMAND_TAIL in text:
        return "not_shown", f"the model received the literal {VARIABLE}"
    found = re.search(r'\\"([^"\\]+)' + re.escape(COMMAND_TAIL), text)
    if found:
        return "shown", f"the model received the path {found.group(1)}"
    return "inconclusive", "the skill's command reached the model with neither form"


def check_bin_on_path(ev: Evidence) -> tuple[Outcome, str]:
    """Shown when the Bash tool's PATH gains a directory holding the plugin's launcher."""
    # The command itself is echoed back with "%s" in each bracket; only the output counts.
    text = "".join(_later_requests(ev))
    which = [m for m in WHICH.findall(text) if m != "%s"]
    path = [m for m in PATHVAR.findall(text) if m != "%s"]
    if not which or not path:
        return "inconclusive", "baseline failed: the Bash tool's output never reached the model"
    before = set(os.environ.get("PATH", "").split(os.pathsep))
    added = [d for d in path[0].split(os.pathsep) if d and d not in before]
    holding = [d for d in added if (Path(d) / "context-audit").is_file()]
    detail = f"command -v found {which[0]}; directories added to PATH: {added}"
    return ("shown" if holding else "not_shown"), detail


def check_hook_root(ev: Evidence) -> tuple[Outcome, str]:
    """Shown when the packaged hook wrote its counters to the run's state directory."""
    if not checks.hook_records(ev, "PostToolUse"):
        return "inconclusive", "baseline failed: the recording hook saw no PostToolUse event"
    counters = ev.run_dir / "state" / "counters.json"
    if not counters.is_file():
        return "not_shown", "the recording hook ran but the packaged hook wrote no counters"
    data = json.loads(counters.read_text(encoding="utf-8"))
    return "shown", f"the packaged hook wrote counters {data}"


def _scenario(name: str, claim: str, call: ToolCall, check) -> Scenario:
    return Scenario(
        name,
        claim,
        [Reply(tool_calls=(call,)), Reply(text="done")],
        [HookSpec("PostToolUse", "mcp__.*", "record", "a")],
        allowed_tools=("mcp__probe__*", "Skill", "Bash"),
        check=check,
        plugin_dir=PLUGIN,
        env={"CONTEXT_AUDIT_HOME": "{run_dir}/state"},
    )


INVOCATION: list[Scenario] = [
    _scenario(
        "plugin-skill-substitution",
        f"{VARIABLE} in a plugin skill body is replaced by a path before the model sees it",
        SKILL_CALL,
        check_skill_substitution,
    ),
    _scenario(
        "plugin-bin-path",
        "A plugin's bin/ directory is on the Bash tool's PATH",
        BASH_CALL,
        check_bin_on_path,
    ),
    _scenario(
        "plugin-hook-root",
        f"{VARIABLE} in the plugin's hook command resolves, so the packaged hook runs",
        MCP_CALL,
        check_hook_root,
    ),
]
