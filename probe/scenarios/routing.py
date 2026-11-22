"""The gate: does Claude Code talk to the stub, with the synthetic key, and nothing else."""

from __future__ import annotations

from pathlib import Path

from probe.scenario import Evidence, Outcome, Scenario
from probe.stub import Reply

MANAGED = Path("/Library/Application Support/ClaudeCode/managed-settings.json")


def _tail(path: Path, lines: int = 20) -> str:
    if not path.exists():
        return "(no debug log)"
    return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])


def check_routing(ev: Evidence) -> tuple[Outcome, str]:
    managed = "present" if MANAGED.exists() else "absent"
    note = f"managed settings file {managed}"
    auths = sorted({r["auth"] for r in ev.requests})
    scripted = [r for r in ev.requests if r["scripted"]]
    messages = [r for r in ev.requests if "/v1/messages" in r["path"]]
    real = [a for a in auths if a in ("bearer", "other-key")]
    if real or any(r["auth"] != "synthetic" for r in messages):
        return "inconclusive", f"requests carried credentials of kind {auths}; {note}"
    if not scripted or ev.completed.exit != 0:
        tail = _tail(ev.run_dir / "debug.log")
        counts = f"{len(scripted)} scripted requests, exit {ev.completed.exit}"
        return "inconclusive", f"{counts}; {note}; debug tail:\n{tail}"
    return "shown", f"{len(ev.requests)} requests, every model request with the synthetic key; {note}"


ROUTING = Scenario(
    name="routing",
    claim="Claude Code can be routed to a loopback stub in place of the model endpoint",
    script=[Reply(text="routed")],
    hooks=[],
    check=check_routing,
)
