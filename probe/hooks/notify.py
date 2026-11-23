"""Exploratory hook: when the packaged hook flags a result, ask for an OSC 9 notification.

It runs the packaged hook on the same event, against a separate state directory
(``PROBE_NOTIFY_HOME``) so the run's own counts are not doubled, and when that hook would warn
it prints only a ``terminalSequence``. The plugin's hook is not changed.
Run by absolute path under ``python3 -I``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
PACKAGED_HOOK = REPO / "context_audit" / "hook.py"
NOTIFY_TEXT = "context-audit: flagged a third-party directive in a tool result"
SEQUENCE = f"\x1b]9;{NOTIFY_TEXT}\x07"


def output_for(packaged_output: str) -> dict | None:
    try:
        out = json.loads(packaged_output)
    except ValueError:
        return None
    if isinstance(out, dict) and "systemMessage" in out:
        return {"terminalSequence": SEQUENCE}
    return None


def main() -> None:
    raw = sys.stdin.buffer.read()
    home = os.environ.get("PROBE_NOTIFY_HOME")
    if not home:
        return
    env = {**os.environ, "CONTEXT_AUDIT_HOME": home}
    done = subprocess.run(
        [sys.executable, "-I", str(PACKAGED_HOOK)],
        input=raw,
        capture_output=True,
        env=env,
        timeout=30,
        check=False,
    )
    out = output_for(done.stdout.decode("utf-8", "replace"))
    if out is not None:
        sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
