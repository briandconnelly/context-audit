# context-audit

A Claude Code plugin, in design, that surfaces third-party text directing a coding agent beyond the user's task.

Nothing is shipped yet.
The design is in `docs/superpowers/specs/`.

## The probe

`probe/` is a development tool, not part of the plugin.
It runs the installed `claude` against local fixtures to find out what Claude Code hooks actually see and can do.

```sh
uv sync
uv run python -m probe                      # every scenario
uv run python -m probe --only result-text   # one scenario; --only may be repeated
uv run python -m probe --report             # also rewrite docs/research/ results
```

It spends no model quota: a local stand-in answers in place of the model endpoint, with a synthetic API key.
Each run uses a disposable profile, a temporary working directory outside your home, and a macOS sandbox that blocks outbound network traffic except loopback.
It needs macOS with `sandbox-exec`, and stops rather than run without it.

Results are in `docs/research/`: the generated outcomes, and hand-written observations.
Raw evidence for each run is under `runs/`, which is not committed.
