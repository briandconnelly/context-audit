# Contributing

Thanks for helping.
This page covers the development setup; user-facing detail is in the [reference](docs/reference.md), and rules for coding agents are in [AGENTS.md](AGENTS.md).

## Setup

You need Python 3.13 or newer and [`uv`](https://docs.astral.sh/uv/).
The package itself has no runtime dependencies; keep it standard-library only.

```sh
uv sync
```

## Checks

Run these before sending any change:

```sh
uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run ty check
```

The same checks, plus file hygiene, shellcheck, actionlint and zizmor, run as [prek](https://github.com/j178/prek) hooks; CI runs them on every pull request.
Install [prek](https://github.com/j178/prek) (`uv tool install prek`) and `shellcheck`, then run `prek install` to check staged files at each commit, or `prek run --all-files` to check everything.
The ruff hooks apply fixes. In CI, pytest prints no tracebacks, so held-out text never reaches the log; rerun a failing test locally to see why.
CI runs on Linux and deselects `perf` tests (wall-clock budgets); tests that launch the probe sandbox skip without macOS `sandbox-exec`. Run the full suite on a Mac before release.

For any change to `context_audit/`, `hooks/`, `bin/`, or `evaluation/`, also run the release gates (see [evaluation/README.md](evaluation/README.md)):

```sh
uv run python -m evaluation.gates
```

The gates run every corpus set through its entry point and score it.
The held-out gates report `not measured`, and the run fails, when `evaluation/heldout/` files are absent.
The "seeded warning investigated end to end" gate needs a probe receipt for the current build: any change to `context_audit/*.py`, `hooks/hooks.json`, or `bin/*` changes the build digest.
To refresh it, write receipts to a state directory and point the gates at them:

```sh
CONTEXT_AUDIT_HOME=runs/receipts uv run python -m probe --receipts
uv run python -m evaluation.gates --receipts runs/receipts/receipts.json
```

## Layout

| Path | What it holds |
| --- | --- |
| `context_audit/` | The package: inventory, text normalization, feature detectors, rules, the hook, the CLI, and the optional decider client. |
| `hooks/`, `bin/` | The plugin's hook definitions and `sh` launchers. |
| `skills/auditing-third-party-context/` | The audit skill. It is executed by a model, so treat its wording as code. |
| `evaluation/` | The labelled corpus, the release gates, and experiments. See [evaluation/README.md](evaluation/README.md). |
| `probe/` | A development tool that runs the real `claude` against fixtures to learn what hooks see. |
| `docs/research/` | Measurements, probe observations, and rulings. |
| `tests/` | The test suite. |

## The evaluation corpus

The corpus is the yardstick for every detector change.

- It is frozen: a corpus file changes only in a commit whose message begins `corpus:` and says why.
- After a permitted change, regenerate the manifest with `uv run python -m evaluation.schema --write-manifest`.
- Held-out sets under `evaluation/heldout/` are scored by `evaluation.gates`, which prints ids and counts, never text, and by the decision-model experiments below only with the owner's say-so.
  Reading held-out text to fix a miss spends that set: say so wherever its numbers are reported.
- Use the invented provider names listed in `evaluation/README.md`; never a real company or product.

## Decision-model experiments

`evaluation/jev_compare.py` and `evaluation/jev_windows.py` compare the scanner with a System One decision model.
They call TypeSafe's hosted API (`https://api.typesafe.ai`) with `TYPESAFE_API_KEY`, sending corpus text.
Get the owner's approval and a request budget before any run that makes new requests, and set `--cap` to that budget.
Every request and response is cached under `runs/`, input text included, so a rerun with `--cap 0` spends nothing and scores only cached items.
Running them on `--sets heldout` sends and caches held-out text; do that only when the owner has agreed to spend that set.
`jev_windows.py` builds its requests with `context_audit.decider`, so its numbers measure the shipped questions.

## The probe

`probe/` runs the installed `claude` against local fixtures to find out what Claude Code hooks actually see and can do.

```sh
uv run python -m probe                      # every scenario
uv run python -m probe --only result-text   # one scenario; --only may be repeated
uv run python -m probe --report             # also rewrite docs/research/ results
CONTEXT_AUDIT_HOME=<state dir> uv run python -m probe --receipts   # write capability receipts
```

It spends no model quota: a local stand-in answers in place of the model endpoint, with a synthetic API key.
Each run uses a disposable profile, a temporary working directory outside your home, and a macOS sandbox that blocks outbound network traffic except loopback.
It needs macOS with `sandbox-exec`, and stops rather than run without it.
Raw evidence for each run is under `runs/`, which is not committed.

## Commits

Use [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`, and `corpus:` for corpus changes).
