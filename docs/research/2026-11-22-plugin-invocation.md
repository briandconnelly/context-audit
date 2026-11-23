# How the audit skill reaches the CLI

Claude Code 2.1.330, run on 2026-11-22 through `probe.runner` against the loopback stub, in the sandbox with a disposable profile.
The routing gate reported `shown` in the same invocation as the three main runs; the controls ran minutes later through `probe.runner.run_scenario` without it.
Each scenario loads this repository with `--plugin-dir` and is defined in `probe/scenarios/invocation.py`.
Evidence is under `runs/task11-invocation-2/` and the controls under `runs/task11-invocation-control/`, which are local and not committed.

## Results

| Scenario | Claim | Outcome |
| --- | --- | --- |
| `plugin-skill-substitution` | `${CLAUDE_PLUGIN_ROOT}` in a skill body is replaced by a path before the model sees it | shown |
| `plugin-bin-path` | The plugin's `bin/` directory is on the Bash tool's `PATH` | shown |
| `plugin-hook-root` | `${CLAUDE_PLUGIN_ROOT}` in the plugin's hook command resolves, so the packaged hook runs | shown |

### Skill body substitution

- The stub scripted a `Skill` call for `context-audit:auditing-third-party-context`.
- The next model request held the skill's command with `/Users/bdc/projects/context-audit` in place of the variable, and no request held the literal `${CLAUDE_PLUGIN_ROOT}`.
- The path is the `--plugin-dir` directory itself, not a cached copy.
- Baseline: the check is inconclusive unless the skill's command reaches the model at all.
- Control: the same run without `--plugin-dir` was inconclusive, because the skill never reached the model.

### `bin/` on the Bash tool's path

- The stub scripted a Bash call that printed `command -v context-audit` and `$PATH`.
- The plugin's `bin/` directory was appended at the end of `PATH`, and it was the only directory added.
- Because it comes last, an installed `context-audit` earlier on `PATH` wins: in these runs `command -v` found the project's virtual environment, which `uv run` had put on the inherited `PATH`.
- Baseline: the check is inconclusive unless the Bash output reaches the model.
- Control: without `--plugin-dir`, no directory was added and the outcome was `not_shown`.

### Hook command root

- The run set `CONTEXT_AUDIT_HOME` to a directory inside the run directory and scripted one MCP call.
- The packaged hook wrote `counters.json` there with one request, one delivered result, and one full scan.
- Baseline: the check is inconclusive unless the probe's own recording hook saw a `PostToolUse` event.
- Control: without `--plugin-dir`, the recording hook ran and no counters were written, so the outcome was `not_shown`.

## Decision

- The brief's first branch applies: the skill names the CLI through `${CLAUDE_PLUGIN_ROOT}`.
- The skill runs `sh "${CLAUDE_PLUGIN_ROOT}/bin/context-audit" scan --json`, not `python3 -I .../cli.py`, because the system `python3` on macOS is 3.9 and the launcher picks the newest interpreter it finds.
- The skill does not rely on `bin/` being on `PATH`, because an older installed copy earlier on `PATH` would shadow it.

## Not probed

- Installation from a marketplace, where the plugin root is a cached copy.
- Whether the substituted path is quoted safely when it contains a double quote.
