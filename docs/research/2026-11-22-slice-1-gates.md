# Slice 1 release gates, first measurement

Measured 2026-11-22 on branch `feat/slice-1` by `uv run python -m evaluation.gates --out runs/task13-gates-r1`, which also runs the latency measurement.
The held-out sets were read only by the gate runner, which prints and writes ids, labels, and counts, never item text.
The implementer did not open, print, or search the held-out files.
This document contains no held-out item text.

## Result

Slice 1 does not pass its release gates.
In-scope recall is 25 of 60 (41.7%) against a floor of 80%, and 142 of 1,000 benign tool results produce a high finding.
Under the dispatch ruling, a failed recall gate is a stop: no detector was changed, no failing item was looked at, and no second round was run.

| Gate | Result | Numerator / denominator |
| --- | --- | --- |
| 1. Every canary produces its expected outcome through its entry point | pass | 52/52 |
| 2. In-scope held-out recall at least 80% (high finding locating the span) | fail | 25/60 |
| 3. No high finding on matched controls | pass | 150/150 |
| 4. No high finding on generated benign tool results | fail | 858/1000 |
| 5. Hook latency p95 at or under 200 ms, no timeouts or failures | pass | 400/400 hook runs clean |
| 6. Seeded warning investigated end to end | pass (Task 12 receipt) | 1/1 |

### Failing ids

- Gate 2, the 35 missed in-scope items: his-002, his-004, his-005, his-007, his-008, his-009, his-012, his-013, his-014, his-015, his-019, his-020, his-022, his-023, his-026, his-027, his-029, his-030, his-031, his-032, his-034, his-036, his-038, his-039, his-040, his-043, his-044, his-045, his-046, his-050, his-051, his-054, his-055, his-056, his-057.
- Gate 4, 142 benign results with a high finding; the full list is in `runs/task13-gates-r1/gates.json`.
  By template: b05 changelog 40, b14 coloured CI output 40, b10 commit messages 34, b02 log lines 25, and b00 the three sentences an earlier review found to be false highs, all 3 of them (ben-0001, ben-0002, ben-0003).

### Gate notes

- Gate 1: the 52 canaries are run through `context_audit.selftest.run_item`, the self-test's own path; an expected-high canary counts only when `context_audit.catch.caught` credits a high finding, and a review or none canary must produce exactly that top severity.
- Gate 2: an item counts only when a high finding passes `caught`; a review finding earns nothing.
- Gate 6: not measured by this task; it reports the `transcript-readback` receipt in `runs/task12-receipts-state-r1/receipts.json`, whose status is `shown` (Claude Code 2.1.330, headless, pre-allowed permissions).
- Budget: gates ran with the default scanner budget (150,000 bytes, 0.12 s); an item whose outcome was a time-budget partial would be re-run up to three times.
  No item needed a retry, none failed to complete, and none raised.

## Ungated measurements

- In-scope recall by family: override+act 13/20, conceal-act+call 8/20, conceal-act+act 4/20.
- In-scope recall by surface (each 6 items): tool_result 3, tool_error 2, tool_description 3, param_description 2, server_instructions 2, skill 2, command 3, agent 2, hook_prompt 3, frontmatter 3.
- Open-set held-out (40 items), expected against produced: of 16 expected none, 16 produced none; of 24 expected review, 6 produced review and 18 produced none; none produced high.
- Open-set agreement by family: act 8/12, call 5/5, solicit 3/5, audience+act 0/5, override 1/3, hidden 1/2, non-english+act 3/4, non-english+call 1/2, non-english+audience+act 0/1, non-english+solicit 0/1.
- Open positives (`evaluation/corpus/positives.jsonl`) recall under the same rule: 47/48; the miss is pos-013, one of the known xfails.
  pos-002 and pos-018, xfail in the corpus test, which scans items as plain fields, are caught here, where they go through the hook path (`from_hook_event`); why the two paths differ was not investigated.
- Review burden: 121.4 review findings per 100 benign results; 639 of 1,000 distinct benign results carry at least one finding of any severity and would need owner triage.
- Controls: none of the six known xfails (ctl-011, ctl-082, ctl-086 among them) produced a high, so gate 3 has no failures.

## Latency

Workload, declared:

- Machine: Apple silicon arm64, 12 CPUs; macOS 27.2.1.
- Python: 3.15.0, the interpreter `bin/context-audit-hook` selects from `PATH` (`.venv/bin/python3.15`).
- Process: one cold `sh bin/context-audit-hook` subprocess per sample, event on stdin, with `HOME` and `CONTEXT_AUDIT_HOME` set to fresh temporary directories; timeout 60 s, Claude Code's default for command hooks.
- Payload mix: 200 PostToolUse events, 60% under 2 KB, 30% about 20 KB, 10% about 100 KB, from the benign generator (seed 20261122), with every 20th payload an open-corpus hook canary instead; serialized sizes 363 bytes to 107,161 bytes, median 628.
- Concurrency: the same 200 payloads sequentially, then 8-way concurrent sharing one state directory.

| Concurrency | p50 | p95 | max | timeouts | non-zero exits |
| --- | --- | --- | --- | --- | --- |
| 1 | 38.5 ms | 102.8 ms | 241.5 ms | 0 | 0 |
| 8 | 46.4 ms | 125.5 ms | 286.6 ms | 0 | 0 |

## Rounds

- Round 0, development only: the runner on the open corpus and the benign set, with empty held-out files.
  Canaries 52/52, controls 150/150, benign 858/1000; recall not measured.
- Round 1, the first and only read of the held-out sets: the numbers above.
  Recall failed, so the run stops here; the benign false highs were not fixed, because a fix would change the detectors and recall must then be re-measured on a held-out set the controller has not yet decided about.

## What the numbers show and do not show

- They show the shipped canaries and the 150 matched controls behave as labelled, which is what the detectors were developed against.
- They show the detectors do not generalize to fresh wording: 41.7% in-scope recall on held-out text written by a separate author, against 47/48 on the open positives.
- They show conceal-act combinations are the weakest family on held-out text (4/20 and 8/20).
- They show ordinary text trips high findings: past-tense and descriptive uses of "silently" and "in the background", imperative-mood commit subjects, and log lines run together into one sentence.
- They show the hook is fast enough on this machine and workload, with headroom at p95.
- They do not show a population rate: each gate is a criterion on a frozen sample of 60, 150, or 1,000 items.
- They do not show that the benign set is representative of real MCP results; it is synthetic and written to be hard on precision.
- They do not show latency on slower machines, older Python builds, or results above 100 KB.
- Gate 6 was not re-run here; it rests on the Task 12 receipt.
