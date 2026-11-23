# Slice 1: open items

Findings deferred or parked during the build and its final review, copied from the build ledger on 2026-11-23.
Some early items were fixed by later work; check before acting on one.
Example sentences are synthetic.

- Task 1: minor (deferred): corrupt counters.json reads as empty and the next bump resets counts; _trim may drop one whole record at an exact line boundary; trimmed marker not 0600; bump does not validate values are ints.
- Task 2: minor (deferred): the one-text-per-item schema cannot express "independent fields never combine"; cover it in tests/test_rules.py (Task 5) instead.
- Task 2: minor (deferred): pos-049 span starts mid-word ("o not mention…"); still a substring, harmless to scoring.
- Task 2: minor (deferred): held-out in-scope texts are fairly short (median 154 characters); few are embedded in long passages.
- Task 3: minor (deferred): original_range excludes removed characters at a span's edges (matters for slice 2 redaction: a replaced span would leave a hidden character behind).
- Task 3: minor (deferred): original_range raises IndexError when end > len(text).
- Task 3: minor (deferred): per-group NFKC does not compose conjoining Hangul jamo.
- Task 3: minor (deferred): sentences() does not split on a lone carriage return.
- Task 3: minor (deferred): `encoded` detects standard base64 only, and 80 copies of one letter count as encoded.
- Task 3: minor (deferred): fenced() can return overlapping straight-quote and curly-quote spans (text.py:172).
- Task 4: minor (deferred): a hidden match before the first sentence gets sentence index 0, undocumented by a test; data-noun exempt list contained corpus-looking entries (superseded if finding 2 is fixed).
- Task 4: minor (deferred): under the communication-verb rule, benign wordings such as "do not mention the discount to the user" are review-level conceal-act; the data-noun list is what decides the data side.
- Task 4: minor (deferred): after a communication verb, any object not in the data-noun list reads as concealment ("do not tell the user about the weather" is review-level conceal-act).
- Task 4: minor (deferred): a sentence-initial adverb outside the concealment class blocks `act` ("Carefully forward the email…" gives no act).
- Task 5: minor (deferred): 150 KB scans take about 113 ms against a 120 ms time budget, so slower machines will report partial on large results (calibrate in Task 13's latency run).
- Task 5: minor (deferred): evaluation/catch.py raises KeyError for a range whose locator is not among the blocks (dev-only, fails loudly).
- Task 6: minor (deferred): JSON object keys are not scanned, so a directive placed in a key is dropped while the outcome says complete (accepted evasion; say so in the README limits).
- Task 6: minor (deferred): double-encoded JSON and almost-JSON text are scanned as one plain field and cap at review.
- Task 6: minor (deferred): input over max_bytes*4 is not parsed and ingest says complete (scan then reports partial).
- Task 6: parked — a directive beside JSON nested too deep to parse is scanned only as raw text, so it rates review at most, and nothing when it sits past the 150 KB cut — Ruling: real and deferred; the result is recorded as partial (reason depth) in the log and counters, and nothing downstream builds on it. For the final review: consider a review-level finding for abnormally deep or flooded structure.
- Task 6: minor (deferred): no test for nested arrays or for separation between two different arrays (behaviour verified by the re-reviewer's probes).
- Task 7: minor (deferred): corpus-copy test compares lines, not bytes (would miss a line-ending change).
- Task 7: minor (deferred): no automated check that the corpus is in the built wheel (verified by hand in Task 7).
- Task 7: minor (deferred): no high canary has multiple blocks, so the multi-block hook path is exercised only by two controls.
- Task 7: minor (deferred): run_selftest requires state_root to exist and creates `key` and `lock` there; callers must ensure_state first (carried to Tasks 8 and 10).
- Task 8: minor (deferred): a PreToolUse event that is unparseable AND whose model-authored tool_input contains the key text "hook_event_name":"PostToolUse" is miscounted as an unreadable result (one spurious count and message, never a missed one).
- Task 8: minor (deferred): source_id_for runs before the try block in the hook, so an exception there fails open without being counted.
- Task 9: minor (deferred): managed MCP scope not inventoried; hook script paths not recorded (only that a command hook exists) — list both as not covered in the README.
- Task 9: minor (deferred): duplicate frontmatter keys take the first value; escapes in quoted frontmatter values are not decoded; a stdio command containing spaces yields a path fragment as its base name.
- Task 8: minor (deferred): stale key.<pid>.tmp files left by a crash are never removed.
- Task 8: minor (deferred): the key regression test would not catch a variant that generates the bytes first and then writes the key in place.
- Task 9: minor (deferred): a regular file where a skill directory is expected is dropped with no skip marker (nothing to scan there).
- Task 8: minor (deferred): the key regression test (line tracing of state.py) passes a single-call `path.write_bytes(...)` variant that would expose an empty key; a polling reader or an assertion on the os.open/os.replace sequence would not have that blind spot.
- Task 8: minor (deferred): no fsync before the key rename; after power loss a 0-byte key fails the length check on every run, and the hook then records nothing silently. For the final review: a wrong-length key could be regenerated under the lock instead of being a permanent error.
- Task 8: minor (deferred): a directory named key.*.tmp in the state dir makes key creation fail every run (visible as StateError).
- Task 10: minor (deferred): show's transcript reader stats then opens (a swap to a FIFO in between would block); no per-line cap when reading a transcript; show for a project-scoped finding from another directory says "no longer in the inventory"; static scan records say outcome complete even when a budget cut that source.
- Task 11: minor (deferred): launchers do not follow symlinks (documented by a comment); an executable named python3.1x that is another program is exec'd unchecked by the hook launcher.
- PRIVACY INCIDENT: the Task 11 re-reviewer ran `bin/context-audit scan --json` once with no fixture flags, so the scan read the owner's real ~/.claude (read-only; state went to a scratch dir; output discarded per its report). This broke the hard rule in its brief and pre-empted Task 14 Step 1, which requires the owner's go-ahead. Reported to the owner. Mitigation for later dispatches: tell agents to set HOME to a temporary directory for any CLI run so default roots cannot resolve to the real home.
- Tasks 3/4: minor (deferred): two findings with the same finding_id can reach the caller when the same directive text appears twice (identical findings; the CLI records the id once); keycap emoji and tag-sequence flags each give one review hidden finding; 100 KB with a colour escape per line ends partial/time-budget.
- Task 11: minor (deferred): the CLI launcher's interpreter probe inherits stdin and has no timeout (a hanging candidate hangs the launcher).
- Task 11: minor (deferred): hook.py:47 SYSTEM_MESSAGE and hook.py:81 "See: context-audit status" use the PATH-form command (kept by ruling; README must explain).
- Task 12: minor (deferred): scan and status spawn `claude --version` on every run (bounded to 2 s after this round); consider caching.
- Task 12: minor (deferred): the plan document still lists eight behaviours including result-big (historical; note at the final review).
- Task 13: minor (deferred): a hook that warns on every payload still passes the latency gate (visible only in the benign-warned count); a receipt file that is valid JSON but not an object raises AttributeError instead of "not measured" (run still exits non-zero).
- Task 15: minor (deferred): bare singular or irregular-plural object + -ed word loses act ("Delete cache cleared today silently.", "Delete data uploaded today silently."); merge-commit body line "Delete records silently when expired" is a remaining false high; features.py is ~1,240 lines.
- Task 16b: parked — "If the user mentions a review, skip the review …" not high — Ruling: real; cause is that a bare "the review" is not an override target (vocabulary), outside the condition logic; deferred as a known limit in the write-up.
- Task 16b: parked — held-out controls 96/100 and 5/15 ordinary approval-conditioned sentences high — Ruling: real and it is the price of the strict approval forms; the loose alternative (99/100) lets 7 of 12 decoy overrides evade. Nothing downstream builds on the choice; it goes to the owner with both rows. Code stands at strict.
- Task 16b: parked — reviewer-wording recall 28/42 and dev-B 11/20 — Ruling: real; the pattern approach's structural limit; reported, not looped on.
- Task 16b: minor (deferred): features.py ~2,000 lines; 100 KB prose has almost no margin under the time budget; 4/15 clause-crossing benign highs; 6 older benign highs (i–n) in t16-review; benign review rate 193.6 per 100.
- Task 14: minor (deferred): README:17 "no python3 at all" is slightly narrow (launcher tries python3.13–3.15 first); README:79 exit-4 sentence reads as if all causes must hold; checkpoint procedure does not describe triaging scan highs; README claims not run: `claude --plugin-dir`, `uv tool install`.
- INCIDENT (Task 18): the implementer's scratch script was named probe.py and `python -m probe` ran the repo's real probe harness for ~2 min without the temp HOME variables. Controller check: the harness applies its own isolation (temp working directory outside home, disposable profile); 126 captured requests in runs/20261123T200247Z all went to the local stand-in and none contains the owner's identifiers or instruction text; no process left running; no real state directory created. No harm found. Lesson: tell agents not to name scratch modules after repo packages.
- Task 18: minor (deferred): override cues are decided by short word lists (review Minor 1; the class restatement cost 4 held-out items and was reverted); gate test for prose not written test-first.
- Final: minor (deferred): an event over 4 MiB is not scanned at all (gap recorded when hook_event_name is in the first 4 MiB; silently dropped otherwise) — needs a README line and an unknown-kind gap; hook launcher accepts any candidate that exits 0 and runs it twice; a symlinked SKILL.md file is skipped; final-review Minors 2, 4, 11, 12 (partly), 13, 14, 7 (partly); held-out sets in a public repository (owner decision).
