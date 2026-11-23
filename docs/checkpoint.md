# Slice 1 checkpoint

Slice 1 is used warn-only in ordinary work, and the trial decides whether slice 2 is built.
The rule for the checkpoint is in the spec, `docs/superpowers/specs/2026-11-22-third-party-context-audit-design.md`, section Checkpoint; this page is the owner's procedure for it.

## Before starting

Write down two numbers, with the date, before the first session of the trial:

1. **Tolerable review burden:** the most on-screen warnings and high findings from `scan` you will triage with `show` per week of ordinary work before the tool costs more than it gives.
   Review findings are counted at the end, not triaged one by one.
2. **Least useful outcome that justifies slice 2:** for example, at least one true warning in the trial, or a stated number of true warnings per week.

Also write down the trial's length or end condition.

## During the trial

1. Install the plugin and the `context-audit` command as `README.md` says.
2. Work normally; do not change what you install or use because of the trial.
3. Each time a warning appears, run the `show` command it names in a separate terminal, and record the finding ID and one verdict:
   - **true:** the span is a third-party directive that exceeds your task or hides something from you;
   - **false:** it is not;
   - **evidence unavailable:** `show` said so;
   - **pending:** not yet triaged.
4. Record verdicts only by finding ID; do not copy third-party text into the trial notes.
5. A false verdict is a rule defect: note it for a synthetic reproduction, and never paste the third-party text into a test.

Auto mode and headless runs are not probed for on-screen delivery, so run `context-audit scan` now and then to catch findings that did not appear on screen.

## At the end

Run `context-audit status` and `context-audit scan`, and report:

- warnings raised, each triaged as true, false, evidence unavailable, or pending;
- review findings logged;
- the observation counts: calls requested, results delivered, fully, partly, and not scanned, and requested calls with no matching result;
- gap records by reason, and whether the event log was trimmed;
- the self-test outcome for each entry point, and any voided claims.

A trial with no warnings at all is a result, and is weighed as one.

## The decision

Compare what the trial reports with the two numbers set before it started, and choose one:

1. **Build slice 2**: live listing, follow-on gating, redaction, and snapshots, as the spec describes.
2. **Narrow the tool**: keep only the surfaces or features that produced true warnings within the tolerable burden.
3. **Stop.**
