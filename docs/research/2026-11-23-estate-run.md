# Estate run

Run 2026-11-23 with the owner's go-ahead: `context-audit scan --json` against the owner's real Claude Code installation, with state kept under `runs/`, which is local and not committed.
This record holds counts, kinds, features and severities only: no source names, no finding IDs, and no third-party text.

## First run, at `2e6a58c`

- Self-test: passed through both entry points.
- Sources: 120 scanned, 1 skipped, 18 MCP servers counted and not listed.
- Findings: 36, of which 14 high and 22 review.
- High findings by kind and features: skill `act`+`conceal-act` 8, skill `act`+`override` 5, agent `act`+`conceal-act` 1, across 9 sources.
  Three of the 14 were one skill present in three cached versions.
- The owner ran `show` for all 14; all 14 were judged false.

High-finding precision on the estate was therefore 0 of 14.
No evaluation set had predicted this.
The benign sets held tool results and short hard negatives, and none resembled long instructional prose, which is what a skill body is.

## Defect classes

Described abstractly; the fixes used synthetic reproductions, never the installed text.

- A manner or omission cue inside a relative clause, a clause with its own subject, or a noun-phrase list item, describing how something else behaves: 5 findings.
- "in the background" read as concealment on its own: 3 findings.
- A word that only looks like an override cue or target, such as a cue used as a noun or a target used as a verb: 2 findings.
- "without" followed by a parameter, or a definitional "without asking", joined to an action in the next list item: 3 findings.
- An omission cue with no user-awareness target in its own clause, beside a sentence that says to tell the user: 1 finding.

## After the fix, at `ffbaf5c`

- Sources: 120 scanned, 1 skipped, 18 MCP servers counted and not listed.
- Findings: 15, of which 0 high and 15 review: `override` 6, `hidden` 3, `solicit` 3, `audience` 2, `conceal-act` 1.

The same commit's gates: canaries 52/52, held-out recall 53/60, controls 150/150, held-out controls 96/100, benign tool results 1000/1000, hook latency p95 121.7 ms sequential and 145.6 ms 8-way.
Two measures were added by this work:

- Generated instructional prose (`evaluation/prose.py`, 300 texts): 243 had a high finding before the fix and none after; it is now a gate.
  The generator and the fix have one author, so this is development evidence.
  A reviewer's own 41 instructional texts gave 0 high.
- Known-high items planted in generated instructional prose at four positions (`evaluation/planted.py`, ungated): 348 of 360 produce a high finding overlapping the planted text.

## What this run does not show

- The estate held no known unexpected directive, so it says nothing about recall.
- The 15 review findings were not triaged.
- MCP tool descriptions and server instructions were not scanned; slice 1 does not start servers.
- No tool call was observed through the hooks in this run.

## After the final review fix wave, at `7668907`

- Sources: 120 scanned, 0 partly scanned, 0 unreadable, 1 skipped as a symlink leaving its root, 18 MCP servers counted and not listed.
- Findings: 15, of which 0 high and 15 review.
