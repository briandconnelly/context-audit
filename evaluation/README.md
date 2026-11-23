# Evaluation corpus

This directory holds the frozen corpus that the scanner's detectors are judged against.
It is dev-only: it is not shipped in the package, and it uses the Python standard library only.
The labelling standard is the `## Definition` section of `docs/superpowers/specs/2026-11-22-third-party-context-audit-design.md`; every label here follows it.

After the freeze commit, a corpus file changes only by a commit whose message begins `corpus:` and states why.

## Files

- `corpus/canaries.jsonl`: the seven worked outcomes from the spec, each on the surfaces where its features apply.
- `corpus/positives.jsonl`: rewordings of the high combinations, expected `high`, plus a few hidden-payload carriers expected `review`.
- `corpus/controls.jsonl`: matched controls, expected `none` or `review`.
- `corpus/paired.jsonl`: pairs of identical items whose `note` labels one authorized and one unauthorized.
- `dev/in_scope.jsonl` and `dev/open_set.jsonl`: the round-1 held-out set, now spent and used as development data.
  Its items keep their original ids and `set` values (`heldout_in_scope`, `heldout_open`).
  Detectors were tuned against it, so its recall supports no recall claim; `gates.py` reports it ungated.
  It is split into dev-A and dev-B: dev-B is every in-scope item whose id number is divisible by 3 (20 items), kept unread as an over-fitting check; dev-A is the other 40.
  `schema.load_dev_a()` loads dev-A without returning dev-B text.
- `heldout/in_scope.jsonl`, `heldout/open_set.jsonl` and `heldout/controls.jsonl`: a fresh held-out set written by a separate author and kept out of the repository until it is measured.
  When `heldout/in_scope.jsonl` or `heldout/controls.jsonl` is absent, its gate is reported `not measured` and the gate run fails.
  `gates.py` prints only ids and counts for anything under `heldout/`.
- `corpus/MANIFEST.json`: SHA-256 of every corpus, development and held-out file that exists, and the item count per file.
- `schema.py`: `load`, `load_all`, `load_dev_a`, `validate`, `file_problems`, and the manifest writer.

Regenerate the manifest after any permitted change with `uv run python -m evaluation.schema --write-manifest`.
It refuses to write while any item is invalid.

## Item schema

Each file is JSON Lines: one object per line, no blank lines, UTF-8.
Every item has exactly these required keys, plus only the optional keys listed below.

| Key | Type | Allowed values |
| --- | --- | --- |
| `id` | string | `<prefix>-NNN` with a three-digit number, unique across all files; the prefix is set by `set` (below) |
| `set` | string | `canary` (`can`), `positive` (`pos`), `control` (`ctl`), `paired` (`par`), `heldout_in_scope` (`his`), `heldout_open` (`hop`), `heldout_control` (`hct`, expected `none` or `review`) |
| `surface` | string | `tool_result`, `tool_error`, `tool_description`, `param_description`, `server_instructions`, `skill`, `command`, `agent`, `hook_prompt`, `frontmatter` |
| `entry` | string | `hook` when `surface` is `tool_result` or `tool_error`, otherwise `scan` |
| `text` | string | the third-party text exactly as it would reach the agent; non-empty |
| `expected` | string | `high`, `review`, or `none`: what the scanner should output for the item |
| `span` | string or null | when `expected` is `high`, a non-empty exact substring of `text` that must lie inside the finding; otherwise `null` |
| `family` | string | lowercase feature names joined by `+`, such as `conceal-act+call` or `split+override+act` |
| `provider` | string | one of the placeholder providers below |
| `template` | string | a template id, see below |

Optional keys:

| Key | Type | Meaning |
| --- | --- | --- |
| `note` | string | free text; required on `paired` items, where it starts with `authorized:` or `unauthorized:` |
| `blocks` | list of strings | for `tool_result` and `tool_error` only: the sibling content blocks of one result, in order; at least two, and `text` must equal the blocks joined by a blank line (`"\n\n"`) |

The `span` rule is strict: `span in text` must be true, character for character, including any invisible characters.

Family names are the spec's feature IDs (`act`, `call`, `conceal-act`, `audience`, `solicit`, `override`, `hidden`) and these descriptors: `split` (directive spread across blocks), `non-english`, `quoted`, `negated`, `withholding`, `approval-conditioned`, `bidi`, `encoded`, `encoded-short`, `benign`, `benign-verb`, `long-instructions`, and `-distant` suffixes for features too far apart to join.

## Placeholder providers

Providers are invented names; never use a real company, product, or service.
Example domains use the reserved `.example` top-level domain.

- `examplecloud`
- `sampleforge`
- `demotracker`
- `fictionalfiles`
- `notarealdb`
- `placeholder-search`
- `examplemail`
- `sampleci`
- `demowiki`
- `mockmetrics`
- `fakeissues`
- `examplecalendar`
- `sampletickets`
- `demostore`

## Template ids

A template id is an opaque split label used to check that results do not hinge on one authoring skeleton.
The frozen corpus uses `t01` to `t14`; held-out authors use `h01` to `h14` or `g01` to `g14`, so the corpus and a held-out set never share a template.
Within each file, no provider and no template may hold more than a fifth of the items.

## Labelling notes

- `act` and `call` alone are reported only on tool results and tool errors; on every other surface a lone `act` or `call` is `none`.
- High needs a combination from the closed table: `conceal-act` + `act`, `conceal-act` + `call`, or `override` + `act`, joined in one sentence or in adjacent sentences where the second refers back to the first.
- Withholding a secret, a negated feature, quoted material, and an override conditioned on the user's own approval never reach high.
- Hidden carriers are not decoded: a payload encoded in tag characters or similar is `hidden` alone, so `review`; a visible high directive with zero-width or bidi characters inside it stays `high`.
- Block quotes and other quotations count as quoted material, like code fences.
- Paired items share everything except `id` and `note`, because the scanner cannot see which session authorized the wording.
