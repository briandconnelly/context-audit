# Evaluation corpus

This directory holds the frozen corpus that the scanner's detectors are judged against.
It is dev-only: it is not shipped in the package, and it uses the Python standard library only.
The labelling standard is the `## Definition` section of `docs/superpowers/specs/2026-11-22-third-party-context-audit-design.md`; every label here follows it.

After the freeze commit, a corpus file changes only by a commit whose message begins `corpus:` and states why.

## Files

- `corpus/canaries.jsonl`: the seven worked outcomes from the spec, each on the surfaces where its features apply.
- `corpus/positives.jsonl`: rewordings of the high combinations, all expected `high`.
- `corpus/controls.jsonl`: matched controls, expected `none` or `review`.
- `corpus/paired.jsonl`: pairs of identical items whose `note` labels one authorized and one unauthorized.
- `heldout/in_scope.jsonl` and `heldout/open_set.jsonl`: written by a separate author, optional until they exist.
- `corpus/MANIFEST.json`: SHA-256 of every corpus and held-out file that exists, and the item count per set.
- `schema.py`: `load`, `load_all`, `validate`, and the manifest writer.

Regenerate the manifest after any permitted change with `uv run python -m evaluation.schema --write-manifest`.
It refuses to write while any item is invalid.

## Item schema

Each file is JSON Lines: one object per line, no blank lines, UTF-8.
Every item has exactly these required keys, plus only the optional keys listed below.

| Key | Type | Allowed values |
| --- | --- | --- |
| `id` | string | `<prefix>-NNN` with a three-digit number, unique across all files; the prefix is set by `set` (below) |
| `set` | string | `canary` (`can`), `positive` (`pos`), `control` (`ctl`), `paired` (`par`), `heldout_in_scope` (`his`), `heldout_open` (`hop`) |
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
The frozen corpus uses `t01` to `t14`; held-out authors use `h01` to `h14`, so the two never share a template.
Within each set, no provider and no template may hold more than a fifth of the items.

## Labelling notes

- `act` and `call` alone are reported only on tool results and tool errors; on every other surface a lone `act` or `call` is `none`.
- High needs a combination from the closed table: `conceal-act` + `act`, `conceal-act` + `call`, or `override` + `act`, joined in one sentence or in adjacent sentences where the second refers back to the first.
- Withholding a secret, a negated feature, quoted material, and an override conditioned on the user's own approval never reach high.
- Paired items share everything except `id` and `note`, because the scanner cannot see which session authorized the wording.
