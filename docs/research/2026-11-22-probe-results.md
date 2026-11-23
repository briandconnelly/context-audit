# Probe results

Claude Code 2.1.330, Darwin arm64, 2026-11-22.
These are exploratory results from the probe's own recording hook.
Coverage receipts come later, from running the probe against the packaged hooks.
Every run used a local stand-in for the model endpoint and spent no model quota.

## Outcomes by claim

| Claim | Scenarios |
| --- | --- |
| Claude Code can be routed to a loopback stub in place of the model endpoint | routing: shown |
| The probe detects an instruction file loaded from above the working directory | isolation-canary: shown |
| With no setting sources, an instruction file above the working directory stays out | isolation-exclusion: shown |
| The result hook receives the complete text of each result shape | result-text: shown; result-structured: shown; result-split: shown; result-big: shown; parallel: shown; competing-hook: shown; resume: shown |
| The failure hook receives error content | error-tool: shown; error-protocol: shown |
| Any inspected hook event carries tool descriptions or server instructions | metadata: not_shown |
| The transcript holds tool results that can be read back by tool-use ID | transcript: shown |
| After a replacement, the transcript still holds the original result | replace-transcript: not_shown |
| Replacing a result keeps the original out of the next request | replace-text: shown; replace-with-competing-hook: shown |
| A hook message appears on the owner's terminal without passing through the model | direct-message: shown |
| A gate's ask reaches the owner before the call runs | ask-baseline: shown; ask-accept: shown; ask-decline: shown; ask-dismiss: shown; ask-retry: shown; ask-dont-ask-again: shown |

## Reasons

- `routing` (shown): 2 requests, every model request with the synthetic key; managed settings file absent
- `isolation-canary` (shown): planted file reached the model: True; guard fired: True
- `isolation-exclusion` (shown): planted file reached the model: False; guard fired: False
- `result-text` (shown): PostToolUse input held all 2 markers
- `result-structured` (shown): of ['structuredContent', 'content text']: the model received ['structuredContent']; the hook received ['structuredContent']
- `result-split` (shown): PostToolUse input held all 2 markers
- `result-big` (shown): hook input held one text of 200,000 characters; next model request has head=True tail=False
- `error-tool` (shown): error text seen in ['PostToolUseFailure']
- `error-protocol` (shown): error text seen in ['PostToolUseFailure']
- `parallel` (shown): one complete record per parallel call (1 and 1 PostToolUse records)
- `competing-hook` (shown): hooks that saw the result: {'a': True, 'b': True}
- `metadata` (not_shown): reached the model: {'instructions': True, 'tool description': True, 'parameter description': True}; hook events carrying each: {'instructions': [], 'tool description': [], 'parameter description': []}; inspected: ['MessageDisplay', 'PostToolBatch', 'PostToolUse', 'PreToolUse', 'SessionEnd', 'SessionStart', 'Stop', 'UserPromptSubmit']
- `transcript` (shown): the transcript line for the tool-use ID holds the result text
- `resume` (shown): the hook ran in the resumed session; session ids seen: 1
- `replace-transcript` (not_shown): transcript holds the original: False; holds the replacement: True
- `replace-text` (shown): the next request has the replacement and the sibling, and not the original
- `replace-with-competing-hook` (shown): the next request has the replacement and the sibling, and not the original; the second hook saw original=True replacement=False
- `direct-message` (shown): the hook message is on screen and in no request to the model
- `ask-baseline` (shown): with no hook, the pre-allowed tool ran with no permission prompt
- `ask-accept` (shown): prompts answered: 1; calls that ran: 1; hook reason shown in the prompt: True
- `ask-decline` (shown): prompts answered: 1; calls that ran: 0; hook reason shown in the prompt: True
- `ask-dismiss` (shown): prompts answered: 1; calls that ran: 0; hook reason shown in the prompt: True
- `ask-retry` (shown): prompts answered: 2; calls that ran: 0; hook reason shown in the prompt: True
- `ask-dont-ask-again` (shown): the hook's ask prompted again and the declined call did not run; calls that ran: 1; second prompt seen: (True,)

## Not shown or inconclusive

### metadata

Outcome: `not_shown`.

    reached the model: {'instructions': True, 'tool description': True, 'parameter description': True}; hook events carrying each: {'instructions': [], 'tool description': [], 'parameter description': []}; inspected: ['MessageDisplay', 'PostToolBatch', 'PostToolUse', 'PreToolUse', 'SessionEnd', 'SessionStart', 'Stop', 'UserPromptSubmit']

### replace-transcript

Outcome: `not_shown`.

    transcript holds the original: False; holds the replacement: True

## Consequences for the design

- **Claude Code can be routed to a loopback stub in place of the model endpoint.** Shown on this build for every scenario run.
- **The probe detects an instruction file loaded from above the working directory.** Shown on this build for every scenario run.
- **With no setting sources, an instruction file above the working directory stays out.** Shown on this build for every scenario run.
- **The result hook receives the complete text of each result shape.** Shown on this build for every scenario run.
- **The failure hook receives error content.** Shown on this build for every scenario run.
- **Any inspected hook event carries tool descriptions or server instructions.** Expected absent: live listing stays the only way to read tool descriptions and server instructions, and absence is claimed only for the events inspected.
- **The transcript holds tool results that can be read back by tool-use ID.** Shown on this build for every scenario run.
- **After a replacement, the transcript still holds the original result.** Not shown for `replace-transcript` (not_shown): After a replacement the transcript holds the replacement, so the investigate command cannot show the original, and the design's Redaction section needs correcting.
- **Replacing a result keeps the original out of the next request.** Shown on this build for every scenario run.
- **A hook message appears on the owner's terminal without passing through the model.** Shown on this build for every scenario run.
- **A gate's ask reaches the owner before the call runs.** Shown on this build for every scenario run.

## Not probed

- Two gated tools at once, and parallel gated calls.
- Auto mode, which is the interactive default, and headless delivery of messages and prompts.
- First-run behaviour: the interactive profile is seeded as already set up.
- Replacement of structured, split, or oversized results.
- A long error string, where the hooks reference documents middle truncation.
- Any hook event that did not fire in these runs.
- A leaked skill list: the isolation guard detects instruction files only.
