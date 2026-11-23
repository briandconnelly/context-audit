# Probe results

Claude Code 2.1.330, Darwin arm64, 2026-11-22.
These are exploratory results from the probe's own recording hook.
Coverage receipts come later, from running the probe against the packaged hooks.
Every run used a local stand-in for the model endpoint and spent no model quota.

## Outcomes by claim

| Claim | Scenarios |
| --- | --- |
| Claude Code can be routed to a loopback stub in place of the model endpoint | routing: shown |
| The result hook receives the complete text of each result shape | result-text: shown; result-structured: shown; result-split: shown; result-big: shown; parallel: shown; competing-hook: shown; resume: shown |
| The failure hook receives error content | error-tool: shown; error-protocol: shown |
| Any inspected hook event carries tool descriptions or server instructions | metadata: not_shown |
| The transcript holds tool results that can be read back by tool-use ID | transcript: shown |
| Replacing a result keeps the original out of the next request | replace-text: shown; replace-with-competing-hook: shown |
| A hook message appears on the owner's terminal without passing through the model | direct-message: shown |
| A gate's ask reaches the owner before the call runs | ask-baseline: shown; ask-accept: shown; ask-decline: shown; ask-dismiss: shown; ask-retry: shown; ask-dont-ask-again: shown |

## Reasons

- `routing` (shown): 2 requests, every model request with the synthetic key; managed settings file absent
- `result-text` (shown): PostToolUse input held all 2 markers
- `result-structured` (shown): PostToolUse input held all 1 markers
- `result-split` (shown): PostToolUse input held all 2 markers
- `result-big` (shown): hook input held both ends of a 200,000 character result; next model request has head=True tail=False
- `error-tool` (shown): error text seen in ['PostToolUseFailure']
- `error-protocol` (shown): error text seen in ['PostToolUseFailure']
- `parallel` (shown): one complete record per parallel call (1 and 1 PostToolUse records)
- `competing-hook` (shown): hooks that saw the result: {'a': True, 'b': True}
- `metadata` (not_shown): reached the model: {'instructions': True, 'tool description': True, 'parameter description': True}; hook events carrying each: {'instructions': [], 'tool description': [], 'parameter description': []}; inspected: ['MessageDisplay', 'PostToolBatch', 'PostToolUse', 'PreToolUse', 'SessionEnd', 'SessionStart', 'Stop', 'UserPromptSubmit']
- `transcript` (shown): the transcript line for the tool-use ID holds the result text
- `resume` (shown): the hook ran in the resumed session; session ids seen: 1
- `replace-text` (shown): the next request has the replacement and the sibling, and not the original
- `replace-with-competing-hook` (shown): the next request has the replacement and the sibling, and not the original; the second hook saw original=True replacement=False
- `direct-message` (shown): the hook message is on screen and in no request to the model
- `ask-baseline` (shown): with no hook, the pre-allowed tool ran with no permission prompt
- `ask-accept` (shown): prompts answered: 1; calls that ran: 1; hook reason shown in the prompt: True
- `ask-decline` (shown): prompts answered: 1; calls that ran: 0; hook reason shown in the prompt: True
- `ask-dismiss` (shown): prompts answered: 1; calls that ran: 0; hook reason shown in the prompt: True
- `ask-retry` (shown): prompts answered: 2; calls that ran: 1; hook reason shown in the prompt: True
- `ask-dont-ask-again` (shown): the hook's ask prompted again after 'don't ask again'; second prompt appeared: True; calls that ran: 2

## Not shown or inconclusive

### metadata

Outcome: `not_shown`.

    reached the model: {'instructions': True, 'tool description': True, 'parameter description': True}; hook events carrying each: {'instructions': [], 'tool description': [], 'parameter description': []}; inspected: ['MessageDisplay', 'PostToolBatch', 'PostToolUse', 'PreToolUse', 'SessionEnd', 'SessionStart', 'Stop', 'UserPromptSubmit']

## Consequences for the design

- **Claude Code can be routed to a loopback stub in place of the model endpoint.** Holds on this build for every scenario run, so the design proceeds as written.
- **The result hook receives the complete text of each result shape.** Holds on this build for every scenario run, so the design proceeds as written.
- **The failure hook receives error content.** Holds on this build for every scenario run, so the design proceeds as written.
- **Any inspected hook event carries tool descriptions or server instructions.** Expected absent: live listing stays the only way to read tool descriptions and server instructions, and absence is claimed only for the events inspected.
- **The transcript holds tool results that can be read back by tool-use ID.** Holds on this build for every scenario run, so the design proceeds as written.
- **Replacing a result keeps the original out of the next request.** Holds on this build for every scenario run, so the design proceeds as written.
- **A hook message appears on the owner's terminal without passing through the model.** Holds on this build for every scenario run, so the design proceeds as written.
- **A gate's ask reaches the owner before the call runs.** Holds on this build for every scenario run, so the design proceeds as written.
