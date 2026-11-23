# Probe observations

Claude Code 2.1.330, macOS, 2026-11-22.
These are things the probe showed that the outcomes table in `2026-11-22-probe-results.md` does not carry, and what each means for the design.
All were observed in the probe's own runs; none is from documentation.

## What the result hook receives

- For an MCP tool, `tool_response` is the list of content blocks, for example `[{"type": "text", "text": "…"}]`.
- The input carries `mcp_server` with `name` and `source`, plus `tool_use_id`, `session_id`, and `transcript_path`.
- `PostToolBatch` also carries every `tool_response` of the batch.
- A tool error (`isError`) and a JSON-RPC error both arrive on `PostToolUseFailure`, as a top-level `error` string, with no `tool_response`.
- Two hooks on the same event both receive the original result, even when the first one replaces it.

## Oversized results

A 200,000 character result reached the hook whole.
The model received a 2 KB preview and the path of a file holding the full result.
The rest of that text can only reach the model through a later file read, which an MCP-only hook matcher does not see.
Design consequence: the scanner sees more than the model does at that moment, and slice 1 should say that text beyond the preview is covered at delivery, not at the later read.

## Metadata

- Server instructions are in the first model request, inside the message that lists MCP server instructions.
- MCP tools are deferred on this build: their descriptions and parameter descriptions reach the model only after a `ToolSearch` call.
- No hook event that fired carried instructions, tool descriptions, or parameter descriptions.
  The `ToolSearch` result seen by `PostToolUse` holds tool names only.
- Events that fired in the run: `MessageDisplay`, `PostToolBatch`, `PostToolUse`, `PreToolUse`, `SessionEnd`, `SessionStart`, `Stop`, `UserPromptSubmit`.
  The other 25 registered events did not fire, so nothing is claimed about them.

Design consequence: live listing remains the only way to read tool descriptions and server instructions.

## Replacement

- `hookSpecificOutput.updatedToolOutput` replaced an MCP text result; the next model request held the replacement and the neighbouring text, and not the original.
- The session transcript also held the replacement and not the original.
  The design's Redaction section says redaction does not remove the text from the transcript; on this build it does.
  That also means the investigate command could not read a redacted original back from the transcript.

## Messages and permission prompts on a terminal

Observed in the default permission mode only; the interactive default on this build is auto mode, which was not probed.

- `systemMessage` from a `PostToolUse` hook is printed as `PostToolUse:<tool> says: <message>` and appears in no model request.
- `permissionDecision: "ask"` from a `PreToolUse` hook raises a permission prompt that shows the hook's reason, even for a tool pre-allowed with `--allowedTools`.
  Nothing ran before the answer.
- The prompt offers Yes, "Yes, and don't ask again", and No.
- Declining or pressing Escape does not run the tool and ends the turn; no further model request is made until the owner types again.
- After "Yes, and don't ask again", the hook's `ask` still prompted on the next call.
  Design consequence: a gate that asks on every call for the session works as the design describes.
- The prompt prints the tool's own description, which is third-party text shown to the owner.

## Isolation, for anyone running Claude Code under test

- Claude Code loads `CLAUDE.md` and `.claude/skills` from every ancestor of its working directory, whatever `HOME` and `CLAUDE_CONFIG_DIR` say.
  A working directory under the owner's home put their real instructions and skill list into the requests.
  The probe now runs in a temporary directory outside the home tree and fails the routing check if any instruction file loads.
- With `ANTHROPIC_BASE_URL` set to a loopback address and a synthetic `ANTHROPIC_API_KEY`, every model request went to the stub with that key.
  Claude Code first sends an unauthenticated request to `/api/hello`.
- A fresh profile's interactive onboarding checks connectivity to the real API host directly and stops when that is blocked.
  The probe seeds the profile as already onboarded, so first-run behaviour is not covered.
- The hooks reference documents `terminalSequence`, a way for a hook to raise a desktop notification without starting a process.
  The design dropped operating-system notifications because hooks start no child processes; this field would allow one, and it is untested.

## Not probed

- Auto mode and headless delivery of messages and prompts.
- Two gated tools at once, and parallel gated calls.
- Structured results under replacement, and replacement of split or oversized results.
- Any hook event that did not fire in these runs.
