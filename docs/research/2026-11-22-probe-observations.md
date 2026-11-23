# Probe observations

Claude Code 2.1.330, macOS, 2026-11-22.
These are things the probe showed that the outcomes table in `2026-11-22-probe-results.md` does not carry, and what each means for the design.

Each statement is marked by what backs it:

- **Checked:** a scenario's check decides it, and it holds in the committed results.
- **Seen in evidence:** read by hand from a run's captured requests, hook inputs, or screen; no check decides it.
- **Seen once, not kept:** observed while building the probe; the evidence was not retained.
- **Inferred:** a conclusion drawn from the above, not observed.

## What the result hook receives

- Checked: the hook receives the full text of text and split results, and one text of the full 200,000 characters for an oversized result.
- Seen in evidence: for a result with only content blocks, `tool_response` is the list of blocks, for example `[{"type": "text", "text": "…"}]`.
- Checked: for a result with both a text block and `structuredContent`, the hook and the model both received `structuredContent` and neither received the text block.
  Seen in evidence: in that case `tool_response` is a string of compact JSON, not a list of blocks.
  Design consequence: the scanner must handle both shapes, and a server's text block can go unread by both hook and model when `structuredContent` is present.
- Seen in evidence: the input carries `mcp_server` with `name` and `source`, plus `tool_use_id`, `session_id`, and `transcript_path`.
- Seen in evidence: `PostToolBatch` also carries every `tool_response` of the batch.
- Checked: a tool error (`isError`) and a JSON-RPC error both reach a hook.
  Seen in evidence: both arrive on `PostToolUseFailure`, as a top-level `error` string, with no `tool_response`.
- Checked: two hooks on the same event both receive the result.
  Seen in evidence: the second still receives the original when the first replaces it.

## Oversized results

- Checked: a 200,000 character result reached the hook whole.
- Seen in evidence: the model received a 2 KB preview and the path of a file holding the full result.
- Seen in evidence: a token-counting request carried the entire result to the model endpoint.
- Inferred: the rest of the text can reach the model only through a later file read, which an MCP-only hook matcher does not see.

Design consequence: the scanner sees more than the model does at that moment, and slice 1 should say that text beyond the preview is covered at delivery, not at a later read.

## Metadata

- Checked: server instructions, tool descriptions, and parameter descriptions all reached the model, and no hook event that fired carried any of them.
- Seen in evidence: server instructions are in the first model request.
- Seen in evidence: for this server, tool and parameter descriptions reached the model only after a `ToolSearch` call, whose result as seen by `PostToolUse` holds tool names only.
  Only one server with seven tools was tried, so nothing is claimed about when tools are deferred.
- Seen in evidence: the events that fired were `MessageDisplay`, `PostToolBatch`, `PostToolUse`, `PreToolUse`, `SessionEnd`, `SessionStart`, `Stop`, and `UserPromptSubmit`.
  The other 25 registered events did not fire, so nothing is claimed about them.

Design consequence: live listing remains the only way to read tool descriptions and server instructions.

## Replacement

- Checked: `hookSpecificOutput.updatedToolOutput` replaced an MCP text result; later requests held the replacement and the neighbouring text, and no request of any kind held the original.
- Checked: after a replacement, the session transcript holds the replacement and not the original.
  The design's Redaction section says redaction does not remove the text from the transcript; on this build it does.
  Design consequence: the investigate command cannot read a redacted original back from the transcript.

## Messages and permission prompts on a terminal

All of this was observed with `--permission-mode default`.
Seen once, not kept: without that flag, an interactive session on this build started in auto mode, which was not probed.

- Checked: `systemMessage` from a `PostToolUse` hook appears on the terminal and in no request to the model.
  Seen in evidence: it is printed as `PostToolUse:<tool> says: <message>`.
- Checked: with no hook, a tool pre-allowed with `--allowedTools` runs with no prompt; with a `PreToolUse` hook returning `permissionDecision: "ask"`, a prompt showing the hook's reason appears, and the tool runs only if the owner accepts.
- Checked: declining or pressing Escape does not run the tool.
  Seen in evidence: either one ends the turn, and no further model request is made until the owner types again.
- Checked: when the owner declines, types again, and the tool is called again, the hook prompts again and the tool does not run unprompted.
- Checked: after "Yes, and don't ask again", the hook's `ask` prompted again on the next call, and declining that prompt stopped the call.
  Design consequence: a gate that asks on every call for the session works as the design describes.
- Seen in evidence: the prompt prints the tool's own description, which is third-party text shown to the owner.

## Isolation, for anyone running Claude Code under test

- Checked: with default setting sources, a `CLAUDE.md` two directories above the working directory was loaded into the model request, although `HOME` and `CLAUDE_CONFIG_DIR` pointed elsewhere.
  The probe's guard detected it.
- Checked: with `--setting-sources ""`, the same file was not loaded.
- Seen once, not kept: early runs from a working directory under the owner's home put their real instructions and skill list into requests to the stub.
  The guard detects instruction files only; it would not see a leaked skill list.
- The probe therefore does both: it passes `--setting-sources ""`, and it runs in a temporary directory outside the home tree.
- Checked: with `ANTHROPIC_BASE_URL` set to a loopback address and a synthetic `ANTHROPIC_API_KEY`, every model request went to the stub with that key, and no request carried any other credential.
  Seen in evidence: Claude Code first sends an unauthenticated request to `/api/hello`.
- Seen once, not kept: a fresh profile's interactive onboarding stopped with a connection error naming the real API host.
  The probe seeds the profile as already onboarded, so first-run behaviour is not covered.
- From the hooks reference: `terminalSequence` lets a hook raise a desktop notification without starting a process; see Packaged hooks for the probe of it.
  The design dropped operating-system notifications because hooks start no child processes; this field would allow one.

## Packaged hooks

These runs load this repository with `--plugin-dir`, so the hook is reached through `hooks/hooks.json` and `bin/context-audit-hook` and writes to a state directory inside the run directory.
The scenarios are in `probe/scenarios/packaged.py`; evidence is under `runs/task12-packaged-r1/`, which is local and not committed.
The routing gate reported `shown` in the same invocation.
Each scenario ran a baseline first, the same run with a benign tool, and every baseline was clean: the packaged hook ran, and there was no finding, owner message, model note, or notification.
These outcomes are the receipts `status` reads, for Claude Code 2.1.330 and plugin 0.0.0.
Each receipt holds only for its frontend and permission mode: terminal runs used `--permission-mode default`, and headless runs passed no mode and pre-allowed the tools (`pre-allowed`).

- Checked: for a text, structured, and split result carrying the canary directive, the counters show the result fully scanned and the event log holds a high finding for the call (`pkg-result-text`, `pkg-result-structured`, `pkg-result-split`).
- Checked: a large result that fits the scanner's budgets, 140,000 characters with the directive at the end, was fully scanned and logged as a high finding, and the model's next request did not carry the directive, so it took the oversized path (`pkg-result-large-in-budget`).
  Seen in evidence: the model received a preview and the note "Output too large (138.5KB). Full output saved to" a file in the profile.
  Seen in evidence: the full result, directive included, was sent to the token-counting endpoint (`/v1/messages/count_tokens`), which is not a scripted model turn.
  Its filler is lines of `x`, chosen so the scan finishes inside the 0.12-second time budget; this receipt says nothing about large results of other text.
- Checked: a 200,000-character result with the directive in its first 1,000 characters was counted partly scanned, a gap record with outcome `partial` and reason `byte-budget` was logged, the directive still produced a high finding, and the next request held the plain `MODEL_NOTE`, not the oversized one (`pkg-result-over-budget`).
  Its baseline, a benign 200,000-character result, was counted partly scanned with no finding and no note.
- Checked: a tool error carrying the canary reached the hook on `PostToolUseFailure` and was logged as a high finding (`pkg-error`).
- Checked: `hookSpecificOutput.additionalContext` from a `PostToolUseFailure` hook is shown: `MODEL_NOTE` was in the next request to the stand-in.
  Seen in evidence: it arrives as a system block labelled `PostToolUseFailure:<tool> hook additional context:`.
- Checked: on a terminal in the default permission mode, the fixed `SYSTEM_MESSAGE` with its finding ID was on screen and in no request, and `MODEL_NOTE` was in the next request (`pkg-direct-message`).
- Checked: `context-audit show` for the logged finding, run with a temporary `HOME`, exited 0 and printed two spans of the canary, each at least 20 characters, read back from the transcript the harness wrote (`pkg-transcript-readback`).
- Checked: a hook output with `terminalSequence` set to an OSC 9 notification put that exact sequence into the raw terminal bytes (`pkg-notification`).
  This ran through a probe wrapper hook, `probe/hooks/notify.py`, beside the packaged hook; the plugin's hook does not emit it, and whether to offer it is the owner's decision.
- Seen once, not kept: outside the harness, a 140,000-character result of short sentences or digit lines took longer than the scanner's 0.12-second time budget and was marked partly scanned.

## Not probed

- Auto mode and headless delivery of messages and prompts.
- Two gated tools at once, and parallel gated calls.
- Replacement of structured, split, or oversized results.
- A long error string on `PostToolUseFailure`, where the hooks reference documents middle truncation.
- Any hook event that did not fire in these runs.
- Whether a saved sign-in exists; the probe only checks that no request carried one.
