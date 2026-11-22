# Hook contract notes

Source: `https://code.claude.com/docs/en/hooks.md`, fetched 2026-11-22 as the page itself (293,944 bytes), not a summary.
These are what the documentation says.
Whether the installed build behaves this way is what the probe measures.

## Events

The page lists 33 events:
`SessionStart`, `Setup`, `UserPromptSubmit`, `UserPromptExpansion`, `PreToolUse`, `PermissionRequest`, `PermissionDenied`, `PostToolUse`, `PostToolUseFailure`, `PostToolBatch`, `Notification`, `MessageDisplay`, `SubagentStart`, `SubagentStop`, `TaskCreated`, `TaskCompleted`, `Stop`, `StopFailure`, `TeammateIdle`, `InstructionsLoaded`, `ConfigChange`, `CwdChanged`, `DirectoryAdded`, `FileChanged`, `WorktreeCreate`, `WorktreeRemove`, `PreCompact`, `PostCompact`, `PreModelSwitch`, `PostModelSwitch`, `Elicitation`, `ElicitationResult`, `SessionEnd`.

## Input fields

- `PostToolUse`: `session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`, `tool_name`, `tool_input`, `tool_response`, `tool_use_id`, and optional `duration_ms`.
  "The exact schema for both depends on the tool."
  "For an MCP tool, the input also carries the `mcp_server` object", which has the server's `name` and a `source`.
- `PostToolUseFailure`: the same `tool_name` and `tool_input`, with the error as a top-level `error` string, plus `is_interrupt` and `duration_ms`.
  There is no `tool_response` on this event.
  "Claude Code middle-truncates long strings around a `... [N characters truncated] ...` marker."
  It "doesn't fire for tool calls rejected before execution", including a permission denial.
- `PreToolUse`: `tool_name`, `tool_input`, `tool_use_id`, and `mcp_server` for an MCP tool.

## Output fields

- Message to the user: top-level `systemMessage`, "Warning message shown to the user".
  In `--output-format stream-json` output "it can arrive as an `SDKInformationalMessage`".
- Replace a result: `hookSpecificOutput.updatedToolOutput` on `PostToolUse`.
  "Replaces the tool's output with the provided value before it is sent to Claude. The value must match the tool's output shape."
  `updatedMCPToolOutput` "Replaces the output for MCP tools only. Prefer `updatedToolOutput`".
  "`PostToolUseFailure` can't rewrite a result."
- `decision: "block"` on `PostToolUse` "adds the `reason` next to the tool result. Claude still sees the original output".
- Ask for permission: on `PreToolUse`, `hookSpecificOutput.permissionDecision: "ask"` with `permissionDecisionReason`, which is "shown to the user in the permission prompt".
  In a `-p` run "where no one can answer that prompt", Claude Code denies the call and Claude reads the reason.
- `hookSpecificOutput` carries `hookEventName`.
- `terminalSequence`: "A terminal escape sequence for Claude Code to emit on your behalf, such as a desktop notification", restricted to OSC `0`/`1`/`2`/`9`/`99`/`777` and BEL.
  This is a way to notify the owner without the hook starting a child process, which the design's Delivery section did not know about.
- `additionalContext`, `systemMessage`, and plain stdout are each capped at 10,000 characters.

## Registration

A settings file registers hooks as `{"hooks": {"<Event>": [{"matcher": "<regex>", "hooks": [{"type": "command", "command": "<shell command>"}]}]}}`.
Tool events match on tool name; `mcp__.*` matches every MCP tool.

## Corrections to the plan's expected names

None for the field names.
One for the failure event: error content arrives in `error`, not `tool_response`.
