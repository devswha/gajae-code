Lists, inspects, awaits, or cancels detached task subagents.

Task launches return immediately. Use this tool when you need direct control over those running subagents; generic `job` remains available for all background job types.

# Operations

## `action: "list"`
Snapshot your visible detached subagents.

## `action: "inspect"`
Inspect selected subagents by `ids`; omit `ids` to inspect current running subagents. Terminal subagents include final output when retained.

## `action: "await"`
Wait for selected subagents by `ids`; omit `ids` to wait for current running subagents.
- Always set `timeout_ms` when the result is not immediately required forever.
- If the timeout elapses, the subagent is still running. This is not a failure.
- On timeout, inspect progress, keep doing independent work, and cancel only if the subagent is no longer needed or is unrecoverably wrong.

## `action: "cancel"`
Stop selected running subagents by `ids`.
- Use only when the subagent is no longer needed, has gone off-track, or is unrecoverably stuck.
