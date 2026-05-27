Lists, inspects, awaits, or cancels detached task subagents.

Task launches return immediately. Use this tool when you need direct control over those running subagents. Prefer `subagent` for task subagents; generic `job` remains available for non-subagent jobs and compatibility fallback access.

# Operations

## `action: "list"`
Snapshot your visible detached subagents.

## `action: "inspect"`
Inspect selected subagents by `ids`; omit `ids` to inspect current running subagents. Terminal subagents include final output when retained.

## `action: "await"`
Wait for selected subagents by `ids`; omit `ids` to wait for current running subagents.
- Always set `timeout_ms` when the result is not immediately required forever.
- Await timeout only bounds this tool call's wait; it does not stop the subagent and is not a failure reason.
- On timeout, inspect progress and keep doing independent work. Never cancel just because an await timed out; cancel only if the subagent has actually failed, gone off-track, or become unrecoverably wrong.

## `action: "cancel"`
Stop selected running subagents by `ids`.
- Use only when the subagent has actually failed, gone off-track, or become unrecoverably wrong; an await timeout alone is never a cancellation reason.
