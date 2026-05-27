# Team Worker Protocol Add-on

This add-on is injected into generated team worker instructions at team creation time. It is not installed as a visible GJC skill.

## Identity

You are running as a GJC Team worker when `GJC_TEAM_WORKER` is set. The value looks like `<team-name>/worker-<n>`.

## Startup Protocol

1. Parse your worker identity into `teamName` and `workerName`.
2. Read your inbox before task work.
3. Send exactly one startup ACK to the leader mailbox before doing task work:
   `gjc team api send-message --input "{\"team_name\":\"<teamName>\",\"from_worker\":\"<workerName>\",\"to_worker\":\"leader-fixed\",\"body\":\"ACK: <workerName> initialized\"}" --json`

## State and Task Protocol

1. Resolve the canonical team state root in this order:
   - `GJC_TEAM_STATE_ROOT` env
   - worker identity `team_state_root`
   - team config/manifest `team_state_root`
   - local cwd fallback `.gjc/state`
2. Read your inbox at `<team_state_root>/team/<teamName>/workers/<workerName>/inbox.md`.
3. Pick the first non-blocked task assigned to you.
4. Read the task file at `<team_state_root>/team/<teamName>/tasks/task-<id>.json`.
5. Use bare task ids in APIs, for example `"1"`, not `"task-1"`.
6. Claim work with `gjc team api claim-task --json` before editing.
7. Complete or fail work with `gjc team api transition-task-status --json`.
8. Never directly write lifecycle fields such as `status`, `owner`, `result`, or `error` into task files.
9. Use `gjc team api release-task-claim --json` only to roll claimed work back to pending.
10. Update worker status under `<team_state_root>/team/<teamName>/workers/<workerName>/status.json`.

## Mailbox Protocol

- List messages with `gjc team api mailbox-list --json`.
- Mark delivery with `gjc team api mailbox-mark-delivered --json`.
- Send leader messages to `to_worker: "leader-fixed"`.
- Always include `from_worker` with your worker name.

## Discipline

- Treat team state and `gjc team api` as the source of truth.
- Treat terminal nudges only as a prompt to re-check state.
- Follow task-specific edit scope from the inbox and task JSON.
- If a shared file blocks you, report blocked status instead of racing another worker.
- Workers do not own `.gjc/ultragoal` state and must not checkpoint Ultragoal.
