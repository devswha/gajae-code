# Test Spec: gajae-code OMP/OMX Runtime

## Verification Gates

### Gate 0 — Import Baseline

- Copy command excludes nested `.git` and preserves needed dotfiles.
- Repo root contains OMP source files after copy.
- Baseline attempts are logged:
  - `bun install`
  - `bun run check`
  - `bun run test`
  - `bun run check:rs`
  - `bun run test:rs`

### Gate 1 — GJC CLI Smoke

- `gjc --help`
- `gjc --version`
- `gjc question --help`
- `gjc state --help`
- `gjc team --help`
- `gjc ultragoal --help`
- `gjc ralplan --help`
- `gjc deep-interview --help`

### Gate 2 — Rebrand Assertions

- Public active-product surfaces do not present `oh-my-pi`, `omp`, `pi-coding-agent`, or `@oh-my-pi` except allowlisted attribution/history/license.
- TUI snapshots/help text use `gajae-code` / `gjc`.
- Package names and CLI bin use gajae-code/gjc naming.

### Gate 3 — Visible Definition Inventory

Expected visible definitions exactly:

- `deep-interview`
- `ralplan`
- `ultragoal`
- `team`

Fail if any visible skill/agent/workflow includes non-selected names such as `plan`, `worker`, `autopilot`, `ralph`, `ai-slop-cleaner`, `code-review`, `autoresearch-goal`, or `performance-goal`.

### Gate 4 — MCP Quarantine Negative Tests

Fail if shipped/default runtime exposes or loads:

- MCP CLI/help command such as `mcp` or `mcp-serve`.
- MCP config defaults.
- MCP server registry/defaults.
- MCP discoverable tool metadata.
- MCP tool selection/default activation.
- MCP docs/help as product-facing functionality.

Any retained MCP-compatible code must be inert, unreachable, undocumented, and tested as non-loadable.

### Gate 5 — Inline/Local Tool Positive Tests

Smoke test preserved local tools/categories after MCP removal:

- read
- write/edit
- bash
- search/find
- AST/local artifact tools where applicable
- Rust-backed native search/shell/text paths where retained

### Gate 6 — Workflow E2E

- `deep-interview` produces context/spec/interview artifacts.
- `ralplan` produces PRD and test-spec artifacts plus consensus record.
- `ultragoal` creates `.omx/ultragoal/brief.md`, `goals.json`, and `ledger.jsonl` and can checkpoint.
- `team` starts tmux workers, records mailbox/status evidence, and shuts down cleanly.

### Gate 7 — Final Quality

- TypeScript build/check/lint/tests pass or blockers are documented.
- Rust build/check/tests pass or blockers are documented.
- Final rebrand and MCP negative greps pass.
- Final code review approves.
