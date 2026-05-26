# PRD: gajae-code OMP/OMX Runtime

## Decision

Build `gajae-code` as a full functional, TypeScript-first derivative of OMP/oh-my-pi with a `gjc` CLI and rebranded TUI, preserving OMP inline/local tools while exposing exactly four workflow definitions from oh-my-codex: `deep-interview`, `ralplan`, `ultragoal`, and `team`.

## Source of Truth

- Deep-interview spec: `.omx/specs/deep-interview-gajae-code-omp-omx-runtime.md`
- Context snapshot: `.omx/context/gajae-code-omp-omx-runtime-20260526T064130Z.md`

## Principles

1. Copy OMP first, then constrain: first execution step imports `.omx/tmp-oh-my-pi` excluding nested `.git`.
2. Exactly four visible definitions: `deep-interview`, `ralplan`, `ultragoal`, `team`.
3. Rebrand completely: public CLI/package/TUI/docs surface becomes `gajae-code` / `gjc`; OMP/oh-my-pi only in attribution/history.
4. No MCP shipped/default: preserve inline/local tools; remove or hard-disable MCP exposure/config/runtime.
5. TypeScript-first: use Rust only for native/performance-critical parts.

## Requirements

### R1 — Baseline OMP Import

- Copy all OMP source files from `.omx/tmp-oh-my-pi` into repo root, including needed dotfiles.
- Exclude nested `.git`.
- Preserve attribution/license.
- Capture baseline build/check status before heavy edits.

### R2 — Product Rebrand

- Rename root/product identity to `gajae-code`.
- Change CLI bin from `omp` to `gjc`.
- Rebrand TUI labels/help/status text.
- Rebrand package scope and user-facing docs.
- Keep upstream names only in attribution/history.

### R3 — Visible Surface Gate

- Remove OMP default commands/skills/rules/agents from default shipped surface.
- Expose exactly four visible workflow definitions:
  - `deep-interview`
  - `ralplan`
  - `ultragoal`
  - `team`
- Rewrite/internalize selected OMX definitions so they do not promote non-selected workflows as user-facing options.
- Support concepts such as planning, worker protocol, code review, and cleanup may exist only as private runtime internals, not visible skills/agents.

### R4 — MCP Quarantine Gate

- Remove or hard-disable MCP-specific dependencies, imports, commands, help text, setup/config defaults, server registries, discoverable metadata, and default tool selection.
- Do not ship/default-load MCP tools or MCP servers.
- Any retained MCP-compatible code must be inert, unreachable, undocumented, and covered by negative tests.

### R5 — Inline/Local Tool Preservation

- Preserve OMP built-in inline/local tools, including file read/write/edit, bash, search/find, AST/local artifact style tools where applicable.
- Keep a narrow MCP-free local tool registry/discovery layer.
- Add positive smoke tests for local tools after MCP quarantine.

### R6 — GJC Runtime Endpoints

Implement/rebrand internal support for:

- `gjc question`
- `gjc state`
- `gjc team`
- `gjc ultragoal`
- `gjc ralplan`
- `gjc deep-interview`

### R7 — Team Runtime

- Port/adapt team runtime from `../oh-my-codex` as internal `gjc team` runtime.
- Preserve tmux lifecycle, state files, worker mailboxes, task lifecycle, status/resume/shutdown behavior.
- Do not expose extra worker/team support definitions beyond the four visible workflows.

### R8 — Ultragoal/Ralplan/Deep-interview Runtime

- Port/adapt durable Ultragoal artifacts and checkpointing.
- Port/adapt Ralplan consensus planning gates.
- Port/adapt Deep-interview structured question/state artifact behavior.
- Rebrand `omx` references to `gjc` in user-facing runtime and docs.

## Non-goals

- No OMP default skills/agents/commands/rules in shipped visible surface.
- No extra OMX skills/agents beyond the four named definitions.
- No MCP shipped/default behavior.
- No product rename away from `gajae-code` / `gjc`.

## ADR

- **Decision:** Use copy-then-constrain from OMP, grafting/reworking selected OMX workflows and team runtime privately.
- **Drivers:** full functionality, preservation of inline/local tools, strict visible-surface minimization, MCP exclusion, user-requested direct OMP copy.
- **Alternatives considered:** fresh minimal runtime, mostly-intact OMP with hidden features, wholesale oh-my-codex vendoring.
- **Why chosen:** fastest path to full functional port while gates mitigate leakage.
- **Consequences:** requires strong negative tests for MCP and visible surface; rebrand is broad; team/ultragoal are high-risk integration lanes.
- **Follow-ups:** Use `$ultragoal` durable ledger and `$team` parallel execution. `$ralph` only as explicit fallback.

## Available Agent Types Roster

- `explore` — repo mapping and symbol/file lookup.
- `architect` — package/runtime boundary design.
- `executor` — implementation/refactor work.
- `debugger` — failures and migration regressions.
- `test-engineer` — acceptance and regression tests.
- `verifier` — final evidence, negative checks, claim validation.
- `code-reviewer` — final architectural/code review.
- `writer` — docs/rebrand docs pass.
- `dependency-expert` — package retention/replacement decisions if needed.

## Ultragoal + Team Staffing Guidance

Use `$ultragoal` as the leader-owned durable ledger. Use `$team` for coordinated parallel lanes.

Suggested goals:

- G001: Import OMP source and establish baseline.
- G002: Rebrand package/CLI/TUI/docs to gajae-code/gjc.
- G003: Remove OMP defaults and enforce exact visible definition inventory.
- G004: Preserve inline/local tools while excluding MCP.
- G005: Port selected OMX workflow definitions and private support runtime.
- G006: Integrate team runtime.
- G007: Integrate ultragoal/ralplan/deep-interview runtime.
- G008: Full verification, docs, cleanup, code review.

Suggested team launch:

```bash
omx team 5:executor "Implement gajae-code from approved RALPLAN: copy .omx/tmp-oh-my-pi excluding .git, rebrand to gjc, preserve inline/local tools, exclude MCP, expose exactly deep-interview/ralplan/ultragoal/team, and verify build/tests."
```

Reasoning by lane:

- Import/rebrand executor: medium.
- MCP/default-surface executor: high.
- OMX workflow/runtime executor: high.
- Team runtime executor: high.
- Test-engineer/verifier: high.
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
