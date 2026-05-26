# Ultragoal Brief: gajae-code OMP/OMX Runtime

Source artifacts:
- PRD: `.omx/plans/prd-gajae-code-omp-omx-runtime.md`
- Test spec: `.omx/plans/test-spec-gajae-code-omp-omx-runtime.md`
- Ralplan handoff: `.omx/ralplan/`

Create exactly these durable implementation stories:

1. Import OMP source and establish baseline
   - Copy `.omx/tmp-oh-my-pi` into repo root, including dotfiles, excluding nested `.git`.
   - Preserve attribution/license.
   - Initialize git if needed.
   - Capture baseline build/check status.

2. Rebrand package, CLI, TUI, and docs
   - Product becomes `gajae-code`; CLI becomes `gjc`.
   - Rebrand package scopes, help text, TUI labels/status, docs.
   - OMP/oh-my-pi only in attribution/history allowlist.

3. Remove OMP defaults and enforce exact visible definitions
   - Remove default OMP commands/skills/rules/agents.
   - Visible workflow definitions must equal exactly `deep-interview`, `ralplan`, `ultragoal`, `team`.
   - Rewrite/internalize selected definition references to non-selected workflows.

4. Preserve inline/local tools while excluding MCP
   - Preserve local tools such as read/write/edit/bash/search/find/AST/local artifact tools.
   - Quarantine/remove MCP dependencies, imports, commands, config, defaults, registries, discoverable metadata, and docs/help.
   - Add positive local-tool smoke tests and negative MCP tests.

5. Port selected OMX workflow definitions and private support runtime
   - Adapt only `deep-interview`, `ralplan`, `ultragoal`, and `team` definitions.
   - Implement private support for planning/worker/review/cleanup concepts without exposing them as definitions.
   - Rebrand user-facing `omx` references to `gjc`.

6. Integrate team runtime
   - Port/adapt `../oh-my-codex` team runtime as `gjc team`.
   - Preserve tmux lifecycle, state, mailbox, tasks, status/resume/shutdown.
   - Verify no extra worker/team definitions are visible.

7. Integrate ultragoal, ralplan, deep-interview command endpoints
   - Implement `gjc question`, `gjc state`, `gjc ultragoal`, `gjc ralplan`, `gjc deep-interview`.
   - Verify artifact creation, state persistence, and checkpoint paths.

8. Full verification, cleanup, docs, and code review
   - Run TS and Rust build/check/test/lint gates.
   - Run rebrand and MCP negative greps.
   - Run local tool positive smoke tests and workflow e2e smoke tests.
   - Final cleanup and code review must approve.

Global constraints:
- TypeScript-first; Rust only for native/performance-critical parts.
- No MCP shipped/default behavior.
- Exactly four visible definitions.
- Preserve OMP inline/local tools.
- Use Team for parallel execution evidence; Ultragoal remains leader-owned durable ledger.
