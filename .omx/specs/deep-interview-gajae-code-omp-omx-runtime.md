# Deep Interview Spec: gajae-code OMP/OMX Runtime

## Metadata

- Source mode: `$deep-interview`
- Profile: standard
- Context type: brownfield/derivative port
- Final ambiguity: 16% (threshold 20%)
- Context snapshot: `.omx/context/gajae-code-omp-omx-runtime-20260526T064130Z.md`
- Transcript: see `.omx/interviews/`

## Intent

Build `gajae-code` as a properly rebranded, full-functional derivative of `https://github.com/can1357/oh-my-pi` (`omp`) that preserves OMP’s inline/local tool capabilities while replacing the skills/agents surface with only four selected OMX workflow definitions from `../oh-my-codex`: `deep-interview`, `ralplan`, `ultragoal`, and `team`.

## Desired Outcome

A TypeScript-first repository with Rust for performance-critical runtime parts where:

1. The CLI entrypoint and user-facing semantics are rebranded from OMP/oh-my-pi to `gajae-code` / `gjc`.
2. The TUI is also rebranded, including visible labels, commands, package naming, help text, and docs, except for attribution/history where appropriate.
3. OMP default skills and agents are removed.
4. OMP MCP behavior is excluded; only inline/local tools are preserved.
5. The four selected OMX workflows work end-to-end using internalized or rewritten support code as needed.

## In Scope

- Fork/import OMP structure as the base runtime where useful.
- Rebrand package names, CLI command, help text, TUI copy, docs, and user-visible semantics to `gajae-code`/`gjc`.
- Preserve OMP inline/local tools (for example file/edit/bash/search-style agent tools) after rebrand.
- Remove OMP default skills and agents.
- Exclude MCP subsystem/defaults; no MCP tools should ship as part of this first target.
- Incorporate exactly these four visible workflow/agent definitions from `../oh-my-codex`:
  - `deep-interview`
  - `ralplan`
  - `ultragoal`
  - `team`
- Include/rewrite internal support needed by those four workflows, such as equivalents for:
  - `gjc question`
  - `gjc state`
  - `gjc team`
  - `gjc ultragoal` / `gjc ralplan` / `gjc deep-interview` routing
  - team runtime support from `oh-my-codex`
- Use TypeScript for primary implementation and Rust only where performance-critical.

## Out of Scope / Non-goals

- Do not keep OMP default skills.
- Do not keep OMP default agents.
- Do not expose extra OMX skills/agents beyond the four named definitions.
- Do not preserve MCP subsystem/default MCP tooling in the first target.
- Do not leave user-facing `oh-my-pi`, `omp`, or OMP semantics in CLI/TUI/docs except attribution/history.
- Do not implement this inside deep-interview; hand off to planning/execution workflow.

## Decision Boundaries

OMX/gajae-code implementation may decide without further confirmation:

- Whether to internalize support dependencies as private runtime modules or rewrite the four workflow definitions to be standalone, combining both approaches as appropriate.
- Which OMP packages/modules are retained, deleted, or simplified, as long as inline/local tools remain functional and MCPs are excluded.
- Which Rust crates remain or are added for performance-critical paths, provided TypeScript remains the main implementation language.
- How to structure `gjc` command endpoints and inline support tools to replace required `omx question`, `omx state`, `omx team`, etc.

Escalate before:

- Exposing any additional skill/agent definition beyond the four named items.
- Reintroducing MCP behavior or default MCP tools.
- Dropping an OMP inline/local tool category instead of preserving/rebranding it.
- Changing the product name/CLI command away from `gajae-code` / `gjc`.

## Constraints

- TypeScript-first codebase.
- Rust reserved for performance-critical parts.
- Full-functional first pass, not merely scaffold or planning-only.
- Visible skill/agent definition inventory must be exactly four: `deep-interview`, `ralplan`, `ultragoal`, `team`.
- OMP inline/local tools must be preserved.
- MCP must be excluded.

## Testable Acceptance Criteria

- `gjc` CLI works and exposes required endpoints/routing for question, state, team, ultragoal, ralplan, and deep-interview flows.
- TUI is rebranded: user-visible labels, commands, package names, help text, and docs no longer present as oh-my-pi/omp except attribution/history.
- Installed/visible skills/agents contain only `deep-interview`, `ralplan`, `ultragoal`, and `team`.
- OMP inline/local tools remain usable after rebrand.
- MCP code/defaults are absent or disabled such that MCP tools are not part of shipped/default behavior.
- TypeScript build/tests pass for retained/reworked runtime.
- Rust build/tests pass for performance-critical crates retained or introduced.

## Assumptions Exposed + Resolutions

- Assumption: “Only four definitions” might break workflows that depend on support skills/agents.
  - Resolution: combine internalized dependencies and standalone rewrites; support code may exist privately but not as visible extra skills/agents.
- Assumption: “Remove tools/MCPs” meant all tools.
  - Resolution: preserve OMP inline/local tools; exclude MCP only.
- Assumption: `omx` support commands can remain as-is.
  - Resolution: implement `gjc` endpoints/inline equivalents for question/state/team/etc.

## Brownfield Evidence vs Inference

Evidence from local inspection:

- Target directory is effectively empty except `.omx`, so implementation will likely import/fork from inspected sources.
- OMP source was cloned into `.omx/tmp-oh-my-pi`; it is a Bun monorepo with packages including coding-agent, agent core, AI, natives, TUI, stats, and swarm extension.
- OMP has `.omp/commands`, `.omp/skills`, and `.omp/rules` defaults that must not survive as user-visible defaults.
- OMP coding-agent has MCP/discoverable-tool integration code; this must be removed/disabled for the gajae-code target.
- `../oh-my-codex` contains selected skill definitions and team runtime/CLI code to adapt.

Inference for planning:

- A clean port likely needs an architecture pass to separate OMP inline tools from MCP integration and to design `gjc` equivalents for OMX runtime commands.
- `team` is the highest-risk workflow because it often has runtime/protocol dependencies; it should be planned and tested early.

## Recommended Handoff

Use `$ralplan` next with this spec as the requirements source of truth:

```text
$plan --consensus --direct .omx/specs/deep-interview-gajae-code-omp-omx-runtime.md
```

Planning should produce PRD and test-spec artifacts before implementation. After planning, use `$ultragoal` for durable goal tracking, optionally with `$team` for parallel implementation lanes.
