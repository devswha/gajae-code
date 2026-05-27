# Gajae-Code

Gajae-Code (`gjc`) is a private MVP coding-agent CLI with a deliberately small workflow surface: four source-bundled workflow skills plus four source-bundled role agents.

It keeps the core coding-agent strengths—fast file/search tools, LSP-aware edits, native helpers, model-provider flexibility, and a terminal TUI—while removing broad inherited workflow sprawl from the default surface.

The default dark TUI identity is the GJC red-claw theme, with brand colors kept separate from warning, error, and diff-removal semantics.

## Current MVP contract

Default public workflow skills are exactly:

| Skill | Purpose | State/artifacts |
| --- | --- | --- |
| `deep-interview` | Socratic requirements interview for ambiguous work. | `.gjc/specs/` |
| `ralplan` | Consensus planning and approval before mutation. | `.gjc/plans/` |
| `ultragoal` | Durable goal decomposition and checkpoint ledger. | `.gjc/ultragoal/` |
| `team` | Tmux-backed parallel execution after approval. | `.gjc/state/team/` |

Default role agents are exactly `executor`, `architect`, `planner`, and `critic`. They are embedded from source prompt files and exposed through task delegation; projects may still provide local `.gjc/agents` overrides when needed.

Default source definitions live under:

```text
packages/coding-agent/src/defaults/gjc/skills/<name>/SKILL.md
packages/coding-agent/src/prompts/agents/<role>.md
```

GJC default skill loading always includes the source-bundled workflow skills, even when no project `.gjc` directory exists. Use `.gjc` for project-local runtime state, specs, plans, goals, team coordination, and optional local overrides.

## Install for local development

```sh
bun install
bun run install:defaults
```

`install:defaults` installs the four bundled GJC workflow skills into the active GJC config directory without overwriting local edits unless forced by the setup command. Bare `gjc setup` does the same normal defaults install; hooks, provider, Python, and speech-to-text setup are optional explicit components.

## Run

```sh
bun packages/coding-agent/src/cli.ts --help
bun packages/coding-agent/src/cli.ts setup --check --json
bun packages/coding-agent/src/cli.ts setup --json
```

When installed globally, use `gjc`:

```sh
gjc --help
gjc setup --check --json
gjc setup --json
```

## Workflow usage

Start with the lightest path that fits the work:

1. Direct edit for clear, low-risk implementation tasks.
2. `deep-interview` for unclear requirements.
3. `ralplan` for architectural/test planning and approval.
4. `ultragoal` for durable multi-goal execution tracking.
5. `team` for approved parallel execution.

Planning workflows must stop at `pending approval` until execution is explicitly approved.

## Provider base URLs

Built-in provider base URL environment variables override the host only; they do not change the selected API transport.

For example, the built-in OpenAI provider uses the Responses API, so:

```sh
OPENAI_BASE_URL=https://proxy.example.com/v1
```

still calls:

```text
https://proxy.example.com/v1/responses
```

If your proxy only supports OpenAI-compatible Chat Completions, configure a custom provider in `models.yml`:

```yaml
providers:
  openai-compatible:
    baseUrl: https://proxy.example.com/v1
    apiKey: OPENAI_API_KEY
    api: openai-completions
    models:
      - id: gpt-4o
        name: GPT-4o via proxy
        api: openai-completions
```

## Development checks

For workflow-definition or rebrand-surface changes, run:

```sh
bun scripts/check-visible-definitions.ts
bun scripts/verify-g002-gates.ts
bun scripts/rebrand-inventory.ts --strict
bun test packages/coding-agent/test/default-gjc-definitions.test.ts
```

For TypeScript/lint verification, run:

```sh
bun run check:ts
```

Do not use `tsc` or `npx tsc` directly.

## Repository layout

| Path | Purpose |
| --- | --- |
| `packages/coding-agent/` | Main `gjc` CLI and TUI product surface |
| `packages/ai/` | Multi-provider model client and stream adapters |
| `packages/agent/` | Agent runtime primitives |
| `packages/tui/` | Terminal UI rendering |
| `packages/natives/` | Native bindings package |
| `packages/stats/` | Local stats dashboard |
| `packages/utils/` | Shared utilities |
| `crates/pi-natives/` | Rust native helpers |
| `.gjc/` | GJC-visible skills, agents, and workflow state |

## CI/CD

The private GitHub repository is configured with:

- default branch: `main`
- development branch: `dev`
- CI workflow on `main`, `dev`, and pull requests
- tag-based release jobs for binaries and npm publishing
- `main` branch protection requiring `check` and `test`

## Attribution

Gajae-Code is a forked/rebranded derivative that preserves upstream attribution where required while presenting GJC commands, package names, and runtime paths in the active product surface.
