import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentTool } from "@gajae-code/agent-core";
import {
	assertDeepInterviewMutationRawPathsAllowed,
	DEEP_INTERVIEW_MUTATION_BLOCK_MESSAGE,
	getDeepInterviewMutationDecision,
} from "@gajae-code/coding-agent/skill-state/deep-interview-mutation-guard";
import { ToolError } from "@gajae-code/coding-agent/tools/tool-errors";

const tempRoots: string[] = [];

function encodePathSegment(value: string): string {
	return encodeURIComponent(value).replaceAll(".", "%2E");
}

async function makeTempRoot(): Promise<string> {
	const root = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-deep-interview-guard-"));
	tempRoots.push(root);
	return root;
}

async function writeActiveDeepInterview(cwd: string, sessionId = "session-a", phase = "interviewing"): Promise<void> {
	const now = new Date().toISOString();
	const sessionDir = path.join(cwd, ".gjc", "state", "sessions", encodePathSegment(sessionId));
	await fs.mkdir(sessionDir, { recursive: true });
	const activeState = {
		version: 1,
		active: true,
		skill: "deep-interview",
		phase,
		updated_at: now,
		active_skills: [
			{
				skill: "deep-interview",
				phase,
				active: true,
				updated_at: now,
				session_id: sessionId,
			},
		],
	};
	await Bun.write(path.join(sessionDir, "skill-active-state.json"), `${JSON.stringify(activeState, null, 2)}\n`);
	await Bun.write(
		path.join(sessionDir, "deep-interview-state.json"),
		`${JSON.stringify({ active: true, current_phase: phase, session_id: sessionId }, null, 2)}\n`,
	);
}

function tool(name: string, extra: Record<string, unknown> = {}): AgentTool {
	return {
		name,
		label: name,
		description: name,
		parameters: {} as never,
		execute: async () => ({ content: [{ type: "text" as const, text: "ok" }] }),
		...extra,
	} as AgentTool;
}

afterEach(async () => {
	await Promise.all(tempRoots.splice(0).map(root => fs.rm(root, { recursive: true, force: true })));
});

describe("deep-interview mutation guard", () => {
	it("allows product write/edit/ast_edit targets while deep-interview is active", async () => {
		const cwd = await makeTempRoot();
		await writeActiveDeepInterview(cwd);

		for (const [name, args] of [
			["write", { path: "packages/coding-agent/src/foo.ts", content: "x" }],
			["edit", { path: "src/foo.ts", edits: [{ old_text: "a", new_text: "b" }] }],
			["ast_edit", { paths: ["packages/**"], ops: [{ pat: "foo", out: "bar" }] }],
		] as const) {
			const decision = await getDeepInterviewMutationDecision({
				cwd,
				sessionId: "session-a",
				tool: tool(name),
				args,
			});
			expect(decision.blocked).toBe(false);
		}
	});

	it("blocks direct .gjc targets while deep-interview is active", async () => {
		const cwd = await makeTempRoot();
		await writeActiveDeepInterview(cwd);

		const blockedCases: Array<[string, AgentTool, unknown]> = [
			["write spec", tool("write"), { path: ".gjc/specs/deep-interview-x.md", content: "x" }],
			["write state", tool("write"), { path: ".gjc/state/deep-interview-x.json", content: "{}" }],
			[
				"edit spec",
				tool("edit"),
				{ path: ".gjc/specs/deep-interview-x.md", edits: [{ old_text: "a", new_text: "b" }] },
			],
			[
				"apply_patch spec",
				tool("edit", { mode: "apply_patch", customWireName: "apply_patch" }),
				{
					input: "*** Begin Patch\n*** Update File: .gjc/specs/deep-interview-x.md\n@@\n-a\n+b\n*** End Patch\n",
				},
			],
			[
				"vim spec",
				tool("edit", { mode: "vim" }),
				{ file: ".gjc/specs/deep-interview-x.md", steps: [{ kbd: [":edit .gjc/state/note.md<CR>"] }] },
			],
			["ast_edit state", tool("ast_edit"), { paths: [".gjc/state/**/*.md"], ops: [{ pat: "foo", out: "bar" }] }],
		];

		for (const [, targetTool, args] of blockedCases) {
			const decision = await getDeepInterviewMutationDecision({
				cwd,
				sessionId: "session-a",
				tool: targetTool,
				args,
			});
			expect(decision.blocked).toBe(true);
			expect(decision.message).toBe(DEEP_INTERVIEW_MUTATION_BLOCK_MESSAGE);
		}
	});

	it("allows non-.gjc paths and blocks .gjc-prefixed target sets", async () => {
		const cwd = await makeTempRoot();
		await writeActiveDeepInterview(cwd);

		for (const rawPath of [
			"../outside.md",
			path.join(os.tmpdir(), "outside-gjc-plan.md"),
			"agent://123",
			"product/archive.zip:product.ts",
			"data.sqlite:rows:1",
		]) {
			const decision = await getDeepInterviewMutationDecision({
				cwd,
				sessionId: "session-a",
				tool: tool("write"),
				args: { path: rawPath, content: "x" },
			});
			expect(decision.blocked).toBe(false);
		}

		for (const rawPath of [".gjc/specs-evil/plan.md", ".gjc/stateful/data.json"]) {
			const decision = await getDeepInterviewMutationDecision({
				cwd,
				sessionId: "session-a",
				tool: tool("write"),
				args: { path: rawPath, content: "x" },
			});
			expect(decision.blocked).toBe(true);
		}

		const mixed = await getDeepInterviewMutationDecision({
			cwd,
			sessionId: "session-a",
			tool: tool("ast_edit"),
			args: { paths: [".gjc/specs/**/*.md", "packages/**"], ops: [{ pat: "foo", out: "bar" }] },
		});
		expect(mixed.blocked).toBe(true);
	});

	it("blocks vim file-switches into .gjc", async () => {
		const cwd = await makeTempRoot();
		await writeActiveDeepInterview(cwd);

		const decision = await getDeepInterviewMutationDecision({
			cwd,
			sessionId: "session-a",
			tool: tool("edit", { mode: "vim" }),
			args: {
				file: "packages/coding-agent/src/product.ts",
				steps: [{ kbd: [":edit .gjc/specs/deep-interview-x.md<CR>", "iunsafe"] }],
			},
		});

		expect(decision.blocked).toBe(true);
		expect(decision.message).toBe(DEEP_INTERVIEW_MUTATION_BLOCK_MESSAGE);
	});

	it("does not block after deep-interview reaches a terminal phase", async () => {
		const cwd = await makeTempRoot();
		await writeActiveDeepInterview(cwd, "session-a", "complete");

		const decision = await getDeepInterviewMutationDecision({
			cwd,
			sessionId: "session-a",
			tool: tool("write"),
			args: { path: "src/product.ts", content: "x" },
		});
		expect(decision.blocked).toBe(false);
	});

	it("guards deferred ast_edit apply .gjc targets unless force override is explicit", async () => {
		const cwd = await makeTempRoot();
		await writeActiveDeepInterview(cwd);

		await expect(
			assertDeepInterviewMutationRawPathsAllowed({
				cwd,
				sessionId: "session-a",
				rawPaths: [".gjc/specs/deep-interview-x.md"],
			}),
		).rejects.toBeInstanceOf(ToolError);
		await expect(
			assertDeepInterviewMutationRawPathsAllowed({
				cwd,
				sessionId: "session-a",
				rawPaths: [".gjc/specs/deep-interview-x.md"],
				forceOverride: true,
			}),
		).resolves.toBeUndefined();
	});
});
