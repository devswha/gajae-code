import { afterEach, describe, expect, it } from "bun:test";
import { AsyncJobManager } from "../../src/async";
import { Settings } from "../../src/config/settings";
import { SubagentTool, type ToolSession } from "../../src/tools";

function createSession(agentId = "0-Main"): ToolSession {
	return {
		cwd: "/tmp",
		hasUI: false,
		settings: Settings.isolated({}),
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		getAgentId: () => agentId,
	} as ToolSession;
}

function createManager(): AsyncJobManager {
	const manager = new AsyncJobManager({
		onJobComplete: async () => {},
		retentionMs: 10_000,
	});
	AsyncJobManager.setInstance(manager);
	return manager;
}

function getText(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content.find(part => part.type === "text")?.text ?? "";
}

describe("SubagentTool", () => {
	afterEach(() => {
		AsyncJobManager.resetForTests();
	});

	it("lists only visible task jobs with subagent metadata", async () => {
		const manager = createManager();
		const tool = new SubagentTool(createSession("0-Main"));
		manager.register(
			"task",
			"visible subagent",
			async () => {
				await Bun.sleep(50);
				return "visible done";
			},
			{
				id: "job-visible",
				ownerId: "0-Main",
				metadata: {
					subagent: {
						id: "0-Visible",
						agent: "executor",
						agentSource: "bundled",
						description: "visible task",
						assignment: "Do visible work.",
					},
				},
			},
		);
		manager.register("task", "hidden subagent", async () => "hidden done", {
			id: "job-hidden",
			ownerId: "1-Other",
			metadata: {
				subagent: {
					id: "1-Hidden",
					agent: "executor",
					agentSource: "bundled",
				},
			},
		});
		manager.register("bash", "generic job", async () => "generic done", { id: "job-bash", ownerId: "0-Main" });

		const result = await tool.execute("subagent-list", { action: "list" });

		expect(result.details?.subagents.map(subagent => subagent.id)).toEqual(["0-Visible"]);
		expect(getText(result)).toContain("0-Visible");
		expect(getText(result)).not.toContain("job-bash");
		await manager.dispose({ timeoutMs: 100 });
	});

	it("await retrieves completed subagent results and acknowledges delivery", async () => {
		const manager = createManager();
		const tool = new SubagentTool(createSession());
		const jobId = manager.register("task", "finished subagent", async () => "subagent result", {
			id: "job-done",
			ownerId: "0-Main",
			metadata: {
				subagent: {
					id: "0-Done",
					agent: "executor",
					agentSource: "project",
					description: "done task",
					assignment: "Return a result.",
				},
			},
		});
		await manager.getJob(jobId)?.promise;

		const result = await tool.execute("subagent-await", { action: "await", ids: ["0-Done"], timeout_ms: 100 });

		expect(result.details?.subagents[0]?.status).toBe("completed");
		expect(result.details?.subagents[0]?.resultText).toContain("subagent result");
		expect(getText(result)).toContain("subagent result");
		expect(manager.hasPendingDeliveries()).toBe(false);
		await manager.dispose({ timeoutMs: 100 });
	});

	it("await timeout is non-terminal and guides continued observation instead of shutdown", async () => {
		const manager = createManager();
		const tool = new SubagentTool(createSession());
		manager.register(
			"task",
			"slow subagent",
			async () => {
				await Bun.sleep(60);
				return "slow result";
			},
			{
				id: "job-slow",
				ownerId: "0-Main",
				metadata: {
					subagent: {
						id: "0-Slow",
						agent: "executor",
						agentSource: "bundled",
						description: "slow task",
						assignment: "Keep working slowly.",
					},
				},
			},
		);

		const result = await tool.execute("subagent-await-timeout", {
			action: "await",
			ids: ["0-Slow"],
			timeout_ms: 1,
		});
		const guidance = result.details?.subagents[0]?.guidance ?? "";

		expect(result.details?.subagents[0]?.status).toBe("running");
		expect(guidance).toContain("Still running");
		expect(guidance).toContain("not a failure");
		expect(guidance).toContain("cancel only if no longer needed");
		expect(guidance).not.toContain("steer");
		expect(guidance).not.toContain("shutdown");
		await manager.dispose({ timeoutMs: 100 });
	});

	it("cancel stops a selected running subagent by subagent id", async () => {
		const manager = createManager();
		const tool = new SubagentTool(createSession());
		manager.register(
			"task",
			"cancel subagent",
			async ({ signal }) => {
				while (!signal.aborted) await Bun.sleep(5);
				throw new Error("cancelled");
			},
			{
				id: "job-cancel",
				ownerId: "0-Main",
				metadata: {
					subagent: {
						id: "0-Cancel",
						agent: "executor",
						agentSource: "bundled",
					},
				},
			},
		);

		const result = await tool.execute("subagent-cancel", { action: "cancel", ids: ["0-Cancel"] });

		expect(result.details?.subagents[0]?.status).toBe("cancelled");
		expect(manager.getJob("job-cancel")?.status).toBe("cancelled");
		await manager.dispose({ timeoutMs: 100 });
	});
});
