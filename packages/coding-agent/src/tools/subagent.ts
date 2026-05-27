import type { AgentTool, AgentToolContext, AgentToolResult, AgentToolUpdateCallback } from "@gajae-code/agent-core";
import { prompt } from "@gajae-code/utils";
import * as z from "zod/v4";
import { type AsyncJob, AsyncJobManager } from "../async";
import subagentDescription from "../prompts/tools/subagent.md" with { type: "text" };
import type { AgentSource } from "../task/types";
import { Ellipsis, truncateToWidth } from "../tui";
import type { ToolSession } from "./index";
import { replaceTabs } from "./render-utils";
import { ToolError } from "./tool-errors";

const DEFAULT_AWAIT_TIMEOUT_MS = 30_000;
const MAX_AWAIT_TIMEOUT_MS = 60 * 60 * 1000;
const DEFAULT_LIST_LIMIT = 10;
const MAX_LIST_LIMIT = 50;
const TEXT_PREVIEW_WIDTH = 12_000;

const subagentSchema = z.object({
	action: z.enum(["list", "inspect", "await", "cancel"]).describe("subagent control action"),
	ids: z.array(z.string()).optional().describe("subagent ids or backing job ids"),
	timeout_ms: z.number().min(0).max(MAX_AWAIT_TIMEOUT_MS).optional().describe("await timeout in milliseconds"),
	limit: z.number().min(1).max(MAX_LIST_LIMIT).optional().describe("maximum subagents to return"),
});

type SubagentParams = z.infer<typeof subagentSchema>;
type SubagentStatus = "running" | "completed" | "failed" | "cancelled" | "not_found" | "already_completed";

export interface SubagentSnapshot {
	id: string;
	jobId: string;
	status: SubagentStatus;
	label: string;
	agent: string;
	agentSource: AgentSource;
	description?: string;
	assignment?: string;
	durationMs: number;
	resultText?: string;
	errorText?: string;
	guidance?: string;
}

export interface SubagentToolDetails {
	subagents: SubagentSnapshot[];
}

export class SubagentTool implements AgentTool<typeof subagentSchema, SubagentToolDetails> {
	readonly name = "subagent";
	readonly label = "Subagent";
	readonly summary = "Manage detached task subagents";
	readonly description: string;
	readonly parameters = subagentSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(subagentDescription);
	}

	async execute(
		_toolCallId: string,
		params: SubagentParams,
		signal?: AbortSignal,
		onUpdate?: AgentToolUpdateCallback<SubagentToolDetails>,
		_context?: AgentToolContext,
	): Promise<AgentToolResult<SubagentToolDetails>> {
		const manager = AsyncJobManager.instance();
		if (!manager) {
			return {
				content: [{ type: "text", text: "No subagent manager is available in this session." }],
				details: { subagents: [] },
			};
		}

		const ownerId = this.session.getAgentId?.() ?? undefined;
		const ownerFilter = ownerId ? { ownerId } : undefined;
		const limit = Math.min(MAX_LIST_LIMIT, Math.max(1, Math.floor(params.limit ?? DEFAULT_LIST_LIMIT)));

		if (params.action === "list") {
			const jobs = this.#listSubagentJobs(manager, ownerFilter, limit);
			return this.#buildResult(manager, jobs, { title: "Subagents" });
		}

		if (params.action === "inspect") {
			const jobs = params.ids?.length
				? this.#visibleJobsByIds(manager, params.ids, ownerId)
				: manager.getRunningJobs(ownerFilter).filter(isSubagentJob);
			return this.#buildResult(manager, jobs, {
				title: "Subagent inspection",
				notFoundIds: this.#notFoundIds(manager, params.ids ?? [], ownerId),
			});
		}

		if (params.action === "cancel") {
			const ids = params.ids ?? [];
			if (ids.length === 0) {
				throw new ToolError("`cancel` requires at least one subagent id.");
			}
			const snapshots: SubagentSnapshot[] = [];
			for (const id of ids) {
				const job = this.#findVisibleJob(manager, id, ownerId);
				if (!job) {
					snapshots.push(this.#missingSnapshot(id, "not_found", "No visible detached subagent matches this id."));
					continue;
				}
				if (job.status !== "running") {
					snapshots.push({ ...this.#snapshot(job), status: "already_completed" });
					continue;
				}
				manager.cancel(job.id, ownerFilter);
				snapshots.push(this.#snapshot(manager.getJob(job.id) ?? job));
			}
			return this.#buildSnapshotResult(snapshots, "Subagent cancellation");
		}

		return this.#awaitSubagents(manager, params, ownerId, ownerFilter, signal, onUpdate);
	}

	async #awaitSubagents(
		manager: AsyncJobManager,
		params: SubagentParams,
		ownerId: string | undefined,
		ownerFilter: { ownerId: string } | undefined,
		signal: AbortSignal | undefined,
		onUpdate: AgentToolUpdateCallback<SubagentToolDetails> | undefined,
	): Promise<AgentToolResult<SubagentToolDetails>> {
		const jobs = params.ids?.length
			? this.#visibleJobsByIds(manager, params.ids, ownerId)
			: manager.getRunningJobs(ownerFilter).filter(isSubagentJob);
		const notFoundIds = this.#notFoundIds(manager, params.ids ?? [], ownerId);
		if (jobs.length === 0) {
			const missing = notFoundIds.map(id =>
				this.#missingSnapshot(id, "not_found", "No visible detached subagent matches this id."),
			);
			return this.#buildSnapshotResult(missing, "Subagent await");
		}

		const runningJobs = jobs.filter(job => job.status === "running");
		if (runningJobs.length === 0) {
			return this.#buildResult(manager, jobs, { title: "Subagent await", notFoundIds });
		}

		const timeoutMs = Math.min(
			MAX_AWAIT_TIMEOUT_MS,
			Math.max(0, Math.floor(params.timeout_ms ?? DEFAULT_AWAIT_TIMEOUT_MS)),
		);
		const watchedJobIds = runningJobs.map(job => job.id);
		manager.watchJobs(watchedJobIds);
		const progressTimer = onUpdate
			? setInterval(() => {
					onUpdate(this.#progressResult(manager, jobs));
				}, 500)
			: undefined;
		onUpdate?.(this.#progressResult(manager, jobs));

		let timedOut = false;
		try {
			const completionPromise = Promise.all(runningJobs.map(job => job.promise));
			const timeoutPromise = Bun.sleep(timeoutMs).then(() => {
				timedOut = true;
			});
			if (signal) {
				const { promise: abortPromise, resolve: abortResolve } = Promise.withResolvers<void>();
				const onAbort = () => abortResolve();
				signal.addEventListener("abort", onAbort, { once: true });
				try {
					await Promise.race([completionPromise, timeoutPromise, abortPromise]);
				} finally {
					signal.removeEventListener("abort", onAbort);
				}
			} else {
				await Promise.race([completionPromise, timeoutPromise]);
			}
		} finally {
			manager.unwatchJobs(watchedJobIds);
			if (progressTimer) clearInterval(progressTimer);
		}

		return this.#buildResult(manager, jobs, { title: "Subagent await", notFoundIds, timedOut });
	}

	#listSubagentJobs(
		manager: AsyncJobManager,
		ownerFilter: { ownerId: string } | undefined,
		limit: number,
	): AsyncJob[] {
		const running = manager.getRunningJobs(ownerFilter).filter(isSubagentJob);
		const recent = manager.getRecentJobs(limit, ownerFilter).filter(isSubagentJob);
		const jobs = [...running, ...recent];
		return this.#dedupeJobs(jobs).slice(0, limit);
	}

	#visibleJobsByIds(manager: AsyncJobManager, ids: string[], ownerId: string | undefined): AsyncJob[] {
		const jobs: AsyncJob[] = [];
		for (const id of ids) {
			const job = this.#findVisibleJob(manager, id, ownerId);
			if (job) jobs.push(job);
		}
		return this.#dedupeJobs(jobs);
	}

	#findVisibleJob(manager: AsyncJobManager, id: string, ownerId: string | undefined): AsyncJob | undefined {
		const trimmedId = id.trim();
		if (!trimmedId) return undefined;
		const direct = manager.getJob(trimmedId);
		if (direct && isSubagentJob(direct) && (!ownerId || direct.ownerId === ownerId)) return direct;
		return manager
			.getAllJobs(ownerId ? { ownerId } : undefined)
			.find(job => isSubagentJob(job) && job.metadata?.subagent?.id === trimmedId);
	}

	#notFoundIds(manager: AsyncJobManager, ids: string[], ownerId: string | undefined): string[] {
		return ids.filter(id => !this.#findVisibleJob(manager, id, ownerId));
	}

	#dedupeJobs(jobs: AsyncJob[]): AsyncJob[] {
		const seen = new Set<string>();
		return jobs.filter(job => {
			if (seen.has(job.id)) return false;
			seen.add(job.id);
			return true;
		});
	}

	#progressResult(manager: AsyncJobManager, jobs: AsyncJob[]): AgentToolResult<SubagentToolDetails> {
		return {
			content: [{ type: "text", text: "" }],
			details: { subagents: this.#snapshots(manager, jobs) },
		};
	}

	#buildResult(
		manager: AsyncJobManager,
		jobs: AsyncJob[],
		options: { title: string; notFoundIds?: string[]; timedOut?: boolean },
	): AgentToolResult<SubagentToolDetails> {
		const snapshots = this.#snapshots(manager, jobs, options.timedOut);
		for (const id of options.notFoundIds ?? []) {
			snapshots.push(this.#missingSnapshot(id, "not_found", "No visible detached subagent matches this id."));
		}
		manager.acknowledgeDeliveries(
			snapshots.filter(s => s.status !== "running" && s.status !== "not_found").map(s => s.jobId),
		);
		return this.#buildSnapshotResult(snapshots, options.title);
	}

	#buildSnapshotResult(snapshots: SubagentSnapshot[], title: string): AgentToolResult<SubagentToolDetails> {
		const lines = [`## ${title} (${snapshots.length})`, ""];
		for (const snapshot of snapshots) {
			lines.push(`### ${snapshot.id} — ${snapshot.status}`);
			if (snapshot.jobId !== snapshot.id) lines.push(`Job: ${snapshot.jobId}`);
			if (snapshot.agent) lines.push(`Agent: ${snapshot.agent} (${snapshot.agentSource})`);
			if (snapshot.description) lines.push(`Description: ${snapshot.description}`);
			if (snapshot.assignment) lines.push("Assignment:", "```", snapshot.assignment, "```");
			if (snapshot.resultText) lines.push("Result:", "```", snapshot.resultText, "```");
			if (snapshot.errorText) lines.push("Error:", "```", snapshot.errorText, "```");
			if (snapshot.guidance) lines.push(`Guidance: ${snapshot.guidance}`);
			lines.push("");
		}
		return {
			content: [{ type: "text", text: lines.join("\n").trimEnd() }],
			details: { subagents: snapshots },
		};
	}

	#snapshots(manager: AsyncJobManager, jobs: AsyncJob[], timedOut = false): SubagentSnapshot[] {
		return jobs.map(job => this.#snapshot(manager.getJob(job.id) ?? job, timedOut));
	}

	#snapshot(job: AsyncJob, timedOut = false): SubagentSnapshot {
		const subagent = job.metadata?.subagent;
		const runningTimeoutGuidance =
			timedOut && job.status === "running"
				? "Still running after the await timeout; this is not a failure. Inspect progress, continue independent work, and cancel only if no longer needed or unrecoverably wrong."
				: undefined;
		return {
			id: subagent?.id ?? job.id,
			jobId: job.id,
			status: job.status,
			label: sanitizeText(job.label),
			agent: subagent?.agent ?? "unknown",
			agentSource: subagent?.agentSource ?? "bundled",
			durationMs: Math.max(0, Date.now() - job.startTime),
			...(subagent?.description ? { description: sanitizeText(subagent.description) } : {}),
			...(subagent?.assignment ? { assignment: sanitizeText(subagent.assignment) } : {}),
			...(job.resultText ? { resultText: sanitizeText(job.resultText) } : {}),
			...(job.errorText ? { errorText: sanitizeText(job.errorText) } : {}),
			...(runningTimeoutGuidance ? { guidance: runningTimeoutGuidance } : {}),
		};
	}

	#missingSnapshot(id: string, status: "not_found", guidance: string): SubagentSnapshot {
		return {
			id,
			jobId: id,
			status,
			label: "missing",
			agent: "unknown",
			agentSource: "bundled",
			durationMs: 0,
			guidance,
		};
	}
}

function isSubagentJob(job: AsyncJob): boolean {
	return job.type === "task" && job.metadata?.subagent !== undefined;
}

function sanitizeText(text: string): string {
	return truncateToWidth(replaceTabs(text), TEXT_PREVIEW_WIDTH, Ellipsis.Unicode);
}
