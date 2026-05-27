import { existsSync } from "fs";
import { readFile } from "fs/promises";

export interface TaskApprovalRecord {
	task_id: string;
	required: boolean;
	status: "pending" | "approved" | "rejected";
	reviewer: string;
	decision_reason: string;
	decided_at: string;
}

interface ApprovalDeps {
	teamName: string;
	cwd: string;
	approvalPath: (teamName: string, taskId: string, cwd: string) => string;
	writeAtomic: (filePath: string, data: string) => Promise<void>;
	appendTeamEvent: (
		teamName: string,
		event: {
			type: "approval_decision";
			worker: string;
			task_id?: string;
			message_id?: string | null;
			reason?: string;
		},
		cwd: string,
	) => Promise<unknown>;
}

export async function writeTaskApproval(approval: TaskApprovalRecord, deps: ApprovalDeps): Promise<void> {
	const p = deps.approvalPath(deps.teamName, approval.task_id, deps.cwd);
	await deps.writeAtomic(p, JSON.stringify(approval, null, 2));
	await deps.appendTeamEvent(
		deps.teamName,
		{
			type: "approval_decision",
			worker: approval.reviewer,
			task_id: approval.task_id,
			message_id: null,
			reason: `${approval.status}:${approval.decision_reason}`,
		},
		deps.cwd,
	);
}

export async function readTaskApproval(taskId: string, deps: ApprovalDeps): Promise<TaskApprovalRecord | null> {
	const p = deps.approvalPath(deps.teamName, taskId, deps.cwd);
	if (!existsSync(p)) return null;

	try {
		const raw = await readFile(p, "utf-8");
		const parsed = JSON.parse(raw) as TaskApprovalRecord;
		if (parsed.task_id !== taskId) return null;
		if (!["pending", "approved", "rejected"].includes(parsed.status)) return null;
		return parsed;
	} catch {
		return null;
	}
}
