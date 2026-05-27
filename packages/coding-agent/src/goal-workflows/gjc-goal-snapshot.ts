import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export type GJCGoalSnapshotStatus = "active" | "complete" | "cancelled" | "failed" | "unknown";

export interface GJCGoalSnapshot {
	available: boolean;
	objective?: string;
	status?: GJCGoalSnapshotStatus;
	tokenBudget?: number;
	remainingTokens?: number | null;
	unavailableReason?: "db_schema_context_error" | "tool_error";
	errorMessage?: string;
	raw: unknown;
}

export interface GJCGoalReconciliation {
	ok: boolean;
	snapshot: GJCGoalSnapshot;
	warnings: string[];
	errors: string[];
}

export interface ReconcileGJCGoalOptions {
	expectedObjective: string;
	acceptedObjectives?: readonly string[];
	allowedStatuses?: readonly GJCGoalSnapshotStatus[];
	requireSnapshot?: boolean;
	requireComplete?: boolean;
}

export class GJCGoalSnapshotError extends Error {}

function safeObject(value: unknown): Record<string, unknown> {
	return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function safeString(value: unknown): string {
	return typeof value === "string" ? value.trim() : "";
}

function safeNumber(value: unknown): number | undefined {
	return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function normalizeStatus(value: unknown): GJCGoalSnapshotStatus {
	const status = safeString(value).toLowerCase();
	if (status === "complete" || status === "completed" || status === "done") return "complete";
	if (status === "cancelled" || status === "canceled") return "cancelled";
	if (status === "failed" || status === "failure") return "failed";
	if (status === "active" || status === "in_progress" || status === "pending" || status === "running") return "active";
	return "unknown";
}

function normalizeObjective(value: string): string {
	return value.replace(/\s+/g, " ").trim();
}

function extractErrorMessage(value: unknown): string {
	const root = safeObject(value);
	const candidates = [
		root.error,
		root.message,
		root.errorMessage,
		root.stderr,
		safeObject(root.error).message,
		safeObject(root.error).error,
	];
	return candidates.map(safeString).find(Boolean) ?? "";
}

export function isGJCGoalDbSchemaContextError(message: string | undefined): boolean {
	const normalized = safeString(message).toLowerCase();
	return (
		Boolean(normalized) &&
		(normalized.includes("no such table: thread_goals") ||
			(normalized.includes("thread_goals") && /\b(?:sqlite|sql|schema|table|database|db)\b/.test(normalized)) ||
			/\b(?:gjc goal|goal)\b.*\b(?:db|database|schema|context)\b.*\b(?:unavailable|missing|failed|error)\b/.test(
				normalized,
			))
	);
}

export function parseGJCGoalSnapshot(value: unknown): GJCGoalSnapshot {
	const root = safeObject(value);
	const hasGoalProperty = Object.hasOwn(root, "goal");
	const goalValue = hasGoalProperty ? root.goal : value;
	const errorMessage =
		hasGoalProperty && goalValue !== null && goalValue !== undefined && goalValue !== false
			? ""
			: extractErrorMessage(value);
	if (!hasGoalProperty && errorMessage) {
		return {
			available: false,
			unavailableReason: isGJCGoalDbSchemaContextError(errorMessage) ? "db_schema_context_error" : "tool_error",
			errorMessage,
			raw: value,
		};
	}
	if (goalValue === null || goalValue === undefined || goalValue === false) {
		if (errorMessage) {
			return {
				available: false,
				unavailableReason: isGJCGoalDbSchemaContextError(errorMessage) ? "db_schema_context_error" : "tool_error",
				errorMessage,
				raw: value,
			};
		}
		return { available: false, raw: value };
	}

	const goal = safeObject(goalValue);
	const objective = safeString(goal.objective ?? goal.goal ?? goal.description ?? root.objective);
	const status = normalizeStatus(goal.status ?? root.status);
	const tokenBudget = safeNumber(goal.token_budget ?? goal.tokenBudget ?? root.token_budget ?? root.tokenBudget);
	const remainingTokens = safeNumber(root.remainingTokens ?? root.remaining_tokens);

	return {
		available: Boolean(objective || status !== "unknown"),
		...(objective ? { objective } : {}),
		status,
		...(tokenBudget !== undefined ? { tokenBudget } : {}),
		remainingTokens: remainingTokens ?? null,
		raw: value,
	};
}

export async function readGJCGoalSnapshotInput(
	raw: string | undefined,
	cwd = process.cwd(),
): Promise<GJCGoalSnapshot | null> {
	if (!raw?.trim()) return null;
	const trimmed = raw.trim();
	try {
		return parseGJCGoalSnapshot(JSON.parse(trimmed));
	} catch {
		const path = resolve(cwd, trimmed);
		if (!existsSync(path)) {
			throw new GJCGoalSnapshotError(`GJC goal snapshot is neither valid JSON nor a readable path: ${trimmed}`);
		}
		try {
			return parseGJCGoalSnapshot(JSON.parse(await readFile(path, "utf-8")));
		} catch (error) {
			throw new GJCGoalSnapshotError(
				`GJC goal snapshot path does not contain valid JSON: ${trimmed}${error instanceof Error ? ` (${error.message})` : ""}`,
			);
		}
	}
}

export function reconcileGJCGoalSnapshot(
	snapshot: GJCGoalSnapshot | null | undefined,
	options: ReconcileGJCGoalOptions,
): GJCGoalReconciliation {
	const effectiveSnapshot = snapshot ?? { available: false, raw: null };
	const errors: string[] = [];
	const warnings: string[] = [];

	if (!effectiveSnapshot.available) {
		const detail = effectiveSnapshot.errorMessage ? ` Last get_goal error: ${effectiveSnapshot.errorMessage}.` : "";
		const diagnostic =
			effectiveSnapshot.unavailableReason === "db_schema_context_error"
				? " GJC goal state is unavailable due to a DB/schema/context error; this is distinct from a normal missing or incomplete goal."
				: "";
		const message = `GJC goal snapshot is absent or reports no active goal; call get_goal and pass its JSON with --gjc-goal-json.${diagnostic}${detail}`;
		if (options.requireSnapshot) errors.push(message);
		else warnings.push(message);
		return { ok: errors.length === 0, snapshot: effectiveSnapshot, warnings, errors };
	}

	const expected = normalizeObjective(options.expectedObjective);
	const accepted = new Set(
		[expected, ...(options.acceptedObjectives ?? []).map(objective => normalizeObjective(objective))].filter(Boolean),
	);
	const actual = normalizeObjective(effectiveSnapshot.objective ?? "");
	if (!actual) {
		errors.push("GJC goal snapshot is missing objective text.");
	} else if (!accepted.has(actual)) {
		errors.push(`GJC goal objective mismatch: expected "${expected}", got "${actual}".`);
	}

	const allowed = options.allowedStatuses ?? (options.requireComplete ? ["complete"] : ["active", "complete"]);
	const actualStatus = effectiveSnapshot.status ?? "unknown";
	if (!allowed.includes(actualStatus)) {
		errors.push(`GJC goal status mismatch: expected ${allowed.join(" or ")}, got ${actualStatus}.`);
	}
	if (options.requireComplete && actualStatus !== "complete") {
		errors.push(
			`GJC goal is not complete; call update_goal({status: "complete"}) only after the objective is actually complete, then pass the fresh get_goal JSON.`,
		);
	}

	return { ok: errors.length === 0, snapshot: effectiveSnapshot, warnings, errors };
}

export function formatGJCGoalReconciliation(reconciliation: GJCGoalReconciliation): string {
	const parts = [...reconciliation.errors, ...reconciliation.warnings];
	return parts.join(" ");
}
