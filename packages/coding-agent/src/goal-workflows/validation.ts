import type { GoalWorkflowValidationSummary } from "./artifacts.js";

export type GoalWorkflowValidationStatus = "pass" | "fail" | "blocker";

export interface GoalWorkflowValidationInput {
	status: GoalWorkflowValidationStatus | boolean;
	summary: string;
	artifactPath?: string;
	checkedAt?: Date;
}

export class GoalWorkflowValidationError extends Error {}

function iso(now = new Date()): string {
	return now.toISOString();
}

function hasPlaceholderEvidence(summary: string): boolean {
	return /\b(?:todo|tbd|placeholder|stub|not\s+implemented|fake\s+pass)\b/i.test(summary);
}

export function normalizeGoalWorkflowValidation(input: GoalWorkflowValidationInput): GoalWorkflowValidationSummary {
	if (!input.summary.trim()) throw new GoalWorkflowValidationError("Validation summary is required.");
	const status =
		input.status === true || input.status === "pass"
			? "validation_passed"
			: input.status === "blocker"
				? "blocked"
				: "failed";
	return {
		status,
		summary: input.summary.trim(),
		artifactPath: input.artifactPath?.trim() || undefined,
		checkedAt: iso(input.checkedAt),
	};
}

export function assertGoalWorkflowCanComplete(validation: GoalWorkflowValidationSummary | undefined): void {
	if (!validation) throw new GoalWorkflowValidationError("Completion requires a validation artifact.");
	if (validation.status !== "validation_passed") {
		throw new GoalWorkflowValidationError(`Completion requires validation_passed; got ${validation.status}.`);
	}
	if (!validation.artifactPath?.trim())
		throw new GoalWorkflowValidationError("Completion requires a validation artifact path.");
	if (hasPlaceholderEvidence(validation.summary)) {
		throw new GoalWorkflowValidationError(
			"Completion requires real validation evidence, not placeholder evaluator text.",
		);
	}
}
