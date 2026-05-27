import type { GoalWorkflowRun } from "./artifacts.js";

export interface GoalWorkflowHandoffOptions {
	run: GoalWorkflowRun;
	title?: string;
	tokenBudget?: number;
	completionCommand?: string;
	degradedMode?: boolean;
}

export function buildGoalWorkflowHandoff(options: GoalWorkflowHandoffOptions): string {
	const createPayload = {
		objective: options.run.objective,
		...(options.tokenBudget ? { token_budget: options.tokenBudget } : {}),
	};
	return [
		options.title ?? `${options.run.workflow} goal-workflow handoff`,
		`Status: ${options.run.status}`,
		`Artifacts: ${options.run.artifactDir}`,
		`Ledger: ${options.run.ledgerPath}`,
		"",
		"GJC goal integration constraints:",
		"- First call get_goal to inspect the active GJC thread goal.",
		"- Call create_goal only if no active goal exists and this handoff is the explicit objective to start.",
		"- If a different active GJC goal exists, finish, checkpoint, or ask the leader before replacing focus.",
		"- Work only this objective until the workflow-specific completion audit passes.",
		'- Call update_goal({status: "complete"}) only after the GJC completion audit and validation artifacts pass, then call get_goal again for a fresh complete snapshot.',
		options.completionCommand
			? `- Then record GJC completion evidence with the fresh snapshot: ${options.completionCommand}`
			: "- Then record GJC completion evidence in the workflow ledger/status artifacts with the fresh get_goal snapshot when the workflow supports --gjc-goal-json.",
		"",
		options.degradedMode
			? "Degraded-mode warning: this shell-rendered handoff did not mutate hidden GJC goal state; the active agent must use get_goal/create_goal/update_goal when those tools are available."
			: "Truth boundary: GJC owns durable workflow artifacts; GJC owns active-thread focus/accounting.",
		"",
		"create_goal payload:",
		JSON.stringify(createPayload, null, 2),
		"",
		"Objective:",
		options.run.objective,
	].join("\n");
}
