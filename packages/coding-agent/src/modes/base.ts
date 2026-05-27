import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";

import { getBaseStateDir, getStatePath } from "../mcp/state-paths.js";

export interface ModeState {
	active: boolean;
	mode: string;
	iteration: number;
	max_iterations: number;
	current_phase: string;
	task_description: string;
	started_at: string;
	updated_at: string;
	[key: string]: unknown;
}

export type ModeName =
	| "autopilot"
	| "autoresearch"
	| "deep-interview"
	| "ralph"
	| "ultrawork"
	| "team"
	| "ultraqa"
	| "ralplan";

async function readJson(path: string): Promise<ModeState | null> {
	if (!existsSync(path)) return null;
	const raw = await readFile(path, "utf-8");
	const parsed = JSON.parse(raw) as unknown;
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
	return parsed as ModeState;
}

async function writeJson(path: string, state: ModeState): Promise<void> {
	await mkdir(getBaseStateDir(), { recursive: true });
	await writeFile(path, `${JSON.stringify(state, null, 2)}\n`);
}

export function getDeprecationWarning(_mode: string): string | null {
	return null;
}

export async function assertModeStartAllowed(_mode: ModeName, _projectRoot?: string): Promise<void> {}

export async function startMode(
	mode: ModeName,
	taskDescription: string,
	maxIterations = 50,
	projectRoot?: string,
): Promise<ModeState> {
	const state: ModeState = {
		active: true,
		mode,
		iteration: 0,
		max_iterations: maxIterations,
		current_phase: "starting",
		task_description: taskDescription,
		started_at: new Date().toISOString(),
		updated_at: new Date().toISOString(),
	};
	await writeJson(getStatePath(mode, projectRoot), state);
	return state;
}

export async function readModeState(mode: string, projectRoot?: string): Promise<ModeState | null> {
	return readJson(getStatePath(mode, projectRoot));
}

export async function readModeStateForSession(
	mode: string,
	_sessionId: string | undefined,
	projectRoot?: string,
): Promise<ModeState | null> {
	return readModeState(mode, projectRoot);
}

export async function readModeStateForActiveDecision(
	mode: string,
	_sessionId: string | undefined,
	projectRoot?: string,
): Promise<ModeState | null> {
	return readModeState(mode, projectRoot);
}

export async function updateModeState(
	mode: string,
	updates: Partial<ModeState>,
	projectRoot?: string,
	_explicitSessionId?: string,
): Promise<ModeState> {
	const existing = (await readModeState(mode, projectRoot)) ?? {
		active: true,
		mode,
		iteration: 0,
		max_iterations: 50,
		current_phase: "running",
		task_description: "",
		started_at: new Date().toISOString(),
		updated_at: new Date().toISOString(),
	};
	const next: ModeState = { ...existing, ...updates, mode, updated_at: new Date().toISOString() };
	await writeJson(getStatePath(mode, projectRoot), next);
	return next;
}

export async function cancelMode(mode: string, projectRoot?: string): Promise<void> {
	await updateModeState(mode, { active: false, current_phase: "cancelled" }, projectRoot);
}

export async function cancelAllModes(projectRoot?: string): Promise<string[]> {
	const dir = getBaseStateDir(projectRoot);
	if (!existsSync(dir)) return [];
	const cancelled: string[] = [];
	for (const entry of await readdir(dir)) {
		if (!entry.endsWith("-state.json")) continue;
		const mode = entry.slice(0, -"-state.json".length);
		await cancelMode(mode, projectRoot);
		cancelled.push(mode);
	}
	return cancelled;
}

export async function listActiveModes(projectRoot?: string): Promise<Array<{ mode: string; state: ModeState }>> {
	const dir = getBaseStateDir(projectRoot);
	if (!existsSync(dir)) return [];
	const modes: Array<{ mode: string; state: ModeState }> = [];
	for (const entry of await readdir(dir)) {
		if (!entry.endsWith("-state.json")) continue;
		const mode = entry.slice(0, -"-state.json".length);
		const state = await readModeState(mode, projectRoot);
		if (state?.active) modes.push({ mode, state });
	}
	return modes;
}

export async function removeModeState(mode: string, projectRoot?: string): Promise<void> {
	await rm(getStatePath(mode, projectRoot), { force: true });
}
