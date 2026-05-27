/**
 * Model Configuration
 *
 * Reads per-mode model overrides and default-env overrides from .gjc-config.json.
 *
 * Config format:
 * {
 *   "env": {
 *     "GJC_DEFAULT_FRONTIER_MODEL": "your-frontier-model",
 *     "GJC_DEFAULT_STANDARD_MODEL": "your-standard-model",
 *     "GJC_DEFAULT_SPARK_MODEL": "your-spark-model"
 *   },
 *   "models": {
 *     "default": "o4-mini",
 *     "team": "gpt-4.1"
 *   },
 *   "agentReasoning": {
 *     "architect": "xhigh"
 *   }
 * }
 *
 * Resolution: mode-specific > "default" key > GJC_DEFAULT_FRONTIER_MODEL > DEFAULT_FRONTIER_MODEL
 */

import { TOML } from "bun";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { codexConfigPath, codexHome } from "../utils/paths.js";

export interface ModelsConfig {
	[mode: string]: string | undefined;
}

export interface GjcConfigEnv {
	[key: string]: string | undefined;
}

export type ConfiguredAgentReasoningEffort = "low" | "medium" | "high" | "xhigh";

interface GjcConfigFile {
	agentReasoning?: Record<string, unknown>;
	env?: GjcConfigEnv;
	models?: ModelsConfig;
}

interface CodexConfigFile {
	model?: unknown;
	model_provider?: unknown;
	model_providers?: Record<string, unknown>;
}

export const GJC_DEFAULT_FRONTIER_MODEL_ENV = "GJC_DEFAULT_FRONTIER_MODEL";
export const GJC_DEFAULT_STANDARD_MODEL_ENV = "GJC_DEFAULT_STANDARD_MODEL";
export const GJC_DEFAULT_SPARK_MODEL_ENV = "GJC_DEFAULT_SPARK_MODEL";
export const GJC_SPARK_MODEL_ENV = "GJC_SPARK_MODEL";
export const GJC_TEAM_CHILD_MODEL_ENV = "GJC_TEAM_CHILD_MODEL";

function readGjcConfigFile(codexHomeOverride?: string): GjcConfigFile | null {
	const configPath = join(codexHomeOverride || codexHome(), ".gjc-config.json");
	if (!existsSync(configPath)) return null;
	try {
		const raw = JSON.parse(readFileSync(configPath, "utf-8"));
		if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
		return raw as GjcConfigFile;
	} catch {
		return null;
	}
}

function readCodexConfigFile(codexHomeOverride?: string): CodexConfigFile | null {
	const configPath = codexHomeOverride ? join(codexHomeOverride, "config.toml") : codexConfigPath();
	if (!existsSync(configPath)) return null;
	try {
		const raw = TOML.parse(readFileSync(configPath, "utf-8"));
		if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
		return raw as CodexConfigFile;
	} catch {
		return null;
	}
}

function readModelsBlock(codexHomeOverride?: string): ModelsConfig | null {
	const config = readGjcConfigFile(codexHomeOverride);
	if (!config) return null;
	if (config.models && typeof config.models === "object" && !Array.isArray(config.models)) {
		return config.models;
	}
	return null;
}

export const DEFAULT_FRONTIER_MODEL = "gpt-5.5";
export const DEFAULT_STANDARD_MODEL = "gpt-5.4-mini";
export const DEFAULT_SPARK_MODEL = "gpt-5.3-codex-spark";
export const DEFAULT_TEAM_CHILD_MODEL = DEFAULT_STANDARD_MODEL;

function normalizeConfiguredValue(value: unknown): string | undefined {
	if (typeof value !== "string") return undefined;
	const trimmed = value.trim();
	return trimmed.length > 0 ? trimmed : undefined;
}

function normalizeAgentReasoningEffort(value: unknown): ConfiguredAgentReasoningEffort | undefined {
	const normalized = normalizeConfiguredValue(value)?.toLowerCase();
	if (normalized === "low" || normalized === "medium" || normalized === "high" || normalized === "xhigh") {
		return normalized;
	}
	return undefined;
}

function normalizeAgentName(value: unknown): string | undefined {
	const normalized = normalizeConfiguredValue(value)?.toLowerCase();
	return normalized && /^[a-z0-9][a-z0-9_-]*$/.test(normalized) ? normalized : undefined;
}

function readConfigEnvValue(key: string, codexHomeOverride?: string): string | undefined {
	const config = readGjcConfigFile(codexHomeOverride);
	if (!config?.env || typeof config.env !== "object" || Array.isArray(config.env)) {
		return undefined;
	}
	return normalizeConfiguredValue(config.env[key]);
}

function readTeamLowComplexityOverride(codexHomeOverride?: string): string | undefined {
	const models = readModelsBlock(codexHomeOverride);
	if (!models) return undefined;
	for (const key of TEAM_LOW_COMPLEXITY_MODEL_KEYS) {
		const value = normalizeConfiguredValue(models[key]);
		if (value) return value;
	}
	return undefined;
}

export function readConfiguredEnvOverrides(codexHomeOverride?: string): NodeJS.ProcessEnv {
	const config = readGjcConfigFile(codexHomeOverride);
	if (!config?.env || typeof config.env !== "object" || Array.isArray(config.env)) {
		return {};
	}

	const resolved: NodeJS.ProcessEnv = {};
	for (const [key, value] of Object.entries(config.env)) {
		const normalized = normalizeConfiguredValue(value);
		if (normalized) resolved[key] = normalized;
	}
	return resolved;
}

export function readAgentReasoningOverrides(
	codexHomeOverride?: string,
): Record<string, ConfiguredAgentReasoningEffort> {
	const config = readGjcConfigFile(codexHomeOverride);
	const raw = config?.agentReasoning;
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};

	const resolved: Record<string, ConfiguredAgentReasoningEffort> = {};
	for (const [key, value] of Object.entries(raw)) {
		const role = normalizeAgentName(key);
		const effort = normalizeAgentReasoningEffort(value);
		if (role && effort) resolved[role] = effort;
	}
	return resolved;
}

export function getAgentReasoningOverride(
	agentName: string | undefined,
	codexHomeOverride?: string,
): ConfiguredAgentReasoningEffort | undefined {
	const normalized = normalizeAgentName(agentName);
	if (!normalized) return undefined;
	return readAgentReasoningOverrides(codexHomeOverride)[normalized];
}

export function readActiveProviderEnvOverrides(
	env: NodeJS.ProcessEnv = process.env,
	codexHomeOverride?: string,
	activeProviderOverride?: string,
): NodeJS.ProcessEnv {
	const config = readCodexConfigFile(codexHomeOverride);
	if (!config) return {};

	const activeProvider =
		normalizeConfiguredValue(activeProviderOverride) ?? normalizeConfiguredValue(config.model_provider);
	if (!activeProvider) return {};

	const providers = config.model_providers;
	if (!providers || typeof providers !== "object" || Array.isArray(providers)) {
		return {};
	}

	const providerConfig = providers[activeProvider];
	if (!providerConfig || typeof providerConfig !== "object" || Array.isArray(providerConfig)) {
		return {};
	}

	const envKey = normalizeConfiguredValue((providerConfig as Record<string, unknown>).env_key);
	if (!envKey) return {};

	const envValue = normalizeConfiguredValue(env[envKey]);
	return envValue ? { [envKey]: envValue } : {};
}

export function getEnvConfiguredMainDefaultModel(
	env: NodeJS.ProcessEnv = process.env,
	codexHomeOverride?: string,
): string | undefined {
	return (
		normalizeConfiguredValue(env[GJC_DEFAULT_FRONTIER_MODEL_ENV]) ??
		readConfigEnvValue(GJC_DEFAULT_FRONTIER_MODEL_ENV, codexHomeOverride)
	);
}

function getCodexConfigRootModel(codexHomeOverride?: string): string | undefined {
	return normalizeConfiguredValue(readCodexConfigFile(codexHomeOverride)?.model);
}

export function getCodexConfigRootModelProvider(codexHomeOverride?: string): string | undefined {
	return normalizeConfiguredValue(readCodexConfigFile(codexHomeOverride)?.model_provider);
}

export function getEnvConfiguredStandardDefaultModel(
	env: NodeJS.ProcessEnv = process.env,
	codexHomeOverride?: string,
): string | undefined {
	return (
		normalizeConfiguredValue(env[GJC_DEFAULT_STANDARD_MODEL_ENV]) ??
		readConfigEnvValue(GJC_DEFAULT_STANDARD_MODEL_ENV, codexHomeOverride)
	);
}

export function getEnvConfiguredSparkDefaultModel(
	env: NodeJS.ProcessEnv = process.env,
	codexHomeOverride?: string,
): string | undefined {
	return (
		normalizeConfiguredValue(env[GJC_DEFAULT_SPARK_MODEL_ENV]) ??
		normalizeConfiguredValue(env[GJC_SPARK_MODEL_ENV]) ??
		readConfigEnvValue(GJC_DEFAULT_SPARK_MODEL_ENV, codexHomeOverride) ??
		readConfigEnvValue(GJC_SPARK_MODEL_ENV, codexHomeOverride)
	);
}

export function getTeamChildModel(codexHomeOverride?: string): string {
	return (
		normalizeConfiguredValue(process.env[GJC_TEAM_CHILD_MODEL_ENV]) ??
		readConfigEnvValue(GJC_TEAM_CHILD_MODEL_ENV, codexHomeOverride) ??
		DEFAULT_TEAM_CHILD_MODEL
	);
}

/**
 * Get the envvar-backed main/default model.
 * Resolution: GJC_DEFAULT_FRONTIER_MODEL > config.toml model > DEFAULT_FRONTIER_MODEL
 */
export function getMainDefaultModel(codexHomeOverride?: string): string {
	return (
		getEnvConfiguredMainDefaultModel(process.env, codexHomeOverride) ??
		getCodexConfigRootModel(codexHomeOverride) ??
		DEFAULT_FRONTIER_MODEL
	);
}

/**
 * Get the envvar-backed standard/default subagent model.
 *
 * Standard-role subagents inherit the configured main/default model unless an
 * explicit standard-lane override is configured. This keeps spawned agents in
 * sync with the leader model while preserving GJC_DEFAULT_STANDARD_MODEL as the
 * opt-in escape hatch for cheaper/specialized standard workers.
 *
 * Resolution: GJC_DEFAULT_STANDARD_MODEL > GJC_DEFAULT_FRONTIER_MODEL > config.toml model > DEFAULT_FRONTIER_MODEL
 */
export function getStandardDefaultModel(codexHomeOverride?: string): string {
	return (
		getEnvConfiguredStandardDefaultModel(process.env, codexHomeOverride) ?? getMainDefaultModel(codexHomeOverride)
	);
}

/**
 * Get the configured model for a specific mode.
 * Resolution: mode-specific override > "default" key > GJC_DEFAULT_FRONTIER_MODEL > DEFAULT_FRONTIER_MODEL
 */
export function getModelForMode(mode: string, codexHomeOverride?: string): string {
	const models = readModelsBlock(codexHomeOverride);
	const modeValue = normalizeConfiguredValue(models?.[mode]);
	if (modeValue) return modeValue;

	const defaultValue = normalizeConfiguredValue(models?.default);
	if (defaultValue) return defaultValue;

	return getMainDefaultModel(codexHomeOverride);
}

const TEAM_LOW_COMPLEXITY_MODEL_KEYS = ["team_low_complexity", "team-low-complexity", "teamLowComplexity"];

/**
 * Get the envvar-backed spark/low-complexity default model.
 * Resolution: GJC_DEFAULT_SPARK_MODEL > GJC_SPARK_MODEL > explicit low-complexity key(s) > DEFAULT_SPARK_MODEL
 */
export function getSparkDefaultModel(codexHomeOverride?: string): string {
	return (
		getEnvConfiguredSparkDefaultModel(process.env, codexHomeOverride) ??
		readTeamLowComplexityOverride(codexHomeOverride) ??
		DEFAULT_SPARK_MODEL
	);
}

/**
 * Get the low-complexity team worker model.
 * Resolution: explicit low-complexity key(s) > GJC_DEFAULT_SPARK_MODEL > GJC_SPARK_MODEL > DEFAULT_SPARK_MODEL
 */
export function getTeamLowComplexityModel(codexHomeOverride?: string): string {
	return readTeamLowComplexityOverride(codexHomeOverride) ?? getSparkDefaultModel(codexHomeOverride);
}
