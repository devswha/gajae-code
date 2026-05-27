import { join } from "path";

interface UnifiedMcpRegistryServer {
	name: string;
	command: string;
	args: string[];
	enabled: boolean;
	startupTimeoutSec?: number;
	approval_mode?: string;
}

export const GJC_PLUGIN_MCP_COMMAND = "gjc";
export const GJC_PLUGIN_MCP_SERVE_SUBCOMMAND = "mcp-serve";

type GjcFirstPartyMcpSpec = {
	name: string;
	title: string;
	entrypoint: string;
	pluginTarget: string;
	startupTimeoutSec: number;
};

const GJC_FIRST_PARTY_MCP_SPECS: readonly GjcFirstPartyMcpSpec[] = [
	{
		name: "gjc_state",
		title: "# GJC State Management MCP Server",
		entrypoint: "state-server.js",
		pluginTarget: "state",
		startupTimeoutSec: 5,
	},
	{
		name: "gjc_memory",
		title: "# GJC Project Memory MCP Server",
		entrypoint: "memory-server.js",
		pluginTarget: "memory",
		startupTimeoutSec: 5,
	},
	{
		name: "gjc_code_intel",
		title: "# GJC Code Intelligence MCP Server (LSP diagnostics, AST search)",
		entrypoint: "code-intel-server.js",
		pluginTarget: "code-intel",
		startupTimeoutSec: 10,
	},
	{
		name: "gjc_trace",
		title: "# GJC Trace MCP Server (agent flow timeline & statistics)",
		entrypoint: "trace-server.js",
		pluginTarget: "trace",
		startupTimeoutSec: 5,
	},
	{
		name: "gjc_wiki",
		title: "# GJC Wiki MCP Server (persistent project knowledge base)",
		entrypoint: "wiki-server.js",
		pluginTarget: "wiki",
		startupTimeoutSec: 5,
	},
	{
		name: "gjc_hermes",
		title: "# GJC Hermes Coordination MCP Server (safe dispatch/status/artifacts)",
		entrypoint: "hermes-server.js",
		pluginTarget: "hermes",
		startupTimeoutSec: 5,
	},
] as const;

export const GJC_FIRST_PARTY_MCP_SERVER_NAMES = GJC_FIRST_PARTY_MCP_SPECS.map(spec => spec.name);

export const GJC_FIRST_PARTY_MCP_ENTRYPOINTS = GJC_FIRST_PARTY_MCP_SPECS.map(spec => spec.entrypoint);

export const GJC_FIRST_PARTY_MCP_PLUGIN_TARGETS = GJC_FIRST_PARTY_MCP_SPECS.map(spec => spec.pluginTarget);

export function resolveGjcFirstPartyMcpEntrypointForPluginTarget(target: string | undefined): string | null {
	if (typeof target !== "string") return null;
	const normalized = target.trim().toLowerCase();
	if (!normalized) return null;
	const spec = GJC_FIRST_PARTY_MCP_SPECS.find(
		candidate => candidate.pluginTarget === normalized || candidate.entrypoint === normalized,
	);
	return spec?.entrypoint ?? null;
}

export function getCurrentNodeExecutablePath(): string {
	return process.execPath;
}

export function getGjcFirstPartySetupMcpServers(pkgRoot: string): Array<UnifiedMcpRegistryServer & { title: string }> {
	return GJC_FIRST_PARTY_MCP_SPECS.map(spec => ({
		name: spec.name,
		title: spec.title,
		command: getCurrentNodeExecutablePath(),
		args: [join(pkgRoot, "dist", "mcp", spec.entrypoint)],
		enabled: true,
		startupTimeoutSec: spec.startupTimeoutSec,
	}));
}

export function buildGjcPluginMcpManifest(options: { enabled?: boolean } = {}): {
	mcpServers: Record<
		string,
		{
			command: string;
			args: string[];
			enabled: boolean;
		}
	>;
} {
	return {
		mcpServers: Object.fromEntries(
			GJC_FIRST_PARTY_MCP_SPECS.map(spec => [
				spec.name,
				{
					command: GJC_PLUGIN_MCP_COMMAND,
					args: [GJC_PLUGIN_MCP_SERVE_SUBCOMMAND, spec.pluginTarget],
					enabled: options.enabled === true,
				},
			]),
		),
	};
}
