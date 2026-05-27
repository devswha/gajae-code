import { describe, expect, test } from "bun:test";

import {
	resolveTeamWorkerCli,
	resolveTeamWorkerCliPlan,
	translateWorkerLaunchArgsForCli,
} from "../../src/team/tmux-session";

describe("GJC team worker CLI selection", () => {
	test("auto and explicit gjc resolve to GJC teammate sessions", () => {
		expect(resolveTeamWorkerCli([], {})).toBe("gjc");
		expect(resolveTeamWorkerCli([], { GJC_TEAM_WORKER_CLI: "gjc" })).toBe("gjc");
		expect(resolveTeamWorkerCliPlan(3, [], { GJC_TEAM_WORKER_CLI_MAP: "auto" })).toEqual(["gjc", "gjc", "gjc"]);
	});

	test("unsupported provider teammate sessions fail before launch", () => {
		for (const provider of ["codex", "claude", "gemini"]) {
			expect(() => resolveTeamWorkerCli([], { GJC_TEAM_WORKER_CLI: provider })).toThrow(
				/GJC team launches GJC teammate sessions only/,
			);
			expect(() => resolveTeamWorkerCliPlan(1, [], { GJC_TEAM_WORKER_CLI_MAP: provider })).toThrow(
				/GJC team launches GJC teammate sessions only/,
			);
		}
	});

	test("GJC launch args are preserved for the GJC teammate CLI", () => {
		expect(translateWorkerLaunchArgsForCli("gjc", ["--model", "frontier"])).toEqual(["--model", "frontier"]);
	});
});
