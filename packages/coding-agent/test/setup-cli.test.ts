import { afterEach, describe, expect, it, vi } from "bun:test";
import { parseSetupArgs } from "../src/cli/setup-cli";

describe("setup CLI parsing", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("defaults bare setup to installing workflow skills", () => {
		expect(parseSetupArgs(["setup"])).toEqual({
			component: "defaults",
			flags: {},
		});
	});

	it("allows bare setup flags for the default workflow skill install", () => {
		expect(parseSetupArgs(["setup", "--check", "--force", "--json"])).toEqual({
			component: "defaults",
			flags: { check: true, force: true, json: true },
		});
	});

	it("keeps optional setup components explicit", () => {
		expect(parseSetupArgs(["setup", "hooks", "-c"])).toEqual({
			component: "hooks",
			flags: { check: true },
		});
	});

	it("rejects provider flags unless provider setup is explicit", () => {
		vi.spyOn(console, "error").mockImplementation(() => {});
		const exit = vi.spyOn(process, "exit").mockImplementation((() => {
			throw new Error("exit");
		}) as (code?: string | number | null | undefined) => never);

		expect(() => parseSetupArgs(["setup", "--provider", "proxy", "--compat", "openai"])).toThrow("exit");
		expect(exit).toHaveBeenCalledWith(1);
	});

	it("allows provider flags for explicit provider setup", () => {
		expect(parseSetupArgs(["setup", "provider", "--provider", "proxy", "--compat", "openai"])).toEqual({
			component: "provider",
			flags: { provider: "proxy", compat: "openai" },
		});
	});
});
