import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { filterProcessEnv, parseEnvFile, parseShellEnvFile } from "../src/env";

const tempDirs: string[] = [];

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		fs.rmSync(dir, { force: true, recursive: true });
	}
});

function writeTempEnv(content: string, fileName = ".env"): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-utils-env-"));
	tempDirs.push(dir);
	const filePath = path.join(dir, fileName);
	fs.writeFileSync(filePath, content);
	return filePath;
}

describe("parseEnvFile", () => {
	it("ignores malformed names and nul-containing values", () => {
		const filePath = writeTempEnv(
			[
				"GOOD=value",
				"_ALSO_GOOD='quoted value'",
				"1BAD=value",
				"BAD-NAME=value",
				"BAD NAME=value",
				"BAD_VALUE=before\0after",
				"# comment",
				"NO_EQUALS",
			].join("\n"),
		);

		expect(parseEnvFile(filePath)).toEqual({
			GOOD: "value",
			_ALSO_GOOD: "quoted value",
		});
	});

	it("keeps legacy GJC_ variables from becoming PI_ defaults", () => {
		const filePath = writeTempEnv("GJC_FEATURE=enabled\nGJC_BAD=before\0after\n");

		expect(parseEnvFile(filePath)).toEqual({
			GJC_FEATURE: "enabled",
		});
	});
});

describe("parseShellEnvFile", () => {
	it("loads simple exported zshrc-style OpenAI env values without executing shell code", () => {
		const filePath = writeTempEnv(
			[
				"export OPENAI_BASE_URL=https://openai-proxy.example.com/v1",
				"OPENAI_API_KEY='shell-key' # local comment",
				"DYNAMIC_VALUE=$(secret-tool lookup service openai)",
				"BACKTICK_VALUE=`secret-tool lookup service openai`",
				"BAD_VALUE=before\0after",
			].join("\n"),
			".zshrc",
		);

		expect(parseShellEnvFile(filePath)).toEqual({
			OPENAI_BASE_URL: "https://openai-proxy.example.com/v1",
			OPENAI_API_KEY: "shell-key",
		});
	});
});

describe("filterProcessEnv", () => {
	it("drops entries that cannot be passed to process spawn env", () => {
		expect(
			filterProcessEnv({
				GOOD: "value",
				EMPTY: "",
				"BAD=NAME": "value",
				BAD_VALUE: "before\0after",
				MISSING: undefined,
			}),
		).toEqual({
			GOOD: "value",
			EMPTY: "",
		});
	});

	it("preserves Windows-style variable names containing parentheses", () => {
		// `ProgramFiles(x86)` and friends are standard on Windows and must
		// survive the scrub so Git Bash discovery in procmgr.ts can resolve
		// 32-bit Program Files installations.
		expect(
			filterProcessEnv({
				"ProgramFiles(x86)": "C:\\Program Files (x86)",
				"CommonProgramFiles(x86)": "C:\\Program Files (x86)\\Common Files",
			}),
		).toEqual({
			"ProgramFiles(x86)": "C:\\Program Files (x86)",
			"CommonProgramFiles(x86)": "C:\\Program Files (x86)\\Common Files",
		});
	});
});
