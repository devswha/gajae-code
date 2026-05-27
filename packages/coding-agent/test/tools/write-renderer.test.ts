import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";

describe("write tool renderer source", () => {
	test("does not render the TypeScript blue-box file icon in the Write header", async () => {
		const source = await readFile("packages/coding-agent/src/tools/write.ts", "utf-8");
		const token = "$" + "{";
		const writeHeader =
			"let text = `" +
			token +
			'formatTitle("Write", uiTheme)} ' +
			token +
			"spinner ? `" +
			token +
			'spinner} ` : ""}' +
			token +
			"pathDisplay}`;";
		expect(source).toContain(writeHeader);
		expect(source).toContain(`description: \`${token}pathDisplay}${token}lineSuffix}\``);
		expect(source).not.toContain(`${token}langIcon} ${token}pathDisplay}`);
	});
});
