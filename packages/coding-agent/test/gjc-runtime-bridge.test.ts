import { afterEach, describe, expect, it } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runGjcRuntimeBridge, runGjcRuntimeBridgeWithHudSidecar } from "../src/commands/gjc-runtime-bridge";

let cleanupRoot: string | undefined;

afterEach(async () => {
	if (cleanupRoot) {
		await rm(cleanupRoot, { recursive: true, force: true });
		cleanupRoot = undefined;
	}
});

describe("gjc runtime bridge", () => {
	it("delegates private endpoints to the configured gjc-compatible runtime", async () => {
		cleanupRoot = await mkdtemp(join(tmpdir(), "gjc-runtime-bridge-"));
		const logPath = join(cleanupRoot, "argv.log");
		const runtimePath = join(cleanupRoot, "gjc-runtime.sh");
		await writeFile(
			runtimePath,
			`#!/bin/sh\nprintf '%s\\n' "$GJC_RUNTIME_BRIDGE_ACTIVE|$1|$2|$3" > ${JSON.stringify(logPath)}\n`,
			{ mode: 0o755 },
		);

		const result = runGjcRuntimeBridge("ultragoal", ["status", "--json"], {
			GJC_RUNTIME_BINARY: runtimePath,
			PATH: "",
		});

		expect(result).toEqual({ status: 0 });
		expect(await readFile(logPath, "utf-8")).toBe("1|ultragoal|status|--json\n");
	});

	it("returns an actionable error when no runtime is available", () => {
		const result = runGjcRuntimeBridge("team", ["api"], { PATH: "" });

		expect(result.status).toBe(1);
		expect(result.error).toContain("gjc team requires the private GJC runtime endpoint implementation");
		expect(result.error).toContain("GJC_RUNTIME_BINARY");
	});
	it("streams workflow HUD sidecar payloads without changing child status", async () => {
		cleanupRoot = await mkdtemp(join(tmpdir(), "gjc-runtime-bridge-"));
		const runtimePath = join(cleanupRoot, "gjc-runtime.sh");
		await writeFile(
			runtimePath,
			`#!/bin/sh
printf '{"version":1,"skill":"ralplan","phase":"planner","hud":{"version":1,"chips":[{"label":"stage","value":"planner"}]}}' > "$GJC_WORKFLOW_HUD_SIDECAR"
/bin/sleep 0.2
printf '{"version":1,"skill":"ralplan","phase":"critic","hud":{"version":1,"chips":[{"label":"stage","value":"critic"}]}}' > "$GJC_WORKFLOW_HUD_SIDECAR"
`,
			{ mode: 0o755 },
		);
		const payloads: string[] = [];

		const result = await runGjcRuntimeBridgeWithHudSidecar("ralplan", ["--direct"], {
			env: { GJC_RUNTIME_BINARY: runtimePath, PATH: "" },
			sidecarSkill: "ralplan",
			pollIntervalMs: 25,
			onHudPayload: payload => {
				payloads.push(payload.phase ?? "");
			},
		});

		expect(result.status).toBe(0);
		expect(result.hudPayload?.phase).toBe("critic");
		expect(payloads).toContain("planner");
		expect(payloads).toContain("critic");
	});

	it("keeps child failure authoritative even with a valid sidecar", async () => {
		cleanupRoot = await mkdtemp(join(tmpdir(), "gjc-runtime-bridge-"));
		const runtimePath = join(cleanupRoot, "gjc-runtime.sh");
		await writeFile(
			runtimePath,
			`#!/bin/sh
printf '{"version":1,"skill":"ralplan","hud":{"version":1,"chips":[{"label":"stage","value":"critic"}]}}' > "$GJC_WORKFLOW_HUD_SIDECAR"
exit 7
`,
			{ mode: 0o755 },
		);

		const result = await runGjcRuntimeBridgeWithHudSidecar("ralplan", [], {
			env: { GJC_RUNTIME_BINARY: runtimePath, PATH: "" },
			sidecarSkill: "ralplan",
			pollIntervalMs: 25,
		});

		expect(result.status).toBe(7);
		expect(result.hudPayload?.hud.chips?.[0]?.value).toBe("critic");
	});
	it("keeps child status when HUD callback rejects", async () => {
		cleanupRoot = await mkdtemp(join(tmpdir(), "gjc-runtime-bridge-"));
		const runtimePath = join(cleanupRoot, "gjc-runtime.sh");
		await writeFile(
			runtimePath,
			`#!/bin/sh
printf '{"version":1,"skill":"ralplan","phase":"critic","hud":{"version":1,"chips":[{"label":"stage","value":"critic"}]}}' > "$GJC_WORKFLOW_HUD_SIDECAR"
`,
			{ mode: 0o755 },
		);

		const result = await runGjcRuntimeBridgeWithHudSidecar("ralplan", [], {
			env: { GJC_RUNTIME_BINARY: runtimePath, PATH: "" },
			sidecarSkill: "ralplan",
			pollIntervalMs: 25,
			onHudPayload: () => {
				throw new Error("boom");
			},
		});

		expect(result.status).toBe(0);
		expect(result.hudPayload?.phase).toBe("critic");
	});
	it("falls back to legacy runtime candidate for sidecar bridges on ENOENT", async () => {
		cleanupRoot = await mkdtemp(join(tmpdir(), "gjc-runtime-bridge-"));
		const runtimePath = join(cleanupRoot, "legacy-gjc-runtime.sh");
		await writeFile(
			runtimePath,
			`#!/bin/sh
printf '{"version":1,"skill":"ralplan","phase":"critic","hud":{"version":1,"chips":[{"label":"stage","value":"critic"}]}}' > "$GJC_WORKFLOW_HUD_SIDECAR"
`,
			{ mode: 0o755 },
		);

		const result = await runGjcRuntimeBridgeWithHudSidecar("ralplan", [], {
			env: {
				GJC_RUNTIME_BINARY: "missing-gjc-runtime",
				GJC_LEGACY_RUNTIME_BINARY: runtimePath,
				PATH: "",
			},
			sidecarSkill: "ralplan",
			pollIntervalMs: 25,
		});

		expect(result.status).toBe(0);
		expect(result.hudPayload?.phase).toBe("critic");
	});
});
