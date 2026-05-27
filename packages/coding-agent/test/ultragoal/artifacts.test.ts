import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
	createUltragoalPlan,
	readUltragoalPlan,
	ULTRAGOAL_BRIEF,
	ULTRAGOAL_DIR,
	ULTRAGOAL_GOALS,
	ULTRAGOAL_LEDGER,
} from "../../src/ultragoal/artifacts";

describe("GJC ultragoal artifacts", () => {
	test("creates upstream-equivalent durable artifacts under .gjc", async () => {
		const cwd = await mkdtemp(join(tmpdir(), "gjc-ultragoal-"));
		try {
			const plan = await createUltragoalPlan(cwd, {
				brief: "Build team and ultragoal parity.",
				goals: [{ title: "Port runtime", objective: "Port the runtime behavior." }],
				gjcGoalMode: "aggregate",
				force: true,
			});

			expect(ULTRAGOAL_DIR).toBe(".gjc/ultragoal");
			expect(plan.briefPath).toBe(".gjc/ultragoal/brief.md");
			expect(plan.goalsPath).toBe(".gjc/ultragoal/goals.json");
			expect(plan.ledgerPath).toBe(".gjc/ultragoal/ledger.jsonl");
			expect(plan.gjcGoalMode).toBe("aggregate");

			await expect(readFile(join(cwd, ULTRAGOAL_DIR, ULTRAGOAL_BRIEF), "utf-8")).resolves.toContain(
				"Build team and ultragoal parity.",
			);
			await expect(readFile(join(cwd, ULTRAGOAL_DIR, ULTRAGOAL_GOALS), "utf-8")).resolves.toContain("Port runtime");
			await expect(readFile(join(cwd, ULTRAGOAL_DIR, ULTRAGOAL_LEDGER), "utf-8")).resolves.toContain("created");

			const reread = await readUltragoalPlan(cwd);
			expect(reread.goals).toHaveLength(1);
			expect(reread.goals[0]?.id).toBe("G001-port-runtime");
		} finally {
			await rm(cwd, { recursive: true, force: true });
		}
	});
});
