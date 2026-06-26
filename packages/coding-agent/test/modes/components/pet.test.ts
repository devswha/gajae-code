import { beforeAll, describe, expect, it } from "bun:test";
import { PetComponent } from "@gajae-code/coding-agent/modes/components/pet";
import { initTheme } from "@gajae-code/coding-agent/modes/theme/theme";
import { visibleWidth } from "@gajae-code/tui";

beforeAll(async () => {
	await initTheme();
});

describe("PetComponent", () => {
	it("renders the idle crab sprite by default", () => {
		const pet = new PetComponent();
		const rendered = Bun.stripANSI(pet.render(40).join("\n"));
		expect(rendered).toContain("(\\(oo)/)");
	});

	it("changes sprite per activity", () => {
		const pet = new PetComponent();

		pet.setActivity("working");
		expect(Bun.stripANSI(pet.render(40).join(""))).toContain(">o");

		pet.setActivity("error");
		expect(Bun.stripANSI(pet.render(40).join(""))).toContain("xx");

		pet.setActivity("wave");
		expect(Bun.stripANSI(pet.render(40).join(""))).toContain("^^");
	});

	it("stays within the available width", () => {
		const pet = new PetComponent();
		for (const w of [10, 24, 80]) {
			for (const line of pet.render(w)) {
				expect(visibleWidth(line)).toBeLessThanOrEqual(w);
			}
		}
	});

	it("renders a colored sprite (carries ANSI styling)", () => {
		const pet = new PetComponent();
		const raw = pet.render(40).join("");
		// Stripped is shorter than raw → ANSI color codes are present.
		expect(raw.length).toBeGreaterThan(Bun.stripANSI(raw).length);
	});

	it("start/stop is safe and idempotent", () => {
		const pet = new PetComponent();
		expect(() => {
			pet.start(() => {});
			pet.start(() => {}); // replaces previous timer
			pet.stop();
			pet.stop(); // no-op
		}).not.toThrow();
	});
});
