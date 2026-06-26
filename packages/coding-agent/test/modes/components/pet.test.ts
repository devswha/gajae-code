import { beforeAll, describe, expect, it } from "bun:test";
import { PetComponent } from "@gajae-code/coding-agent/modes/components/pet";
import { initTheme } from "@gajae-code/coding-agent/modes/theme/theme";
import { setTerminalTrueColor, visibleWidth } from "@gajae-code/tui";

beforeAll(async () => {
	await initTheme();
});

describe("PetComponent (ASCII fallback)", () => {
	it("renders the idle crab sprite by default", () => {
		setTerminalTrueColor(false);
		try {
			const pet = new PetComponent();
			expect(Bun.stripANSI(pet.render(40).join("\n"))).toContain("(\\(oo)/)");
		} finally {
			setTerminalTrueColor(false);
		}
	});

	it("changes sprite per activity", () => {
		setTerminalTrueColor(false);
		try {
			const pet = new PetComponent();
			pet.setActivity("working");
			expect(Bun.stripANSI(pet.render(40).join(""))).toContain(">o");
			pet.setActivity("error");
			expect(Bun.stripANSI(pet.render(40).join(""))).toContain("xx");
			pet.setActivity("wave");
			expect(Bun.stripANSI(pet.render(40).join(""))).toContain("^^");
		} finally {
			setTerminalTrueColor(false);
		}
	});
});

describe("PetComponent (truecolor pixel sprite)", () => {
	it("renders a multi-line half-block crab", () => {
		setTerminalTrueColor(true);
		try {
			const pet = new PetComponent();
			const lines = pet.render(80);
			expect(lines.length).toBeGreaterThan(1); // multi-row sprite
			const rendered = Bun.stripANSI(lines.join("\n"));
			expect(rendered).toMatch(/[▀▄]/u);
			expect(rendered).not.toContain("(\\(oo)/)"); // not the ASCII fallback
		} finally {
			setTerminalTrueColor(false);
		}
	});

	it("stays within the available width in both modes", () => {
		for (const truecolor of [false, true]) {
			setTerminalTrueColor(truecolor);
			try {
				const pet = new PetComponent();
				for (const w of [14, 24, 80]) {
					for (const line of pet.render(w)) {
						expect(visibleWidth(line)).toBeLessThanOrEqual(w);
					}
				}
			} finally {
				setTerminalTrueColor(false);
			}
		}
	});
});

describe("PetComponent lifecycle", () => {
	it("start/stop is safe and idempotent", () => {
		const pet = new PetComponent();
		expect(() => {
			pet.start(() => {});
			pet.start(() => {});
			pet.stop();
			pet.stop();
		}).not.toThrow();
	});
});
