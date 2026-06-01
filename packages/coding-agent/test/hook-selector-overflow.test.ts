import { beforeAll, describe, expect, it } from "bun:test";
import { HookSelectorComponent } from "@gajae-code/coding-agent/modes/components/hook-selector";
import { getThemeByName, setThemeInstance, theme } from "@gajae-code/coding-agent/modes/theme/theme";
import { visibleWidth } from "@gajae-code/tui";

beforeAll(async () => {
	const themeInstance = await getThemeByName("dark");
	if (!themeInstance) {
		throw new Error("Failed to load dark theme for tests");
	}
	setThemeInstance(themeInstance);
});

// =============================================================================
// Required Test 3 — True baseline legacy regression
//
// Captured from pre-implementation `HookSelectorComponent.render(80)` BEFORE
// any `wrapFocused` behavior was added. Both omitted and `wrapFocused:false`
// must exactly equal this fixture; any drift means today's bytes regressed
// for shared selector consumers (plan-mode, session-delete, MCP wizard,
// registry-search, restart picker, branch-summary).
// =============================================================================

const BASELINE_LONG_FOCUSED =
	"Alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec romeo sierra tango";
const BASELINE_LONG_NON_FOCUSED =
	"Zulu yankee xray whiskey victor uniform tango sierra romeo quebec papa oscar november mike lima kilo juliet india hotel golf";
const BASELINE_SHORT = "short option";

const BASELINE_OUTLINED_RENDER_80_STRIPPED = [
	"────────────────────────────────────────────────────────────────────────────────",
	"",
	" Choose an option                                                               ",
	"",
	"────────────────────────────────────────────────────────────────────────────────",
	"│❯ Alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mi…│",
	"│  Zulu yankee xray whiskey victor uniform tango sierra romeo quebec papa osca…│",
	"│  short option                                                                │",
	"────────────────────────────────────────────────────────────────────────────────",
	"",
	" up/down navigate  enter select  esc cancel                                     ",
	"",
	"────────────────────────────────────────────────────────────────────────────────",
].join("\n");

function renderStripped(
	width: number,
	opts: { outline?: boolean; wrapFocused?: boolean; initialIndex?: number; maxVisible?: number },
	options: string[] = [BASELINE_LONG_FOCUSED, BASELINE_LONG_NON_FOCUSED, BASELINE_SHORT],
): string {
	const component = new HookSelectorComponent(
		"Choose an option",
		options,
		() => {},
		() => {},
		opts,
	);
	return Bun.stripANSI(component.render(width).join("\n"));
}

describe("HookSelectorComponent", () => {
	it("keeps outlined options within render width", () => {
		const options = [
			"aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;b",
			"bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;aaa;bbb;a",
			"a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b;a;b",
		];
		const component = new HookSelectorComponent(
			"Which pattern do you prefer?",
			options,
			() => {},
			() => {},
			{ outline: true, initialIndex: 0 },
		);

		const width = 80;
		const lines = component.render(width);
		for (const line of lines) {
			expect(visibleWidth(Bun.stripANSI(line))).toBeLessThanOrEqual(width);
		}
	});

	it("legacy outlined render at width 80 is byte-identical to captured baseline (wrapFocused unset)", () => {
		const rendered = renderStripped(80, { outline: true, initialIndex: 0, maxVisible: 5 });
		expect(rendered).toBe(BASELINE_OUTLINED_RENDER_80_STRIPPED);
	});

	it("legacy outlined render at width 80 is byte-identical to captured baseline (wrapFocused:false)", () => {
		const rendered = renderStripped(80, { outline: true, initialIndex: 0, maxVisible: 5, wrapFocused: false });
		expect(rendered).toBe(BASELINE_OUTLINED_RENDER_80_STRIPPED);
	});
});
