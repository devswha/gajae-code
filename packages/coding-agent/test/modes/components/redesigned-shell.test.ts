import { beforeAll, describe, expect, it } from "bun:test";
import type { AssistantMessage } from "@gajae-code/ai";
import { resetSettingsForTest, Settings } from "@gajae-code/coding-agent/config/settings";
import { AssistantMessageComponent } from "@gajae-code/coding-agent/modes/components/assistant-message";
import { BashExecutionComponent } from "@gajae-code/coding-agent/modes/components/bash-execution";
import { EvalExecutionComponent } from "@gajae-code/coding-agent/modes/components/eval-execution";
import { FooterComponent } from "@gajae-code/coding-agent/modes/components/footer";
import { STATUS_LINE_PRESETS } from "@gajae-code/coding-agent/modes/components/status-line/presets";
import { UserMessageComponent } from "@gajae-code/coding-agent/modes/components/user-message";
import { WelcomeComponent } from "@gajae-code/coding-agent/modes/components/welcome";
import { initTheme } from "@gajae-code/coding-agent/modes/theme/theme";
import type { AgentSession } from "@gajae-code/coding-agent/session/agent-session";
import { type TUI, visibleWidth } from "@gajae-code/tui";

function createFooterSession(): AgentSession {
	return {
		state: {
			model: { id: "very-long-model-name-for-footer-budget", contextWindow: 200_000 },
		},
		sessionManager: {
			getEntries: () => [
				{
					type: "message",
					message: {
						role: "assistant",
						usage: {
							input: 1234,
							output: 567,
							cacheRead: 89,
							cacheWrite: 12,
							cost: { total: 0.123 },
							premiumRequests: 0,
						},
					},
				},
			],
		},
		getContextUsage: () => ({ contextWindow: 200_000, percent: 42.5 }),
		modelRegistry: { isUsingOAuth: () => false },
	} as unknown as AgentSession;
}

function createAssistantMessage(text: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text }],
		api: "anthropic-messages",
		provider: "anthropic",
		model: "claude-sonnet-4-5",
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "stop",
		timestamp: Date.now(),
	};
}

beforeAll(async () => {
	resetSettingsForTest();
	await Settings.init({ inMemory: true });
	await initTheme(false);
});

describe("redesigned interactive shell chrome", () => {
	it("renders distinct GJC-native user and assistant turns", () => {
		const user = Bun.stripANSI(new UserMessageComponent("hello").render(80).join("\n"));
		const assistant = Bun.stripANSI(
			new AssistantMessageComponent(createAssistantMessage("hi")).render(80).join("\n"),
		);

		expect(user).toContain("operator input");
		expect(assistant).toContain("gajae reply");
		expect(user).not.toContain("you submitted");
		expect(assistant).not.toContain("agent response");
	});

	it("keeps the GJC forge launch surface responsive", () => {
		const component = new WelcomeComponent("1.2.3", "gpt-5.5", "openai");
		const lines = component.render(54);
		const rendered = Bun.stripANSI(lines.join("\n"));

		expect(rendered).toContain("Gajae forge");
		expect(rendered).toContain("╭╮  ╭╮  ╭╮");
		expect(rendered).not.toContain("●");
		for (const line of lines) {
			expect(visibleWidth(line)).toBeLessThanOrEqual(54);
		}
	});

	it("renders execution rails without breaking output caps", () => {
		const ui = { requestRender: () => {} } as unknown as TUI;
		const bash = new BashExecutionComponent("printf ready", ui, false);
		bash.setComplete(0, false, { output: Array.from({ length: 160 }, (_, i) => `line-${i}`).join("\n") });
		const bashRendered = Bun.stripANSI(bash.render(80).join("\n"));

		expect(bashRendered).toContain("shell · $ printf");
		expect(bashRendered).toContain("ctrl+o to expand");
		expect(bashRendered).not.toContain("line-0\n");
		for (const line of bash.render(80)) {
			expect(visibleWidth(line)).toBeLessThanOrEqual(80);
		}
	});

	it("keeps eval execution headers compact and mode-labeled", () => {
		const ui = { requestRender: () => {} } as unknown as TUI;
		const py = new EvalExecutionComponent("print('ready')", ui, false, "python");
		const js = new EvalExecutionComponent("1 + 1", ui, false, "js");

		expect(Bun.stripANSI(py.render(80).join("\n"))).toContain("python · >>>");
		expect(Bun.stripANSI(js.render(80).join("\n"))).toContain("node · >>>");
	});

	it("keeps eval continuation aligned for multiline code", () => {
		const ui = { requestRender: () => {} } as unknown as TUI;
		const py = new EvalExecutionComponent("print('a')\nprint('b')", ui, false, "python");
		const stripped = Bun.stripANSI(py.render(80).join("\n"));

		expect(stripped).toContain("python · >>> print('a')");
		expect(stripped).toContain("          print('b')");
	});

	it("keeps OSC 133 prompt markers scoped to the message body", () => {
		const rendered = new UserMessageComponent("hello").render(80);

		expect(rendered[0]).not.toContain("\x1b]133;A\x07");
		expect(rendered[1]).not.toContain("\x1b]133;A\x07");
		expect(rendered[2]).toContain("\x1b]133;A\x07");
		expect(rendered[rendered.length - 2]).toContain("\x1b]133;B\x07\x1b]133;C\x07");
		expect(rendered[rendered.length - 1]).not.toContain("\x1b]133;B\x07");
	});

	it("budgets footer prefixes before truncating pulse", () => {
		const footer = new FooterComponent(createFooterSession());
		const lines = footer.render(72);
		const rendered = Bun.stripANSI(lines.join("\n"));

		expect(rendered).toContain("cwd");
		expect(rendered).toContain("pulse");
		expect(rendered).toContain("very-long-mod");
		for (const line of lines) {
			expect(visibleWidth(line)).toBeLessThanOrEqual(72);
		}
	});

	it("keeps public status presets on the GJC identity", () => {
		for (const [name, preset] of Object.entries(STATUS_LINE_PRESETS)) {
			expect(preset.leftSegments, name).not.toContain("pi");
		}

		expect(STATUS_LINE_PRESETS.full.leftSegments).toContain("gajae");
		expect(STATUS_LINE_PRESETS.nerd.leftSegments).toContain("gajae");
	});

	it("keeps the default status preset dense and pulse-forward", () => {
		expect(STATUS_LINE_PRESETS.default.leftSegments).toEqual(["model", "mode", "git", "pr", "path"]);
		expect(STATUS_LINE_PRESETS.default.rightSegments).toEqual(["session_name", "token_rate", "context_pct", "cost"]);
		expect(STATUS_LINE_PRESETS.default.segmentOptions?.path?.maxLength).toBe(32);
	});

	it("keeps forge launch rendering on the bounded-work path", () => {
		const component = new WelcomeComponent("1.2.3", "gpt-5.5", "openai", [
			{ name: "very-long-session-name".repeat(10), timeAgo: "2h" },
		]);
		const first = component.render(96);
		const second = component.render(96);

		expect(first).toHaveLength(second.length);
		expect(first.join("\n")).toBe(second.join("\n"));
		for (const line of first) {
			expect(visibleWidth(line)).toBeLessThanOrEqual(96);
		}
	});
});
