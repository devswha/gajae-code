import { type Component, padding } from "@gajae-code/tui";
import { type ThemeColor, theme } from "../theme/theme";

/**
 * Activity states the pet can reflect, mapped from the agent's live state.
 * `wave` is a transient celebration shown right after work finishes.
 */
export type PetActivity = "idle" | "working" | "wave" | "error";

/** Two-frame walk cycle per state. Every frame is exactly {@link SPRITE_WIDTH} wide. */
const FRAMES: Record<PetActivity, readonly [string, string]> = {
	idle: ["(\\(oo)/)", "(/(oo)\\)"],
	working: ["(\\(>o)/)", "(/(o<)\\)"],
	wave: ["(\\(^^)/)", "\\/(^^)\\/"],
	error: ["(\\(xx)/)", "(/(xx)\\)"],
};

const SPRITE_WIDTH = 8;
/** Animation cadence; working scuttles at double the step so it reads as busy. */
const TICK_MS = 180;
/** How long the celebratory wave lasts after work finishes. */
const WAVE_MS = 1600;

const COLOR_FOR: Record<PetActivity, ThemeColor> = {
	idle: "accent",
	working: "warning",
	wave: "success",
	error: "error",
};

/**
 * A small crab companion that scuttles back and forth on its own line and
 * changes animation/color to reflect what the agent is doing. Modeled after the
 * "codex pets" idea: a terminal-native pet that visualizes agent state without
 * touching the welcome banner or stealing input focus.
 */
export class PetComponent implements Component {
	#timer: ReturnType<typeof setInterval> | null = null;
	#requestRender?: () => void;
	#getActivity?: () => PetActivity;

	#frame = 0;
	#x = 0;
	#dir: 1 | -1 = 1;
	#activity: PetActivity = "idle";
	#prevWorking = false;
	#waveUntil = 0;
	#maxX = 0;

	invalidate(): void {}

	/**
	 * Begin animating. `getActivity` is polled each tick for the base state
	 * (typically derived from `session.isStreaming`); the pet itself layers the
	 * transient `wave` on top when work transitions back to idle.
	 */
	start(requestRender: () => void, getActivity?: () => PetActivity): void {
		this.stop();
		this.#requestRender = requestRender;
		this.#getActivity = getActivity;
		this.#timer = setInterval(() => this.#tick(), TICK_MS);
	}

	stop(): void {
		if (this.#timer != null) {
			clearInterval(this.#timer);
			this.#timer = null;
		}
	}

	/** Force a state. Used by tests and callers without a polling source. */
	setActivity(activity: PetActivity): void {
		this.#activity = activity;
	}

	/** Resolve the current frame's state, applying the post-work wave. */
	#resolveActivity(now: number): PetActivity {
		const base = this.#getActivity?.() ?? this.#activity;
		const working = base === "working";
		if (this.#prevWorking && !working && base !== "error") {
			this.#waveUntil = now + WAVE_MS;
		}
		this.#prevWorking = working;
		if (!working && base !== "error" && now < this.#waveUntil) return "wave";
		return base;
	}

	#tick(): void {
		const now = performance.now();
		this.#activity = this.#resolveActivity(now);
		this.#frame ^= 1;
		const step = this.#activity === "working" ? 2 : 1;
		this.#x += this.#dir * step;
		if (this.#x >= this.#maxX) {
			this.#x = this.#maxX;
			this.#dir = -1;
		} else if (this.#x <= 0) {
			this.#x = 0;
			this.#dir = 1;
		}
		this.#requestRender?.();
	}

	render(width: number): string[] {
		const track = Math.max(SPRITE_WIDTH, width);
		this.#maxX = Math.max(0, track - SPRITE_WIDTH);
		if (this.#x > this.#maxX) this.#x = this.#maxX;
		const sprite = FRAMES[this.#activity][this.#frame];
		return [padding(this.#x) + theme.fg(COLOR_FOR[this.#activity], sprite)];
	}
}
