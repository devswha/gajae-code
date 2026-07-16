import { type Component, padding, TERMINAL } from "@gajae-code/tui";
import { type ThemeColor, theme } from "../theme/theme";
import { PET_SPRITE_FRAMES, PET_SPRITE_HEIGHT, PET_SPRITE_WIDTH } from "./pet-sprite.generated";

/**
 * Activity states the pet can reflect, mapped from the agent's live state.
 * `wave` is a transient celebration shown right after work finishes.
 */
export type PetActivity = "idle" | "working" | "wave" | "error";

/** Low-fidelity fallback: a two-frame ASCII crab walk per state (width {@link ASCII_WIDTH}). */
const ASCII_FRAMES: Record<PetActivity, readonly [string, string]> = {
	idle: ["(\\(oo)/)", "(/(oo)\\)"],
	working: ["(\\(>o)/)", "(/(o<)\\)"],
	wave: ["(\\(^^)/)", "\\/(^^)\\/"],
	error: ["(\\(xx)/)", "(/(xx)\\)"],
};
const ASCII_WIDTH = 8;

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
 * reflects what the agent is doing. Modeled after the "codex pets" idea: a
 * terminal-native pet that visualizes agent state without touching the welcome
 * banner or stealing input focus.
 *
 * On truecolor terminals it renders a precise half-block pixel sprite of the
 * Gajae mascot (two bob frames); elsewhere it falls back to a tiny ASCII crab.
 * A small colored status pip beside the pet signals the current activity.
 */
export class PetComponent implements Component {
	#timer: ReturnType<typeof setInterval> | null = null;
	#requestRender?: () => void;
	#getActivity?: () => PetActivity;

	#frame = 0;
	#x = 0;
	#activity: PetActivity = "idle";
	#prevWorking = false;
	#waveUntil = 0;

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

	#usePixelSprite(): boolean {
		return TERMINAL.trueColor && PET_SPRITE_FRAMES.length > 0;
	}

	#spriteWidth(): number {
		return this.#usePixelSprite() ? PET_SPRITE_WIDTH : ASCII_WIDTH;
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
		// Advance the frame cycle: 12 is divisible by both the 2-frame ASCII walk
		// and the 4-frame pixel walk, so each render's modulo stays in phase.
		this.#frame = (this.#frame + 1) % 12;
		this.#requestRender?.();
	}

	/** Small colored status indicator shown beside the pet (idle shows none). */
	#statusPip(): string {
		switch (this.#activity) {
			case "working":
				return theme.fg("warning", this.#frame === 0 ? "*" : "+");
			case "wave":
				return theme.fg("success", "!");
			case "error":
				return theme.fg("error", "x");
			default:
				return "";
		}
	}

	render(width: number): string[] {
		const spriteWidth = this.#spriteWidth();
		const track = Math.max(spriteWidth, width);
		// Animate in place: keep the pet centered, no horizontal sliding.
		this.#x = Math.max(0, Math.floor((track - spriteWidth) / 2));

		if (this.#usePixelSprite()) return this.#renderPixel();
		return this.#renderAscii();
	}

	#renderPixel(): string[] {
		const frame = PET_SPRITE_FRAMES[this.#frame % PET_SPRITE_FRAMES.length];
		const pad = padding(this.#x);
		const pip = this.#statusPip();
		const pipRow = Math.floor(PET_SPRITE_HEIGHT / 2);
		return frame.map((row, i) => pad + row + (i === pipRow && pip ? ` ${pip}` : ""));
	}

	#renderAscii(): string[] {
		const sprite = ASCII_FRAMES[this.#activity][this.#frame % 2];
		const pip = this.#statusPip();
		return [padding(this.#x) + theme.fg(COLOR_FOR[this.#activity], sprite) + (pip ? ` ${pip}` : "")];
	}
}
