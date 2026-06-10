const STREAM_IDLE_TIMEOUT_PATTERN = /\bstream stalled while waiting for the next event\b/i;
const GENERIC_ABORT_PATTERN = /^Request was aborted\.?$/i;

export function buildAbortDisplayMessage({
	errorMessage,
	retryAttempt,
}: {
	errorMessage?: string;
	retryAttempt: number;
}): string {
	const baseMessage =
		retryAttempt > 0
			? `Aborted after ${retryAttempt} retry attempt${retryAttempt > 1 ? "s" : ""}`
			: "Operation aborted";
	const cause = normalizeAbortCause(errorMessage);
	if (!cause) return baseMessage;

	return `${baseMessage}: ${cause}${streamIdleTimeoutHint(cause)}`;
}

function normalizeAbortCause(errorMessage: string | undefined): string {
	const trimmed = errorMessage?.trim();
	if (!trimmed || GENERIC_ABORT_PATTERN.test(trimmed)) return "";
	return trimmed;
}

function streamIdleTimeoutHint(cause: string): string {
	if (!STREAM_IDLE_TIMEOUT_PATTERN.test(cause)) return "";
	const separator = /[.!?]$/.test(cause) ? " " : ". ";
	return `${separator}Hint: set PI_STREAM_IDLE_TIMEOUT_MS=300000 for slow reasoning/proxy streams, or PI_STREAM_IDLE_TIMEOUT_MS=0 to disable the watchdog.`;
}
