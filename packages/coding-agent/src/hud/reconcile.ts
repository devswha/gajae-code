export const GJC_TMUX_HUD_OWNER_ENV = "GJC_TMUX_HUD_OWNER";

export interface ReconcileHudForPromptSubmitResult {
	status:
		| "skipped_not_tmux"
		| "skipped_no_entry"
		| "skipped_not_gjc_owned_tmux"
		| "skipped_no_session_id"
		| "resized"
		| "recreated"
		| "replaced_duplicates"
		| "failed";
	paneId: string | null;
	desiredHeight: number | null;
	duplicateCount: number;
}

export async function reconcileHudForPromptSubmit(): Promise<ReconcileHudForPromptSubmitResult> {
	return { status: "skipped_not_tmux", paneId: null, desiredHeight: null, duplicateCount: 0 };
}
