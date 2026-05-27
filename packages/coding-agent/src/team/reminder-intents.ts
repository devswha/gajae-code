export const TEAM_REMINDER_INTENTS = [
	"followup-reuse",
	"followup-relaunch",
	"stalled-unblock",
	"done-review-or-shutdown",
	"pending-mailbox-review",
] as const;

export type TeamReminderIntent = (typeof TEAM_REMINDER_INTENTS)[number];

export interface TeamReminderDirective {
	text: string;
	intent: TeamReminderIntent;
}

export function isTeamReminderIntent(value: unknown): value is TeamReminderIntent {
	return typeof value === "string" && TEAM_REMINDER_INTENTS.includes(value as TeamReminderIntent);
}

export function resolveLeaderNudgeIntent(
	reason: string,
	options: { leaderActionState?: string } = {},
): TeamReminderIntent {
	const leaderActionState =
		typeof options.leaderActionState === "string" ? options.leaderActionState : "still_actionable";

	switch (reason) {
		case "new_mailbox_message":
		case "stale_leader_with_messages":
			return "pending-mailbox-review";
		case "ack_without_start_evidence":
		case "stuck_waiting_on_leader":
			return "stalled-unblock";
		case "done_waiting_on_leader":
			return "done-review-or-shutdown";
		case "all_workers_idle":
			if (leaderActionState === "done_waiting_on_leader") return "done-review-or-shutdown";
			if (leaderActionState === "stuck_waiting_on_leader") return "stalled-unblock";
			return "followup-relaunch";
		case "stale_leader_panes_alive":
			return "followup-reuse";
		default:
			if (leaderActionState === "done_waiting_on_leader") return "done-review-or-shutdown";
			if (leaderActionState === "stuck_waiting_on_leader") return "stalled-unblock";
			return "followup-reuse";
	}
}
