/**
 * MCP-aligned gateway for all team operations.
 *
 * Both the MCP server (state-server.ts) and the runtime (runtime.ts)
 * import from this module instead of state.ts directly.
 * state.ts remains the private persistence layer.
 *
 * Every exported function here corresponds to (or backs) an MCP tool
 * with the same semantic name, ensuring the runtime contract matches
 * the external MCP surface.
 */

// === Types (re-exported) ===
export type {
	ClaimTaskResult,
	PermissionsSnapshot,
	ReclaimTaskResult,
	ReleaseTaskClaimResult,
	ShutdownAck,
	TaskApprovalRecord,
	TaskReadiness,
	TeamConfig,
	TeamDispatchRequest,
	TeamDispatchRequestInput,
	TeamDispatchRequestKind,
	TeamDispatchRequestStatus,
	TeamDispatchTransportPreference,
	TeamEvent,
	TeamGovernance,
	TeamLeader,
	TeamLeaderAttentionState,
	TeamLeaderDecisionState,
	TeamMailbox,
	TeamMailboxMessage,
	TeamManifestV2,
	TeamMonitorSnapshotState,
	TeamPhaseState,
	TeamPolicy,
	TeamSummary,
	TeamTask,
	TeamTaskClaim,
	TeamTaskV2,
	TeamWorkerIntegrationState,
	TransitionTaskResult,
	WorkerHeartbeat,
	WorkerInfo,
	WorkerStatus,
} from "./state.js";
// === Constants ===
// === Team lifecycle ===
// === Worker operations ===
// === Task operations ===
// === Messaging ===
// === Events ===
// === Approvals ===
// === Summary ===
// === Shutdown control ===
// === Monitor snapshot ===
// === Worker status write ===
// === Scaling lock ===
// === Dispatch lock helpers ===
// === Atomic write (shared utility) ===
export {
	ABSOLUTE_MAX_WORKERS,
	appendTeamEvent as teamAppendEvent,
	broadcastMessage as teamBroadcast,
	claimTask as teamClaimTask,
	cleanupTeamState as teamCleanup,
	computeTaskReadiness as teamComputeTaskReadiness,
	createTask as teamCreateTask,
	DEFAULT_MAX_WORKERS,
	enqueueDispatchRequest as teamEnqueueDispatchRequest,
	getTeamSummary as teamGetSummary,
	initTeamState as teamInit,
	listDispatchRequests as teamListDispatchRequests,
	listMailboxMessages as teamListMailbox,
	listTasks as teamListTasks,
	markDispatchRequestDelivered as teamMarkDispatchRequestDelivered,
	markDispatchRequestNotified as teamMarkDispatchRequestNotified,
	markMessageDelivered as teamMarkMessageDelivered,
	markMessageNotified as teamMarkMessageNotified,
	markOwnedTeamsLeaderSessionStopped as teamMarkOwnedTeamsLeaderSessionStopped,
	markTeamLeaderSessionStopped as teamMarkLeaderSessionStopped,
	migrateV1ToV2 as teamMigrateV1ToV2,
	normalizeTeamGovernance as teamNormalizeGovernance,
	normalizeTeamPolicy as teamNormalizePolicy,
	readDispatchRequest as teamReadDispatchRequest,
	readMonitorSnapshot as teamReadMonitorSnapshot,
	readShutdownAck as teamReadShutdownAck,
	readTask as teamReadTask,
	readTaskApproval as teamReadTaskApproval,
	readTeamConfig as teamReadConfig,
	readTeamLeaderAttention as teamReadLeaderAttention,
	readTeamManifestV2 as teamReadManifest,
	readTeamPhase as teamReadPhase,
	readWorkerHeartbeat as teamReadWorkerHeartbeat,
	readWorkerStatus as teamReadWorkerStatus,
	reclaimExpiredTaskClaim as teamReclaimExpiredTaskClaim,
	releaseTaskClaim as teamReleaseTaskClaim,
	resolveDispatchLockTimeoutMs,
	saveTeamConfig as teamSaveConfig,
	sendDirectMessage as teamSendMessage,
	transitionDispatchRequest as teamTransitionDispatchRequest,
	transitionTaskStatus as teamTransitionTaskStatus,
	updateTask as teamUpdateTask,
	updateWorkerHeartbeat as teamUpdateWorkerHeartbeat,
	withScalingLock as teamWithScalingLock,
	writeAtomic,
	writeMonitorSnapshot as teamWriteMonitorSnapshot,
	writeShutdownRequest as teamWriteShutdownRequest,
	writeTaskApproval as teamWriteTaskApproval,
	writeTeamLeaderAttention as teamWriteLeaderAttention,
	writeTeamManifestV2 as teamWriteManifest,
	writeTeamPhase as teamWritePhase,
	writeWorkerIdentity as teamWriteWorkerIdentity,
	writeWorkerInbox as teamWriteWorkerInbox,
	writeWorkerStatus as teamWriteWorkerStatus,
} from "./state.js";
