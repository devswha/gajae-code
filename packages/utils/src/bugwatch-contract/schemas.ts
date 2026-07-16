import { BugwatchContractError, canonicalizeJson, type JsonValue, jsonObject, parseCanonicalJson } from "./canonical";
import { authenticatedHash, computeEventId, fatalCoreHash, sha256Hex, validatePolicyChain, verifyMac } from "./crypto";
import {
	BUGWATCH_FINGERPRINT_VERSION,
	BUGWATCH_FIXTURE_MANIFEST_HASH,
	BUGWATCH_LOG_SCHEMA_VERSION,
	BUGWATCH_NOISE_VERSION,
	BUGWATCH_REDACTION_VERSION,
	BUGWATCH_SCHEMA_CATALOG_HASH,
	BUGWATCH_SCHEMA_MAJOR,
	BUGWATCH_SCHEMA_MINOR,
	BUGWATCH_SEVERITY_VERSION,
	EMERGENCY_LOGICAL_SLOTS,
	EMERGENCY_PAGES_PER_LOGICAL_SLOT,
	INBOX_ENVELOPE_BYTES,
	INBOX_SLOTS,
	isBugwatchTextRedacted,
} from "./versions";

export const POLICY_SEMANTIC_SCHEMA = "gjc-bugwatch-policy-semantics/v1" as const;
export const UINT64_MAX = "9223372036854775807" as const;

export interface DaemonPolicyV1 {
	enabled: boolean;
	pollMs: number;
}
export interface IngestPolicyV1 {
	maxFilesPerTick: number;
	maxBytesPerTick: number;
	maxRowsPerTick: number;
	maxWorkMsPerTick: number;
	maxRowBytes: number;
	maxPartialBytes: number;
	maxDiscardBytes: number;
	partialMaxAgeMs: number;
}
export interface InboxPolicyV1 {}
export interface ArchivePolicyV1 {
	filesPerCycle: number;
	compressedBytesPerCycle: number;
	decompressedBytesPerCycle: number;
	workMsPerCycle: number;
}
export interface CoveragePolicyV1 {}
export interface StorePolicyV1 {
	maxDbBytes: number;
	maxWalBytes: number;
	maxOutboxBytes: number;
}
export interface CandidatePolicyV1 {
	highFatalPerRoot: number;
	mediumPerRoot: number;
	lowPerRoot: number;
}
export interface JobsPolicyV1 {
	activeGlobal: number;
	activePerRoot: number;
	maxAttempts: number;
	wallMs: number;
}
export interface ContextPolicyV1 {
	persistedGlobalBytes: number;
	ttlDays: number;
}
export interface TriagePolicyV1 {
	upstreamEnabled: boolean;
}
export interface RetentionPolicyV1 {
	observationDays: number;
	jobDays: number;
	runDays: number;
}

export interface PolicySemanticV1 {
	schema: typeof POLICY_SEMANTIC_SCHEMA;
	scopeId: string;
	daemon: DaemonPolicyV1;
	ingest: IngestPolicyV1;
	inbox: InboxPolicyV1;
	archive: ArchivePolicyV1;
	coverage: CoveragePolicyV1;
	store: StorePolicyV1;
	candidate: CandidatePolicyV1;
	jobs: JobsPolicyV1;
	context: ContextPolicyV1;
	triage: TriagePolicyV1;
	retention: RetentionPolicyV1;
}
/** Creates the canonical, default-off policy for a single scope. */
export function createPolicySemanticV1(scopeId: string): PolicySemanticV1 {
	if (scopeId.length === 0 || scopeId.length > 4096)
		throw new BugwatchContractError("INVALID_SCHEMA", "scopeId must be a non-empty bounded string");
	return {
		schema: POLICY_SEMANTIC_SCHEMA,
		scopeId,
		daemon: { enabled: false, pollMs: 1000 },
		ingest: {
			maxFilesPerTick: 32,
			maxBytesPerTick: 1_048_576,
			maxRowsPerTick: 1000,
			maxWorkMsPerTick: 50,
			maxRowBytes: 262_144,
			maxPartialBytes: 262_144,
			maxDiscardBytes: 4_194_304,
			partialMaxAgeMs: 300_000,
		},
		inbox: {},
		archive: {
			filesPerCycle: 2,
			compressedBytesPerCycle: 25_165_824,
			decompressedBytesPerCycle: 33_554_432,
			workMsPerCycle: 2000,
		},
		coverage: {},
		store: { maxDbBytes: 536_870_912, maxWalBytes: 67_108_864, maxOutboxBytes: 67_108_864 },
		candidate: { highFatalPerRoot: 2000, mediumPerRoot: 2000, lowPerRoot: 1000 },
		jobs: { activeGlobal: 100, activePerRoot: 20, maxAttempts: 5, wallMs: 600_000 },
		context: { persistedGlobalBytes: 67_108_864, ttlDays: 7 },
		triage: { upstreamEnabled: false },
		retention: { observationDays: 30, jobDays: 90, runDays: 30 },
	};
}
export interface ScopePolicyRevisionV2 {
	schema: "gjc-bugwatch-policy-revision/v2";
	scopeId: string;
	generation: number;
	semantic: PolicySemanticV1;
	contentHash: string;
	previousGeneration: number | null;
	previousRevisionHash: string | null;
	previousContentHash: string | null;
	casTokenHash: string;
	createdAt: string;
	writerId: string;
	keyId: string;
	mac: string;
}
export interface ScopePolicyHeadV2 {
	schema: "gjc-bugwatch-policy-head/v2";
	scopeId: string;
	generation: number;
	revisionHash: string;
	contentHash: string;
	casToken: string;
	updatedAt: string;
	keyId: string;
	mac: string;
}

export interface LeaseV1 {
	schema: "gjc-bugwatch-lease/v1";
	scopeId: string;
	claimTokenHash: string;
	ownerId: string;
	role: "daemon" | "fallback";
	pid: number;
	pidStartToken: string;
	executableFingerprint: string;
	protocolMajor: number;
	storeMin: number;
	storeMax: number;
	phase: "claiming" | "published" | "quiescing";
	heartbeatAt: string;
	policyGeneration: number;
	policyHash: string;
	rollbackState: "none" | "quiescing" | "exporting" | "fallback_active" | "complete" | "failed";
	keyId: string;
	mac: string;
}
export interface FatalKeyringV1 {
	schema: "gjc-bugwatch-fatal-keyring/v1";
	scopeId: string;
	currentKeyId: string;
	previousKeyIds: string[];
	casToken: string;
	revision: number;
	updatedAt: string;
}
export interface StoreOperationMemberV1 {
	member: "db" | "wal" | "shm";
	sourcePathHash: string;
	expectedPresence: boolean;
	expectedSize: number | null;
	expectedHash: string | null;
	quarantinePathHash: string;
}
export interface StoreOperationCoreV1 {
	schema: "gjc-bugwatch-store-operation-core/v1";
	scopeId: string;
	operationId: string;
	ownerId: string;
	claimTokenHash: string;
	kind: "migrate" | "restore" | "quarantine" | "rebuild";
	fromVersion: number;
	toVersion: number | null;
	members: StoreOperationMemberV1[];
	startedAt: string;
	keyId: string;
	mac: string;
}
export interface StoreOperationStepV1 {
	schema: "gjc-bugwatch-store-operation-step/v1";
	scopeId: string;
	operationId: string;
	coreHash: string;
	stepIndex: number;
	member: "db" | "wal" | "shm";
	action: "move_intent" | "move_complete" | "verified_absent";
	expectedSourceHash: string | null;
	observedDestinationHash: string | null;
	previousStepHash: string | null;
	occurredAt: string;
	keyId: string;
	mac: string;
}
export interface RollbackBundleV1 {
	schema: "gjc-bugwatch-rollback-bundle/v1";
	scopeId: string;
	epochId: string;
	roleTransitionTokenHash: string;
	bundleVersion: 1;
	state: "quiescing" | "exporting" | "exported" | "released" | "fallback_active" | "importing" | "complete" | "failed";
	manifestHash: string | null;
	itemCount: number;
	byteCount: number;
	itemsDigest: string | null;
	sourceWatermarkHash: string | null;
	createdAt: string;
	exportedAt: string | null;
	keyId: string;
	mac: string;
}
export interface RollbackBundleItemV1 {
	schema: "gjc-bugwatch-rollback-bundle-item/v1";
	scopeId: string;
	epochId: string;
	itemIndex: number;
	itemType: RollbackSpoolItemV1["itemType"];
	payload: JsonValue;
	payloadHash: string;
	itemHash: string;
	previousItemHash: string | null;
	createdAt: string;
	keyId: string;
	mac: string;
}
export interface RollbackSpoolManifestV1 {
	schema: "gjc-bugwatch-rollback-spool-manifest/v1";
	scopeId: string;
	epochId: string;
	segmentIndex: number;
	state: "open" | "closed" | "quarantined";
	itemCount: number;
	byteCount: number;
	itemsDigest: string | null;
	previousManifestHash: string | null;
	closedAt: string | null;
	keyId: string;
	mac: string;
}
export const ROLLBACK_ITEM_TYPES = [
	"root",
	"root_alias",
	"boot",
	"attachment",
	"coverage_range",
	"source",
	"source_checkpoint",
	"archive_alias",
	"physical_row",
	"overflow",
	"observation",
	"candidate",
	"cursor_watermark",
	"inbox_ack",
] as const;
export type RollbackItemTypeV1 = (typeof ROLLBACK_ITEM_TYPES)[number];

export interface RollbackSpoolItemV1 {
	schema: "gjc-bugwatch-rollback-spool-item/v1";
	scopeId: string;
	epochId: string;
	segmentIndex: number;
	itemIndex: number;
	itemType: RollbackItemTypeV1;
	payload: JsonValue;
	payloadHash: string;
	itemHash: string;
	previousItemHash: string | null;
	createdAt: string;
	keyId: string;
	mac: string;
}
export interface RollbackInboxAckV1 {
	schema: "gjc-bugwatch-rollback-inbox-ack/v1";
	scopeId: string;
	epochId: string;
	slot: number;
	slotGeneration: number;
	eventId: string;
	segmentIndex: number;
	spoolItemHash: string;
	acknowledgedAt: string;
	keyId: string;
	mac: string;
}
export interface RootControlV1 {
	schema: "gjc-bugwatch-root/v1";
	scopeId: string;
	rootId: string;
	canonicalPath: string;
	enabled: boolean;
	persistContext: boolean;
	generation: number;
	projectPolicyHash: string;
	baselineEpochId: string | null;
	activeMutationId: string | null;
	updatedAt: string;
	nonce: string;
	keyId: string;
	mac: string;
}
export interface RootMutationOutputV2 {
	target: "old_root" | "new_root";
	pathHash: string;
	precondition: "missing" | "present";
	expectedOldContentHash: string | null;
	pendingContentHash: string;
	finalContentHash: string;
	desiredRootGeneration: number;
	publicationOrder: 1 | 2;
}
export interface RootMutationCoreV1 {
	schema: "gjc-bugwatch-root-mutation-core/v1";
	scopeId: string;
	mutationId: string;
	action: "enable" | "disable" | "set_context" | "move";
	expectedPolicyGeneration: number;
	expectedPolicyHash: string;
	oldRootId: string | null;
	newRootId: string | null;
	outputs: RootMutationOutputV2[];
	createdAt: string;
	actorPid: number;
	actorPidStartToken: string;
	keyId: string;
	mac: string;
}
export interface RootMutationRenameStepV2 {
	schema: "gjc-bugwatch-root-rename-step/v2";
	scopeId: string;
	mutationId: string;
	coreHash: string;
	stepIndex: number;
	target: "old_root" | "new_root";
	lifecycle: "pending" | "final";
	action: "rename_intent" | "rename_complete";
	expectedDestinationHash: string | null;
	sourceTempHash: string;
	desiredDestinationHash: string;
	observedDestinationHash: string | null;
	previousStepHash: string | null;
	occurredAt: string;
	keyId: string;
	mac: string;
}

export interface BootCoreV1 {
	schema: "gjc-bugwatch-boot-core/v1";
	scopeId: string;
	bootId: string;
	bootTokenHash: string;
	pid: number;
	pidStartToken: string;
	producer: string;
	startedAt: string;
	initialPolicyGeneration: number;
	initialPolicyHash: string;
	fatalKeyId: string;
	gjcVersion: string;
	buildSha: string | null;
	sequenceOrigin: "1";
	maxSequence: typeof UINT64_MAX;
	keyId: string;
	mac: string;
}
export interface BootTransportStartV1 {
	schema: "gjc-bugwatch-transport-start/v1";
	scopeId: string;
	bootId: string;
	bootCoreHash: string;
	transportEpoch: number;
	policyGeneration: number;
	policyHash: string;
	startSequence: string;
	startedAt: string;
	fileEnabled: boolean;
	keyId: string;
	previousRecordHash: string | null;
	mac: string;
}
export interface BootTransportCloseV1 {
	schema: "gjc-bugwatch-transport-close/v1";
	scopeId: string;
	bootId: string;
	bootCoreHash: string;
	transportEpoch: number;
	startRecordHash: string;
	endSequenceInclusive: string;
	endedAt: string;
	outcome: "closed" | "flush_failed" | "hard_stop_unknown";
	keyId: string;
	previousRecordHash: string;
	mac: string;
}
export interface BootFinalV1 {
	schema: "gjc-bugwatch-boot-final/v1";
	scopeId: string;
	bootId: string;
	bootCoreHash: string;
	finalSequence: string;
	endedAt: string;
	state: "clean" | "crashed" | "unknown_disable";
	lastTransportRecordHash: string;
	attachmentSnapshotHash: string;
	keyId: string;
	previousRecordHash: string;
	mac: string;
}
export type CaptureAuthorityV1 =
	| {
			schema: "gjc-bugwatch-capture/v1";
			state: "captured";
			scopeId: string;
			policyGeneration: number;
			policyHash: string;
			bootCoreHash: string;
			transportEpoch: number;
			transportStartHash: string;
			durableChannel: "file" | "fatal_inbox";
			keyId: string;
	  }
	| {
			schema: "gjc-bugwatch-capture/v1";
			state: "disabled" | "unpublished" | "transport_excluded";
			reason: "daemon_disabled" | "manifest_unavailable" | "file_transport_disabled";
	  };
export interface AttachmentV1 {
	schema: "gjc-bugwatch-attachment/v1";
	scopeId: string;
	attachmentId: string;
	attachmentTokenHash: string;
	bootId: string;
	bootCoreHash: string;
	rootId: string;
	sessionId: string | null;
	startedAt: string;
	endedAt: string | null;
	state: "prepared" | "active" | "ended" | "unknown" | "aborted";
	managedSessionRoot: string | null;
	sessionFile: string | null;
	rootGeneration: number;
	baselineEpochId: string;
	publishSequence: string | null;
	retireSequence: string | null;
	keyId: string;
	mac: string;
}
export interface FatalEnvelopeV1 {
	schema: "gjc-bugwatch-fatal/v1";
	category: "gjc-internal";
	scopeId: string;
	keyId: string;
	bootId: string;
	recordSeq: string;
	eventId: string;
	crashCorrelationId: string;
	kind: "uncaught_exception" | "unhandled_rejection";
	occurredAt: string;
	producer: string;
	attachmentId: string | null;
	rootId: string | null;
	sessionId: string | null;
	severity: "fatal";
	message: string;
	stackTop: string | null;
	redactionVersion: 1;
	fatalCoreHash: string;
	mac: string;
}
export type SourceAuthorityStateV1 =
	| "active"
	| "draining"
	| "exhausted"
	| "generation_changed"
	| "orphaned"
	| "quarantined"
	| "archive_ambiguous"
	| "capacity_blocked";

export interface SourceAuthorityV1 {
	schema: "gjc-bugwatch-source/v1";
	scopeId: string;
	segmentId: string;
	generation: number;
	sourceKind: "log" | "inbox" | "rollback";
	pathHash: string;
	fileIdentityHint: string;
	prefixAnchorLength: number;
	prefixHash: string;
	committedOffset: number;
	boundaryHash: string | null;
	checkpointDigest: string;
	state: SourceAuthorityStateV1;
	updatedAt: string;
	keyId: string;
	mac: string;
}
export interface SourceCheckpointV1 {
	schema: "gjc-bugwatch-source-checkpoint/v1";
	scopeId: string;
	segmentId: string;
	generation: number;
	kind: "chunk" | "tail";
	chunkIndex: number;
	startOffset: number;
	endOffset: number;
	hash: string;
	keyId: string;
	mac: string;
}
export interface ArchiveAliasV1 {
	schema: "gjc-bugwatch-archive-alias/v1";
	scopeId: string;
	archiveDigest: string;
	uncompressedLength: number;
	segmentId: string;
	generation: number;
	lineageKind: "full" | "prefix";
	verifiedCheckpointDigest: string;
	createdAt: string;
	keyId: string;
	mac: string;
}

export type MonitorDisableActionV1 =
	| {
			kind: "gjc_cron";
			ownerSessionId: string;
			ownerPid: number;
			ownerPidStartToken: string;
			cronId: string;
			expression: string;
			promptHash: string;
	  }
	| {
			kind: "user_cron";
			expectedCrontabHash: string;
			markerLineHash: string;
			jobLineHash: string;
			markerLineBytesBase64: string;
			jobLineBytesBase64: string;
	  }
	| {
			kind: "systemd_user";
			units: {
				name: "gjc-bugwatch.service" | "gjc-bugwatch.timer";
				expectedPropertiesHash: string;
				expectedFragmentPathHash: string;
			}[];
			operation: "disable_now";
	  }
	| {
			kind: "process";
			pid: number;
			pidStartToken: string;
			uid: string;
			executableHash: string;
			argvHash: string;
			signal: "TERM";
	  }
	| {
			kind: "process_force";
			pid: number;
			pidStartToken: string;
			uid: string;
			executableHash: string;
			argvHash: string;
			signal: "KILL";
	  }
	| {
			kind: "tmux_pane";
			serverIdentityHash: string;
			paneId: string;
			sessionId: string;
			tagHash: string;
			commandHash: string;
	  }
	| { kind: "tmux_session"; serverIdentityHash: string; sessionId: string; paneIds: string[]; allPaneTagsHash: string }
	| {
			kind: "plugin_feature";
			pluginName: string;
			pluginVersion: string;
			pluginPathHash: string;
			manifestHash: string;
			expectedRuntimeConfigGeneration: number;
			expectedRuntimeConfigHash: string;
			feature: "bugwatchAutomation.enabled";
			from: true;
			to: false;
	  };
export interface MonitorDisableAuthorizationV1 {
	schema: "gjc-bugwatch-monitor-disable-auth/v1";
	scopeId: string;
	authorizationId: string;
	inventoryEpochId: string;
	monitorId: string;
	adapterKind: MonitorInventoryV1["kind"];
	stableIdentifier: string;
	expectedConfigHash: string;
	allowedAction: MonitorDisableActionV1;
	authorizedAt: string;
	expiresAt: string;
	nonce: string;
	keyId: string;
	mac: string;
}
export interface MonitorInventoryV1 {
	schema: "gjc-bugwatch-monitor-inventory/v1";
	scopeId: string;
	inventoryEpochId: string;
	monitorId: string;
	kind: "gjc_cron" | "user_cron" | "systemd_user" | "process" | "tmux" | "plugin";
	stableIdentifier: string;
	configHash: string;
	coveredRootIds: string[];
	status: "active" | "inactive" | "unknown";
	observedAt: string;
	adapterEvidenceHash: string;
	keyId: string;
	mac: string;
}
export interface MonitorDisableReceiptV1 {
	schema: "gjc-bugwatch-monitor-disable-receipt/v1";
	scopeId: string;
	authorizationId: string;
	actionHash: string;
	inventoryEpochId: string;
	monitorId: string;
	adapterKind: MonitorInventoryV1["kind"];
	beforeHash: string;
	afterHash: string | null;
	startedAt: string;
	finishedAt: string;
	result: "disabled" | "already_inactive" | "unavailable" | "refused" | "partial_failure" | "failed";
	steps: { name: string; attempted: boolean; ok: boolean; evidenceHash: string | null; errorCode: string | null }[];
	coveredRootIds: string[];
	keyId: string;
	mac: string;
}

export const AUTHORITY_CLASS_NAMES = [
	"schema_meta",
	"fingerprint_version_mappings",
	"scope_policies",
	"scope_policy_heads",
	"roots",
	"root_aliases",
	"root_mutations",
	"root_mutation_outputs",
	"root_mutation_steps",
	"root_mutation_rename_steps",
	"producer_boots",
	"boot_transport_records",
	"boot_final_records",
	"session_attachments",
	"attachment_transitions",
	"producer_coverage",
	"producer_ranges",
	"sources",
	"source_checkpoints",
	"archive_aliases",
	"physical_rows",
	"identity_quarantines",
	"observations",
	"candidates",
	"overflow_buckets",
	"capacity_blocks",
	"job_inputs",
	"triage_jobs",
	"triage_results",
	"artifact_outbox",
	"projection_heads",
	"job_projection_requirements",
	"manual_artifacts",
	"fingerprint_prefix_aliases",
	"import_epochs",
	"context_records",
	"coverage_epochs",
	"coverage_source_watermarks",
	"coverage_boot_watermarks",
	"coverage_boot_ranges",
	"rollback_epochs",
	"rollback_items",
	"old_monitor_inventory_epochs",
	"old_monitors",
	"old_monitor_root_coverage",
	"legacy_disable_receipts",
	"monitor_disable_authorizations",
	"monitor_disable_receipts",
	"store_operations",
	"store_operation_members",
	"authority_snapshot_packs",
	"store_operation_journal",
	"authority_snapshot_items",
	"source_archive_replay",
	"inbox_emergency_replay",
	"rollback_spool_replay",
	"registry_replay",
	"upstream_cache",
	"daemon_runs",
	"sqlite_wal_shm",
	"ephemeral_context_ipc",
	"derived_health_counters",
] as const;
export const AUTHORITY_LOGICAL_SOURCE_MAPPING = {
	sqlite_wal_shm: "sqlite_wal_and_shm_files",
	ephemeral_context_ipc: "runtime_context_ipc",
	derived_health_counters: "derived_runtime_counters",
} as const satisfies Partial<Record<AuthorityClassV1, string>>;
export type AuthorityClassV1 = (typeof AUTHORITY_CLASS_NAMES)[number];
export const SOURCE_FRONTIER_ITEM_TYPES = ["sources"] as const;
export const REGISTRY_FRONTIER_ITEM_TYPES = [
	"producer_boots",
	"boot_transport_records",
	"boot_final_records",
	"session_attachments",
	"attachment_transitions",
] as const;
export const INBOX_FRONTIER_ITEM_TYPES = ["inbox_emergency_replay"] as const;
export const EMERGENCY_FRONTIER_ITEM_TYPES = ["inbox_emergency_replay"] as const;
export const ROLLBACK_FRONTIER_ITEM_TYPES = ["rollback_spool_replay"] as const;
export const ARTIFACT_FRONTIER_ITEM_TYPES = ["artifact_outbox"] as const;

export type SourceFrontierItemTypeV1 = (typeof SOURCE_FRONTIER_ITEM_TYPES)[number];
export type RegistryFrontierItemTypeV1 = (typeof REGISTRY_FRONTIER_ITEM_TYPES)[number];
export type InboxFrontierItemTypeV1 = (typeof INBOX_FRONTIER_ITEM_TYPES)[number];
export type EmergencyFrontierItemTypeV1 = (typeof EMERGENCY_FRONTIER_ITEM_TYPES)[number];
export type RollbackFrontierItemTypeV1 = (typeof ROLLBACK_FRONTIER_ITEM_TYPES)[number];
export type ArtifactFrontierItemTypeV1 = (typeof ARTIFACT_FRONTIER_ITEM_TYPES)[number];
export const AUTHORITY_SNAPSHOT_POLICY: Readonly<
	Record<AuthorityClassV1, { mode: "payload" | "external_replay" | "excluded_safe"; reconstructiveSource: string }>
> = {
	schema_meta: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	fingerprint_version_mappings: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	scope_policies: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	scope_policy_heads: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	roots: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	root_aliases: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	root_mutations: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	root_mutation_outputs: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	root_mutation_steps: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	root_mutation_rename_steps: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	producer_boots: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	boot_transport_records: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	boot_final_records: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	session_attachments: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	attachment_transitions: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	producer_coverage: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	producer_ranges: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	sources: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	source_checkpoints: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	archive_aliases: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	physical_rows: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	identity_quarantines: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	observations: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	candidates: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	overflow_buckets: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	capacity_blocks: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	job_inputs: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	triage_jobs: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	triage_results: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	artifact_outbox: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	projection_heads: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	job_projection_requirements: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	manual_artifacts: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	fingerprint_prefix_aliases: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	import_epochs: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	context_records: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	coverage_epochs: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	coverage_source_watermarks: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	coverage_boot_watermarks: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	coverage_boot_ranges: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	rollback_epochs: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	rollback_items: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	old_monitor_inventory_epochs: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	old_monitors: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	old_monitor_root_coverage: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	legacy_disable_receipts: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	monitor_disable_authorizations: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	monitor_disable_receipts: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	store_operations: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	store_operation_members: { mode: "payload", reconstructiveSource: "snapshot_payload" },
	authority_snapshot_packs: {
		mode: "external_replay",
		reconstructiveSource: "authenticated_retained_snapshot_manifests",
	},
	store_operation_journal: {
		mode: "external_replay",
		reconstructiveSource: "authenticated_retained_store_operation_journal",
	},
	authority_snapshot_items: { mode: "external_replay", reconstructiveSource: "authenticated_retained_snapshot_items" },
	source_archive_replay: {
		mode: "external_replay",
		reconstructiveSource: "retained_centralized_log_archive_paths_with_source_offset_checkpoint_frontier",
	},
	inbox_emergency_replay: {
		mode: "external_replay",
		reconstructiveSource: "authenticated_fatal_inbox_emergency_slots_with_acknowledgment_slot_generation_frontier",
	},
	rollback_spool_replay: {
		mode: "external_replay",
		reconstructiveSource: "verified_rollback_spool_segment_manifests_items_with_import_ack_frontier",
	},
	registry_replay: {
		mode: "external_replay",
		reconstructiveSource: "authenticated_append_only_boot_transport_final_attachment_registry_hash_chain_frontier",
	},
	upstream_cache: { mode: "excluded_safe", reconstructiveSource: "not_applicable" },
	daemon_runs: { mode: "excluded_safe", reconstructiveSource: "not_applicable" },
	sqlite_wal_shm: { mode: "excluded_safe", reconstructiveSource: "not_applicable" },
	ephemeral_context_ipc: { mode: "excluded_safe", reconstructiveSource: "not_applicable" },
	derived_health_counters: { mode: "excluded_safe", reconstructiveSource: "not_applicable" },
};
export interface SnapshotCutoffV1 {
	operationId: string;
	quiesceTokenHash: string;
	cutoffAt: string;
	sqliteBackupHash: string;
	schemaMetaHash: string;
	sourceWatermarksHash: string;
	registryFrontiersHash: string;
	inboxFrontierHash: string;
	emergencyFrontierHash: string;
	rollbackSpoolFrontierHash: string;
	artifactFrontierHash: string;
}
interface SnapshotFrontierRecordCoreV1 {
	sequence: number;
	recordHash: string;
	previousRecordHash: string | null;
}
interface AuthenticatedReplayFrontierRecordCoreV1 extends SnapshotFrontierRecordCoreV1 {
	schema: "gjc-bugwatch-external-replay-record/v1";
	domain:
		| "gjc-bugwatch-external-replay-registry-v1"
		| "gjc-bugwatch-external-replay-inbox-v1"
		| "gjc-bugwatch-external-replay-emergency-v1"
		| "gjc-bugwatch-external-replay-rollback-v1"
		| "gjc-bugwatch-external-replay-artifact-v1";
	keyId: string;
	mac: string;
}
export type SnapshotFrontierRecordV1 = SnapshotFrontierRecordCoreV1 &
	(
		| {
				kind: "source";
				itemType: SourceFrontierItemTypeV1;
				authorityId: string;
				payloadHash: string;
				sourceId: string;
				generation: number;
				committedOffset: number;
				boundaryHash: string | null;
				checkpointDigest: string;
				occurredAt: string;
		  }
		| (AuthenticatedReplayFrontierRecordCoreV1 & {
				kind: "registry";
				itemType: RegistryFrontierItemTypeV1;
				authorityId: string;
				payloadHash: string;
				bootId: string;
				transportEpoch: number | null;
				attachmentId: string | null;
				transitionStep: number | null;
				occurredAt: string;
		  })
		| (AuthenticatedReplayFrontierRecordCoreV1 & {
				kind: "inbox";
				itemType: InboxFrontierItemTypeV1;
				authorityId: string;
				payloadHash: string;
				slot: number;
				slotGeneration: number;
				occurredAt: string;
		  })
		| (AuthenticatedReplayFrontierRecordCoreV1 & {
				kind: "emergency";
				itemType: EmergencyFrontierItemTypeV1;
				authorityId: string;
				payloadHash: string;
				logicalSlot: number;
				page: number;
				pageGeneration: number;
				occurredAt: string;
		  })
		| (AuthenticatedReplayFrontierRecordCoreV1 & {
				kind: "rollback";
				itemType: RollbackFrontierItemTypeV1;
				authorityId: string;
				payloadHash: string;
				epochId: string;
				segmentIndex: number;
				occurredAt: string;
		  })
		| (AuthenticatedReplayFrontierRecordCoreV1 & {
				kind: "artifact";
				itemType: ArtifactFrontierItemTypeV1;
				authorityId: string;
				payloadHash: string;
				artifactId: string;
				outboxSequence: string;
				occurredAt: string;
		  })
	);
export interface SQLiteBackupFrontierV1 {
	scopeId: string;
	backupId: string;
	backupBytes: string;
	backupHash: string;
	databaseHash: string;
	dataVersionBefore: number;
	dataVersionAfter: number;
	createdAt: string;
}
export interface SchemaMetaFrontierV1 {
	id: number;
	schema_major: number;
	schema_minor: number;
	log_schema_version: number;
	redaction_version: number;
	noise_version: number;
	severity_version: number;
	fingerprint_version: number;
	fixture_manifest_hash: string;
	schema_catalog_hash: string;
	created_at_ms: number;
	migrated_at_ms: number;
}
export interface SourceWatermarkFrontierV1 {
	scopeId: string;
	entries: Array<{
		sourceId: string;
		generation: number;
		committedOffset: number;
		records: SnapshotFrontierRecordV1[];
	}>;
}
export interface RegistryFrontierV1 {
	scopeId: string;
	entries: Array<{ bootId: string; transportEpoch: number; records: SnapshotFrontierRecordV1[] }>;
}
export interface InboxFrontierV1 {
	scopeId: string;
	entries: Array<{ slot: number; slotGeneration: number; records: SnapshotFrontierRecordV1[] }>;
}
export interface EmergencyFrontierV1 {
	scopeId: string;
	entries: Array<{ logicalSlot: number; page: number; pageGeneration: number; records: SnapshotFrontierRecordV1[] }>;
}
export interface RollbackSpoolFrontierV1 {
	scopeId: string;
	entries: Array<{ epochId: string; segmentIndex: number; records: SnapshotFrontierRecordV1[] }>;
}
export interface ArtifactOutboxFrontierV1 {
	scopeId: string;
	entries: Array<{ artifactId: string; outboxSequence: string; records: SnapshotFrontierRecordV1[] }>;
}
export interface AuthoritySnapshotFrontierEvidenceV1 {
	sqliteBackup: SQLiteBackupFrontierV1;
	schemaMeta: SchemaMetaFrontierV1;
	sourceWatermarks: SourceWatermarkFrontierV1;
	registryFrontiers: RegistryFrontierV1;
	inboxFrontier: InboxFrontierV1;
	emergencyFrontier: EmergencyFrontierV1;
	rollbackSpoolFrontier: RollbackSpoolFrontierV1;
	artifactFrontier: ArtifactOutboxFrontierV1;
}
export interface SnapshotClassEntryV1 {
	className: AuthorityClassV1;
	mode: "payload" | "external_replay" | "excluded_safe";
	itemCount: number;
	byteCount: number;
	itemsSha256: string;
	classDigest: string;
	reconstructiveSource: string;
}
export interface AuthoritySnapshotItemV1 {
	schema: "gjc-bugwatch-authority-item/v1";
	index: number;
	itemType: AuthorityClassV1;
	authorityId: string;
	payload: JsonValue;
	payloadHash: string;
	previousItemHash: string | null;
	keyId: string;
	mac: string;
}
export interface SnapshotKeyReferenceV1 {
	keyId: string;
	keyDigest: string;
}
export interface AuthoritySnapshotManifestV2 {
	schema: "gjc-bugwatch-authority-snapshot/v2";
	scopeId: string;
	snapshotId: string;
	kind: "migration" | "rebuild" | "cutover" | "rollback" | "manual_authority";
	policyGeneration: number;
	storeSchemaMajor: number;
	fixtureManifestHash: string;
	createdAt: string;
	itemCount: number;
	byteCount: number;
	itemsSha256: string;
	merkleRoot: string;
	previousSnapshotId: string | null;
	previousManifestHash: string | null;
	cutoff: SnapshotCutoffV1;
	classes: SnapshotClassEntryV1[];
	snapshotKeyId: string;
	snapshotKeyDigest: string;
	policyKeyringId: string;
	policyKeyringDigest: string;
	policyKeyringSource: "protected_retained_policy_keyring";
	fatalKeyringId: string;
	fatalKeyringDigest: string;
	fatalKeyringSource: "protected_retained_fatal_keyring";
	registryKeyringId: string;
	registryKeyringDigest: string;
	registryKeyringSource: "protected_retained_registry_keyring";
	rollbackKeyringId: string;
	rollbackKeyringDigest: string;
	rollbackKeyringSource: "protected_retained_rollback_keyring";
	keyId: string;
	mac: string;
}

function requireKeys(object: { [key: string]: JsonValue }, keys: readonly string[], context: string): void {
	const actual = Object.keys(object);
	if (actual.length !== keys.length || actual.some(key => !keys.includes(key)))
		throw new BugwatchContractError("UNKNOWN_FIELD", `${context} contains unknown or missing fields`);
}
function valueObject(value: JsonValue, context: string): { [key: string]: JsonValue } {
	return jsonObject(value, context);
}
function stringField(object: { [key: string]: JsonValue }, key: string): string {
	const value = object[key];
	if (typeof value !== "string") throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a string`);
	return value;
}
function numberField(object: { [key: string]: JsonValue }, key: string): number {
	const value = object[key];
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a non-negative integer`);
	return value;
}
function pidField(object: { [key: string]: JsonValue }, key: string): number {
	const value = numberField(object, key);
	if (value < 1 || value > 2_147_483_647)
		throw new BugwatchContractError("OUT_OF_RANGE", `${key} is outside the pid range`);
	return value;
}
function booleanField(object: { [key: string]: JsonValue }, key: string): boolean {
	const value = object[key];
	if (typeof value !== "boolean") throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be boolean`);
	return value;
}
function exactObject(value: JsonValue, keys: readonly string[], context: string): { [key: string]: JsonValue } {
	const object = valueObject(value, context);
	requireKeys(object, keys, context);
	return object;
}
function policyObject(
	value: JsonValue,
	keys: readonly string[],
	ranges: Readonly<Record<string, readonly [number, number]>> = {},
): void {
	const object = exactObject(value, keys, "policy");
	for (const key of keys) {
		if (key in ranges) {
			const number = numberField(object, key);
			const [min, max] = ranges[key];
			if (number < min || number > max)
				throw new BugwatchContractError("OUT_OF_RANGE", `${key} is outside its compiled range`);
		}
	}
}

export function parsePolicySemanticV1(input: string | JsonValue): PolicySemanticV1 {
	const value = typeof input === "string" ? parseCanonicalJson(input) : input;
	const object = exactObject(
		value,
		[
			"schema",
			"scopeId",
			"daemon",
			"ingest",
			"inbox",
			"archive",
			"coverage",
			"store",
			"candidate",
			"jobs",
			"context",
			"triage",
			"retention",
		],
		"policy semantic",
	);
	if (stringField(object, "schema") !== POLICY_SEMANTIC_SCHEMA)
		throw new BugwatchContractError("UNSUPPORTED_SCHEMA", "Unsupported policy semantic schema");
	boundedString(object.scopeId, "scopeId");
	policyObject(object.daemon, ["enabled", "pollMs"], { pollMs: [250, 10_000] });
	booleanField(valueObject(object.daemon, "daemon"), "enabled");
	policyObject(
		object.ingest,
		[
			"maxFilesPerTick",
			"maxBytesPerTick",
			"maxRowsPerTick",
			"maxWorkMsPerTick",
			"maxRowBytes",
			"maxPartialBytes",
			"maxDiscardBytes",
			"partialMaxAgeMs",
		],
		{
			maxFilesPerTick: [1, 128],
			maxBytesPerTick: [65536, 8388608],
			maxRowsPerTick: [1, 5000],
			maxWorkMsPerTick: [5, 200],
			maxRowBytes: [16384, 524288],
			maxPartialBytes: [16384, 524288],
			maxDiscardBytes: [262144, 8388608],
			partialMaxAgeMs: [10000, 900000],
		},
	);
	policyObject(object.inbox, []);
	policyObject(
		object.archive,
		["filesPerCycle", "compressedBytesPerCycle", "decompressedBytesPerCycle", "workMsPerCycle"],
		{
			filesPerCycle: [0, 4],
			compressedBytesPerCycle: [0, 33554432],
			decompressedBytesPerCycle: [0, 67108864],
			workMsPerCycle: [0, 5000],
		},
	);
	policyObject(object.coverage, []);
	policyObject(object.store, ["maxDbBytes", "maxWalBytes", "maxOutboxBytes"], {
		maxDbBytes: [1, 1073741824],
		maxWalBytes: [1, 134217728],
		maxOutboxBytes: [1, 134217728],
	});
	policyObject(object.candidate, ["highFatalPerRoot", "mediumPerRoot", "lowPerRoot"], {
		highFatalPerRoot: [100, 10000],
		mediumPerRoot: [0, 10000],
		lowPerRoot: [0, 10000],
	});
	policyObject(object.jobs, ["activeGlobal", "activePerRoot", "maxAttempts", "wallMs"], {
		activeGlobal: [1, 500],
		activePerRoot: [1, 100],
		maxAttempts: [1, 10],
		wallMs: [10000, 900000],
	});
	policyObject(object.context, ["persistedGlobalBytes", "ttlDays"], {
		persistedGlobalBytes: [1, 134217728],
		ttlDays: [1, 30],
	});
	policyObject(object.triage, ["upstreamEnabled"]);
	booleanField(valueObject(object.triage, "triage"), "upstreamEnabled");
	policyObject(object.retention, ["observationDays", "jobDays", "runDays"], {
		observationDays: [7, 365],
		jobDays: [7, 365],
		runDays: [7, 365],
	});
	return object as unknown as PolicySemanticV1;
}

const NULLABLE_FIELDS_BY_SCHEMA: Readonly<Record<string, ReadonlySet<string>>> = {
	"gjc-bugwatch-policy-revision/v2": new Set(["previousRevisionHash", "previousContentHash"]),
	"gjc-bugwatch-root/v1": new Set(["baselineEpochId", "activeMutationId"]),
	"gjc-bugwatch-root-mutation-core/v1": new Set(["oldRootId", "newRootId"]),
	"gjc-bugwatch-root-mutation-db-state/v1": new Set(["previousPhase", "previousStateHash"]),
	"gjc-bugwatch-root-rename-step/v2": new Set([
		"expectedDestinationHash",
		"observedDestinationHash",
		"previousStepHash",
	]),
	"gjc-bugwatch-boot-core/v1": new Set(["buildSha"]),
	"gjc-bugwatch-transport-start/v1": new Set(["previousRecordHash"]),
	"gjc-bugwatch-attachment/v1": new Set([
		"sessionId",
		"endedAt",
		"managedSessionRoot",
		"sessionFile",
		"publishSequence",
		"retireSequence",
	]),
	"gjc-bugwatch-fatal/v1": new Set(["attachmentId", "rootId", "sessionId", "stackTop"]),
	"gjc-bugwatch-source/v1": new Set(["boundaryHash"]),
	"gjc-bugwatch-monitor-disable-receipt/v1": new Set(["afterHash"]),
	"gjc-bugwatch-monitor-disable-authorization/v1": new Set(["consumedAt"]),
	"gjc-bugwatch-store-operation-core/v1": new Set(["toVersion"]),
	"gjc-bugwatch-store-operation-step/v1": new Set([
		"expectedSourceHash",
		"observedDestinationHash",
		"previousStepHash",
	]),
	"gjc-bugwatch-rollback-bundle/v1": new Set(["manifestHash", "itemsDigest", "sourceWatermarkHash", "exportedAt"]),
	"gjc-bugwatch-rollback-bundle-item/v1": new Set(["previousItemHash"]),
	"gjc-bugwatch-rollback-spool-manifest/v1": new Set(["itemsDigest", "previousManifestHash", "closedAt"]),
	"gjc-bugwatch-rollback-spool-item/v1": new Set(["previousItemHash"]),
	"gjc-bugwatch-authority-snapshot/v2": new Set(["previousSnapshotId", "previousManifestHash"]),
};

const BOOLEAN_FIELDS = new Set(["enabled", "persistContext", "fileEnabled", "attempted", "ok", "expectedPresence"]);
const ARRAY_FIELDS = new Set(["outputs", "coveredRootIds", "steps", "classes", "members", "previousKeyIds"]);
const DECIMAL_FIELDS = new Set([
	"recordSeq",
	"startSequence",
	"endSequenceInclusive",
	"finalSequence",
	"publishSequence",
	"retireSequence",
]);
const INTEGER_FIELDS = new Set([
	"generation",
	"pid",
	"initialPolicyGeneration",
	"policyGeneration",
	"transportEpoch",
	"expectedPolicyGeneration",
	"desiredRootGeneration",
	"actorPid",
	"stepIndex",
	"rootGeneration",
	"prefixAnchorLength",
	"committedOffset",
	"chunkIndex",
	"startOffset",
	"endOffset",
	"uncompressedLength",
	"itemCount",
	"redactionVersion",
	"protocolMajor",
	"storeMin",
	"storeMax",
	"keyEpoch",
	"fromVersion",
	"toVersion",
	"currentStep",
	"bundleVersion",
	"revision",
	"storeSchemaMajor",
	"byteCount",
	"segmentIndex",
	"slot",
	"slotGeneration",
	"itemIndex",
]);
const HASH_FIELD = /(?:Hash|Digest)$/;
const ENUMS: Readonly<Record<string, readonly string[]>> = {
	"gjc-bugwatch-boot-core/v1:sequenceOrigin": ["1"],
	"gjc-bugwatch-transport-close/v1:outcome": ["closed", "flush_failed", "hard_stop_unknown"],
	"gjc-bugwatch-boot-final/v1:state": ["clean", "crashed", "unknown_disable"],
	"gjc-bugwatch-fatal/v1:kind": ["uncaught_exception", "unhandled_rejection"],
	"gjc-bugwatch-fatal/v1:severity": ["fatal"],
	"gjc-bugwatch-fatal/v1:category": ["gjc-internal"],
	"gjc-bugwatch-root-mutation-core/v1:action": ["enable", "disable", "set_context", "move"],
	"gjc-bugwatch-root-rename-step/v2:target": ["old_root", "new_root"],
	"gjc-bugwatch-root-rename-step/v2:lifecycle": ["pending", "final"],
	"gjc-bugwatch-root-rename-step/v2:action": ["rename_intent", "rename_complete"],
	"gjc-bugwatch-attachment/v1:state": ["prepared", "active", "ended", "unknown", "aborted"],
	"gjc-bugwatch-source/v1:sourceKind": ["log", "inbox", "rollback"],
	"gjc-bugwatch-source/v1:state": [
		"active",
		"draining",
		"exhausted",
		"generation_changed",
		"orphaned",
		"quarantined",
		"archive_ambiguous",
		"capacity_blocked",
	],
	"gjc-bugwatch-source-checkpoint/v1:kind": ["chunk", "tail"],
	"gjc-bugwatch-archive-alias/v1:lineageKind": ["full", "prefix"],
	"gjc-bugwatch-monitor-inventory/v1:kind": ["gjc_cron", "user_cron", "systemd_user", "process", "tmux", "plugin"],
	"gjc-bugwatch-monitor-inventory/v1:status": ["active", "inactive", "unknown"],
	"gjc-bugwatch-monitor-disable-receipt/v1:adapterKind": [
		"gjc_cron",
		"user_cron",
		"systemd_user",
		"process",
		"tmux",
		"plugin",
	],
	"gjc-bugwatch-monitor-disable-receipt/v1:result": [
		"disabled",
		"already_inactive",
		"unavailable",
		"refused",
		"partial_failure",
		"failed",
	],
};

function boundedString(value: JsonValue, key: string): string {
	if (typeof value !== "string" || value.length === 0 || value.length > 4096)
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a non-empty bounded string`);
	return value;
}
function canonicalUtcTimestamp(value: string, key: string): void {
	if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a canonical UTC timestamp`);
	}
	const instant = new Date(value);
	if (Number.isNaN(instant.getTime()) || instant.toISOString() !== value)
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a canonical UTC timestamp`);
}

function decimalSequence(value: JsonValue, key: string): void {
	if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value) || BigInt(value) > BigInt(UINT64_MAX))
		throw new BugwatchContractError("INVALID_SEQUENCE", `${key} must be an int64 decimal sequence`);
}

const OBJECT_FIELDS = new Set(["semantic", "cutoff", "action", "allowedAction", "payload"]);

function validateEnvelopeFields(object: { [key: string]: JsonValue }, schema: string): void {
	const nullableFields = NULLABLE_FIELDS_BY_SCHEMA[schema] ?? new Set<string>();
	for (const [key, value] of Object.entries(object)) {
		if (key === "schema" || OBJECT_FIELDS.has(key)) continue;
		if (key === "previousGeneration") {
			if (value !== null && (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1))
				throw new BugwatchContractError("INVALID_SCHEMA", "previousGeneration must be null or a positive integer");
			continue;
		}
		if (nullableFields.has(key) && value === null) continue;
		if (BOOLEAN_FIELDS.has(key)) {
			if (typeof value !== "boolean") throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be boolean`);
			continue;
		}
		if (ARRAY_FIELDS.has(key)) {
			if (!Array.isArray(value) || value.length > 1024)
				throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a bounded array`);
			continue;
		}
		if (DECIMAL_FIELDS.has(key)) {
			decimalSequence(value, key);
			continue;
		}
		if (key === "maxSequence") {
			if (value !== UINT64_MAX)
				throw new BugwatchContractError("INVALID_SEQUENCE", "maxSequence must equal int64 max");
			continue;
		}
		if (INTEGER_FIELDS.has(key)) {
			if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a non-negative safe integer`);
			if ((key === "pid" || key === "actorPid") && (value < 1 || value > 2_147_483_647))
				throw new BugwatchContractError("OUT_OF_RANGE", `${key} is outside the pid range`);
			if (key === "redactionVersion" && value !== 1)
				throw new BugwatchContractError("INVALID_SCHEMA", "redactionVersion must be 1");
			continue;
		}
		if (schema === "gjc-bugwatch-fatal/v1" && (key === "message" || key === "stackTop")) {
			if (typeof value !== "string" || value.length === 0)
				throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a non-empty string`);
			continue;
		}
		const string = boundedString(value, key);
		if ((key === "mac" || key === "hash" || HASH_FIELD.test(key)) && !/^[0-9a-f]{64}$/.test(string))
			throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be lowercase SHA-256 hex`);
		if (key.endsWith("At")) canonicalUtcTimestamp(string, key);
		const allowed = ENUMS[`${schema}:${key}`];
		if (allowed !== undefined && !allowed.includes(string))
			throw new BugwatchContractError("INVALID_SCHEMA", `${key} is not an allowed value`);
	}
}
function validateNestedEnvelopeFields(object: { [key: string]: JsonValue }, schema: string): void {
	const coveredRootIds = object.coveredRootIds;
	if (
		coveredRootIds !== undefined &&
		(!Array.isArray(coveredRootIds) ||
			coveredRootIds.some(entry => typeof entry !== "string" || entry.length === 0 || entry.length > 256))
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "coveredRootIds entries must be bounded strings");
	if (schema === "gjc-bugwatch-root-mutation-core/v1") {
		const outputs = object.outputs;
		if (!Array.isArray(outputs) || outputs.length === 0 || outputs.length > 2)
			throw new BugwatchContractError("INVALID_SCHEMA", "outputs must contain one or two entries");
		const targets = new Set<string>();
		const publicationOrders = new Set<number>();
		for (const output of outputs) {
			const entry = exactObject(
				output,
				[
					"target",
					"pathHash",
					"precondition",
					"expectedOldContentHash",
					"pendingContentHash",
					"finalContentHash",
					"desiredRootGeneration",
					"publicationOrder",
				],
				"root mutation output",
			);
			if (
				typeof entry.target !== "string" ||
				!["old_root", "new_root"].includes(entry.target) ||
				typeof entry.precondition !== "string" ||
				!["missing", "present"].includes(entry.precondition) ||
				(entry.expectedOldContentHash !== null &&
					(typeof entry.expectedOldContentHash !== "string" ||
						!/^[0-9a-f]{64}$/.test(entry.expectedOldContentHash))) ||
				["pathHash", "pendingContentHash", "finalContentHash"].some(
					key => typeof entry[key] !== "string" || !/^[0-9a-f]{64}$/.test(entry[key] as string),
				) ||
				entry.pendingContentHash === entry.finalContentHash ||
				typeof entry.desiredRootGeneration !== "number" ||
				!Number.isSafeInteger(entry.desiredRootGeneration) ||
				entry.desiredRootGeneration < 1 ||
				(entry.publicationOrder !== 1 && entry.publicationOrder !== 2)
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "invalid root mutation output");
			if (
				targets.has(entry.target) ||
				publicationOrders.has(entry.publicationOrder) ||
				(entry.precondition === "missing" && entry.expectedOldContentHash !== null) ||
				(entry.precondition === "present" && entry.expectedOldContentHash === null)
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "inconsistent root mutation outputs");
			targets.add(entry.target);
			publicationOrders.add(entry.publicationOrder);
		}
		const action = stringField(object, "action");
		const oldRootId = object.oldRootId;
		const newRootId = object.newRootId;
		if (action === "move") {
			const orderedTargets = outputs.map(output => valueObject(output, "root mutation output"));
			if (
				typeof oldRootId !== "string" ||
				typeof newRootId !== "string" ||
				oldRootId === newRootId ||
				targets.size !== 2 ||
				orderedTargets.find(entry => entry.target === "new_root")?.publicationOrder !== 1 ||
				orderedTargets.find(entry => entry.target === "old_root")?.publicationOrder !== 2 ||
				orderedTargets.find(entry => entry.target === "new_root")?.precondition !== "missing" ||
				orderedTargets.find(entry => entry.target === "old_root")?.precondition !== "present"
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "move mutation outputs must publish new then old");
		} else if (action === "enable") {
			const output = valueObject(outputs[0], "root mutation output");
			if (
				oldRootId !== null ||
				typeof newRootId !== "string" ||
				targets.size !== 1 ||
				!targets.has("new_root") ||
				!publicationOrders.has(1) ||
				output.precondition !== "missing"
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "enable mutation output contract is invalid");
		} else if (action === "disable") {
			const output = valueObject(outputs[0], "root mutation output");
			if (
				typeof oldRootId !== "string" ||
				newRootId !== null ||
				targets.size !== 1 ||
				!targets.has("old_root") ||
				!publicationOrders.has(1) ||
				output.precondition !== "present"
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "disable mutation output contract is invalid");
		} else {
			const output = valueObject(outputs[0], "root mutation output");
			if (
				action !== "set_context" ||
				typeof oldRootId !== "string" ||
				newRootId !== oldRootId ||
				targets.size !== 1 ||
				!targets.has("new_root") ||
				!publicationOrders.has(1) ||
				output.precondition !== "present"
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "set_context mutation output contract is invalid");
		}
	}
	if (schema === "gjc-bugwatch-store-operation-core/v1") {
		const members = object.members;
		if (!Array.isArray(members) || members.length !== 3)
			throw new BugwatchContractError("INVALID_SCHEMA", "store operation must declare db, wal, and shm members");
		const memberNames = new Set<string>();
		const pathHashes = new Set<string>();
		for (const memberValue of members) {
			const member = exactObject(
				memberValue,
				["member", "sourcePathHash", "expectedPresence", "expectedSize", "expectedHash", "quarantinePathHash"],
				"store operation member",
			);
			const name = stringField(member, "member");
			if (
				memberNames.has(name) ||
				!["db", "wal", "shm"].includes(name) ||
				typeof member.expectedPresence !== "boolean" ||
				(member.expectedSize !== null &&
					(typeof member.expectedSize !== "number" ||
						!Number.isSafeInteger(member.expectedSize) ||
						member.expectedSize < 0)) ||
				(member.expectedHash !== null &&
					!/^[0-9a-f]{64}$/.test(boundedString(member.expectedHash, "expectedHash"))) ||
				member.expectedPresence !== (member.expectedSize !== null && member.expectedHash !== null)
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "invalid store operation member");
			const sourcePathHash = parseHash(member, "sourcePathHash");
			const quarantinePathHash = parseHash(member, "quarantinePathHash");
			if (
				sourcePathHash === quarantinePathHash ||
				pathHashes.has(sourcePathHash) ||
				pathHashes.has(quarantinePathHash)
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "store operation paths must be distinct");
			memberNames.add(name);
			pathHashes.add(sourcePathHash);
			pathHashes.add(quarantinePathHash);
		}
	}
	if (schema === "gjc-bugwatch-monitor-disable-receipt/v1") {
		const steps = object.steps;
		if (!Array.isArray(steps) || steps.length > 1024)
			throw new BugwatchContractError("INVALID_SCHEMA", "steps must be a bounded array");
		for (const step of steps) {
			const entry = exactObject(
				step,
				["name", "attempted", "ok", "evidenceHash", "errorCode"],
				"monitor disable step",
			);
			boundedString(entry.name, "step name");
			booleanField(entry, "attempted");
			booleanField(entry, "ok");
			for (const key of ["evidenceHash", "errorCode"] as const) {
				if (entry[key] !== null) {
					const text = boundedString(entry[key], key);
					if (key === "evidenceHash" && !/^[0-9a-f]{64}$/.test(text))
						throw new BugwatchContractError("INVALID_SCHEMA", "step evidenceHash must be lowercase SHA-256 hex");
				}
			}
		}
	}
	if (schema === "gjc-bugwatch-authority-snapshot/v2") {
		const cutoff = exactObject(
			object.cutoff,
			[
				"operationId",
				"quiesceTokenHash",
				"cutoffAt",
				"sqliteBackupHash",
				"schemaMetaHash",
				"sourceWatermarksHash",
				"registryFrontiersHash",
				"inboxFrontierHash",
				"emergencyFrontierHash",
				"rollbackSpoolFrontierHash",
				"artifactFrontierHash",
			],
			"snapshot cutoff",
		);
		for (const [key, value] of Object.entries(cutoff)) {
			const text = boundedString(value, key);
			if (key.endsWith("Hash") && !/^[0-9a-f]{64}$/.test(text))
				throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be lowercase SHA-256 hex`);
			if (key === "cutoffAt") canonicalUtcTimestamp(text, key);
		}
		const classes = object.classes;
		if (!Array.isArray(classes) || classes.length !== AUTHORITY_CLASS_NAMES.length)
			throw new BugwatchContractError("INVALID_SCHEMA", "snapshot must contain every authority class exactly once");
		const seen = new Set<string>();
		for (const entryValue of classes) {
			const entry = exactObject(
				entryValue,
				["className", "mode", "itemCount", "byteCount", "itemsSha256", "classDigest", "reconstructiveSource"],
				"snapshot class entry",
			);
			const className = stringField(entry, "className");
			const expectedClassName = AUTHORITY_CLASS_NAMES[seen.size];
			if (className !== expectedClassName)
				throw new BugwatchContractError("INVALID_SCHEMA", "snapshot classes must use canonical order");
			seen.add(className);
			const mode = stringField(entry, "mode");
			const policy = AUTHORITY_SNAPSHOT_POLICY[className as AuthorityClassV1];
			if (mode !== policy.mode || entry.reconstructiveSource !== policy.reconstructiveSource)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"snapshot class mode or reconstructive source is not permitted",
				);
			if (!Number.isSafeInteger(numberField(entry, "itemCount")) || numberField(entry, "itemCount") < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "invalid snapshot class item count");
			if (!Number.isSafeInteger(numberField(entry, "byteCount")) || numberField(entry, "byteCount") < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "invalid snapshot class byte count");
			parseHash(entry, "itemsSha256");
			parseHash(entry, "classDigest");
		}
	}
}
function parseHash(object: { [key: string]: JsonValue }, key: string): string {
	const value = boundedString(object[key], key);
	if (!/^[0-9a-f]{64}$/.test(value))
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be lowercase SHA-256 hex`);
	return value;
}
function isExactCronLine(line: string): boolean {
	return line.endsWith("\n") && line.length > 1 && !/[\r\0\n]/.test(line.slice(0, -1));
}
function isFatalKeyId(value: string): boolean {
	return /^[0-9a-f]{32}$/.test(value);
}
function requireFatalKeyId(value: string, key: string): void {
	if (!isFatalKeyId(value))
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a lowercase derived key ID`);
}
function isExactUtf8(bytes: Uint8Array, value: string): boolean {
	const encoded = new TextEncoder().encode(value);
	return encoded.byteLength === bytes.byteLength && encoded.every((byte, index) => byte === bytes[index]);
}

function decodeCanonicalBase64(value: JsonValue, key: string): Uint8Array {
	const encoded = boundedString(value, key);
	if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be canonical Base64`);
	const decoded = Buffer.from(encoded, "base64");
	if (decoded.byteLength === 0 || decoded.toString("base64") !== encoded)
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be non-empty canonical Base64`);
	return decoded;
}

function parseUniqueStringArray(value: JsonValue, key: string): string[] {
	const entries = parseStringArray(value, key);
	if (entries.length === 0 || new Set(entries).size !== entries.length)
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a non-empty unique string array`);
	return entries;
}

function parseStringArray(value: JsonValue, key: string): string[] {
	if (!Array.isArray(value) || value.length > 1024)
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a bounded string array`);
	return value.map((entry, index) => boundedString(entry, `${key}[${index}]`));
}

export function parseCaptureAuthorityV1(input: string | JsonValue): CaptureAuthorityV1 {
	const value = typeof input === "string" ? parseCanonicalJson(input) : input;
	const object = valueObject(value, "capture authority");
	if (stringField(object, "schema") !== "gjc-bugwatch-capture/v1")
		throw new BugwatchContractError("UNSUPPORTED_SCHEMA", "Unsupported capture authority schema");
	const state = stringField(object, "state");
	if (state === "captured") {
		const entry = exactObject(
			object,
			[
				"schema",
				"state",
				"scopeId",
				"policyGeneration",
				"policyHash",
				"bootCoreHash",
				"transportEpoch",
				"transportStartHash",
				"durableChannel",
				"keyId",
			],
			"captured authority",
		);
		const durableChannel = stringField(entry, "durableChannel");
		if (durableChannel !== "file" && durableChannel !== "fatal_inbox")
			throw new BugwatchContractError("INVALID_SCHEMA", "durableChannel is not allowed");
		const policyGeneration = numberField(entry, "policyGeneration");
		const transportEpoch = numberField(entry, "transportEpoch");
		if (policyGeneration < 1 || transportEpoch < 1)
			throw new BugwatchContractError("INVALID_SCHEMA", "policy generation and transport epoch must be positive");
		return {
			schema: "gjc-bugwatch-capture/v1",
			state,
			scopeId: boundedString(entry.scopeId, "scopeId"),
			policyGeneration,
			policyHash: parseHash(entry, "policyHash"),
			bootCoreHash: parseHash(entry, "bootCoreHash"),
			transportEpoch,
			transportStartHash: parseHash(entry, "transportStartHash"),
			durableChannel,
			keyId: boundedString(entry.keyId, "keyId"),
		};
	}
	if (state !== "disabled" && state !== "unpublished" && state !== "transport_excluded")
		throw new BugwatchContractError("INVALID_SCHEMA", "capture state is not allowed");
	const entry = exactObject(object, ["schema", "state", "reason"], "unavailable capture authority");
	const reason = stringField(entry, "reason");
	if (reason === "daemon_disabled" || reason === "manifest_unavailable" || reason === "file_transport_disabled") {
		return { schema: "gjc-bugwatch-capture/v1", state, reason };
	}
	throw new BugwatchContractError("INVALID_SCHEMA", "capture reason is not allowed");
}
export function parseMonitorDisableActionV1(input: string | JsonValue): MonitorDisableActionV1 {
	const value = typeof input === "string" ? parseCanonicalJson(input) : input;
	const object = valueObject(value, "monitor disable action");
	const kind = stringField(object, "kind");
	if (kind === "gjc_cron") {
		const entry = exactObject(
			object,
			["kind", "ownerSessionId", "ownerPid", "ownerPidStartToken", "cronId", "expression", "promptHash"],
			kind,
		);
		return {
			kind,
			ownerSessionId: boundedString(entry.ownerSessionId, "ownerSessionId"),
			ownerPid: pidField(entry, "ownerPid"),
			ownerPidStartToken: boundedString(entry.ownerPidStartToken, "ownerPidStartToken"),
			cronId: boundedString(entry.cronId, "cronId"),
			expression: boundedString(entry.expression, "expression"),
			promptHash: parseHash(entry, "promptHash"),
		};
	}
	if (kind === "user_cron") {
		const entry = exactObject(
			object,
			[
				"kind",
				"expectedCrontabHash",
				"markerLineHash",
				"jobLineHash",
				"markerLineBytesBase64",
				"jobLineBytesBase64",
			],
			kind,
		);
		const markerLineBytes = decodeCanonicalBase64(entry.markerLineBytesBase64, "markerLineBytesBase64");
		const jobLineBytes = decodeCanonicalBase64(entry.jobLineBytesBase64, "jobLineBytesBase64");
		const markerLine = new TextDecoder().decode(markerLineBytes);
		const jobLine = new TextDecoder().decode(jobLineBytes);
		if (
			markerLineBytes.byteLength > 4096 ||
			jobLineBytes.byteLength > 4096 ||
			!/^# gjc-bugwatch [A-Za-z0-9_-]{1,256}\n$/.test(markerLine) ||
			!isExactCronLine(markerLine) ||
			!isExactUtf8(markerLineBytes, markerLine) ||
			!isExactUtf8(jobLineBytes, jobLine) ||
			!isExactCronLine(jobLine) ||
			markerLine === jobLine
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"user_cron requires distinct bounded bugwatch marker and job lines",
			);
		const markerLineHash = parseHash(entry, "markerLineHash");
		const jobLineHash = parseHash(entry, "jobLineHash");
		if (sha256Hex(markerLineBytes) !== markerLineHash || sha256Hex(jobLineBytes) !== jobLineHash)
			throw new BugwatchContractError("INVALID_HASH", "user_cron line bytes do not match declared hashes");
		return {
			kind,
			expectedCrontabHash: parseHash(entry, "expectedCrontabHash"),
			markerLineHash,
			jobLineHash,
			markerLineBytesBase64: boundedString(entry.markerLineBytesBase64, "markerLineBytesBase64"),
			jobLineBytesBase64: boundedString(entry.jobLineBytesBase64, "jobLineBytesBase64"),
		};
	}
	if (kind === "process" || kind === "process_force") {
		const entry = exactObject(
			object,
			["kind", "pid", "pidStartToken", "uid", "executableHash", "argvHash", "signal"],
			kind,
		);
		const signal = stringField(entry, "signal");
		if ((kind === "process" && signal !== "TERM") || (kind === "process_force" && signal !== "KILL"))
			throw new BugwatchContractError("INVALID_SCHEMA", "process action kind and signal must match");
		if (kind === "process") {
			return {
				kind,
				pid: pidField(entry, "pid"),
				pidStartToken: boundedString(entry.pidStartToken, "pidStartToken"),
				uid: boundedString(entry.uid, "uid"),
				executableHash: parseHash(entry, "executableHash"),
				argvHash: parseHash(entry, "argvHash"),
				signal: "TERM",
			};
		}
		return {
			kind,
			pid: pidField(entry, "pid"),
			pidStartToken: boundedString(entry.pidStartToken, "pidStartToken"),
			uid: boundedString(entry.uid, "uid"),
			executableHash: parseHash(entry, "executableHash"),
			argvHash: parseHash(entry, "argvHash"),
			signal: "KILL",
		};
	}
	if (kind === "tmux_pane") {
		const entry = exactObject(
			object,
			["kind", "serverIdentityHash", "paneId", "sessionId", "tagHash", "commandHash"],
			kind,
		);
		return {
			kind,
			serverIdentityHash: parseHash(entry, "serverIdentityHash"),
			paneId: boundedString(entry.paneId, "paneId"),
			sessionId: boundedString(entry.sessionId, "sessionId"),
			tagHash: parseHash(entry, "tagHash"),
			commandHash: parseHash(entry, "commandHash"),
		};
	}
	if (kind === "tmux_session") {
		const entry = exactObject(
			object,
			["kind", "serverIdentityHash", "sessionId", "paneIds", "allPaneTagsHash"],
			kind,
		);
		return {
			kind,
			serverIdentityHash: parseHash(entry, "serverIdentityHash"),
			sessionId: boundedString(entry.sessionId, "sessionId"),
			paneIds: parseUniqueStringArray(entry.paneIds, "paneIds"),
			allPaneTagsHash: parseHash(entry, "allPaneTagsHash"),
		};
	}
	if (kind === "plugin_feature") {
		const entry = exactObject(
			object,
			[
				"kind",
				"pluginName",
				"pluginVersion",
				"pluginPathHash",
				"manifestHash",
				"expectedRuntimeConfigGeneration",
				"expectedRuntimeConfigHash",
				"feature",
				"from",
				"to",
			],
			kind,
		);
		if (
			entry.feature !== "bugwatchAutomation.enabled" ||
			entry.from !== true ||
			entry.to !== false ||
			numberField(entry, "expectedRuntimeConfigGeneration") < 1
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "invalid plugin feature action");
		return {
			kind,
			pluginName: boundedString(entry.pluginName, "pluginName"),
			pluginVersion: boundedString(entry.pluginVersion, "pluginVersion"),
			pluginPathHash: parseHash(entry, "pluginPathHash"),
			manifestHash: parseHash(entry, "manifestHash"),
			expectedRuntimeConfigGeneration: numberField(entry, "expectedRuntimeConfigGeneration"),
			expectedRuntimeConfigHash: parseHash(entry, "expectedRuntimeConfigHash"),
			feature: "bugwatchAutomation.enabled",
			from: true,
			to: false,
		};
	}
	if (kind === "systemd_user") {
		const entry = exactObject(object, ["kind", "units", "operation"], kind);
		if (
			entry.operation !== "disable_now" ||
			!Array.isArray(entry.units) ||
			entry.units.length === 0 ||
			entry.units.length > 2
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "invalid systemd action");
		const names = new Set<string>();
		const units = entry.units.map(unit => {
			const parsed = exactObject(
				unit,
				["name", "expectedPropertiesHash", "expectedFragmentPathHash"],
				"systemd unit",
			);
			const name = stringField(parsed, "name");
			if ((name !== "gjc-bugwatch.service" && name !== "gjc-bugwatch.timer") || names.has(name))
				throw new BugwatchContractError("INVALID_SCHEMA", "invalid or duplicate systemd unit name");
			names.add(name);
			const unitName: "gjc-bugwatch.service" | "gjc-bugwatch.timer" = name;
			return {
				name: unitName,
				expectedPropertiesHash: parseHash(parsed, "expectedPropertiesHash"),
				expectedFragmentPathHash: parseHash(parsed, "expectedFragmentPathHash"),
			};
		});
		return { kind, units, operation: "disable_now" };
	}
	throw new BugwatchContractError("INVALID_SCHEMA", "unsupported monitor disable action kind");
}
function monitorAdapterKind(action: MonitorDisableActionV1): MonitorInventoryV1["kind"] {
	if (action.kind === "process" || action.kind === "process_force") return "process";
	if (action.kind === "tmux_pane" || action.kind === "tmux_session") return "tmux";
	if (action.kind === "plugin_feature") return "plugin";
	return action.kind;
}
export function parseMonitorDisableAuthorizationV1(input: string | JsonValue): MonitorDisableAuthorizationV1 {
	const authorization = parseEnvelope<MonitorDisableAuthorizationV1>(input, "gjc-bugwatch-monitor-disable-auth/v1", [
		"schema",
		"scopeId",
		"authorizationId",
		"inventoryEpochId",
		"monitorId",
		"adapterKind",
		"stableIdentifier",
		"expectedConfigHash",
		"allowedAction",
		"authorizedAt",
		"expiresAt",
		"nonce",
		"keyId",
		"mac",
	]);
	const allowedAction = parseMonitorDisableActionV1(authorization.allowedAction as unknown as JsonValue);
	if (authorization.adapterKind !== monitorAdapterKind(allowedAction))
		throw new BugwatchContractError(
			"INVALID_SCHEMA",
			"monitor authorization adapter kind does not match allowed action",
		);
	if (authorization.expiresAt <= authorization.authorizedAt)
		throw new BugwatchContractError("INVALID_SCHEMA", "monitor authorization expiry must follow authorization");
	return { ...authorization, allowedAction };
}

function parseEnvelope<T>(input: string | JsonValue, schema: string, keys: readonly string[]): T {
	const value = typeof input === "string" ? parseCanonicalJson(input) : input;
	const object = exactObject(value, keys, schema);
	if (stringField(object, "schema") !== schema)
		throw new BugwatchContractError("UNSUPPORTED_SCHEMA", `Unsupported schema: ${stringField(object, "schema")}`);
	validateEnvelopeFields(object, schema);
	validateNestedEnvelopeFields(object, schema);
	return object as unknown as T;
}
export function parseScopePolicyRevisionV2(input: string | JsonValue): ScopePolicyRevisionV2 {
	const revision = parseEnvelope<ScopePolicyRevisionV2>(input, "gjc-bugwatch-policy-revision/v2", [
		"schema",
		"scopeId",
		"generation",
		"semantic",
		"contentHash",
		"previousGeneration",
		"previousRevisionHash",
		"previousContentHash",
		"casTokenHash",
		"createdAt",
		"writerId",
		"keyId",
		"mac",
	]);
	if (!Number.isInteger(revision.generation) || revision.generation < 1)
		throw new BugwatchContractError("INVALID_SCHEMA", "policy generation must be a positive integer");
	parsePolicySemanticV1(revision.semantic as unknown as JsonValue);
	parseHash(revision as unknown as { [key: string]: JsonValue }, "contentHash");
	parseHash(revision as unknown as { [key: string]: JsonValue }, "casTokenHash");
	if (
		(revision.generation === 1) !==
		(revision.previousGeneration === null &&
			revision.previousRevisionHash === null &&
			revision.previousContentHash === null)
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "policy predecessor fields are inconsistent");
	if (
		revision.generation > 1 &&
		(revision.previousGeneration !== revision.generation - 1 ||
			revision.previousRevisionHash === null ||
			revision.previousContentHash === null)
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "policy predecessor fields are inconsistent");
	if (revision.semantic.scopeId !== revision.scopeId)
		throw new BugwatchContractError("INVALID_SCHEMA", "policy semantic scope must match revision scope");
	return revision;
}
export function parseScopePolicyHeadV2(input: string | JsonValue): ScopePolicyHeadV2 {
	const head = parseEnvelope<ScopePolicyHeadV2>(input, "gjc-bugwatch-policy-head/v2", [
		"schema",
		"scopeId",
		"generation",
		"revisionHash",
		"contentHash",
		"casToken",
		"updatedAt",
		"keyId",
		"mac",
	]);
	if (!Number.isInteger(head.generation) || head.generation < 1)
		throw new BugwatchContractError("INVALID_SCHEMA", "policy head generation must be a positive integer");
	parseHash(head as unknown as { [key: string]: JsonValue }, "revisionHash");
	parseHash(head as unknown as { [key: string]: JsonValue }, "contentHash");
	return head;
}
export function parseBootCoreV1(input: string | JsonValue): BootCoreV1 {
	const core = parseEnvelope<BootCoreV1>(input, "gjc-bugwatch-boot-core/v1", [
		"schema",
		"scopeId",
		"bootId",
		"bootTokenHash",
		"pid",
		"pidStartToken",
		"producer",
		"startedAt",
		"initialPolicyGeneration",
		"initialPolicyHash",
		"fatalKeyId",
		"gjcVersion",
		"buildSha",
		"sequenceOrigin",
		"maxSequence",
		"keyId",
		"mac",
	]);
	if (core.initialPolicyGeneration < 1)
		throw new BugwatchContractError("OUT_OF_RANGE", "initial policy generation must be positive");
	if (!isFatalKeyId(core.fatalKeyId) || !isFatalKeyId(core.keyId))
		throw new BugwatchContractError("INVALID_SCHEMA", "boot key IDs must be lowercase derived key IDs");
	return core;
}
export function parseBootTransportStartV1(input: string | JsonValue): BootTransportStartV1 {
	const start = parseEnvelope<BootTransportStartV1>(input, "gjc-bugwatch-transport-start/v1", [
		"schema",
		"scopeId",
		"bootId",
		"bootCoreHash",
		"transportEpoch",
		"policyGeneration",
		"policyHash",
		"startSequence",
		"startedAt",
		"fileEnabled",
		"keyId",
		"previousRecordHash",
		"mac",
	]);
	if (start.transportEpoch < 1 || start.policyGeneration < 1)
		throw new BugwatchContractError("OUT_OF_RANGE", "transport epoch and policy generation must be positive");
	return start;
}
export function parseBootTransportCloseV1(input: string | JsonValue): BootTransportCloseV1 {
	const close = parseEnvelope<BootTransportCloseV1>(input, "gjc-bugwatch-transport-close/v1", [
		"schema",
		"scopeId",
		"bootId",
		"bootCoreHash",
		"transportEpoch",
		"startRecordHash",
		"endSequenceInclusive",
		"endedAt",
		"outcome",
		"keyId",
		"previousRecordHash",
		"mac",
	]);
	if (close.transportEpoch < 1) throw new BugwatchContractError("OUT_OF_RANGE", "transportEpoch must be positive");
	return close;
}
export const parseBootFinalV1 = (input: string | JsonValue): BootFinalV1 =>
	parseEnvelope(input, "gjc-bugwatch-boot-final/v1", [
		"schema",
		"scopeId",
		"bootId",
		"bootCoreHash",
		"finalSequence",
		"endedAt",
		"state",
		"lastTransportRecordHash",
		"attachmentSnapshotHash",
		"keyId",
		"previousRecordHash",
		"mac",
	]);
export function parseRootControlV1(input: string | JsonValue): RootControlV1 {
	const root = parseEnvelope<RootControlV1>(input, "gjc-bugwatch-root/v1", [
		"schema",
		"scopeId",
		"rootId",
		"canonicalPath",
		"enabled",
		"persistContext",
		"generation",
		"projectPolicyHash",
		"baselineEpochId",
		"activeMutationId",
		"updatedAt",
		"nonce",
		"keyId",
		"mac",
	]);
	if (root.generation < 1) throw new BugwatchContractError("OUT_OF_RANGE", "root generation must be positive");
	return root;
}
export function parseFatalEnvelopeV1(input: string | JsonValue): FatalEnvelopeV1 {
	const fatal = parseEnvelope<FatalEnvelopeV1>(input, "gjc-bugwatch-fatal/v1", [
		"schema",
		"scopeId",
		"category",
		"keyId",
		"bootId",
		"recordSeq",
		"eventId",
		"crashCorrelationId",
		"kind",
		"occurredAt",
		"producer",
		"attachmentId",
		"rootId",
		"sessionId",
		"severity",
		"message",
		"stackTop",
		"redactionVersion",
		"fatalCoreHash",
		"mac",
	]);
	requireFatalKeyId(fatal.keyId, "keyId");
	if (!/^[0-9a-f]{64}$/.test(fatal.eventId) || fatal.eventId !== computeEventId(fatal.bootId, fatal.recordSeq))
		throw new BugwatchContractError("INVALID_SCHEMA", "fatal eventId does not match its boot reservation");
	if (fatal.fatalCoreHash !== fatalCoreHash(fatal as unknown as JsonValue))
		throw new BugwatchContractError("INVALID_HASH", "fatalCoreHash does not match fatal core");
	if (!isBugwatchTextRedacted(fatal.message) || (fatal.stackTop !== null && !isBugwatchTextRedacted(fatal.stackTop)))
		throw new BugwatchContractError("INVALID_SCHEMA", "fatal text must already be deterministically redacted");
	if (fatal.message.length > 4096 || (fatal.stackTop !== null && fatal.stackTop.length > 4096))
		throw new BugwatchContractError("OUT_OF_RANGE", "fatal text exceeds the inbox field limit");
	if (
		new TextEncoder().encode(`${canonicalizeJson(fatal as unknown as JsonValue)}\n`).byteLength > INBOX_ENVELOPE_BYTES
	)
		throw new BugwatchContractError("OUT_OF_RANGE", "fatal envelope exceeds inbox byte limit");
	return fatal;
}
export function parseFatalEnvelopeSlotBytesV1(bytes: Uint8Array): FatalEnvelopeV1 {
	if (bytes.byteLength > INBOX_ENVELOPE_BYTES)
		throw new BugwatchContractError("OUT_OF_RANGE", "fatal slot bytes exceed inbox byte limit");
	if (bytes.byteLength < 2 || bytes[bytes.byteLength - 1] !== 0x0a)
		throw new BugwatchContractError("INVALID_JSON", "fatal slot bytes must end with exactly one LF");
	const jsonBytes = bytes.subarray(0, -1);
	const json = new TextDecoder().decode(jsonBytes);
	if (!isExactUtf8(jsonBytes, json))
		throw new BugwatchContractError("INVALID_JSON", "fatal slot bytes must be exact UTF-8");
	return parseFatalEnvelopeV1(parseCanonicalJson(json));
}
export function parseLeaseV1(input: string | JsonValue): LeaseV1 {
	const lease = parseEnvelope<LeaseV1>(input, "gjc-bugwatch-lease/v1", [
		"schema",
		"scopeId",
		"claimTokenHash",
		"ownerId",
		"role",
		"pid",
		"pidStartToken",
		"executableFingerprint",
		"protocolMajor",
		"storeMin",
		"storeMax",
		"phase",
		"heartbeatAt",
		"policyGeneration",
		"policyHash",
		"rollbackState",
		"keyId",
		"mac",
	]);
	if (
		lease.protocolMajor < 1 ||
		lease.storeMin < 1 ||
		lease.storeMax < lease.storeMin ||
		lease.policyGeneration < 1 ||
		!["daemon", "fallback"].includes(lease.role) ||
		!["claiming", "published", "quiescing"].includes(lease.phase) ||
		!["none", "quiescing", "exporting", "fallback_active", "complete", "failed"].includes(lease.rollbackState)
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "lease compatibility or liveness fields are invalid");
	return lease;
}
export function parseFatalKeyringV1(input: string | JsonValue): FatalKeyringV1 {
	const keyring = parseEnvelope<FatalKeyringV1>(input, "gjc-bugwatch-fatal-keyring/v1", [
		"schema",
		"scopeId",
		"currentKeyId",
		"previousKeyIds",
		"casToken",
		"revision",
		"updatedAt",
	]);
	if (
		keyring.revision < 1 ||
		!isFatalKeyId(keyring.currentKeyId) ||
		!Array.isArray(keyring.previousKeyIds) ||
		keyring.previousKeyIds.length > 1024 ||
		keyring.previousKeyIds.some(keyId => typeof keyId !== "string" || !isFatalKeyId(keyId)) ||
		new Set(keyring.previousKeyIds).size !== keyring.previousKeyIds.length ||
		keyring.previousKeyIds.includes(keyring.currentKeyId)
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "invalid fatal keyring CAS history");
	return keyring;
}
export function parseStoreOperationCoreV1(input: string | JsonValue): StoreOperationCoreV1 {
	const core = parseEnvelope<StoreOperationCoreV1>(input, "gjc-bugwatch-store-operation-core/v1", [
		"schema",
		"scopeId",
		"operationId",
		"ownerId",
		"claimTokenHash",
		"kind",
		"fromVersion",
		"toVersion",
		"members",
		"startedAt",
		"keyId",
		"mac",
	]);
	if (
		!["migrate", "restore", "quarantine", "rebuild"].includes(core.kind) ||
		core.fromVersion < 1 ||
		(core.kind === "migrate") !== (core.toVersion !== null) ||
		(core.toVersion !== null && (core.toVersion < 1 || core.toVersion === core.fromVersion))
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "invalid immutable store operation core");
	return core;
}
export function parseStoreOperationStepV1(input: string | JsonValue): StoreOperationStepV1 {
	const step = parseEnvelope<StoreOperationStepV1>(input, "gjc-bugwatch-store-operation-step/v1", [
		"schema",
		"scopeId",
		"operationId",
		"coreHash",
		"stepIndex",
		"member",
		"action",
		"expectedSourceHash",
		"observedDestinationHash",
		"previousStepHash",
		"occurredAt",
		"keyId",
		"mac",
	]);
	if (
		!["db", "wal", "shm"].includes(step.member) ||
		!["move_intent", "move_complete", "verified_absent"].includes(step.action) ||
		(step.action === "move_intent" && (step.expectedSourceHash === null || step.observedDestinationHash !== null)) ||
		(step.action === "move_complete" &&
			(step.expectedSourceHash === null || step.observedDestinationHash === null)) ||
		(step.action === "verified_absent" && (step.expectedSourceHash !== null || step.observedDestinationHash !== null))
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "invalid chained store operation step");
	return step;
}
export function parseRollbackBundleV1(input: string | JsonValue): RollbackBundleV1 {
	const bundle = parseEnvelope<RollbackBundleV1>(input, "gjc-bugwatch-rollback-bundle/v1", [
		"schema",
		"scopeId",
		"epochId",
		"roleTransitionTokenHash",
		"bundleVersion",
		"state",
		"manifestHash",
		"itemCount",
		"byteCount",
		"itemsDigest",
		"sourceWatermarkHash",
		"createdAt",
		"exportedAt",
		"keyId",
		"mac",
	]);
	const exported = ["exported", "released", "fallback_active", "importing", "complete"].includes(bundle.state);
	if (
		bundle.bundleVersion !== 1 ||
		![
			"quiescing",
			"exporting",
			"exported",
			"released",
			"fallback_active",
			"importing",
			"complete",
			"failed",
		].includes(bundle.state) ||
		exported !==
			(bundle.manifestHash !== null &&
				bundle.itemsDigest !== null &&
				bundle.sourceWatermarkHash !== null &&
				bundle.exportedAt !== null) ||
		(!exported &&
			(bundle.manifestHash !== null ||
				bundle.itemsDigest !== null ||
				bundle.sourceWatermarkHash !== null ||
				bundle.exportedAt !== null)) ||
		bundle.itemCount > 100_000 ||
		bundle.byteCount > 67_108_864
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "invalid bounded rollback bundle");
	return bundle;
}
export type RollbackKeyResolverV1 = (keyId: string) => Uint8Array | undefined;

function requireRollbackKey(keyForId: RollbackKeyResolverV1, keyId: string): Uint8Array {
	const key = keyForId(keyId);
	if (key === undefined) throw new BugwatchContractError("INVALID_SCHEMA", "rollback envelope key is unavailable");
	return key;
}

export function verifyRollbackBundleV1(
	bundleInput: string | JsonValue,
	itemsInput: readonly (string | JsonValue)[],
	keyForId: RollbackKeyResolverV1,
): void {
	const bundle = parseRollbackBundleV1(bundleInput);
	verifyMac(
		bundle as unknown as JsonValue,
		"gjc-bugwatch-rollback-bundle-v1",
		requireRollbackKey(keyForId, bundle.keyId),
	);
	if (!["exported", "released", "fallback_active", "importing", "complete"].includes(bundle.state))
		throw new BugwatchContractError("INVALID_SCHEMA", "only exported rollback bundles are reconstructive");
	if (itemsInput.length !== bundle.itemCount)
		throw new BugwatchContractError("INVALID_SCHEMA", "bundle item count does not match bundle");
	let byteCount = 0;
	let previousItemHash: string | null = null;
	const hashes: string[] = [];
	for (let index = 0; index < itemsInput.length; index++) {
		const item = parseRollbackBundleItemV1(itemsInput[index]);
		verifyMac(
			item as unknown as JsonValue,
			"gjc-bugwatch-rollback-bundle-item-v1",
			requireRollbackKey(keyForId, item.keyId),
		);
		if (
			item.scopeId !== bundle.scopeId ||
			item.epochId !== bundle.epochId ||
			item.itemIndex !== index ||
			item.previousItemHash !== previousItemHash
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "bundle item order or chain is invalid");
		byteCount += new TextEncoder().encode(canonicalizeJson(item as unknown as JsonValue)).byteLength + 1;
		hashes.push(item.itemHash);
		previousItemHash = item.itemHash;
	}
	const digest = sha256Hex(hashes.join("\n"));
	if (byteCount !== bundle.byteCount || bundle.itemsDigest !== digest || bundle.manifestHash !== digest)
		throw new BugwatchContractError("INVALID_HASH", "rollback bundle manifest does not match reconstructive items");
}
export function parseRollbackSpoolManifestV1(input: string | JsonValue): RollbackSpoolManifestV1 {
	const manifest = parseEnvelope<RollbackSpoolManifestV1>(input, "gjc-bugwatch-rollback-spool-manifest/v1", [
		"schema",
		"scopeId",
		"epochId",
		"segmentIndex",
		"state",
		"itemCount",
		"byteCount",
		"itemsDigest",
		"previousManifestHash",
		"closedAt",
		"keyId",
		"mac",
	]);
	const closed = manifest.state === "closed";
	if (
		!["open", "closed", "quarantined"].includes(manifest.state) ||
		closed !== (manifest.itemsDigest !== null && manifest.closedAt !== null) ||
		manifest.itemCount > 100_000 ||
		manifest.byteCount > 67_108_864
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "invalid rollback spool manifest");
	return manifest;
}
function requireRollbackPayloadScope(payload: JsonValue, scopeId: string): { [key: string]: JsonValue } {
	const object = valueObject(payload, "rollback payload");
	if (boundedString(object.scopeId, "payload scopeId") !== scopeId)
		throw new BugwatchContractError("INVALID_SCHEMA", "rollback payload scope does not match item");
	return object;
}

function sqliteInteger(object: { [key: string]: JsonValue }, key: string): number {
	const value = object[key];
	if (typeof value !== "number" || !Number.isSafeInteger(value))
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a SQLite integer`);
	return value;
}

function sqliteText(object: { [key: string]: JsonValue }, key: string): string {
	const value = object[key];
	if (typeof value !== "string") throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be SQLite text`);
	return value;
}

function nullableSqliteText(object: { [key: string]: JsonValue }, key: string): string | null {
	const value = object[key];
	if (value !== null && typeof value !== "string")
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be SQLite text or null`);
	return value;
}

function nullableSqliteInteger(object: { [key: string]: JsonValue }, key: string): number | null {
	const value = object[key];
	if (value !== null && (typeof value !== "number" || !Number.isSafeInteger(value)))
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a SQLite integer or null`);
	return value;
}

function nullableHash(object: { [key: string]: JsonValue }, key: string): void {
	if (object[key] !== null) parseHash(object, key);
}

function sqliteBoolean(object: { [key: string]: JsonValue }, key: string): void {
	const value = object[key];
	if (typeof value !== "boolean") throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be boolean`);
}

function rollbackRow(
	payload: { [key: string]: JsonValue },
	keys: readonly string[],
	context: string,
): { [key: string]: JsonValue } {
	return exactObject(payload, ["scopeId", ...keys], context);
}

function enumField(object: { [key: string]: JsonValue }, key: string, values: readonly string[]): void {
	if (!values.includes(sqliteText(object, key))) throw new BugwatchContractError("INVALID_SCHEMA", `invalid ${key}`);
}

function validateRollbackPayload(item: RollbackBundleItemV1 | RollbackSpoolItemV1): void {
	const payload = requireRollbackPayloadScope(item.payload, item.scopeId);
	switch (item.itemType) {
		case "root": {
			const row = rollbackRow(
				payload,
				[
					"rootId",
					"kind",
					"canonicalPath",
					"enabled",
					"revision",
					"projectPolicyHash",
					"registeredAtMs",
					"disabledAtMs",
					"persistContext",
					"baselineEpochId",
					"activeMutationId",
				],
				"rollback root",
			);
			sqliteText(row, "rootId");
			enumField(row, "kind", ["project", "unattributed", "service"]);
			nullableSqliteText(row, "canonicalPath");
			sqliteBoolean(row, "enabled");
			if (sqliteInteger(row, "revision") < 1)
				throw new BugwatchContractError("INVALID_SCHEMA", "revision must be positive");
			parseHash(row, "projectPolicyHash");
			sqliteInteger(row, "registeredAtMs");
			nullableSqliteInteger(row, "disabledAtMs");
			sqliteBoolean(row, "persistContext");
			nullableSqliteText(row, "baselineEpochId");
			nullableSqliteText(row, "activeMutationId");
			if ((row.kind === "project") !== (row.canonicalPath !== null))
				throw new BugwatchContractError("INVALID_SCHEMA", "root kind and canonicalPath disagree");
			return;
		}
		case "root_alias": {
			const row = rollbackRow(
				payload,
				["oldRootId", "newRootId", "moveEpochId", "oldPathHash", "newPathHash", "createdAtMs"],
				"rollback root alias",
			);
			sqliteText(row, "oldRootId");
			sqliteText(row, "newRootId");
			sqliteText(row, "moveEpochId");
			parseHash(row, "oldPathHash");
			parseHash(row, "newPathHash");
			sqliteInteger(row, "createdAtMs");
			if (row.oldRootId === row.newRootId)
				throw new BugwatchContractError("INVALID_SCHEMA", "root alias identities must differ");
			return;
		}
		case "boot": {
			const row = rollbackRow(
				payload,
				[
					"bootId",
					"bootCoreHash",
					"pid",
					"pidStartToken",
					"producer",
					"startedAtMs",
					"initialPolicyGeneration",
					"initialPolicyHash",
					"fatalKeyId",
					"gjcVersion",
					"buildSha",
					"finalSeq",
					"finalState",
					"finalRecordHash",
				],
				"rollback producer boot",
			);
			sqliteText(row, "bootId");
			parseHash(row, "bootCoreHash");
			if (sqliteInteger(row, "pid") < 1) throw new BugwatchContractError("INVALID_SCHEMA", "pid must be positive");
			sqliteText(row, "pidStartToken");
			sqliteText(row, "producer");
			sqliteInteger(row, "startedAtMs");
			if (sqliteInteger(row, "initialPolicyGeneration") < 1)
				throw new BugwatchContractError("INVALID_SCHEMA", "initialPolicyGeneration must be positive");
			parseHash(row, "initialPolicyHash");
			sqliteText(row, "fatalKeyId");
			sqliteText(row, "gjcVersion");
			nullableSqliteText(row, "buildSha");
			const finalSeq = nullableSqliteInteger(row, "finalSeq");
			if (finalSeq !== null && finalSeq < 1)
				throw new BugwatchContractError("INVALID_SCHEMA", "finalSeq must be positive");
			if (row.finalState !== null)
				enumField(row, "finalState", ["clean", "crashed", "unknown_disable", "unknown_hard_kill"]);
			else nullableSqliteText(row, "finalState");
			nullableHash(row, "finalRecordHash");
			return;
		}
		case "attachment": {
			const row = rollbackRow(
				payload,
				[
					"attachmentId",
					"attachmentTokenHash",
					"bootId",
					"bootCoreHash",
					"rootId",
					"sessionId",
					"startedAtMs",
					"endedAtMs",
					"state",
					"managedSessionRoot",
					"sessionFile",
					"rootGeneration",
					"baselineEpochId",
					"publishSeq",
					"retireSeq",
					"currentTransitionHash",
				],
				"rollback session attachment",
			);
			sqliteText(row, "attachmentId");
			parseHash(row, "attachmentTokenHash");
			sqliteText(row, "bootId");
			parseHash(row, "bootCoreHash");
			sqliteText(row, "rootId");
			nullableSqliteText(row, "sessionId");
			const startedAtMs = sqliteInteger(row, "startedAtMs");
			const endedAtMs = nullableSqliteInteger(row, "endedAtMs");
			if (endedAtMs !== null && endedAtMs < startedAtMs)
				throw new BugwatchContractError("INVALID_SCHEMA", "endedAtMs precedes startedAtMs");
			enumField(row, "state", ["prepared", "active", "ended", "unknown", "aborted"]);
			nullableSqliteText(row, "managedSessionRoot");
			nullableSqliteText(row, "sessionFile");
			if (sqliteInteger(row, "rootGeneration") < 1)
				throw new BugwatchContractError("INVALID_SCHEMA", "rootGeneration must be positive");
			sqliteText(row, "baselineEpochId");
			nullableSqliteInteger(row, "publishSeq");
			nullableSqliteInteger(row, "retireSeq");
			parseHash(row, "currentTransitionHash");
			return;
		}
		case "coverage_range": {
			const row = rollbackRow(payload, ["bootId", "startSeq", "endSeq"], "rollback producer range");
			sqliteText(row, "bootId");
			const startSeq = sqliteInteger(row, "startSeq");
			const endSeq = sqliteInteger(row, "endSeq");
			if (startSeq < 1 || endSeq < startSeq)
				throw new BugwatchContractError("INVALID_SCHEMA", "invalid producer range");
			return;
		}
		case "source": {
			const row = rollbackRow(
				payload,
				[
					"segmentId",
					"generation",
					"sourceKind",
					"path",
					"fileIdentityHint",
					"prefixAnchorLength",
					"prefixHash",
					"committedOffset",
					"boundaryHash",
					"checkpointDigest",
					"validationState",
					"state",
					"blockId",
					"updatedAtMs",
				],
				"rollback source",
			);
			sqliteText(row, "segmentId");
			if (sqliteInteger(row, "generation") < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "generation must be non-negative");
			enumField(row, "sourceKind", ["log", "inbox", "rollback"]);
			sqliteText(row, "path");
			sqliteText(row, "fileIdentityHint");
			const prefixAnchorLength = sqliteInteger(row, "prefixAnchorLength");
			if (prefixAnchorLength < 0 || prefixAnchorLength > 4096)
				throw new BugwatchContractError("INVALID_SCHEMA", "invalid prefixAnchorLength");
			parseHash(row, "prefixHash");
			if (sqliteInteger(row, "committedOffset") < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "committedOffset must be non-negative");
			nullableHash(row, "boundaryHash");
			parseHash(row, "checkpointDigest");
			enumField(row, "validationState", ["unvalidated", "revalidating", "valid", "mismatch", "ambiguous"]);
			enumField(row, "state", [
				"active",
				"draining",
				"exhausted",
				"generation_changed",
				"orphaned",
				"quarantined",
				"archive_ambiguous",
				"capacity_blocked",
			]);
			nullableSqliteText(row, "blockId");
			sqliteInteger(row, "updatedAtMs");
			return;
		}
		case "source_checkpoint": {
			const row = rollbackRow(
				payload,
				["segmentId", "generation", "kind", "chunkIndex", "startOffset", "endOffset", "hash", "validatedAtMs"],
				"rollback source checkpoint",
			);
			sqliteText(row, "segmentId");
			if (sqliteInteger(row, "generation") < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "generation must be non-negative");
			enumField(row, "kind", ["chunk", "tail"]);
			if (
				sqliteInteger(row, "chunkIndex") < 0 ||
				sqliteInteger(row, "startOffset") < 0 ||
				sqliteInteger(row, "endOffset") <= sqliteInteger(row, "startOffset")
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "invalid source checkpoint offsets");
			parseHash(row, "hash");
			nullableSqliteInteger(row, "validatedAtMs");
			return;
		}
		case "archive_alias": {
			const row = rollbackRow(
				payload,
				[
					"archiveDigest",
					"uncompressedLength",
					"segmentId",
					"generation",
					"lineageKind",
					"verifiedCheckpointDigest",
					"createdAtMs",
				],
				"rollback archive alias",
			);
			parseHash(row, "archiveDigest");
			if (sqliteInteger(row, "uncompressedLength") < 0 || sqliteInteger(row, "generation") < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "invalid archive alias numeric field");
			sqliteText(row, "segmentId");
			enumField(row, "lineageKind", ["full", "prefix"]);
			parseHash(row, "verifiedCheckpointDigest");
			sqliteInteger(row, "createdAtMs");
			return;
		}
		case "physical_row": {
			const row = rollbackRow(
				payload,
				["segmentId", "generation", "endOffset", "rawHash", "bootId", "recordSeq", "eventId", "disposition"],
				"rollback physical row",
			);
			sqliteText(row, "segmentId");
			if (sqliteInteger(row, "generation") < 0 || sqliteInteger(row, "endOffset") <= 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "invalid physical row location");
			parseHash(row, "rawHash");
			nullableSqliteText(row, "bootId");
			nullableSqliteInteger(row, "recordSeq");
			nullableSqliteText(row, "eventId");
			enumField(row, "disposition", [
				"candidate",
				"filtered",
				"self",
				"service",
				"disabled_root",
				"diagnostic",
				"overflow",
			]);
			return;
		}
		case "overflow": {
			const row = rollbackRow(
				payload,
				["rootId", "severity", "windowStartMs", "count", "firstAtMs", "lastAtMs", "firstRawHash", "lastRawHash"],
				"rollback overflow bucket",
			);
			sqliteText(row, "rootId");
			enumField(row, "severity", ["low", "medium"]);
			sqliteInteger(row, "windowStartMs");
			if (sqliteInteger(row, "count") < 1)
				throw new BugwatchContractError("INVALID_SCHEMA", "count must be positive");
			if (sqliteInteger(row, "lastAtMs") < sqliteInteger(row, "firstAtMs"))
				throw new BugwatchContractError("INVALID_SCHEMA", "overflow timestamps are reversed");
			parseHash(row, "firstRawHash");
			parseHash(row, "lastRawHash");
			return;
		}
		case "observation": {
			const row = rollbackRow(
				payload,
				[
					"eventId",
					"rootId",
					"bootId",
					"attachmentId",
					"correlationId",
					"recordSeq",
					"fingerprintVersion",
					"fingerprintHash",
					"fingerprintText",
					"severity",
					"category",
					"message",
					"stackTop",
					"occurredAtMs",
					"createdAtMs",
				],
				"rollback observation",
			);
			sqliteText(row, "eventId");
			sqliteText(row, "rootId");
			nullableSqliteText(row, "bootId");
			nullableSqliteText(row, "attachmentId");
			nullableSqliteText(row, "correlationId");
			nullableSqliteInteger(row, "recordSeq");
			sqliteInteger(row, "fingerprintVersion");
			parseHash(row, "fingerprintHash");
			sqliteText(row, "fingerprintText");
			enumField(row, "severity", ["fatal", "high", "medium", "low", "diagnostic"]);
			enumField(row, "category", ["gjc-internal", "error", "warn", "diagnostic"]);
			sqliteText(row, "message");
			nullableSqliteText(row, "stackTop");
			nullableSqliteInteger(row, "occurredAtMs");
			sqliteInteger(row, "createdAtMs");
			return;
		}
		case "candidate": {
			const row = rollbackRow(
				payload,
				[
					"rootId",
					"fingerprintVersion",
					"fingerprintHash",
					"count",
					"severity",
					"category",
					"sampleEventId",
					"policyState",
					"latestRevision",
					"nextEligibleAtMs",
				],
				"rollback candidate",
			);
			sqliteText(row, "rootId");
			sqliteInteger(row, "fingerprintVersion");
			parseHash(row, "fingerprintHash");
			if (sqliteInteger(row, "count") < 1)
				throw new BugwatchContractError("INVALID_SCHEMA", "count must be positive");
			sqliteText(row, "severity");
			sqliteText(row, "category");
			nullableSqliteText(row, "sampleEventId");
			enumField(row, "policyState", [
				"open",
				"drafted",
				"resolved",
				"dismissed",
				"suppressed",
				"capacity_blocked",
				"candidate_authority_unknown",
				"triage_authority_unknown",
			]);
			if (sqliteInteger(row, "latestRevision") < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "latestRevision must be non-negative");
			nullableSqliteInteger(row, "nextEligibleAtMs");
			return;
		}
		case "cursor_watermark": {
			const row = rollbackRow(
				payload,
				["epochId", "segmentId", "generation", "offset", "boundaryHash", "checkpointDigest", "sourceState"],
				"rollback coverage source watermark",
			);
			sqliteText(row, "epochId");
			sqliteText(row, "segmentId");
			if (sqliteInteger(row, "generation") < 0 || sqliteInteger(row, "offset") < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "invalid watermark location");
			nullableHash(row, "boundaryHash");
			nullableHash(row, "checkpointDigest");
			sqliteText(row, "sourceState");
			return;
		}
		case "inbox_ack":
			exactObject(
				payload,
				["scopeId", "epochId", "slot", "slotGeneration", "eventId", "segmentIndex", "acknowledgedAt"],
				"rollback inbox acknowledgement",
			);
			if (
				numberField(payload, "slot") >= 8192 ||
				numberField(payload, "slotGeneration") < 1 ||
				!/^[0-9a-f]{64}$/.test(stringField(payload, "eventId"))
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "invalid rollback inbox acknowledgement payload");
			canonicalUtcTimestamp(boundedString(payload.acknowledgedAt, "acknowledgedAt"), "acknowledgedAt");
			return;
	}
}

function parseRollbackItem(
	input: string | JsonValue,
	schema: "gjc-bugwatch-rollback-bundle-item/v1" | "gjc-bugwatch-rollback-spool-item/v1",
): RollbackBundleItemV1 | RollbackSpoolItemV1 {
	const item = parseEnvelope<RollbackBundleItemV1 | RollbackSpoolItemV1>(input, schema, [
		"schema",
		"scopeId",
		"epochId",
		...(schema === "gjc-bugwatch-rollback-spool-item/v1" ? ["segmentIndex"] : []),
		"itemIndex",
		"itemType",
		"payload",
		"payloadHash",
		"itemHash",
		"previousItemHash",
		"createdAt",
		"keyId",
		"mac",
	]);
	if (!ROLLBACK_ITEM_TYPES.includes(item.itemType as RollbackItemTypeV1))
		throw new BugwatchContractError("INVALID_SCHEMA", "invalid rollback item type");
	validateRollbackPayload(item);
	if (item.payloadHash !== authenticatedHash(item.payload))
		throw new BugwatchContractError("INVALID_HASH", "rollback item payload hash does not match payload");
	const withoutHash: { [key: string]: JsonValue } = {};
	for (const [key, value] of Object.entries(item as unknown as { [key: string]: JsonValue }))
		if (key !== "itemHash" && key !== "mac") withoutHash[key] = value;
	if (item.itemHash !== authenticatedHash(withoutHash))
		throw new BugwatchContractError("INVALID_HASH", "rollback item hash does not match item");
	return item;
}
export function parseRollbackBundleItemV1(input: string | JsonValue): RollbackBundleItemV1 {
	return parseRollbackItem(input, "gjc-bugwatch-rollback-bundle-item/v1") as RollbackBundleItemV1;
}
export function parseRollbackSpoolItemV1(input: string | JsonValue): RollbackSpoolItemV1 {
	return parseRollbackItem(input, "gjc-bugwatch-rollback-spool-item/v1") as RollbackSpoolItemV1;
}
function inboxAckPayload(ack: RollbackInboxAckV1): JsonValue {
	return {
		scopeId: ack.scopeId,
		epochId: ack.epochId,
		slot: ack.slot,
		slotGeneration: ack.slotGeneration,
		eventId: ack.eventId,
		segmentIndex: ack.segmentIndex,
		acknowledgedAt: ack.acknowledgedAt,
	};
}

export function verifyRollbackSpoolSegmentV1(
	manifestInput: string | JsonValue,
	itemsInput: readonly (string | JsonValue)[],
	acksInput: readonly (string | JsonValue)[],
	keyForId: RollbackKeyResolverV1,
): void {
	const manifest = parseRollbackSpoolManifestV1(manifestInput);
	verifyMac(
		manifest as unknown as JsonValue,
		"gjc-bugwatch-rollback-spool-manifest-v1",
		requireRollbackKey(keyForId, manifest.keyId),
	);
	if (manifest.state !== "closed")
		throw new BugwatchContractError("INVALID_SCHEMA", "only closed spool segments are replayable");
	if (itemsInput.length !== manifest.itemCount)
		throw new BugwatchContractError("INVALID_SCHEMA", "spool item count does not match manifest");
	let byteCount = 0;
	let previousItemHash: string | null = null;
	const hashes: string[] = [];
	const items = new Map<string, RollbackSpoolItemV1>();
	for (let index = 0; index < itemsInput.length; index++) {
		const item = parseRollbackSpoolItemV1(itemsInput[index]);
		verifyMac(
			item as unknown as JsonValue,
			"gjc-bugwatch-rollback-spool-item-v1",
			requireRollbackKey(keyForId, item.keyId),
		);
		if (
			item.scopeId !== manifest.scopeId ||
			item.epochId !== manifest.epochId ||
			item.segmentIndex !== manifest.segmentIndex ||
			item.itemIndex !== index ||
			item.previousItemHash !== previousItemHash
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "spool item order or chain is invalid");
		byteCount += new TextEncoder().encode(canonicalizeJson(item as unknown as JsonValue)).byteLength + 1;
		hashes.push(item.itemHash);
		items.set(item.itemHash, item);
		previousItemHash = item.itemHash;
	}
	if (byteCount !== manifest.byteCount || sha256Hex(hashes.join("\n")) !== manifest.itemsDigest)
		throw new BugwatchContractError("INVALID_HASH", "spool manifest digest or byte count does not match items");
	const acknowledgedItemHashes = new Set<string>();
	for (const ackInput of acksInput) {
		const ack = parseRollbackInboxAckV1(ackInput);
		verifyMac(
			ack as unknown as JsonValue,
			"gjc-bugwatch-rollback-inbox-ack-v1",
			requireRollbackKey(keyForId, ack.keyId),
		);
		const item = items.get(ack.spoolItemHash);
		if (
			ack.scopeId !== manifest.scopeId ||
			ack.epochId !== manifest.epochId ||
			ack.segmentIndex !== manifest.segmentIndex ||
			item?.itemType !== "inbox_ack" ||
			canonicalizeJson(item.payload) !== canonicalizeJson(inboxAckPayload(ack)) ||
			acknowledgedItemHashes.has(ack.spoolItemHash)
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"inbox acknowledgement is not bound to its closed spool item",
			);
		acknowledgedItemHashes.add(ack.spoolItemHash);
	}
	for (const item of items.values())
		if (item.itemType === "inbox_ack" && !acknowledgedItemHashes.has(item.itemHash))
			throw new BugwatchContractError("INVALID_SCHEMA", "closed spool inbox acknowledgement is missing");
}
export function parseRollbackInboxAckV1(input: string | JsonValue): RollbackInboxAckV1 {
	const ack = parseEnvelope<RollbackInboxAckV1>(input, "gjc-bugwatch-rollback-inbox-ack/v1", [
		"schema",
		"scopeId",
		"epochId",
		"slot",
		"slotGeneration",
		"eventId",
		"segmentIndex",
		"spoolItemHash",
		"acknowledgedAt",
		"keyId",
		"mac",
	]);
	if (ack.slot >= 8192 || ack.slotGeneration < 1 || !/^[0-9a-f]{64}$/.test(ack.eventId))
		throw new BugwatchContractError("INVALID_SCHEMA", "invalid rollback inbox acknowledgement");
	return ack;
}
export function parseRootMutationCoreV1(input: string | JsonValue): RootMutationCoreV1 {
	const mutation = parseEnvelope<RootMutationCoreV1>(input, "gjc-bugwatch-root-mutation-core/v1", [
		"schema",
		"scopeId",
		"mutationId",
		"action",
		"expectedPolicyGeneration",
		"expectedPolicyHash",
		"oldRootId",
		"newRootId",
		"outputs",
		"createdAt",
		"actorPid",
		"actorPidStartToken",
		"keyId",
		"mac",
	]);
	if (mutation.expectedPolicyGeneration < 1)
		throw new BugwatchContractError("OUT_OF_RANGE", "expected policy generation must be positive");
	return mutation;
}

export type RootMutationDbPhaseV1 =
	| "prepared"
	| "publishing"
	| "files_published"
	| "db_applied"
	| "baseline_complete"
	| "files_finalized"
	| "committed"
	| "aborted"
	| "conflict";

const ROOT_MUTATION_DB_PHASE_CHAIN: readonly RootMutationDbPhaseV1[] = [
	"prepared",
	"publishing",
	"files_published",
	"db_applied",
	"baseline_complete",
	"files_finalized",
	"committed",
];

export function parseRootMutationDbStateV1(input: string | JsonValue): RootMutationDbStateV1 {
	const state = parseEnvelope<RootMutationDbStateV1>(input, "gjc-bugwatch-root-mutation-db-state/v1", [
		"schema",
		"scopeId",
		"mutationId",
		"coreHash",
		"phase",
		"previousPhase",
		"previousStateHash",
		"keyId",
		"mac",
	]);
	if (
		![...ROOT_MUTATION_DB_PHASE_CHAIN, "aborted", "conflict"].includes(state.phase) ||
		(state.previousPhase !== null &&
			![...ROOT_MUTATION_DB_PHASE_CHAIN, "aborted", "conflict"].includes(state.previousPhase)) ||
		(state.previousPhase === null) !== (state.previousStateHash === null)
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "invalid root mutation database state");
	return state;
}
export const parseRootMutationRenameStepV2 = (input: string | JsonValue): RootMutationRenameStepV2 =>
	parseEnvelope(input, "gjc-bugwatch-root-rename-step/v2", [
		"schema",
		"scopeId",
		"mutationId",
		"coreHash",
		"stepIndex",
		"target",
		"lifecycle",
		"action",
		"expectedDestinationHash",
		"sourceTempHash",
		"desiredDestinationHash",
		"observedDestinationHash",
		"previousStepHash",
		"occurredAt",
		"keyId",
		"mac",
	]);
export function parseAttachmentV1(input: string | JsonValue): AttachmentV1 {
	const attachment = parseEnvelope<AttachmentV1>(input, "gjc-bugwatch-attachment/v1", [
		"schema",
		"scopeId",
		"attachmentId",
		"attachmentTokenHash",
		"bootId",
		"bootCoreHash",
		"rootId",
		"sessionId",
		"startedAt",
		"endedAt",
		"state",
		"managedSessionRoot",
		"sessionFile",
		"rootGeneration",
		"baselineEpochId",
		"publishSequence",
		"retireSequence",
		"keyId",
		"mac",
	]);
	if (attachment.rootGeneration < 1)
		throw new BugwatchContractError("OUT_OF_RANGE", "attachment root generation must be positive");
	return attachment;
}
export function parseSourceAuthorityV1(input: string | JsonValue): SourceAuthorityV1 {
	const source = parseEnvelope<SourceAuthorityV1>(input, "gjc-bugwatch-source/v1", [
		"schema",
		"scopeId",
		"segmentId",
		"generation",
		"sourceKind",
		"pathHash",
		"fileIdentityHint",
		"prefixAnchorLength",
		"prefixHash",
		"committedOffset",
		"boundaryHash",
		"checkpointDigest",
		"state",
		"updatedAt",
		"keyId",
		"mac",
	]);
	if (source.prefixAnchorLength > 4096)
		throw new BugwatchContractError("OUT_OF_RANGE", "prefixAnchorLength must not exceed 4096");
	return source;
}
export function parseSourceCheckpointV1(input: string | JsonValue): SourceCheckpointV1 {
	const checkpoint = parseEnvelope<SourceCheckpointV1>(input, "gjc-bugwatch-source-checkpoint/v1", [
		"schema",
		"scopeId",
		"segmentId",
		"generation",
		"kind",
		"chunkIndex",
		"startOffset",
		"endOffset",
		"hash",
		"keyId",
		"mac",
	]);
	if (checkpoint.endOffset <= checkpoint.startOffset)
		throw new BugwatchContractError("OUT_OF_RANGE", "checkpoint endOffset must exceed startOffset");
	return checkpoint;
}
export const parseArchiveAliasV1 = (input: string | JsonValue): ArchiveAliasV1 =>
	parseEnvelope(input, "gjc-bugwatch-archive-alias/v1", [
		"schema",
		"scopeId",
		"archiveDigest",
		"uncompressedLength",
		"segmentId",
		"generation",
		"lineageKind",
		"verifiedCheckpointDigest",
		"createdAt",
		"keyId",
		"mac",
	]);
export const parseMonitorInventoryV1 = (input: string | JsonValue): MonitorInventoryV1 =>
	parseEnvelope(input, "gjc-bugwatch-monitor-inventory/v1", [
		"schema",
		"scopeId",
		"inventoryEpochId",
		"monitorId",
		"kind",
		"stableIdentifier",
		"configHash",
		"coveredRootIds",
		"status",
		"observedAt",
		"adapterEvidenceHash",
		"keyId",
		"mac",
	]);
export const parseMonitorDisableReceiptV1 = (input: string | JsonValue): MonitorDisableReceiptV1 =>
	parseEnvelope(input, "gjc-bugwatch-monitor-disable-receipt/v1", [
		"schema",
		"scopeId",
		"authorizationId",
		"actionHash",
		"inventoryEpochId",
		"monitorId",
		"adapterKind",
		"beforeHash",
		"afterHash",
		"startedAt",
		"finishedAt",
		"result",
		"steps",
		"coveredRootIds",
		"keyId",
		"mac",
	]);
function parseSnapshotClassEntryV1(value: JsonValue, index: number): SnapshotClassEntryV1 {
	const entry = exactObject(
		value,
		["className", "mode", "itemCount", "byteCount", "itemsSha256", "classDigest", "reconstructiveSource"],
		"snapshot class entry",
	);
	const className = stringField(entry, "className") as AuthorityClassV1;
	if (!AUTHORITY_CLASS_NAMES.includes(className) || AUTHORITY_CLASS_NAMES[index] !== className)
		throw new BugwatchContractError(
			"INVALID_SCHEMA",
			"snapshot classes must exactly match the closed ordered inventory",
		);
	const policy = AUTHORITY_SNAPSHOT_POLICY[className];
	if (entry.mode !== policy.mode || stringField(entry, "reconstructiveSource") !== policy.reconstructiveSource)
		throw new BugwatchContractError("INVALID_SCHEMA", `snapshot class ${className} has an incompatible treatment`);
	numberField(entry, "itemCount");
	numberField(entry, "byteCount");
	parseHash(entry, "itemsSha256");
	parseHash(entry, "classDigest");
	return entry as unknown as SnapshotClassEntryV1;
}

function requireSnapshotPayloadAtOrBefore(payload: JsonValue, cutoffAt: string): void {
	if (Array.isArray(payload)) {
		for (const value of payload) requireSnapshotPayloadAtOrBefore(value, cutoffAt);
		return;
	}
	if (payload === null || typeof payload !== "object") return;
	for (const [key, value] of Object.entries(payload)) {
		if (key.endsWith("At") && typeof value === "string" && value > cutoffAt)
			throw new BugwatchContractError("INVALID_SCHEMA", "snapshot contains a post-cutoff record");
		if (
			key.endsWith("_at_ms") &&
			value !== null &&
			(typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > Date.parse(cutoffAt))
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "snapshot contains an invalid or post-cutoff record");
		requireSnapshotPayloadAtOrBefore(value, cutoffAt);
	}
}
export type SnapshotPayloadClassV1 = Exclude<
	AuthorityClassV1,
	| "authority_snapshot_packs"
	| "store_operation_journal"
	| "authority_snapshot_items"
	| "source_archive_replay"
	| "inbox_emergency_replay"
	| "rollback_spool_replay"
	| "registry_replay"
	| "upstream_cache"
	| "daemon_runs"
	| "sqlite_wal_shm"
	| "ephemeral_context_ipc"
	| "derived_health_counters"
>;
export const SNAPSHOT_PAYLOAD_CLASSES = [
	"schema_meta",
	"fingerprint_version_mappings",
	"scope_policies",
	"scope_policy_heads",
	"roots",
	"root_aliases",
	"root_mutations",
	"root_mutation_outputs",
	"root_mutation_steps",
	"root_mutation_rename_steps",
	"producer_boots",
	"boot_transport_records",
	"boot_final_records",
	"session_attachments",
	"attachment_transitions",
	"producer_coverage",
	"producer_ranges",
	"sources",
	"source_checkpoints",
	"archive_aliases",
	"physical_rows",
	"identity_quarantines",
	"observations",
	"candidates",
	"overflow_buckets",
	"capacity_blocks",
	"job_inputs",
	"triage_jobs",
	"triage_results",
	"artifact_outbox",
	"projection_heads",
	"job_projection_requirements",
	"manual_artifacts",
	"fingerprint_prefix_aliases",
	"import_epochs",
	"context_records",
	"coverage_epochs",
	"coverage_source_watermarks",
	"coverage_boot_watermarks",
	"coverage_boot_ranges",
	"rollback_epochs",
	"rollback_items",
	"old_monitor_inventory_epochs",
	"old_monitors",
	"old_monitor_root_coverage",
	"legacy_disable_receipts",
	"monitor_disable_authorizations",
	"monitor_disable_receipts",
	"store_operations",
	"store_operation_members",
] as const satisfies readonly SnapshotPayloadClassV1[];

const SNAPSHOT_LITERAL_ROW_COLUMNS: Readonly<Record<SnapshotPayloadClassV1, readonly string[]>> = Object.freeze(
	Object.fromEntries(
		[
			[
				"schema_meta",
				"id schema_major schema_minor log_schema_version redaction_version noise_version severity_version fingerprint_version fixture_manifest_hash schema_catalog_hash created_at_ms migrated_at_ms",
			],
			[
				"fingerprint_version_mappings",
				"from_version from_hash to_version to_hash fixture_manifest_hash approved_at_ms",
			],
			[
				"scope_policies",
				"scope_id generation revision_hash semantic_json content_hash previous_generation previous_revision_hash previous_content_hash cas_token_hash created_at_ms writer_id key_id mac",
			],
			[
				"scope_policy_heads",
				"scope_id generation revision_hash content_hash cas_token_hash head_json updated_at_ms key_id mac",
			],
			[
				"roots",
				"root_id kind canonical_path enabled revision project_policy_hash registered_at_ms disabled_at_ms persist_context baseline_epoch_id active_mutation_id root_json",
			],
			["root_aliases", "old_root_id new_root_id move_epoch_id old_path_hash new_path_hash created_at_ms"],
			[
				"root_mutations",
				"mutation_id scope_id action core_hash core_json expected_policy_generation expected_policy_hash old_root_id new_root_id phase step_index current_step_hash created_at_ms updated_at_ms",
			],
			[
				"root_mutation_outputs",
				"mutation_id target path_hash precondition expected_old_content_hash pending_content_hash final_content_hash desired_root_generation publication_order pending_state final_state",
			],
			[
				"root_mutation_steps",
				"scope_id mutation_id core_hash step_index phase previous_phase previous_state_hash key_id mac record_hash created_at_ms recorded_at_ms",
			],
			[
				"root_mutation_rename_steps",
				"mutation_id step_index target lifecycle action expected_destination_hash source_temp_hash desired_destination_hash observed_destination_hash previous_step_hash step_hash occurred_at_ms key_id mac",
			],
			[
				"producer_boots",
				"boot_id scope_id boot_core_hash pid pid_start_token producer started_at_ms initial_policy_generation initial_policy_hash fatal_key_id gjc_version build_sha final_seq final_state final_record_hash boot_core_json",
			],
			[
				"boot_transport_records",
				"boot_id transport_epoch record_kind record_hash start_record_hash policy_generation policy_hash start_seq end_seq file_enabled outcome previous_record_hash record_json created_at_ms",
			],
			[
				"boot_final_records",
				"boot_id record_hash final_seq state last_transport_record_hash attachment_snapshot_hash previous_record_hash record_json created_at_ms",
			],
			[
				"session_attachments",
				"attachment_id scope_id attachment_token_hash boot_id boot_core_hash root_id session_id started_at_ms ended_at_ms state managed_session_root session_file root_generation baseline_epoch_id publish_seq retire_seq current_transition_hash attachment_json",
			],
			[
				"attachment_transitions",
				"attachment_id step_index transition_hash state previous_transition_hash occurred_at_ms record_json record_byte_count key_id mac",
			],
			["producer_coverage", "boot_id contiguous_through max_seen final_seq state updated_at_ms"],
			["producer_ranges", "boot_id start_seq end_seq"],
			[
				"sources",
				"segment_id generation source_kind path file_identity_hint prefix_anchor_length prefix_hash committed_offset boundary_hash checkpoint_digest validation_state state block_id updated_at_ms",
			],
			["source_checkpoints", "segment_id generation kind chunk_index start_offset end_offset hash validated_at_ms"],
			[
				"archive_aliases",
				"archive_digest uncompressed_length segment_id generation lineage_kind verified_checkpoint_digest created_at_ms",
			],
			["physical_rows", "segment_id generation end_offset raw_hash boot_id record_seq event_id disposition"],
			[
				"identity_quarantines",
				"quarantine_id segment_id generation expected_offset raw_hash claimed_boot_id claimed_attachment_id claimed_root_id claimed_event_id reason state created_at_ms resolved_at_ms",
			],
			[
				"observations",
				"event_id root_id boot_id attachment_id correlation_id record_seq fingerprint_version fingerprint_hash fingerprint_text severity category message stack_top occurred_at_ms created_at_ms",
			],
			[
				"candidates",
				"root_id fingerprint_version fingerprint_hash count severity category sample_event_id policy_state latest_revision next_eligible_at_ms",
			],
			[
				"overflow_buckets",
				"root_id severity window_start_ms count first_at_ms last_at_ms first_raw_hash last_raw_hash",
			],
			[
				"capacity_blocks",
				"block_id segment_id generation expected_offset raw_hash root_id severity reason state emergency_slot created_at_ms cleared_at_ms",
			],
			[
				"job_inputs",
				"job_id root_id fingerprint_version fingerprint_hash revision policy_version input_json input_hash input_byte_count created_at_ms",
			],
			[
				"triage_jobs",
				"job_id state attempts max_attempts lease_token lease_expires_at_ms next_attempt_at_ms worker_protocol_major updated_at_ms",
			],
			[
				"triage_results",
				"result_id job_id attempt lease_token result_kind result_json input_hash context_hash evidence_hash output_hash output_byte_count upstream_sha created_at_ms",
			],
			[
				"artifact_outbox",
				"outbox_id job_id result_id artifact_kind target_relpath immutable required projection_kind required_projection_generation expected_prior_hash content_hash content content_byte_count state attempts updated_at_ms",
			],
			[
				"projection_heads",
				"root_id projection_kind target_relpath next_generation dirty_through_generation applied_generation state claim_token claim_generation current_hash version updated_at_ms",
			],
			["job_projection_requirements", "job_id root_id projection_kind required_generation"],
			[
				"manual_artifacts",
				"artifact_id root_id path kind fingerprint_version full_fingerprint_hash revision content_hash content content_byte_count ownership import_epoch_id created_at_ms",
			],
			["fingerprint_prefix_aliases", "root_id fingerprint_version full_hash prefix_len prefix source artifact_id"],
			[
				"import_epochs",
				"epoch_id root_id kind source_path_hash source_content_hash byte_count item_count state started_at_ms completed_at_ms",
			],
			[
				"context_records",
				"context_id job_id path content_hash byte_count expires_at_ms state deleted_at_ms delete_proof_hash",
			],
			[
				"coverage_epochs",
				"epoch_id root_id kind state policy_revision coverage_status started_at_ms completed_at_ms receipt_hash",
			],
			[
				"coverage_source_watermarks",
				"epoch_id segment_id generation offset boundary_hash checkpoint_digest source_state",
			],
			[
				"coverage_boot_watermarks",
				"epoch_id boot_id root_relation frontier max_seen final_seq coverage_state range_digest",
			],
			["coverage_boot_ranges", "epoch_id boot_id start_seq end_seq"],
			[
				"rollback_epochs",
				"epoch_id scope_id role_transition_token bundle_version state manifest_hash limits_json bundle_json spool_manifest_json inbox_ack_json created_at_ms exported_at_ms released_at_ms completed_at_ms",
			],
			[
				"rollback_items",
				"epoch_id item_index item_type item_hash payload_hash payload_byte_count state payload item_schema key_id mac item_json",
			],
			[
				"old_monitor_inventory_epochs",
				"inventory_epoch_id scope_id state started_at_ms completed_at_ms receipt_hash",
			],
			[
				"old_monitors",
				"inventory_epoch_id monitor_id kind stable_identifier owner config_hash status observed_at_ms inventory_json",
			],
			["old_monitor_root_coverage", "inventory_epoch_id monitor_id root_id coverage_kind"],
			["legacy_disable_receipts", "receipt_id root_id receipt_hash payload payload_json created_at_ms"],
			[
				"monitor_disable_authorizations",
				"authorization_id scope_id inventory_epoch_id monitor_id action_kind action_hash expected_config_hash consume_nonce_hash state authorized_at_ms expires_at_ms consumed_at_ms action_json authorization_json key_id mac",
			],
			[
				"monitor_disable_receipts",
				"receipt_id authorization_id scope_id inventory_epoch_id monitor_id adapter_kind action_hash before_hash after_hash result steps_json covered_roots_json receipt_json started_at_ms finished_at_ms receipt_hash key_id mac",
			],
			[
				"store_operations",
				"operation_id owner_id claim_token_hash kind from_version to_version phase core_hash current_step current_step_hash backup_path quarantine_path watermark_hash core_json started_at_ms updated_at_ms",
			],
			[
				"store_operation_members",
				"operation_id member source_path_hash expected_presence expected_size expected_hash quarantine_path_hash state observed_source_hash observed_quarantine_hash step_json updated_at_ms",
			],
		].map(([className, columns]) => [className, columns.split(" ")]),
	) as unknown as Record<SnapshotPayloadClassV1, readonly string[]>,
);
/** Frozen schema-1.7 field inventory used by payload validators and parity tests. */
export const SNAPSHOT_PAYLOAD_FIELD_SETS: Readonly<Record<SnapshotPayloadClassV1, readonly string[]>> =
	SNAPSHOT_LITERAL_ROW_COLUMNS;

export type SnapshotColumnTypeV1 =
	| "text"
	| "integer"
	| "boolean"
	| "nullable_text"
	| "nullable_integer"
	| "nullable_boolean";
export interface SnapshotRowSpecV1 {
	readonly fields: readonly string[];
	readonly types: readonly SnapshotColumnTypeV1[];
}
const snapshotRowSpec = (className: SnapshotPayloadClassV1, signature: string): SnapshotRowSpecV1 => {
	const fields = SNAPSHOT_LITERAL_ROW_COLUMNS[className];
	const types = [...signature].map(token => {
		switch (token) {
			case "T":
				return "text" as const;
			case "I":
				return "integer" as const;
			case "B":
				return "boolean" as const;
			case "b":
				return "nullable_boolean" as const;
			case "t":
				return "nullable_text" as const;
			case "i":
				return "nullable_integer" as const;
			default:
				throw new BugwatchContractError("INVALID_SCHEMA", `invalid snapshot row specification for ${className}`);
		}
	});
	if (types.length !== fields.length)
		throw new BugwatchContractError(
			"INVALID_SCHEMA",
			`snapshot row specification field count mismatch for ${className}`,
		);
	return { fields, types };
};
/** Exact schema-1.7 SQLite storage/nullability contract for every payload table. */
export const SNAPSHOT_PAYLOAD_ROW_SPECS: Readonly<Record<SnapshotPayloadClassV1, SnapshotRowSpecV1>> = Object.freeze({
	schema_meta: snapshotRowSpec("schema_meta", "IIIIIIIITTII"),
	fingerprint_version_mappings: snapshotRowSpec("fingerprint_version_mappings", "ITITTI"),
	scope_policies: snapshotRowSpec("scope_policies", "TITTTit tTITTT".replaceAll(" ", "")),
	scope_policy_heads: snapshotRowSpec("scope_policy_heads", "TITTTTITT"),
	roots: snapshotRowSpec("roots", "TTtBITIiBttt"),
	root_aliases: snapshotRowSpec("root_aliases", "TTTTTI"),
	root_mutations: snapshotRowSpec("root_mutations", "TTTTTITttTITII"),
	root_mutation_outputs: snapshotRowSpec("root_mutation_outputs", "TTTTtTTIITT"),
	root_mutation_steps: snapshotRowSpec("root_mutation_steps", "TTTITttTTTII"),
	root_mutation_rename_steps: snapshotRowSpec("root_mutation_rename_steps", "TITTTtTTttTITT"),
	producer_boots: snapshotRowSpec("producer_boots", "TTTITTIITTTtittT"),
	boot_transport_records: snapshotRowSpec("boot_transport_records", "TITTtITiibttTI"),
	boot_final_records: snapshotRowSpec("boot_final_records", "TTITTTTTI"),
	session_attachments: snapshotRowSpec("session_attachments", "TTTTTTtIiTttITiiTT"),
	attachment_transitions: snapshotRowSpec("attachment_transitions", "TITTtITITT"),
	producer_coverage: snapshotRowSpec("producer_coverage", "TIIiTI"),
	producer_ranges: snapshotRowSpec("producer_ranges", "TII"),
	sources: snapshotRowSpec("sources", "TITTTITItTTTtI"),
	source_checkpoints: snapshotRowSpec("source_checkpoints", "TITI IITi".replaceAll(" ", "")),
	archive_aliases: snapshotRowSpec("archive_aliases", "TITITTI"),
	physical_rows: snapshotRowSpec("physical_rows", "TIITtitT"),
	identity_quarantines: snapshotRowSpec("identity_quarantines", "TTIITttttTTIi"),
	observations: snapshotRowSpec("observations", "TTtttiITTTTTtiI"),
	candidates: snapshotRowSpec("candidates", "TITITTtTIi"),
	overflow_buckets: snapshotRowSpec("overflow_buckets", "TTIIIITT"),
	capacity_blocks: snapshotRowSpec("capacity_blocks", "TTIITTTTTiIi"),
	job_inputs: snapshotRowSpec("job_inputs", "TTITITTTII"),
	triage_jobs: snapshotRowSpec("triage_jobs", "TTIIt iiII".replaceAll(" ", "")),
	triage_results: snapshotRowSpec("triage_results", "TTITTTTtTTItI"),
	artifact_outbox: snapshotRowSpec("artifact_outbox", "TTTTTB Bt itTTITII".replaceAll(" ", "")),
	projection_heads: snapshotRowSpec("projection_heads", "TTTIIITtitII"),
	job_projection_requirements: snapshotRowSpec("job_projection_requirements", "TTTI"),
	manual_artifacts: snapshotRowSpec("manual_artifacts", "TTTTitiTTITtI"),
	fingerprint_prefix_aliases: snapshotRowSpec("fingerprint_prefix_aliases", "TITITTt"),
	import_epochs: snapshotRowSpec("import_epochs", "TTTTTIITii"),
	context_records: snapshotRowSpec("context_records", "TTTTIITit"),
	coverage_epochs: snapshotRowSpec("coverage_epochs", "TTTTTTIit"),
	coverage_source_watermarks: snapshotRowSpec("coverage_source_watermarks", "TTI IttT".replaceAll(" ", "")),
	coverage_boot_watermarks: snapshotRowSpec("coverage_boot_watermarks", "TTTIIiTT"),
	coverage_boot_ranges: snapshotRowSpec("coverage_boot_ranges", "TTII"),
	rollback_epochs: snapshotRowSpec("rollback_epochs", "TTTITtTTTTIiii"),
	rollback_items: snapshotRowSpec("rollback_items", "TITTTITTTTTT"),
	old_monitor_inventory_epochs: snapshotRowSpec("old_monitor_inventory_epochs", "TTTIit"),
	old_monitors: snapshotRowSpec("old_monitors", "TTTTTTTIT"),
	old_monitor_root_coverage: snapshotRowSpec("old_monitor_root_coverage", "TTTT"),
	legacy_disable_receipts: snapshotRowSpec("legacy_disable_receipts", "TTTTTI"),
	monitor_disable_authorizations: snapshotRowSpec("monitor_disable_authorizations", "TTTTTTTTTIIiTTTT"),
	monitor_disable_receipts: snapshotRowSpec("monitor_disable_receipts", "TTTTTTTTtTTTTIITTT"),
	store_operations: snapshotRowSpec("store_operations", "TTTTIiTTIttttTII"),
	store_operation_members: snapshotRowSpec("store_operation_members", "TTTBitTTttTI"),
});

export const SNAPSHOT_ROW_AUTHORITY_COLUMNS: Readonly<Partial<Record<SnapshotPayloadClassV1, string>>> = {
	scope_policies: "scope_id",
	scope_policy_heads: "scope_id",
	roots: "root_id",
	root_mutations: "mutation_id",
	root_mutation_outputs: "mutation_id",
	root_mutation_steps: "mutation_id",
	root_mutation_rename_steps: "mutation_id",
	producer_boots: "boot_id",
	boot_transport_records: "boot_id",
	boot_final_records: "boot_id",
	session_attachments: "attachment_id",
	attachment_transitions: "attachment_id",
	producer_coverage: "boot_id",
	producer_ranges: "boot_id",
	sources: "segment_id",
	source_checkpoints: "segment_id",
	archive_aliases: "archive_digest",
	store_operations: "operation_id",
	store_operation_members: "operation_id",
};
const SQLITE_ENUMS: Readonly<Record<string, readonly string[]>> = {
	"roots.kind": ["project", "unattributed", "service"],
	"root_mutations.action": ["enable", "disable", "set_context", "move"],
	"root_mutations.phase": [
		"prepared",
		"publishing",
		"files_published",
		"db_applied",
		"baseline_complete",
		"files_finalized",
		"committed",
		"aborted",
		"conflict",
	],
	"root_mutation_outputs.target": ["old_root", "new_root"],
	"root_mutation_outputs.precondition": ["missing", "present"],
	"root_mutation_outputs.pending_state": ["prepared", "intent", "published", "verified", "conflict"],
	"root_mutation_outputs.final_state": ["prepared", "intent", "published", "verified", "conflict"],
	"root_mutation_steps.phase": [
		"prepared",
		"publishing",
		"files_published",
		"db_applied",
		"baseline_complete",
		"files_finalized",
		"committed",
		"aborted",
		"conflict",
	],
	"coverage_epochs.kind": ["enable_baseline", "shadow", "cutover", "rollback", "reconcile", "disable"],
	"coverage_epochs.state": ["open", "complete", "failed"],
	"coverage_epochs.coverage_status": ["covered", "gap", "unknown"],
	"boot_final_records.state": ["clean", "crashed", "unknown_disable"],
	"attachment_transitions.state": ["prepared", "active", "ended", "unknown", "aborted"],
	"source_checkpoints.kind": ["chunk", "tail"],
	"archive_aliases.lineage_kind": ["full", "prefix"],
	"identity_quarantines.reason": [
		"missing_boot",
		"event_mismatch",
		"attachment_mismatch",
		"root_mismatch",
		"interval_mismatch",
		"manifest_conflict",
	],
	"identity_quarantines.state": ["active", "reconciled", "dismissed"],
	"candidates.policy_state": [
		"open",
		"drafted",
		"resolved",
		"dismissed",
		"suppressed",
		"capacity_blocked",
		"candidate_authority_unknown",
		"triage_authority_unknown",
	],
	"overflow_buckets.severity": ["low", "medium"],
	"capacity_blocks.reason": ["candidate", "db", "wal", "outbox", "coverage_fragmentation", "inbox"],
	"capacity_blocks.state": ["active", "cleared"],
	"rollback_epochs.state": [
		"quiescing",
		"exporting",
		"exported",
		"released",
		"fallback_active",
		"importing",
		"complete",
		"failed",
	],
	"rollback_items.state": ["pending", "applied", "duplicate", "failed"],
	"old_monitor_inventory_epochs.state": ["collecting", "complete", "failed"],
	"old_monitors.kind": ["gjc_cron", "user_cron", "systemd_user", "process", "tmux", "plugin"],
	"old_monitors.status": ["active", "inactive", "unknown"],
	"old_monitor_root_coverage.coverage_kind": ["global", "explicit", "inferred", "unknown"],
	"monitor_disable_authorizations.state": ["authorized", "executing", "consumed", "expired", "refused"],
	"monitor_disable_receipts.result": [
		"disabled",
		"already_inactive",
		"unavailable",
		"refused",
		"partial_failure",
		"failed",
	],
	"root_mutation_rename_steps.target": ["old_root", "new_root"],
	"root_mutation_rename_steps.lifecycle": ["pending", "final"],
	"root_mutation_rename_steps.action": ["rename_intent", "rename_complete"],
	"artifact_outbox.artifact_kind": ["draft", "receipt", "projection"],
	"artifact_outbox.state": ["pending", "materialized", "adopted", "conflict", "failed", "cancelled"],
	"projection_heads.projection_kind": ["index", "resolved_markdown", "resolved_jsonl"],
	"projection_heads.state": ["clean", "dirty", "materializing"],
	"manual_artifacts.kind": ["draft", "index", "resolved_markdown", "resolved_jsonl"],
	"manual_artifacts.ownership": ["manual", "legacy_generated"],
	"fingerprint_prefix_aliases.prefix_len": ["8", "12", "16", "64"],
	"fingerprint_prefix_aliases.source": ["generated", "imported"],
	"context_records.state": ["present", "deleting", "deleted"],
	"import_epochs.kind": ["legacy_resolved", "legacy_drafts", "manual_refresh", "rollback_import"],
	"import_epochs.state": ["importing", "complete", "failed"],
	"coverage_boot_watermarks.root_relation": ["attached", "unattributed", "service"],
	"producer_boots.final_state": ["clean", "crashed", "unknown_disable", "unknown_hard_kill"],
	"boot_transport_records.record_kind": ["start", "close"],
	"session_attachments.state": ["prepared", "active", "ended", "unknown", "aborted"],
	"sources.source_kind": ["log", "inbox", "rollback"],
	"sources.validation_state": ["unvalidated", "revalidating", "valid", "mismatch", "ambiguous"],
	"sources.state": [
		"active",
		"draining",
		"exhausted",
		"generation_changed",
		"orphaned",
		"quarantined",
		"archive_ambiguous",
		"capacity_blocked",
	],
	"physical_rows.disposition": ["candidate", "filtered", "self", "service", "disabled_root", "diagnostic", "overflow"],
	"observations.severity": ["fatal", "high", "medium", "low", "diagnostic"],
	"observations.category": ["gjc-internal", "error", "warn", "diagnostic"],
	"triage_jobs.state": [
		"queued",
		"running",
		"retryable",
		"awaiting_artifacts",
		"completed",
		"deferred",
		"matched",
		"dismissed",
		"quarantined",
		"conflict",
		"disabled",
	],
	"triage_results.result_kind": ["draft", "matched", "dismissed", "deferred", "retryable", "quarantined"],
	"store_operations.kind": ["migrate", "restore", "quarantine", "rebuild"],
	"store_operation_members.member": ["db", "wal", "shm"],
	"store_operation_members.state": ["pending", "intent_recorded", "moved", "verified_absent", "mismatch", "conflict"],
	"producer_coverage.state": ["open", "complete", "gap", "unknown_hard_kill", "reconciled_with_gap"],
};

const SCOPE_POLICY_REVISION_LITERAL_COLUMNS = [
	"scope_id",
	"generation",
	"revision_hash",
	"semantic_json",
	"content_hash",
	"previous_generation",
	"previous_revision_hash",
	"previous_content_hash",
	"cas_token_hash",
	"created_at_ms",
	"writer_id",
	"key_id",
	"mac",
] as const;
const SCOPE_POLICY_HEAD_LITERAL_COLUMNS = [
	"scope_id",
	"generation",
	"revision_hash",
	"content_hash",
	"cas_token_hash",
	"head_json",
	"updated_at_ms",
	"key_id",
	"mac",
] as const;

type SnapshotScopePolicyLiteralV1 =
	| { kind: "revision"; value: ScopePolicyRevisionV2 }
	| { kind: "head"; value: ScopePolicyHeadV2 };

function snapshotPolicyTimestamp(value: JsonValue, key: string): string {
	if (typeof value !== "number" || !Number.isSafeInteger(value))
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a SQLite integer`);
	const instant = new Date(value);
	if (Number.isNaN(instant.getTime()))
		throw new BugwatchContractError("INVALID_SCHEMA", `${key} must be a valid SQLite millisecond timestamp`);
	const timestamp = instant.toISOString();
	canonicalUtcTimestamp(timestamp, key);
	return timestamp;
}

function parseSnapshotScopePolicyLiteral(value: JsonValue): SnapshotScopePolicyLiteralV1 {
	const candidate = valueObject(value, "snapshot scope policy row");
	if ("semantic_json" in candidate) {
		const row = exactObject(candidate, SCOPE_POLICY_REVISION_LITERAL_COLUMNS, "snapshot scope policy revision row");
		const semanticJson = stringField(row, "semantic_json");
		const semantic = parseCanonicalJson(semanticJson);
		if (canonicalizeJson(semantic) !== semanticJson)
			throw new BugwatchContractError("INVALID_SCHEMA", "snapshot policy semantic_json is not canonical");
		const revision = parseScopePolicyRevisionV2({
			schema: "gjc-bugwatch-policy-revision/v2",
			scopeId: stringField(row, "scope_id"),
			generation: numberField(row, "generation"),
			semantic,
			contentHash: stringField(row, "content_hash"),
			previousGeneration: row.previous_generation,
			previousRevisionHash: row.previous_revision_hash,
			previousContentHash: row.previous_content_hash,
			casTokenHash: stringField(row, "cas_token_hash"),
			createdAt: snapshotPolicyTimestamp(row.created_at_ms, "created_at_ms"),
			writerId: stringField(row, "writer_id"),
			keyId: stringField(row, "key_id"),
			mac: stringField(row, "mac"),
		});
		if (authenticatedHash(revision as unknown as JsonValue) !== stringField(row, "revision_hash"))
			throw new BugwatchContractError("INVALID_HASH", "snapshot policy revision_hash does not match revision");
		return { kind: "revision", value: revision };
	}
	const row = exactObject(candidate, SCOPE_POLICY_HEAD_LITERAL_COLUMNS, "snapshot scope policy head row");
	const headJson = stringField(row, "head_json");
	const parsedHead = parseCanonicalJson(headJson);
	if (canonicalizeJson(parsedHead) !== headJson)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot policy head_json is not canonical");
	const head = parseScopePolicyHeadV2(parsedHead);
	if (
		head.scopeId !== stringField(row, "scope_id") ||
		head.generation !== numberField(row, "generation") ||
		head.revisionHash !== stringField(row, "revision_hash") ||
		head.contentHash !== stringField(row, "content_hash") ||
		head.keyId !== stringField(row, "key_id") ||
		head.mac !== stringField(row, "mac")
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot policy head scalars do not match head_json");
	if (sha256Hex(head.casToken) !== stringField(row, "cas_token_hash"))
		throw new BugwatchContractError("INVALID_HASH", "snapshot policy head cas_token_hash does not match head_json");
	return { kind: "head", value: head };
}

function verifySnapshotScopePolicyGraph(
	items: readonly AuthoritySnapshotItemV1[],
	scopeId: string,
	policyGeneration: number,
	keys: AuthoritySnapshotRetainedKeyringV1 | undefined,
): void {
	const policyRows = items
		.filter(item => item.itemType === "scope_policies" || item.itemType === "scope_policy_heads")
		.map(item => parseSnapshotScopePolicyLiteral(item.payload));
	const revisions = policyRows
		.filter((row): row is { kind: "revision"; value: ScopePolicyRevisionV2 } => row.kind === "revision")
		.map(row => row.value)
		.sort((left, right) => left.generation - right.generation);
	const heads = policyRows
		.filter((row): row is { kind: "head"; value: ScopePolicyHeadV2 } => row.kind === "head")
		.map(row => row.value);
	if (heads.length !== 1)
		throw new BugwatchContractError("POLICY_CHAIN_GAP", "snapshot must contain exactly one policy head");
	const verified = validatePolicyChain(
		heads[0],
		revisions,
		candidateKeyId => requireRetainedSnapshotKey(keys, candidateKeyId, "policy_keyring").keyBytes,
	);
	if (verified.head.scopeId !== scopeId || verified.head.generation !== policyGeneration)
		throw new BugwatchContractError("POLICY_CHAIN_GAP", "snapshot policy head does not match manifest");
	const terminal = verified.revisions.at(-1);
	if (terminal === undefined || sha256Hex(verified.head.casToken) !== terminal.casTokenHash)
		throw new BugwatchContractError(
			"POLICY_CHAIN_GAP",
			"snapshot policy head CAS token does not match terminal revision",
		);
}

function canonicalSnapshotBlob(value: JsonValue, context: string): Uint8Array {
	if (typeof value !== "string" || !value.startsWith("base64:"))
		throw new BugwatchContractError("INVALID_SCHEMA", `${context} must use canonical base64 BLOB encoding`);
	const encoded = value.slice("base64:".length);
	if (encoded.length === 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))
		throw new BugwatchContractError("INVALID_SCHEMA", `${context} is not canonical base64`);
	const bytes = Buffer.from(encoded, "base64");
	if (bytes.toString("base64") !== encoded)
		throw new BugwatchContractError("INVALID_SCHEMA", `${context} is not canonical base64`);
	return bytes;
}

function validateSnapshotBlobColumns(itemType: SnapshotPayloadClassV1, row: { [key: string]: JsonValue }): void {
	if (itemType === "rollback_items") {
		const bytes = canonicalSnapshotBlob(row.payload, "snapshot rollback_items.payload");
		if (
			numberField(row, "payload_byte_count") !== bytes.byteLength ||
			sha256Hex(bytes) !== stringField(row, "payload_hash")
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "rollback payload bytes do not match count or hash");
	}
	if ((itemType === "artifact_outbox" || itemType === "manual_artifacts") && row.content !== null) {
		const bytes = canonicalSnapshotBlob(row.content, `snapshot ${itemType}.content`);
		if (
			numberField(row, "content_byte_count") !== bytes.byteLength ||
			sha256Hex(bytes) !== stringField(row, "content_hash")
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "artifact content bytes do not match count or hash");
	}
	if (itemType === "legacy_disable_receipts") {
		const bytes = canonicalSnapshotBlob(row.payload, "snapshot legacy_disable_receipts.payload");
		if (sha256Hex(bytes) !== stringField(row, "receipt_hash"))
			throw new BugwatchContractError("INVALID_HASH", "legacy receipt payload bytes do not match receipt_hash");
	}
}
function canonicalSnapshotJson(value: JsonValue, context: string): JsonValue {
	const encoded = stringField({ value }, "value");
	const parsed = parseCanonicalJson(encoded);
	if (canonicalizeJson(parsed) !== encoded)
		throw new BugwatchContractError("INVALID_SCHEMA", `${context} is not canonical JSON`);
	return parsed;
}

function validateSnapshotJsonColumns(itemType: SnapshotPayloadClassV1, row: { [key: string]: JsonValue }): void {
	const validateCanonicalJsonBytes = (field: string, byteCount: string, context: string): JsonValue => {
		const encoded = stringField(row, field);
		const value = canonicalSnapshotJson(encoded, context);
		if (new TextEncoder().encode(encoded).byteLength !== numberField(row, byteCount))
			throw new BugwatchContractError("INVALID_SCHEMA", `${context} byte count does not match canonical JSON`);
		return value;
	};
	if (itemType === "job_inputs") {
		const input = validateCanonicalJsonBytes("input_json", "input_byte_count", "snapshot job input");
		if (sha256Hex(canonicalizeJson(input)) !== stringField(row, "input_hash"))
			throw new BugwatchContractError("INVALID_HASH", "snapshot job input_json does not match input_hash");
	}
	if (itemType === "triage_results") {
		const result = validateCanonicalJsonBytes("result_json", "output_byte_count", "snapshot triage result");
		if (sha256Hex(canonicalizeJson(result)) !== stringField(row, "output_hash"))
			throw new BugwatchContractError("INVALID_HASH", "snapshot triage result_json does not match output_hash");
	}
	if (itemType === "monitor_disable_authorizations") {
		const action = canonicalSnapshotJson(row.action_json, "snapshot monitor disable action");
		parseMonitorDisableActionV1(action);
		if (sha256Hex(canonicalizeJson(action)) !== stringField(row, "action_hash"))
			throw new BugwatchContractError("INVALID_HASH", "snapshot monitor action_json does not match action_hash");
	}
	if (itemType === "monitor_disable_receipts") {
		canonicalSnapshotJson(row.steps_json, "snapshot monitor disable receipt steps");
		canonicalSnapshotJson(row.covered_roots_json, "snapshot monitor disable receipt roots");
	}
	if (itemType === "attachment_transitions") {
		const encoded = stringField(row, "record_json");
		const transition = canonicalSnapshotJson(encoded, "snapshot attachment transition");
		if (new TextEncoder().encode(encoded).byteLength !== numberField(row, "record_byte_count"))
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"attachment transition record byte count does not match canonical JSON",
			);
		if (authenticatedHash(transition) !== stringField(row, "transition_hash"))
			throw new BugwatchContractError(
				"INVALID_HASH",
				"attachment transition record_json does not match transition_hash",
			);
	}
	if (itemType === "store_operation_members") {
		canonicalSnapshotJson(row.step_json, "snapshot store operation member step");
	}
}

const RESERVED_ROOT_POLICY_HASH = "0000000000000000000000000000000000000000000000000000000000000000" as const;

function validateReservedRoot(row: { [key: string]: JsonValue }): void {
	const kind = stringField(row, "kind");
	if (
		(kind !== "service" && kind !== "unattributed") ||
		row.root_id !== kind ||
		row.canonical_path !== null ||
		row.root_json !== null ||
		row.enabled !== 1 ||
		row.revision !== 1 ||
		row.project_policy_hash !== RESERVED_ROOT_POLICY_HASH ||
		row.disabled_at_ms !== null ||
		row.persist_context !== 0 ||
		row.baseline_epoch_id !== null ||
		row.active_mutation_id !== null
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "reserved root does not use its fixed identity and defaults");
}

function validateSnapshotTableChecks(itemType: SnapshotPayloadClassV1, row: { [key: string]: JsonValue }): void {
	const integerAtLeast = (key: string, minimum: number): void => {
		if (numberField(row, key) < minimum)
			throw new BugwatchContractError("INVALID_SCHEMA", `snapshot ${itemType}.${key} violates its SQLite CHECK`);
	};
	const enumValue = (key: string, values: readonly string[]): void => {
		if (!values.includes(stringField(row, key)))
			throw new BugwatchContractError("INVALID_SCHEMA", `snapshot ${itemType}.${key} violates its SQLite CHECK`);
	};
	switch (itemType) {
		case "schema_meta":
			if (row.id !== 1) throw new BugwatchContractError("INVALID_SCHEMA", "schema_meta.id must be one");
			return;
		case "scope_policies":
			if (
				(numberField(row, "generation") === 1 &&
					(row.previous_generation !== null ||
						row.previous_revision_hash !== null ||
						row.previous_content_hash !== null)) ||
				(numberField(row, "generation") > 1 &&
					(row.previous_generation !== numberField(row, "generation") - 1 ||
						row.previous_revision_hash === null ||
						row.previous_content_hash === null))
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"scope policy predecessor fields violate its SQLite CHECK",
				);
			return;
		case "roots":
			integerAtLeast("revision", 1);
			if (row.kind === "project") {
				if (row.canonical_path === null || row.root_json === null)
					throw new BugwatchContractError("INVALID_SCHEMA", "root authority violates its kind coupling");
				return;
			}
			validateReservedRoot(row);
			return;

		case "root_mutation_outputs":
			integerAtLeast("desired_root_generation", 1);
			if (
				row.pending_content_hash === row.final_content_hash ||
				(row.precondition === "missing") !== (row.expected_old_content_hash === null)
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "root mutation output violates its SQLite CHECK");
			return;
		case "producer_boots":
			if (numberField(row, "pid") <= 0 || numberField(row, "initial_policy_generation") < 1)
				throw new BugwatchContractError("INVALID_SCHEMA", "producer boot numeric CHECK failed");
			if (row.final_seq !== null && numberField(row, "final_seq") < 1)
				throw new BugwatchContractError("INVALID_SCHEMA", "producer boot final sequence is invalid");
			return;
		case "session_attachments":
			integerAtLeast("root_generation", 1);
			if (row.ended_at_ms !== null && numberField(row, "ended_at_ms") < numberField(row, "started_at_ms"))
				throw new BugwatchContractError("INVALID_SCHEMA", "attachment end precedes its start");
			return;
		case "boot_transport_records":
			if (
				(row.record_kind === "start" &&
					(row.start_seq === null || (row.file_enabled !== 0 && row.file_enabled !== 1))) ||
				(row.record_kind === "close" && (row.start_record_hash === null || row.end_seq === null))
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "boot transport record fields violate kind coupling");
			return;
		case "attachment_transitions":
			integerAtLeast("step_index", 0);
			if (stringField(row, "key_id").length === 0 || !/^[0-9a-f]{64}$/.test(stringField(row, "mac")))
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"attachment transition key or MAC violates its SQLite CHECK",
				);
			return;
		case "producer_coverage":
			integerAtLeast("contiguous_through", 0);
			if (numberField(row, "max_seen") < numberField(row, "contiguous_through"))
				throw new BugwatchContractError("INVALID_SCHEMA", "producer coverage sequence bounds are invalid");
			return;
		case "store_operation_members":
			if (row.source_path_hash === row.quarantine_path_hash)
				throw new BugwatchContractError("INVALID_SCHEMA", "store operation member paths must differ");
			return;
		case "root_aliases":
			if (row.old_root_id === row.new_root_id)
				throw new BugwatchContractError("INVALID_SCHEMA", "root alias cannot reference itself");
			return;
		case "sources":
			integerAtLeast("generation", 0);
			if (numberField(row, "prefix_anchor_length") < 0 || numberField(row, "prefix_anchor_length") > 4096)
				throw new BugwatchContractError("INVALID_SCHEMA", "source prefix anchor is outside its SQLite range");
			return;
		case "source_checkpoints":
			integerAtLeast("generation", 0);
			integerAtLeast("chunk_index", 0);
			integerAtLeast("start_offset", 0);
			if (numberField(row, "end_offset") <= numberField(row, "start_offset"))
				throw new BugwatchContractError("INVALID_SCHEMA", "source checkpoint end offset must follow start offset");
			return;
		case "physical_rows":
			integerAtLeast("generation", 0);
			if (numberField(row, "end_offset") <= 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "physical row end offset must be positive");
			return;
		case "candidates":
			if (numberField(row, "count") <= 0 || numberField(row, "latest_revision") < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "candidate numeric CHECK failed");
			return;
		case "triage_jobs": {
			integerAtLeast("attempts", 0);
			const maxAttempts = numberField(row, "max_attempts");
			if (maxAttempts < 1 || maxAttempts > 10)
				throw new BugwatchContractError("INVALID_SCHEMA", "triage max_attempts is outside its SQLite range");
			const running = row.state === "running";
			if (running !== (row.lease_token !== null && row.lease_expires_at_ms !== null))
				throw new BugwatchContractError("INVALID_SCHEMA", "triage lease fields violate state coupling");
			return;
		}
		case "projection_heads": {
			integerAtLeast("next_generation", 0);
			if (
				numberField(row, "applied_generation") > numberField(row, "dirty_through_generation") ||
				numberField(row, "dirty_through_generation") > numberField(row, "next_generation")
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "projection generation ordering failed");
			const materializing = row.state === "materializing";
			if (materializing !== (row.claim_token !== null && row.claim_generation !== null))
				throw new BugwatchContractError("INVALID_SCHEMA", "projection claim fields violate state coupling");
			return;
		}
		case "context_records":
			if (numberField(row, "byte_count") < 1 || numberField(row, "byte_count") > 16_384)
				throw new BugwatchContractError("INVALID_SCHEMA", "context byte_count is outside its SQLite range");
			if ((row.deleted_at_ms === null) !== (row.delete_proof_hash === null))
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"context deletion proof and timestamp must be jointly nullable",
				);
			return;
		case "old_monitors":
			integerAtLeast("observed_at_ms", 0);
			enumValue("kind", ["gjc_cron", "user_cron", "systemd_user", "process", "tmux", "plugin"]);
			enumValue("status", ["active", "inactive", "unknown"]);
			return;
		case "rollback_items":
			integerAtLeast("item_index", 0);
			integerAtLeast("payload_byte_count", 0);
			enumValue("state", ["pending", "applied", "duplicate", "failed"]);
			return;
		case "archive_aliases":
			integerAtLeast("uncompressed_length", 0);
			return;
		case "producer_ranges":
			integerAtLeast("start_seq", 1);
			if (numberField(row, "end_seq") < numberField(row, "start_seq"))
				throw new BugwatchContractError("INVALID_SCHEMA", `${itemType} sequence bounds are invalid`);
			return;
		case "coverage_boot_ranges":
			if (numberField(row, "end_seq") < numberField(row, "start_seq"))
				throw new BugwatchContractError("INVALID_SCHEMA", `${itemType} sequence bounds are invalid`);
			return;
		case "capacity_blocks":
			integerAtLeast("generation", 0);
			if (
				row.emergency_slot !== null &&
				(numberField(row, "emergency_slot") < 0 || numberField(row, "emergency_slot") > 127)
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "capacity emergency slot is outside its SQLite range");
			return;
		case "job_inputs":
			integerAtLeast("revision", 1);
			return;
		case "triage_results":
			integerAtLeast("attempt", 1);
			return;
		case "artifact_outbox":
			integerAtLeast("content_byte_count", 0);
			integerAtLeast("attempts", 0);
			return;
		case "job_projection_requirements":
			integerAtLeast("required_generation", 1);
			return;
		case "fingerprint_prefix_aliases":
			if (![8, 12, 16, 64].includes(numberField(row, "prefix_len")))
				throw new BugwatchContractError("INVALID_SCHEMA", "fingerprint prefix length violates its SQLite CHECK");
			return;
		case "import_epochs":
			integerAtLeast("byte_count", 0);
			integerAtLeast("item_count", 0);
			return;
		default:
			return;
	}
}
function validateLiteralSnapshotRow(item: AuthoritySnapshotItemV1, expectedClass?: SnapshotPayloadClassV1): void {
	if (expectedClass !== undefined && item.itemType !== expectedClass)
		throw new BugwatchContractError(
			"INVALID_SCHEMA",
			`snapshot validator cannot accept ${item.itemType} as ${expectedClass}`,
		);
	const candidate = valueObject(item.payload, `snapshot ${item.itemType} row`);
	const row = exactObject(
		candidate,
		item.itemType === "scope_policies"
			? SCOPE_POLICY_REVISION_LITERAL_COLUMNS
			: item.itemType === "scope_policy_heads"
				? SCOPE_POLICY_HEAD_LITERAL_COLUMNS
				: SNAPSHOT_LITERAL_ROW_COLUMNS[item.itemType as SnapshotPayloadClassV1],
		`snapshot ${item.itemType} row`,
	);
	const spec =
		item.itemType === "scope_policies" || item.itemType === "scope_policy_heads"
			? SNAPSHOT_PAYLOAD_ROW_SPECS[item.itemType]
			: SNAPSHOT_PAYLOAD_ROW_SPECS[item.itemType as SnapshotPayloadClassV1];
	for (const [index, key] of spec.fields.entries()) {
		const value = row[key];
		const type = spec.types[index];
		if (value === null) {
			if (type !== "nullable_text" && type !== "nullable_integer" && type !== "nullable_boolean")
				throw new BugwatchContractError("INVALID_SCHEMA", `snapshot ${item.itemType}.${key} is not nullable`);
			continue;
		}
		if (type === "boolean" || type === "nullable_boolean") {
			if (value !== 0 && value !== 1)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					`snapshot ${item.itemType}.${key} is not a SQLite boolean`,
				);
			continue;
		}
		if (type === "integer" || type === "nullable_integer") {
			if (typeof value !== "number" || !Number.isSafeInteger(value))
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					`snapshot ${item.itemType}.${key} is not a SQLite integer`,
				);
			continue;
		}
		if (typeof value !== "string")
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				`snapshot ${item.itemType}.${key} is not a SQLite TEXT/BLOB scalar`,
			);
		if (key.endsWith("_hash") || key.endsWith("_digest") || key === "hash") parseHash(row, key);
		const values = SQLITE_ENUMS[`${item.itemType}.${key}`];
		if (values !== undefined && !values.includes(value))
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				`snapshot ${item.itemType}.${key} is not an allowed enum value`,
			);
	}
	validateSnapshotTableChecks(item.itemType as SnapshotPayloadClassV1, row);
	validateSnapshotJsonColumns(item.itemType as SnapshotPayloadClassV1, row);
	validateSnapshotBlobColumns(item.itemType as SnapshotPayloadClassV1, row);
	const authorityColumn = SNAPSHOT_ROW_AUTHORITY_COLUMNS[item.itemType as SnapshotPayloadClassV1];
	if (authorityColumn !== undefined && stringField(row, authorityColumn) !== item.authorityId)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot row authority ID does not match payload");
	if (item.itemType === "schema_meta" && (row.id !== 1 || item.authorityId !== "1"))
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot schema metadata identity does not match");
	if (item.itemType === "root_mutation_steps") {
		const state = {
			schema: "gjc-bugwatch-root-mutation-db-state/v1",
			scopeId: stringField(row, "scope_id"),
			mutationId: stringField(row, "mutation_id"),
			coreHash: stringField(row, "core_hash"),
			phase: stringField(row, "phase"),
			previousPhase: row.previous_phase,
			previousStateHash: row.previous_state_hash,
			keyId: stringField(row, "key_id"),
			mac: stringField(row, "mac"),
		};
		parseRootMutationDbStateV1(state);
		if (authenticatedHash(state as unknown as JsonValue) !== stringField(row, "record_hash"))
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"root mutation state record hash does not match authority state",
			);
	}
	if (item.itemType === "scope_policies" || item.itemType === "scope_policy_heads")
		parseSnapshotScopePolicyLiteral(row);
}

export type SnapshotPayloadValidatorV1 = (item: AuthoritySnapshotItemV1, graph: SnapshotPayloadGraphV1) => void;
export interface SnapshotPayloadGraphV1 {
	scopeId: string;
	items: readonly AuthoritySnapshotItemV1[];
	policyKey: AuthoritySnapshotRetainedKeyringV1 | undefined;
	registryKey: AuthoritySnapshotRetainedKeyringV1 | undefined;
	fatalKey: AuthoritySnapshotRetainedKeyringV1 | undefined;
	rollbackKey: AuthoritySnapshotRetainedKeyringV1 | undefined;
}

/** A closed, per-table validator registry; a validator never accepts another table's row. */
export const SNAPSHOT_PAYLOAD_VALIDATORS: Readonly<Record<SnapshotPayloadClassV1, SnapshotPayloadValidatorV1>> =
	Object.freeze({
		schema_meta: (item, _graph) => validateLiteralSnapshotRow(item, "schema_meta"),
		fingerprint_version_mappings: (item, _graph) => validateLiteralSnapshotRow(item, "fingerprint_version_mappings"),
		scope_policies: (item, _graph) => validateLiteralSnapshotRow(item, "scope_policies"),
		scope_policy_heads: (item, _graph) => validateLiteralSnapshotRow(item, "scope_policy_heads"),
		roots: (item, _graph) => validateLiteralSnapshotRow(item, "roots"),
		root_aliases: (item, _graph) => validateLiteralSnapshotRow(item, "root_aliases"),
		root_mutations: (item, _graph) => validateLiteralSnapshotRow(item, "root_mutations"),
		root_mutation_outputs: (item, _graph) => validateLiteralSnapshotRow(item, "root_mutation_outputs"),
		root_mutation_steps: (item, _graph) => validateLiteralSnapshotRow(item, "root_mutation_steps"),
		root_mutation_rename_steps: (item, _graph) => validateLiteralSnapshotRow(item, "root_mutation_rename_steps"),
		producer_boots: (item, _graph) => validateLiteralSnapshotRow(item, "producer_boots"),
		boot_transport_records: (item, _graph) => validateLiteralSnapshotRow(item, "boot_transport_records"),
		boot_final_records: (item, _graph) => validateLiteralSnapshotRow(item, "boot_final_records"),
		session_attachments: (item, _graph) => validateLiteralSnapshotRow(item, "session_attachments"),
		attachment_transitions: (item, _graph) => validateLiteralSnapshotRow(item, "attachment_transitions"),
		producer_coverage: (item, _graph) => validateLiteralSnapshotRow(item, "producer_coverage"),
		producer_ranges: (item, _graph) => validateLiteralSnapshotRow(item, "producer_ranges"),
		sources: (item, _graph) => validateLiteralSnapshotRow(item, "sources"),
		source_checkpoints: (item, _graph) => validateLiteralSnapshotRow(item, "source_checkpoints"),
		archive_aliases: (item, _graph) => validateLiteralSnapshotRow(item, "archive_aliases"),
		physical_rows: (item, _graph) => validateLiteralSnapshotRow(item, "physical_rows"),
		identity_quarantines: (item, _graph) => validateLiteralSnapshotRow(item, "identity_quarantines"),
		observations: (item, _graph) => validateLiteralSnapshotRow(item, "observations"),
		candidates: (item, _graph) => validateLiteralSnapshotRow(item, "candidates"),
		overflow_buckets: (item, _graph) => validateLiteralSnapshotRow(item, "overflow_buckets"),
		capacity_blocks: (item, _graph) => validateLiteralSnapshotRow(item, "capacity_blocks"),
		job_inputs: (item, _graph) => validateLiteralSnapshotRow(item, "job_inputs"),
		triage_jobs: (item, _graph) => validateLiteralSnapshotRow(item, "triage_jobs"),
		triage_results: (item, _graph) => validateLiteralSnapshotRow(item, "triage_results"),
		artifact_outbox: (item, _graph) => validateLiteralSnapshotRow(item, "artifact_outbox"),
		projection_heads: (item, _graph) => validateLiteralSnapshotRow(item, "projection_heads"),
		job_projection_requirements: (item, _graph) => validateLiteralSnapshotRow(item, "job_projection_requirements"),
		manual_artifacts: (item, _graph) => validateLiteralSnapshotRow(item, "manual_artifacts"),
		fingerprint_prefix_aliases: (item, _graph) => validateLiteralSnapshotRow(item, "fingerprint_prefix_aliases"),
		import_epochs: (item, _graph) => validateLiteralSnapshotRow(item, "import_epochs"),
		context_records: (item, _graph) => validateLiteralSnapshotRow(item, "context_records"),
		coverage_epochs: (item, _graph) => validateLiteralSnapshotRow(item, "coverage_epochs"),
		coverage_source_watermarks: (item, _graph) => validateLiteralSnapshotRow(item, "coverage_source_watermarks"),
		coverage_boot_watermarks: (item, _graph) => validateLiteralSnapshotRow(item, "coverage_boot_watermarks"),
		coverage_boot_ranges: (item, _graph) => validateLiteralSnapshotRow(item, "coverage_boot_ranges"),
		rollback_epochs: (item, _graph) => validateLiteralSnapshotRow(item, "rollback_epochs"),
		rollback_items: (item, _graph) => validateLiteralSnapshotRow(item, "rollback_items"),
		old_monitor_inventory_epochs: (item, _graph) => validateLiteralSnapshotRow(item, "old_monitor_inventory_epochs"),
		old_monitors: (item, _graph) => validateLiteralSnapshotRow(item, "old_monitors"),
		old_monitor_root_coverage: (item, _graph) => validateLiteralSnapshotRow(item, "old_monitor_root_coverage"),
		legacy_disable_receipts: (item, _graph) => validateLiteralSnapshotRow(item, "legacy_disable_receipts"),
		monitor_disable_authorizations: (item, _graph) =>
			validateLiteralSnapshotRow(item, "monitor_disable_authorizations"),
		monitor_disable_receipts: (item, _graph) => validateLiteralSnapshotRow(item, "monitor_disable_receipts"),
		store_operations: (item, _graph) => validateLiteralSnapshotRow(item, "store_operations"),
		store_operation_members: (item, _graph) => validateLiteralSnapshotRow(item, "store_operation_members"),
	});

function requireEmbeddedSnapshotKey(
	keyring: AuthoritySnapshotRetainedKeyringV1 | undefined,
	item: AuthoritySnapshotItemV1,
	field: string,
	name: string,
): AuthoritySnapshotKeyMaterialV1 {
	const row = valueObject(item.payload, `snapshot ${item.itemType} row`);
	const envelope = valueObject(canonicalSnapshotJson(row[field], `snapshot ${field}`), `snapshot ${field}`);
	return requireRetainedSnapshotKey(keyring, stringField(envelope, "keyId"), name);
}

function verifyEmbeddedRegistryRecord(item: AuthoritySnapshotItemV1, graph: SnapshotPayloadGraphV1): void {
	if (!["boot_transport_records", "boot_final_records"].includes(item.itemType)) return;
	const key = requireEmbeddedSnapshotKey(graph.fatalKey, item, "record_json", "fatal_keyring");
	const row = valueObject(item.payload, `snapshot ${item.itemType} row`);
	const encoded = stringField(row, "record_json");
	const record = parseCanonicalJson(encoded);
	if (canonicalizeJson(record) !== encoded)
		throw new BugwatchContractError("INVALID_SCHEMA", "embedded registry record_json is not canonical");
	const envelope = valueObject(record, "embedded registry record");
	if (stringField(envelope, "keyId") !== key.keyId)
		throw new BugwatchContractError("INVALID_MAC", "embedded registry record key does not match retained keyring");
	if (item.itemType === "boot_transport_records") {
		if (row.record_kind === "start") {
			const parsed = parseBootTransportStartV1(record);
			verifyMac(parsed as unknown as JsonValue, "gjc-bugwatch-transport-start-v1", key.keyBytes);
			if (
				authenticatedHash(parsed as unknown as JsonValue) !== stringField(row, "record_hash") ||
				parsed.bootId !== stringField(row, "boot_id") ||
				parsed.transportEpoch !== numberField(row, "transport_epoch") ||
				parsed.policyGeneration !== numberField(row, "policy_generation") ||
				parsed.policyHash !== stringField(row, "policy_hash") ||
				parsed.startSequence !== String(numberField(row, "start_seq")) ||
				parsed.fileEnabled !== (row.file_enabled === 1) ||
				parsed.previousRecordHash !== row.previous_record_hash ||
				row.start_record_hash !== null ||
				row.end_seq !== null ||
				row.outcome !== null
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "embedded transport start does not project to its row");
			return;
		}
		const parsed = parseBootTransportCloseV1(record);
		verifyMac(parsed as unknown as JsonValue, "gjc-bugwatch-transport-close-v1", key.keyBytes);
		if (
			authenticatedHash(parsed as unknown as JsonValue) !== stringField(row, "record_hash") ||
			parsed.bootId !== stringField(row, "boot_id") ||
			parsed.transportEpoch !== numberField(row, "transport_epoch") ||
			parsed.startRecordHash !== row.start_record_hash ||
			parsed.endSequenceInclusive !== String(numberField(row, "end_seq")) ||
			parsed.outcome !== row.outcome ||
			parsed.previousRecordHash !== row.previous_record_hash ||
			row.start_seq !== null ||
			row.file_enabled !== null
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "embedded transport close does not project to its row");
		return;
	}
	const parsed = parseBootFinalV1(record);
	verifyMac(parsed as unknown as JsonValue, "gjc-bugwatch-boot-final-v1", key.keyBytes);
	if (
		authenticatedHash(parsed as unknown as JsonValue) !== stringField(row, "record_hash") ||
		parsed.bootId !== stringField(row, "boot_id") ||
		parsed.finalSequence !== String(numberField(row, "final_seq")) ||
		parsed.state !== row.state ||
		parsed.lastTransportRecordHash !== stringField(row, "last_transport_record_hash") ||
		parsed.attachmentSnapshotHash !== stringField(row, "attachment_snapshot_hash") ||
		parsed.previousRecordHash !== stringField(row, "previous_record_hash")
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "embedded boot final does not project to its row");
}

function embeddedCanonicalEnvelope(row: { [key: string]: JsonValue }, field: string, context: string): JsonValue {
	return canonicalSnapshotJson(row[field], context);
}

function verifyEmbeddedAuthority(item: AuthoritySnapshotItemV1, graph: SnapshotPayloadGraphV1): void {
	const row = valueObject(item.payload, `snapshot ${item.itemType} row`);
	switch (item.itemType) {
		case "roots": {
			if (row.kind !== "project") {
				validateReservedRoot(row);
				return;
			}

			const key = requireEmbeddedSnapshotKey(graph.registryKey, item, "root_json", "registry_keyring");
			const authority = parseRootControlV1(embeddedCanonicalEnvelope(row, "root_json", "snapshot root_json"));
			verifyMac(authority as unknown as JsonValue, "gjc-bugwatch-root-v1", key.keyBytes);
			if (
				authority.keyId !== key.keyId ||
				authority.rootId !== row.root_id ||
				authority.canonicalPath !== row.canonical_path ||
				authority.enabled !== (row.enabled === 1) ||
				authority.persistContext !== (row.persist_context === 1) ||
				authority.generation !== row.revision ||
				authority.projectPolicyHash !== row.project_policy_hash ||
				authority.baselineEpochId !== row.baseline_epoch_id ||
				authority.activeMutationId !== row.active_mutation_id
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "root authority does not project to snapshot row");
			return;
		}
		case "producer_boots": {
			const key = requireEmbeddedSnapshotKey(graph.fatalKey, item, "boot_core_json", "fatal_keyring");
			const authority = parseBootCoreV1(embeddedCanonicalEnvelope(row, "boot_core_json", "snapshot boot_core_json"));
			verifyMac(authority as unknown as JsonValue, "gjc-bugwatch-boot-core-v1", key.keyBytes);
			if (
				authority.keyId !== key.keyId ||
				authenticatedHash(authority as unknown as JsonValue) !== row.boot_core_hash ||
				authority.bootId !== row.boot_id ||
				authority.scopeId !== row.scope_id ||
				authority.pid !== row.pid ||
				authority.pidStartToken !== row.pid_start_token ||
				authority.producer !== row.producer ||
				authority.startedAt !== snapshotPolicyTimestamp(row.started_at_ms, "started_at_ms") ||
				authority.initialPolicyGeneration !== row.initial_policy_generation ||
				authority.initialPolicyHash !== row.initial_policy_hash ||
				authority.fatalKeyId !== row.fatal_key_id ||
				authority.gjcVersion !== row.gjc_version ||
				authority.buildSha !== row.build_sha
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "boot core does not project to snapshot row");
			return;
		}
		case "session_attachments": {
			const key = requireEmbeddedSnapshotKey(graph.fatalKey, item, "attachment_json", "fatal_keyring");
			const authority = parseAttachmentV1(
				embeddedCanonicalEnvelope(row, "attachment_json", "snapshot attachment_json"),
			);
			verifyMac(authority as unknown as JsonValue, "gjc-bugwatch-attachment-v1", key.keyBytes);
			if (
				authority.keyId !== key.keyId ||
				authority.attachmentId !== row.attachment_id ||
				authority.scopeId !== row.scope_id ||
				authority.attachmentTokenHash !== row.attachment_token_hash ||
				authority.bootId !== row.boot_id ||
				authority.bootCoreHash !== row.boot_core_hash ||
				authority.rootId !== row.root_id ||
				authority.sessionId !== row.session_id ||
				authority.startedAt !== snapshotPolicyTimestamp(row.started_at_ms, "started_at_ms") ||
				authority.endedAt !==
					(row.ended_at_ms === null ? null : snapshotPolicyTimestamp(row.ended_at_ms, "ended_at_ms")) ||
				authority.state !== row.state ||
				authority.managedSessionRoot !== row.managed_session_root ||
				authority.sessionFile !== row.session_file ||
				authority.rootGeneration !== row.root_generation ||
				authority.baselineEpochId !== row.baseline_epoch_id ||
				authority.publishSequence !== (row.publish_seq === null ? null : String(row.publish_seq)) ||
				authority.retireSequence !== (row.retire_seq === null ? null : String(row.retire_seq)) ||
				authenticatedHash(authority as unknown as JsonValue) !== row.current_transition_hash
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "attachment authority does not project to snapshot row");
			return;
		}
		case "attachment_transitions": {
			const key = requireEmbeddedSnapshotKey(graph.fatalKey, item, "record_json", "fatal_keyring");
			const authority = parseAttachmentV1(
				embeddedCanonicalEnvelope(row, "record_json", "snapshot attachment transition"),
			);
			verifyMac(authority as unknown as JsonValue, "gjc-bugwatch-attachment-v1", key.keyBytes);
			if (
				authority.keyId !== key.keyId ||
				authority.keyId !== row.key_id ||
				authority.mac !== row.mac ||
				authority.attachmentId !== row.attachment_id ||
				authority.state !== row.state ||
				authenticatedHash(authority as unknown as JsonValue) !== row.transition_hash
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"attachment transition authority does not project to snapshot row",
				);
			return;
		}
		case "old_monitors": {
			const key = requireEmbeddedSnapshotKey(graph.registryKey, item, "inventory_json", "registry_keyring");
			const authority = parseMonitorInventoryV1(
				embeddedCanonicalEnvelope(row, "inventory_json", "snapshot inventory_json"),
			);
			verifyMac(authority as unknown as JsonValue, "gjc-bugwatch-monitor-inventory-v1", key.keyBytes);
			if (
				authority.keyId !== key.keyId ||
				authority.inventoryEpochId !== row.inventory_epoch_id ||
				authority.monitorId !== row.monitor_id ||
				authority.kind !== row.kind ||
				authority.stableIdentifier !== row.stable_identifier ||
				authority.configHash !== row.config_hash ||
				authority.status !== row.status ||
				authority.observedAt !== snapshotPolicyTimestamp(row.observed_at_ms, "observed_at_ms")
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "monitor inventory does not project to snapshot row");
			return;
		}
		case "monitor_disable_authorizations": {
			const key = requireEmbeddedSnapshotKey(graph.registryKey, item, "authorization_json", "registry_keyring");
			const authority = parseMonitorDisableAuthorizationV1(
				embeddedCanonicalEnvelope(row, "authorization_json", "snapshot monitor disable authorization"),
			);
			verifyMac(authority as unknown as JsonValue, "gjc-bugwatch-monitor-disable-auth-v1", key.keyBytes);
			if (
				authority.keyId !== key.keyId ||
				authority.keyId !== row.key_id ||
				authority.mac !== row.mac ||
				authority.scopeId !== row.scope_id ||
				authority.authorizationId !== row.authorization_id ||
				authority.inventoryEpochId !== row.inventory_epoch_id ||
				authority.monitorId !== row.monitor_id ||
				authority.adapterKind !== row.action_kind ||
				authority.expectedConfigHash !== row.expected_config_hash ||
				sha256Hex(canonicalizeJson(authority.allowedAction as unknown as JsonValue)) !== row.action_hash ||
				sha256Hex(authority.nonce) !== row.consume_nonce_hash ||
				snapshotPolicyTimestamp(row.authorized_at_ms, "authorized_at_ms") !== authority.authorizedAt ||
				snapshotPolicyTimestamp(row.expires_at_ms, "expires_at_ms") !== authority.expiresAt
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "monitor authorization does not project to snapshot row");
			return;
		}
		case "monitor_disable_receipts": {
			const key = requireEmbeddedSnapshotKey(graph.registryKey, item, "receipt_json", "registry_keyring");
			const authority = parseMonitorDisableReceiptV1(
				embeddedCanonicalEnvelope(row, "receipt_json", "snapshot receipt_json"),
			);
			verifyMac(authority as unknown as JsonValue, "gjc-bugwatch-monitor-disable-receipt-v1", key.keyBytes);
			if (
				authority.keyId !== key.keyId ||
				authority.keyId !== row.key_id ||
				authority.mac !== row.mac ||
				authority.scopeId !== row.scope_id ||
				authenticatedHash(authority as unknown as JsonValue) !== row.receipt_hash ||
				authority.authorizationId !== row.authorization_id ||
				authority.actionHash !== row.action_hash ||
				authority.inventoryEpochId !== row.inventory_epoch_id ||
				authority.monitorId !== row.monitor_id ||
				authority.adapterKind !== row.adapter_kind ||
				authority.beforeHash !== row.before_hash ||
				authority.afterHash !== row.after_hash ||
				authority.result !== row.result ||
				canonicalizeJson(authority.steps as unknown as JsonValue) !== row.steps_json ||
				canonicalizeJson(authority.coveredRootIds as unknown as JsonValue) !== row.covered_roots_json ||
				authority.startedAt !== snapshotPolicyTimestamp(row.started_at_ms, "started_at_ms") ||
				authority.finishedAt !== snapshotPolicyTimestamp(row.finished_at_ms, "finished_at_ms")
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "monitor receipt does not project to snapshot row");

			return;
		}
		case "store_operations": {
			const key = requireEmbeddedSnapshotKey(graph.registryKey, item, "core_json", "registry_keyring");
			const authority = parseStoreOperationCoreV1(
				embeddedCanonicalEnvelope(row, "core_json", "snapshot store core_json"),
			);
			verifyMac(authority as unknown as JsonValue, "gjc-bugwatch-store-operation-core-v1", key.keyBytes);
			if (
				authority.keyId !== key.keyId ||
				authenticatedHash(authority as unknown as JsonValue) !== row.core_hash ||
				authority.operationId !== row.operation_id ||
				authority.ownerId !== row.owner_id ||
				authority.claimTokenHash !== row.claim_token_hash ||
				authority.kind !== row.kind ||
				authority.fromVersion !== row.from_version ||
				authority.toVersion !== row.to_version
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "store core does not project to snapshot row");
			return;
		}
		case "rollback_epochs": {
			const bundle = parseRollbackBundleV1(embeddedCanonicalEnvelope(row, "bundle_json", "snapshot bundle_json"));
			const manifest = parseRollbackSpoolManifestV1(
				embeddedCanonicalEnvelope(row, "spool_manifest_json", "snapshot spool_manifest_json"),
			);
			const ack = parseRollbackInboxAckV1(
				embeddedCanonicalEnvelope(row, "inbox_ack_json", "snapshot inbox_ack_json"),
			);
			const bundleKey = requireRetainedSnapshotKey(graph.rollbackKey, bundle.keyId, "rollback_keyring");
			const manifestKey = requireRetainedSnapshotKey(graph.rollbackKey, manifest.keyId, "rollback_keyring");
			const ackKey = requireRetainedSnapshotKey(graph.rollbackKey, ack.keyId, "rollback_keyring");
			verifyMac(bundle as unknown as JsonValue, "gjc-bugwatch-rollback-bundle-v1", bundleKey.keyBytes);
			verifyMac(manifest as unknown as JsonValue, "gjc-bugwatch-rollback-spool-manifest-v1", manifestKey.keyBytes);
			verifyMac(ack as unknown as JsonValue, "gjc-bugwatch-rollback-inbox-ack-v1", ackKey.keyBytes);
			if (
				bundle.scopeId !== row.scope_id ||
				bundle.epochId !== row.epoch_id ||
				bundle.bundleVersion !== row.bundle_version ||
				bundle.state !== row.state ||
				bundle.manifestHash !== row.manifest_hash ||
				manifest.scopeId !== row.scope_id ||
				manifest.epochId !== row.epoch_id ||
				ack.scopeId !== row.scope_id ||
				ack.epochId !== row.epoch_id
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "rollback authority does not project to snapshot row");
			return;
		}
		case "rollback_items": {
			const key = requireEmbeddedSnapshotKey(graph.rollbackKey, item, "item_json", "rollback_keyring");
			const authority = parseRollbackBundleItemV1(
				embeddedCanonicalEnvelope(row, "item_json", "snapshot rollback item"),
			);
			verifyMac(authority as unknown as JsonValue, "gjc-bugwatch-rollback-bundle-item-v1", key.keyBytes);
			if (
				authority.keyId !== key.keyId ||
				authority.keyId !== row.key_id ||
				authority.mac !== row.mac ||
				authority.epochId !== row.epoch_id ||
				authority.itemIndex !== row.item_index ||
				authority.itemType !== row.item_type ||
				authority.itemHash !== row.item_hash ||
				authority.payloadHash !== row.payload_hash
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"rollback item authority does not project to snapshot row",
				);
			return;
		}
		default:
			return;
	}
}

export function validateSnapshotPayload(item: AuthoritySnapshotItemV1, graph: SnapshotPayloadGraphV1): void {
	const validator = SNAPSHOT_PAYLOAD_VALIDATORS[item.itemType as SnapshotPayloadClassV1];
	if (validator === undefined)
		throw new BugwatchContractError(
			"UNSUPPORTED_SCHEMA",
			`snapshot class ${item.itemType} has no authority payload validator`,
		);
	validator(item, graph);
	verifyEmbeddedRegistryRecord(item, graph);
	verifyEmbeddedAuthority(item, graph);
	const row = valueObject(item.payload, "snapshot payload");
	if ("scope_id" in row && stringField(row, "scope_id") !== graph.scopeId)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot row scope does not match manifest scope");
}

export function validateSnapshotGraph(graph: SnapshotPayloadGraphV1): void {
	const rows = (className: SnapshotPayloadClassV1) =>
		graph.items
			.filter(item => item.itemType === className)
			.map(item => valueObject(item.payload, `snapshot ${className} row`));
	const has = (className: SnapshotPayloadClassV1, column: string, value: JsonValue) =>
		rows(className).some(row => row[column] === value);
	const requireReference = (
		className: SnapshotPayloadClassV1,
		column: string,
		targetClass: SnapshotPayloadClassV1,
		targetColumn: string,
	): void => {
		for (const row of rows(className)) {
			if (row[column] !== null && !has(targetClass, targetColumn, row[column]))
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					`snapshot ${className}.${column} has no ${targetClass} authority`,
				);
		}
	};
	for (const [className, column, targetClass, targetColumn] of [
		["root_aliases", "old_root_id", "roots", "root_id"],
		["root_aliases", "new_root_id", "roots", "root_id"],
		["root_mutations", "old_root_id", "roots", "root_id"],
		["root_mutations", "new_root_id", "roots", "root_id"],
		["root_mutation_outputs", "mutation_id", "root_mutations", "mutation_id"],
		["root_mutation_steps", "mutation_id", "root_mutations", "mutation_id"],
		["root_mutation_rename_steps", "mutation_id", "root_mutations", "mutation_id"],
		["boot_transport_records", "boot_id", "producer_boots", "boot_id"],
		["boot_final_records", "boot_id", "producer_boots", "boot_id"],
		["session_attachments", "boot_id", "producer_boots", "boot_id"],
		["session_attachments", "root_id", "roots", "root_id"],
		["attachment_transitions", "attachment_id", "session_attachments", "attachment_id"],
		["producer_coverage", "boot_id", "producer_boots", "boot_id"],
		["producer_ranges", "boot_id", "producer_boots", "boot_id"],
		["source_checkpoints", "segment_id", "sources", "segment_id"],
		["archive_aliases", "segment_id", "sources", "segment_id"],
		["physical_rows", "segment_id", "sources", "segment_id"],
		["physical_rows", "boot_id", "producer_boots", "boot_id"],
		["identity_quarantines", "segment_id", "sources", "segment_id"],
		["identity_quarantines", "claimed_root_id", "roots", "root_id"],
		["identity_quarantines", "claimed_boot_id", "producer_boots", "boot_id"],
		["identity_quarantines", "claimed_attachment_id", "session_attachments", "attachment_id"],
		["observations", "root_id", "roots", "root_id"],
		["observations", "boot_id", "producer_boots", "boot_id"],
		["observations", "attachment_id", "session_attachments", "attachment_id"],
		["candidates", "root_id", "roots", "root_id"],
		["candidates", "sample_event_id", "observations", "event_id"],
		["overflow_buckets", "root_id", "roots", "root_id"],
		["capacity_blocks", "segment_id", "sources", "segment_id"],
		["capacity_blocks", "root_id", "roots", "root_id"],
		["job_inputs", "root_id", "roots", "root_id"],
		["triage_jobs", "job_id", "job_inputs", "job_id"],
		["triage_results", "job_id", "triage_jobs", "job_id"],
		["artifact_outbox", "job_id", "triage_jobs", "job_id"],
		["artifact_outbox", "result_id", "triage_results", "result_id"],
		["projection_heads", "root_id", "roots", "root_id"],
		["job_projection_requirements", "job_id", "triage_jobs", "job_id"],
		["job_projection_requirements", "root_id", "roots", "root_id"],
		["manual_artifacts", "root_id", "roots", "root_id"],
		["manual_artifacts", "import_epoch_id", "import_epochs", "epoch_id"],
		["fingerprint_prefix_aliases", "root_id", "roots", "root_id"],
		["fingerprint_prefix_aliases", "artifact_id", "manual_artifacts", "artifact_id"],
		["import_epochs", "root_id", "roots", "root_id"],
		["context_records", "job_id", "triage_jobs", "job_id"],
		["coverage_epochs", "root_id", "roots", "root_id"],
		["coverage_source_watermarks", "epoch_id", "coverage_epochs", "epoch_id"],
		["coverage_source_watermarks", "segment_id", "sources", "segment_id"],
		["coverage_boot_watermarks", "epoch_id", "coverage_epochs", "epoch_id"],
		["coverage_boot_watermarks", "boot_id", "producer_boots", "boot_id"],
		["coverage_boot_ranges", "epoch_id", "coverage_epochs", "epoch_id"],
		["coverage_boot_ranges", "boot_id", "producer_boots", "boot_id"],
		["rollback_items", "epoch_id", "rollback_epochs", "epoch_id"],
		["old_monitors", "inventory_epoch_id", "old_monitor_inventory_epochs", "inventory_epoch_id"],
		["old_monitor_root_coverage", "inventory_epoch_id", "old_monitor_inventory_epochs", "inventory_epoch_id"],
		["old_monitor_root_coverage", "root_id", "roots", "root_id"],
		["legacy_disable_receipts", "root_id", "roots", "root_id"],
		["monitor_disable_authorizations", "inventory_epoch_id", "old_monitor_inventory_epochs", "inventory_epoch_id"],
		["monitor_disable_receipts", "authorization_id", "monitor_disable_authorizations", "authorization_id"],
		["store_operation_members", "operation_id", "store_operations", "operation_id"],
	] as const)
		requireReference(className, column, targetClass, targetColumn);
	const monitorRows = rows("old_monitors");
	for (const authorizationRow of rows("monitor_disable_authorizations")) {
		const authorization = parseMonitorDisableAuthorizationV1(
			embeddedCanonicalEnvelope(authorizationRow, "authorization_json", "snapshot monitor authorization"),
		);
		const authorizationKey = requireRetainedSnapshotKey(graph.registryKey, authorization.keyId, "registry_keyring");
		verifyMac(
			authorization as unknown as JsonValue,
			"gjc-bugwatch-monitor-disable-auth-v1",
			authorizationKey.keyBytes,
		);
		if (
			authorization.keyId !== authorizationRow.key_id ||
			authorization.mac !== authorizationRow.mac ||
			authorization.scopeId !== authorizationRow.scope_id ||
			authorization.authorizationId !== authorizationRow.authorization_id ||
			authorization.inventoryEpochId !== authorizationRow.inventory_epoch_id ||
			authorization.monitorId !== authorizationRow.monitor_id ||
			authorization.adapterKind !== authorizationRow.action_kind ||
			authorization.expectedConfigHash !== authorizationRow.expected_config_hash
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"monitor authorization row does not project its signed authority",
			);
		const inventories = monitorRows.filter(
			row => row.inventory_epoch_id === authorization.inventoryEpochId && row.monitor_id === authorization.monitorId,
		);
		if (inventories.length !== 1)
			throw new BugwatchContractError(
				"AUTHORITY_MISSING",
				"monitor authorization must resolve to exactly one authenticated inventory row",
			);
		const inventory = parseMonitorInventoryV1(
			embeddedCanonicalEnvelope(inventories[0], "inventory_json", "snapshot monitor inventory"),
		);
		const inventoryKey = requireRetainedSnapshotKey(graph.registryKey, inventory.keyId, "registry_keyring");
		verifyMac(inventory as unknown as JsonValue, "gjc-bugwatch-monitor-inventory-v1", inventoryKey.keyBytes);
		if (
			inventory.scopeId !== authorization.scopeId ||
			inventory.kind !== authorization.adapterKind ||
			inventory.stableIdentifier !== authorization.stableIdentifier ||
			inventory.configHash !== authorization.expectedConfigHash ||
			inventory.keyId !== authorization.keyId
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"monitor authorization does not preserve authenticated inventory continuity",
			);
	}
	for (const receiptRow of rows("monitor_disable_receipts")) {
		const authorizations = rows("monitor_disable_authorizations").filter(
			candidate => candidate.authorization_id === receiptRow.authorization_id,
		);
		if (authorizations.length !== 1)
			throw new BugwatchContractError(
				"AUTHORITY_MISSING",
				"monitor receipt must resolve to exactly one authenticated authorization row",
			);
		const authorizationRow = authorizations[0];
		const receipt = parseMonitorDisableReceiptV1(
			embeddedCanonicalEnvelope(receiptRow, "receipt_json", "snapshot monitor receipt"),
		);
		const receiptKey = requireRetainedSnapshotKey(graph.registryKey, receipt.keyId, "registry_keyring");
		if (
			receipt.keyId !== receiptKey.keyId ||
			receipt.keyId !== receiptRow.key_id ||
			receipt.mac !== receiptRow.mac ||
			receipt.scopeId !== receiptRow.scope_id ||
			authenticatedHash(receipt as unknown as JsonValue) !== receiptRow.receipt_hash ||
			receipt.authorizationId !== receiptRow.authorization_id ||
			receipt.actionHash !== receiptRow.action_hash ||
			receipt.inventoryEpochId !== receiptRow.inventory_epoch_id ||
			receipt.monitorId !== receiptRow.monitor_id ||
			receipt.adapterKind !== receiptRow.adapter_kind ||
			receipt.beforeHash !== receiptRow.before_hash ||
			receipt.afterHash !== receiptRow.after_hash ||
			receipt.result !== receiptRow.result ||
			canonicalizeJson(receipt.steps as unknown as JsonValue) !== receiptRow.steps_json ||
			canonicalizeJson(receipt.coveredRootIds as unknown as JsonValue) !== receiptRow.covered_roots_json ||
			receipt.startedAt !== snapshotPolicyTimestamp(receiptRow.started_at_ms, "started_at_ms") ||
			receipt.finishedAt !== snapshotPolicyTimestamp(receiptRow.finished_at_ms, "finished_at_ms")
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "monitor receipt row does not project its signed authority");
		verifyMac(receipt as unknown as JsonValue, "gjc-bugwatch-monitor-disable-receipt-v1", receiptKey.keyBytes);
		const authorization = parseMonitorDisableAuthorizationV1(
			embeddedCanonicalEnvelope(authorizationRow, "authorization_json", "snapshot monitor authorization"),
		);
		const inventories = monitorRows.filter(
			row => row.inventory_epoch_id === receipt.inventoryEpochId && row.monitor_id === receipt.monitorId,
		);
		if (
			inventories.length !== 1 ||
			receipt.keyId !== authorization.keyId ||
			receipt.scopeId !== authorization.scopeId ||
			receipt.authorizationId !== authorization.authorizationId ||
			receipt.inventoryEpochId !== authorization.inventoryEpochId ||
			receipt.monitorId !== authorization.monitorId ||
			receipt.adapterKind !== authorization.adapterKind ||
			receipt.actionHash !== authorizationRow.action_hash
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"monitor receipt does not bind the authenticated authorization identity",
			);
		const inventory = parseMonitorInventoryV1(
			embeddedCanonicalEnvelope(inventories[0], "inventory_json", "snapshot monitor inventory"),
		);
		if (
			inventory.scopeId !== receipt.scopeId ||
			inventory.kind !== receipt.adapterKind ||
			canonicalizeJson(inventory.coveredRootIds as unknown as JsonValue) !==
				canonicalizeJson(receipt.coveredRootIds as unknown as JsonValue)
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"monitor receipt does not preserve authenticated inventory scope and coverage",
			);
	}
	const requireCompositeReference = (
		className: SnapshotPayloadClassV1,
		columns: readonly string[],
		targetClass: SnapshotPayloadClassV1,
		targetColumns: readonly string[],
	): void => {
		for (const row of rows(className)) {
			if (columns.some(column => row[column] === null)) continue;
			if (
				!rows(targetClass).some(target =>
					columns.every((column, index) => row[column] === target[targetColumns[index]]),
				)
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					`snapshot ${className} has no ${targetClass} authority for its complete composite key`,
				);
		}
	};
	for (const [className, columns, targetClass, targetColumns] of [
		["source_checkpoints", ["segment_id", "generation"], "sources", ["segment_id", "generation"]],
		["archive_aliases", ["segment_id", "generation"], "sources", ["segment_id", "generation"]],
		["physical_rows", ["segment_id", "generation"], "sources", ["segment_id", "generation"]],
		["identity_quarantines", ["segment_id", "generation"], "sources", ["segment_id", "generation"]],
		["capacity_blocks", ["segment_id", "generation"], "sources", ["segment_id", "generation"]],
		["coverage_source_watermarks", ["segment_id", "generation"], "sources", ["segment_id", "generation"]],
		["coverage_boot_ranges", ["epoch_id", "boot_id"], "coverage_boot_watermarks", ["epoch_id", "boot_id"]],
		[
			"old_monitor_root_coverage",
			["inventory_epoch_id", "monitor_id"],
			"old_monitors",
			["inventory_epoch_id", "monitor_id"],
		],
		[
			"job_inputs",
			["root_id", "fingerprint_version", "fingerprint_hash"],
			"candidates",
			["root_id", "fingerprint_version", "fingerprint_hash"],
		],
		[
			"job_projection_requirements",
			["root_id", "projection_kind"],
			"projection_heads",
			["root_id", "projection_kind"],
		],
	] as const)
		requireCompositeReference(className, columns, targetClass, targetColumns);
	const mutations = rows("root_mutations");
	if (new Set(mutations.map(row => stringField(row, "mutation_id"))).size !== mutations.length)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot root mutation summaries must be unique");
	const mutationSteps = rows("root_mutation_steps");
	for (const mutation of mutations) {
		const states = mutationSteps
			.filter(step => step.mutation_id === mutation.mutation_id)
			.sort((left, right) => numberField(left, "step_index") - numberField(right, "step_index"));
		if (states.length === 0) throw new BugwatchContractError("INVALID_SCHEMA", "root mutation state chain is empty");
		const coreJson = stringField(mutation, "core_json");
		const coreInput = parseCanonicalJson(coreJson);
		if (canonicalizeJson(coreInput) !== coreJson)
			throw new BugwatchContractError("INVALID_SCHEMA", "root mutation core_json is not canonical");
		const core = parseRootMutationCoreV1(coreInput);
		const coreKey = requireRetainedSnapshotKey(graph.registryKey, core.keyId, "registry_keyring");
		verifyMac(core as unknown as JsonValue, "gjc-bugwatch-root-mutation-core-v1", coreKey.keyBytes);
		if (
			authenticatedHash(core as unknown as JsonValue) !== stringField(mutation, "core_hash") ||
			core.scopeId !== stringField(mutation, "scope_id") ||
			core.mutationId !== stringField(mutation, "mutation_id") ||
			core.action !== stringField(mutation, "action") ||
			core.expectedPolicyGeneration !== numberField(mutation, "expected_policy_generation") ||
			core.expectedPolicyHash !== stringField(mutation, "expected_policy_hash") ||
			core.oldRootId !== mutation.old_root_id ||
			core.newRootId !== mutation.new_root_id ||
			snapshotPolicyTimestamp(mutation.created_at_ms, "created_at_ms") !== core.createdAt
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"root mutation scalars do not project from authenticated core_json",
			);
		const outputs = rows("root_mutation_outputs").filter(output => output.mutation_id === mutation.mutation_id);
		if (outputs.length !== core.outputs.length)
			throw new BugwatchContractError(
				"AUTHORITY_MISSING",
				"root mutation outputs do not cover authenticated core outputs",
			);
		for (const output of core.outputs) {
			const row = outputs.filter(candidate => candidate.target === output.target);
			if (
				row.length !== 1 ||
				row[0].path_hash !== output.pathHash ||
				row[0].precondition !== output.precondition ||
				row[0].expected_old_content_hash !== output.expectedOldContentHash ||
				row[0].pending_content_hash !== output.pendingContentHash ||
				row[0].final_content_hash !== output.finalContentHash ||
				row[0].desired_root_generation !== output.desiredRootGeneration ||
				row[0].publication_order !== output.publicationOrder
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"root mutation output does not project from authenticated core",
				);
		}
		const renameSteps = rows("root_mutation_rename_steps")
			.filter(step => step.mutation_id === mutation.mutation_id)
			.sort((left, right) => numberField(left, "step_index") - numberField(right, "step_index"));
		const parsedRenameSteps = renameSteps.map(row =>
			parseRootMutationRenameStepV2({
				schema: "gjc-bugwatch-root-rename-step/v2",
				scopeId: core.scopeId,
				mutationId: stringField(row, "mutation_id"),
				coreHash: authenticatedHash(core as unknown as JsonValue),
				stepIndex: numberField(row, "step_index"),
				target: stringField(row, "target"),
				lifecycle: stringField(row, "lifecycle"),
				action: stringField(row, "action"),
				expectedDestinationHash: row.expected_destination_hash,
				sourceTempHash: stringField(row, "source_temp_hash"),
				desiredDestinationHash: stringField(row, "desired_destination_hash"),
				observedDestinationHash: row.observed_destination_hash,
				previousStepHash: row.previous_step_hash,
				occurredAt: snapshotPolicyTimestamp(row.occurred_at_ms, "occurred_at_ms"),
				keyId: stringField(row, "key_id"),
				mac: stringField(row, "mac"),
			}),
		);
		for (const [index, step] of parsedRenameSteps.entries()) {
			verifyMac(step as unknown as JsonValue, "gjc-bugwatch-root-rename-step-v2", coreKey.keyBytes);
			if (
				step.keyId !== core.keyId ||
				authenticatedHash(step as unknown as JsonValue) !== renameSteps[index].step_hash ||
				step.previousStepHash !==
					(index === 0 ? null : authenticatedHash(parsedRenameSteps[index - 1] as unknown as JsonValue))
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"root mutation rename step is not an authenticated chain",
				);
		}
		if (parsedRenameSteps.length > 0)
			authenticatedRootSteps(core, parsedRenameSteps as unknown as JsonValue[], coreKey.keyBytes);
		const keyId = core.keyId;
		let previous: RootMutationDbStateV1 | undefined;
		for (const [index, row] of states.entries()) {
			if (numberField(row, "step_index") !== index)
				throw new BugwatchContractError("INVALID_SCHEMA", "root mutation state chain has a step index hole");
			const state = parseRootMutationDbStateV1({
				schema: "gjc-bugwatch-root-mutation-db-state/v1",
				scopeId: stringField(row, "scope_id"),
				mutationId: stringField(row, "mutation_id"),
				coreHash: stringField(row, "core_hash"),
				phase: stringField(row, "phase"),
				previousPhase: row.previous_phase,
				previousStateHash: row.previous_state_hash,
				keyId: stringField(row, "key_id"),
				mac: stringField(row, "mac"),
			});
			if (
				authenticatedHash(state as unknown as JsonValue) !== stringField(row, "record_hash") ||
				state.scopeId !== mutation.scope_id ||
				state.coreHash !== mutation.core_hash ||
				state.keyId !== keyId
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"root mutation state does not share its summary authority",
				);
			verifyMac(state as unknown as JsonValue, "gjc-bugwatch-root-mutation-db-state-v1", coreKey.keyBytes);
			if (previous?.phase === "conflict" || previous?.phase === "aborted" || previous?.phase === "committed")
				throw new BugwatchContractError("INVALID_SCHEMA", "root mutation state follows a terminal phase");
			const expectedPhase =
				index === 0
					? "prepared"
					: ROOT_MUTATION_DB_PHASE_CHAIN[
							ROOT_MUTATION_DB_PHASE_CHAIN.indexOf(previous?.phase as RootMutationDbPhaseV1) + 1
						];
			const terminalTransition =
				state.phase === "conflict" ||
				(state.phase === "aborted" && (previous?.phase === "prepared" || previous?.phase === "publishing"));
			if (
				index === 0
					? state.phase !== "prepared" || state.previousPhase !== null || state.previousStateHash !== null
					: state.previousPhase !== previous?.phase ||
						state.previousStateHash !== authenticatedHash(previous as unknown as JsonValue) ||
						(state.phase !== expectedPhase && !terminalTransition)
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"root mutation state is not an authenticated phase chain",
				);
			previous = state;
		}
		const terminal = states.at(-1);
		if (
			terminal === undefined ||
			terminal.step_index !== mutation.step_index ||
			terminal.record_hash !== mutation.current_step_hash ||
			terminal.phase !== mutation.phase
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"root mutation does not link its terminal mutable state to an authenticated step",
			);
		validateRootMutationAuthorityGraphV1({
			core: core as unknown as JsonValue,
			outputs: outputs.map(output => ({
				target: stringField(output, "target") as RootMutationOutputV2["target"],
				pathHash: stringField(output, "path_hash"),
				precondition: stringField(output, "precondition") as RootMutationOutputV2["precondition"],
				expectedOldContentHash: output.expected_old_content_hash as string | null,
				pendingContentHash: stringField(output, "pending_content_hash"),
				finalContentHash: stringField(output, "final_content_hash"),
				desiredRootGeneration: numberField(output, "desired_root_generation"),
				publicationOrder: numberField(output, "publication_order") as RootMutationOutputV2["publicationOrder"],
			})),
			steps: parsedRenameSteps as unknown as JsonValue[],
			dbStates: states.map(row => ({
				schema: "gjc-bugwatch-root-mutation-db-state/v1",
				scopeId: stringField(row, "scope_id"),
				mutationId: stringField(row, "mutation_id"),
				coreHash: stringField(row, "core_hash"),
				phase: stringField(row, "phase"),
				previousPhase: row.previous_phase,
				previousStateHash: row.previous_state_hash,
				keyId: stringField(row, "key_id"),
				mac: stringField(row, "mac"),
			})),
			keyBytes: coreKey.keyBytes,
		});
	}
	if (graph.fatalKey === undefined && rows("producer_boots").length > 0)
		throw new BugwatchContractError("AUTHORITY_MISSING", "authority_missing:fatal_keyring");
	for (const boot of rows("producer_boots")) {
		const core = parseBootCoreV1(
			embeddedCanonicalEnvelope(boot, "boot_core_json", "snapshot producer boot core_json"),
		);
		const coreKey = requireRetainedSnapshotKey(graph.fatalKey, core.keyId, "fatal_keyring");
		if (authenticatedHash(core as unknown as JsonValue) !== boot.boot_core_hash)
			throw new BugwatchContractError("INVALID_SCHEMA", "producer boot core does not bind its retained authority");
		verifyMac(core as unknown as JsonValue, "gjc-bugwatch-boot-core-v1", coreKey.keyBytes);
		const transportRows = rows("boot_transport_records")
			.filter(row => row.boot_id === boot.boot_id)
			.sort(
				(left, right) =>
					numberField(left, "transport_epoch") - numberField(right, "transport_epoch") ||
					(left.record_kind === "start" ? -1 : 1),
			);
		let previousTransportHash: string | null = null;
		const starts = new Set<string>();
		for (const transportRow of transportRows) {
			const isStart = transportRow.record_kind === "start";
			const transport = isStart
				? parseBootTransportStartV1(
						embeddedCanonicalEnvelope(transportRow, "record_json", "snapshot boot transport record_json"),
					)
				: parseBootTransportCloseV1(
						embeddedCanonicalEnvelope(transportRow, "record_json", "snapshot boot transport record_json"),
					);
			const recordHash = authenticatedHash(transport as unknown as JsonValue);
			const occurredAt = "startedAt" in transport ? transport.startedAt : transport.endedAt;
			const transportKey = requireRetainedSnapshotKey(graph.fatalKey, transport.keyId, "fatal_keyring");
			if (
				transport.bootId !== boot.boot_id ||
				transport.scopeId !== boot.scope_id ||
				transport.bootCoreHash !== boot.boot_core_hash ||
				transport.previousRecordHash !== previousTransportHash ||
				recordHash !== transportRow.record_hash ||
				transportRow.created_at_ms !== Date.parse(occurredAt) ||
				("startSequence" in transport
					? transport.startSequence !== String(transportRow.start_seq)
					: !starts.has(transport.startRecordHash))
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"boot transport row does not bind to its authenticated core and predecessor chain",
				);
			verifyMac(
				transport as unknown as JsonValue,
				isStart ? "gjc-bugwatch-transport-start-v1" : "gjc-bugwatch-transport-close-v1",
				transportKey.keyBytes,
			);
			if (isStart) starts.add(recordHash);
			previousTransportHash = recordHash;
		}
		const finals = rows("boot_final_records").filter(row => row.boot_id === boot.boot_id);
		if ((boot.final_record_hash === null) !== (finals.length === 0) || finals.length > 1)
			throw new BugwatchContractError("INVALID_SCHEMA", "producer boot final head is incomplete");
		if (finals.length === 1) {
			const finalRow = finals[0];
			const final = parseBootFinalV1(
				embeddedCanonicalEnvelope(finalRow, "record_json", "snapshot boot final record_json"),
			);
			const finalKey = requireRetainedSnapshotKey(graph.fatalKey, final.keyId, "fatal_keyring");
			if (
				final.bootId !== boot.boot_id ||
				final.scopeId !== boot.scope_id ||
				final.bootCoreHash !== boot.boot_core_hash ||
				final.previousRecordHash !== previousTransportHash ||
				authenticatedHash(final as unknown as JsonValue) !== finalRow.record_hash ||
				finalRow.created_at_ms !== Date.parse(final.endedAt) ||
				finalRow.record_hash !== boot.final_record_hash ||
				Number(final.finalSequence) !== boot.final_seq ||
				final.state !== boot.final_state
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"boot final row does not bind to its authenticated core and transport head",
				);
			verifyMac(final as unknown as JsonValue, "gjc-bugwatch-boot-final-v1", finalKey.keyBytes);
		}
	}
	for (const monitor of rows("old_monitors")) {
		const inventory = parseMonitorInventoryV1(
			embeddedCanonicalEnvelope(monitor, "inventory_json", "snapshot monitor inventory_json"),
		);
		const coveredRootIds = rows("old_monitor_root_coverage")
			.filter(
				coverage =>
					coverage.inventory_epoch_id === monitor.inventory_epoch_id && coverage.monitor_id === monitor.monitor_id,
			)
			.map(coverage => stringField(coverage, "root_id"))
			.sort();
		if (
			inventory.coveredRootIds.length !== coveredRootIds.length ||
			[...inventory.coveredRootIds].sort().some((rootId, index) => rootId !== coveredRootIds[index])
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"monitor root coverage does not project from authenticated inventory",
			);
	}
	if (graph.fatalKey === undefined && rows("session_attachments").length > 0)
		throw new BugwatchContractError("AUTHORITY_MISSING", "authority_missing:fatal_keyring");
	for (const attachment of rows("session_attachments")) {
		const transitions = rows("attachment_transitions")
			.filter(row => row.attachment_id === attachment.attachment_id)
			.sort((left, right) => numberField(left, "step_index") - numberField(right, "step_index"));
		if (transitions.length === 0)
			throw new BugwatchContractError("AUTHORITY_MISSING", "attachment has no authenticated transition chain");
		let previousHash: string | null = null;
		let current: AttachmentV1 | undefined;
		for (const [index, row] of transitions.entries()) {
			const authority = parseAttachmentV1(
				embeddedCanonicalEnvelope(row, "record_json", "snapshot attachment transition"),
			);
			const authorityKey = requireRetainedSnapshotKey(graph.fatalKey, authority.keyId, "fatal_keyring");
			if (
				authority.keyId !== row.key_id ||
				authority.mac !== row.mac ||
				numberField(row, "step_index") !== index ||
				authority.attachmentId !== attachment.attachment_id ||
				authority.state !== row.state ||
				authority.scopeId !== attachment.scope_id ||
				authority.attachmentTokenHash !== attachment.attachment_token_hash ||
				authority.bootId !== attachment.boot_id ||
				authority.bootCoreHash !== attachment.boot_core_hash ||
				authority.rootId !== attachment.root_id ||
				authority.sessionId !== attachment.session_id ||
				authority.rootGeneration !== attachment.root_generation ||
				authority.baselineEpochId !== attachment.baseline_epoch_id ||
				authenticatedHash(authority as unknown as JsonValue) !== row.transition_hash ||
				row.previous_transition_hash !== previousHash
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"attachment transition does not project from authenticated authority",
				);
			verifyMac(authority as unknown as JsonValue, "gjc-bugwatch-attachment-v1", authorityKey.keyBytes);
			previousHash = authenticatedHash(authority as unknown as JsonValue);
			current = authority;
		}
		if (
			current === undefined ||
			attachment.current_transition_hash !== previousHash ||
			current.state !== attachment.state ||
			current.managedSessionRoot !== attachment.managed_session_root ||
			current.sessionFile !== attachment.session_file ||
			current.publishSequence !== (attachment.publish_seq === null ? null : String(attachment.publish_seq)) ||
			current.retireSequence !== (attachment.retire_seq === null ? null : String(attachment.retire_seq)) ||
			current.endedAt !==
				(attachment.ended_at_ms === null ? null : snapshotPolicyTimestamp(attachment.ended_at_ms, "ended_at_ms"))
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"attachment current state does not link to its authenticated transition head",
			);
	}
	for (const memberRow of rows("store_operation_members")) {
		if (graph.registryKey === undefined)
			throw new BugwatchContractError("AUTHORITY_MISSING", "authority_missing:registry_keyring");
		const operation = rows("store_operations").find(row => row.operation_id === memberRow.operation_id);
		if (operation === undefined) continue;
		const core = parseStoreOperationCoreV1(
			embeddedCanonicalEnvelope(operation, "core_json", "snapshot store operation core_json"),
		);
		const step = parseStoreOperationStepV1(
			embeddedCanonicalEnvelope(memberRow, "step_json", "snapshot store operation member step_json"),
		);
		const coreKey = requireRetainedSnapshotKey(graph.registryKey, core.keyId, "registry_keyring");
		const stepKey = requireRetainedSnapshotKey(graph.registryKey, step.keyId, "registry_keyring");
		if (
			authenticatedHash(core as unknown as JsonValue) !== operation.core_hash ||
			core.operationId !== operation.operation_id ||
			core.ownerId !== operation.owner_id ||
			core.claimTokenHash !== operation.claim_token_hash ||
			core.kind !== operation.kind ||
			core.fromVersion !== operation.from_version ||
			core.toVersion !== operation.to_version ||
			core.startedAt !== snapshotPolicyTimestamp(operation.started_at_ms, "started_at_ms") ||
			step.keyId !== core.keyId ||
			step.scopeId !== core.scopeId ||
			step.operationId !== memberRow.operation_id ||
			step.coreHash !== operation.core_hash ||
			step.member !== memberRow.member ||
			step.occurredAt !== snapshotPolicyTimestamp(memberRow.updated_at_ms, "updated_at_ms")
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"store operation member step does not project from its core",
			);
		verifyMac(core as unknown as JsonValue, "gjc-bugwatch-store-operation-core-v1", coreKey.keyBytes);
		verifyMac(step as unknown as JsonValue, "gjc-bugwatch-store-operation-step-v1", stepKey.keyBytes);
		const coreMember = core.members.find(candidate => candidate.member === memberRow.member);
		if (
			coreMember === undefined ||
			coreMember.sourcePathHash !== memberRow.source_path_hash ||
			Number(coreMember.expectedPresence) !== memberRow.expected_presence ||
			coreMember.expectedSize !== memberRow.expected_size ||
			coreMember.expectedHash !== memberRow.expected_hash ||
			coreMember.quarantinePathHash !== memberRow.quarantine_path_hash
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "store operation member does not project from its core");
		const expectedState =
			step.action === "move_intent"
				? "intent_recorded"
				: step.action === "move_complete"
					? "moved"
					: "verified_absent";
		if (
			memberRow.state !== expectedState ||
			step.expectedSourceHash !== memberRow.expected_hash ||
			step.observedDestinationHash !== memberRow.observed_quarantine_hash
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"store operation member state does not project from its step",
			);
	}
	for (const operation of rows("store_operations")) {
		if (graph.registryKey === undefined)
			throw new BugwatchContractError("AUTHORITY_MISSING", "authority_missing:registry_keyring");
		const steps = rows("store_operation_members")
			.filter(row => row.operation_id === operation.operation_id)
			.map(row => ({
				row,
				step: parseStoreOperationStepV1(
					embeddedCanonicalEnvelope(row, "step_json", "snapshot store operation member step_json"),
				),
			}))
			.sort((left, right) => left.step.stepIndex - right.step.stepIndex);
		const core = parseStoreOperationCoreV1(
			embeddedCanonicalEnvelope(operation, "core_json", "snapshot store operation core_json"),
		);
		if (steps.length !== core.members.length)
			throw new BugwatchContractError(
				"AUTHORITY_MISSING",
				"store operation members do not cover authenticated core",
			);
		let previousHash: string | null = null;
		for (const [index, { step }] of steps.entries()) {
			if (
				step.stepIndex !== index ||
				step.previousStepHash !== previousHash ||
				new Set(steps.map(entry => entry.step.member)).size !== steps.length
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"store operation steps do not form a complete authenticated member chain",
				);
			previousHash = authenticatedHash(step as unknown as JsonValue);
			if (
				index === steps.length - 1 &&
				(operation.current_step !== step.stepIndex || operation.current_step_hash !== previousHash)
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"store operation current head does not bind to its authenticated step",
				);
		}
	}
}

export function parseAuthoritySnapshotItemV1(input: string | JsonValue): AuthoritySnapshotItemV1 {
	const value = typeof input === "string" ? parseCanonicalJson(input) : input;
	const item = exactObject(
		value,
		["schema", "index", "itemType", "authorityId", "payload", "payloadHash", "previousItemHash", "keyId", "mac"],
		"authority snapshot item",
	);
	if (item.schema !== "gjc-bugwatch-authority-item/v1")
		throw new BugwatchContractError("INVALID_SCHEMA", "invalid authority snapshot item schema");
	if (!Number.isSafeInteger(numberField(item, "index")) || numberField(item, "index") < 0)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot item index must be a non-negative safe integer");
	if (!AUTHORITY_CLASS_NAMES.includes(stringField(item, "itemType") as AuthorityClassV1))
		throw new BugwatchContractError("INVALID_SCHEMA", "unknown snapshot item class");
	boundedString(stringField(item, "authorityId"), "authorityId");
	parseHash(item, "payloadHash");
	if (sha256Hex(canonicalizeJson(item.payload)) !== item.payloadHash)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot item payload hash does not match payload");
	if (item.previousItemHash !== null) parseHash(item, "previousItemHash");
	boundedString(stringField(item, "keyId"), "keyId");
	parseHash(item, "mac");
	return item as unknown as AuthoritySnapshotItemV1;
}

export interface AuthoritySnapshotKeyMaterialV1 {
	keyId: string;
	keyBytes: Uint8Array;
}
export type AuthoritySnapshotRetainedKeyringV1 =
	| AuthoritySnapshotKeyMaterialV1
	| readonly AuthoritySnapshotKeyMaterialV1[];
export interface AuthoritySnapshotPackKeyringsV1 {
	snapshot: AuthoritySnapshotKeyMaterialV1 | undefined;
	policy?: AuthoritySnapshotRetainedKeyringV1 | undefined;
	fatal: AuthoritySnapshotRetainedKeyringV1 | undefined;
	registry: AuthoritySnapshotRetainedKeyringV1 | undefined;
	rollback?: AuthoritySnapshotRetainedKeyringV1 | undefined;
}
export interface AuthoritySnapshotPackVerificationV1 {
	manifest: AuthoritySnapshotManifestV2;
	items: AuthoritySnapshotItemV1[];
}

function snapshotItemBytes(items: readonly AuthoritySnapshotItemV1[]): Uint8Array {
	return new TextEncoder().encode(items.map(item => `${canonicalizeJson(item as unknown as JsonValue)}\n`).join(""));
}
function snapshotClassDigest(items: readonly AuthoritySnapshotItemV1[]): string {
	return sha256Hex(
		canonicalizeJson(items.map(item => authenticatedHash(item as unknown as JsonValue)) as unknown as JsonValue),
	);
}
function snapshotMerkleRoot(items: readonly AuthoritySnapshotItemV1[]): string {
	let level = items.map(item => authenticatedHash(item as unknown as JsonValue));
	if (level.length === 0) return sha256Hex("");
	while (level.length > 1) {
		const next: string[] = [];
		for (let index = 0; index < level.length; index += 2)
			next.push(sha256Hex(`${level[index]}${level[index + 1] ?? level[index]}`));
		level = next;
	}
	return level[0];
}
function retainedSnapshotKeys(
	keyring: AuthoritySnapshotRetainedKeyringV1 | undefined,
	name: string,
): readonly AuthoritySnapshotKeyMaterialV1[] {
	if (keyring === undefined) throw new BugwatchContractError("AUTHORITY_MISSING", `authority_missing:${name}`);
	const keys = "keyBytes" in keyring ? [keyring] : keyring;
	if (keys.length === 0) throw new BugwatchContractError("AUTHORITY_MISSING", `authority_missing:${name}`);
	const keyIds = new Set<string>();
	const keyDigests = new Set<string>();
	for (const key of keys) {
		if (
			boundedString(key.keyId, "keyId").length === 0 ||
			keyIds.has(key.keyId) ||
			keyDigests.has(sha256Hex(key.keyBytes))
		)
			throw new BugwatchContractError("INVALID_SCHEMA", `invalid retained ${name}`);
		keyIds.add(key.keyId);
		keyDigests.add(sha256Hex(key.keyBytes));
	}
	return keys;
}

function requireRetainedSnapshotKey(
	keyring: AuthoritySnapshotRetainedKeyringV1 | undefined,
	keyId: string,
	name: string,
): AuthoritySnapshotKeyMaterialV1 {
	const key = retainedSnapshotKeys(keyring, name).find(candidate => candidate.keyId === keyId);
	if (key === undefined) throw new BugwatchContractError("AUTHORITY_MISSING", `authority_missing:${name}:${keyId}`);
	return key;
}

function requireSnapshotKey(
	reference: SnapshotKeyReferenceV1,
	keyring: AuthoritySnapshotRetainedKeyringV1 | undefined,
	name: string,
): Uint8Array {
	const material = requireRetainedSnapshotKey(keyring, reference.keyId, name);
	if (sha256Hex(material.keyBytes) !== reference.keyDigest)
		throw new BugwatchContractError("INVALID_MAC", `${name} key reference does not match retained keyring`);
	return material.keyBytes;
}

function parseFrontierRecords(value: JsonValue, cutoffAt: string, context: string): SnapshotFrontierRecordV1[] {
	if (!Array.isArray(value) || value.length > 16_384)
		throw new BugwatchContractError("INVALID_SCHEMA", `${context} records must be a bounded array`);
	let previousRecordHash: string | null = null;
	return value.map((value, index) => {
		const candidate = valueObject(value, `${context} record`);
		const kind = stringField(candidate, "kind");
		const keys =
			kind === "source"
				? [
						"sequence",
						"kind",
						"itemType",
						"authorityId",
						"payloadHash",
						"sourceId",
						"generation",
						"committedOffset",
						"boundaryHash",
						"checkpointDigest",
						"occurredAt",
						"recordHash",
						"previousRecordHash",
					]
				: kind === "registry"
					? [
							"sequence",
							"schema",
							"domain",
							"kind",
							"itemType",
							"authorityId",
							"payloadHash",
							"bootId",
							"transportEpoch",
							"attachmentId",
							"transitionStep",
							"occurredAt",
							"recordHash",
							"previousRecordHash",
							"keyId",
							"mac",
						]
					: kind === "inbox"
						? [
								"sequence",
								"schema",
								"domain",
								"kind",
								"itemType",
								"authorityId",
								"payloadHash",
								"slot",
								"slotGeneration",
								"occurredAt",
								"recordHash",
								"previousRecordHash",
								"keyId",
								"mac",
							]
						: kind === "emergency"
							? [
									"sequence",
									"schema",
									"domain",
									"kind",
									"itemType",
									"authorityId",
									"payloadHash",
									"logicalSlot",
									"page",
									"pageGeneration",
									"occurredAt",
									"recordHash",
									"previousRecordHash",
									"keyId",
									"mac",
								]
							: kind === "rollback"
								? [
										"sequence",
										"schema",
										"domain",
										"kind",
										"itemType",
										"authorityId",
										"payloadHash",
										"epochId",
										"segmentIndex",
										"occurredAt",
										"recordHash",
										"previousRecordHash",
										"keyId",
										"mac",
									]
								: kind === "artifact"
									? [
											"sequence",
											"schema",
											"domain",
											"kind",
											"itemType",
											"authorityId",
											"payloadHash",
											"artifactId",
											"outboxSequence",
											"occurredAt",
											"recordHash",
											"previousRecordHash",
											"keyId",
											"mac",
										]
									: undefined;
		if (keys === undefined)
			throw new BugwatchContractError("INVALID_SCHEMA", `${context} record has an unknown authority kind`);
		const record = exactObject(candidate, keys, `${context} record`);
		if (numberField(record, "sequence") !== index)
			throw new BugwatchContractError("INVALID_SCHEMA", `${context} records must have no sequence holes`);
		const recordHash = parseHash(record, "recordHash");
		const { recordHash: _recordHash, mac: _mac, ...identity } = record;
		if (sha256Hex(canonicalizeJson(identity)) !== recordHash || record.previousRecordHash !== previousRecordHash)
			throw new BugwatchContractError("INVALID_SCHEMA", `${context} record hash or chain is invalid`);
		const occurredAt = stringField(record, "occurredAt");
		canonicalUtcTimestamp(occurredAt, `${context} occurredAt`);
		if (occurredAt > cutoffAt)
			throw new BugwatchContractError("INVALID_SCHEMA", `${context} record is after the snapshot cutoff`);
		parseHash(record, "payloadHash");
		const itemTypes =
			kind === "source"
				? SOURCE_FRONTIER_ITEM_TYPES
				: kind === "registry"
					? REGISTRY_FRONTIER_ITEM_TYPES
					: kind === "inbox"
						? INBOX_FRONTIER_ITEM_TYPES
						: kind === "emergency"
							? EMERGENCY_FRONTIER_ITEM_TYPES
							: kind === "rollback"
								? ROLLBACK_FRONTIER_ITEM_TYPES
								: ARTIFACT_FRONTIER_ITEM_TYPES;
		if (!(itemTypes as readonly string[]).includes(stringField(record, "itemType")))
			throw new BugwatchContractError("INVALID_SCHEMA", `${context} record itemType is not valid for its authority`);
		if (boundedString(record.authorityId, "authorityId").length === 0)
			throw new BugwatchContractError("INVALID_SCHEMA", `${context} record authority is invalid`);
		if (kind === "source") {
			if (numberField(record, "generation") < 0 || numberField(record, "committedOffset") < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", `${context} source record is invalid`);
			if (record.boundaryHash !== null) parseHash(record, "boundaryHash");
			parseHash(record, "checkpointDigest");
		} else if (kind === "registry") {
			if (
				boundedString(record.bootId, "bootId").length === 0 ||
				(record.transportEpoch !== null && numberField(record, "transportEpoch") < 1)
			)
				throw new BugwatchContractError("INVALID_SCHEMA", `${context} registry record is invalid`);
			if (
				(stringField(record, "itemType") === "attachment_transitions" &&
					(record.attachmentId === null ||
						record.transitionStep === null ||
						boundedString(record.attachmentId, "attachmentId").length === 0 ||
						numberField(record, "transitionStep") < 0)) ||
				(stringField(record, "itemType") !== "attachment_transitions" &&
					(record.attachmentId !== null || record.transitionStep !== null))
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					`${context} registry attachment composite identity is invalid`,
				);
		} else if (kind === "inbox") {
			if (numberField(record, "slot") < 0 || numberField(record, "slotGeneration") < 1)
				throw new BugwatchContractError("INVALID_SCHEMA", `${context} inbox record is invalid`);
		} else if (kind === "emergency") {
			if (
				numberField(record, "logicalSlot") < 0 ||
				numberField(record, "page") < 0 ||
				numberField(record, "pageGeneration") < 1
			)
				throw new BugwatchContractError("INVALID_SCHEMA", `${context} emergency record is invalid`);
		} else if (kind === "rollback") {
			if (boundedString(record.epochId, "epochId").length === 0 || numberField(record, "segmentIndex") < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", `${context} rollback record is invalid`);
		} else if (
			boundedString(record.artifactId, "artifactId").length === 0 ||
			!/^(0|[1-9][0-9]*)$/.test(stringField(record, "outboxSequence"))
		) {
			throw new BugwatchContractError("INVALID_SCHEMA", `${context} artifact record is invalid`);
		}
		previousRecordHash = recordHash;
		return record as unknown as SnapshotFrontierRecordV1;
	});
}
function replayDomainForKind(kind: Exclude<SnapshotFrontierRecordV1["kind"], "source">): string {
	return `gjc-bugwatch-external-replay-${kind}-v1`;
}

function verifyReplayFrontierRecord(record: SnapshotFrontierRecordV1, keyrings: AuthoritySnapshotPackKeyringsV1): void {
	if (record.kind === "source") return;
	if (record.schema !== "gjc-bugwatch-external-replay-record/v1" || record.domain !== replayDomainForKind(record.kind))
		throw new BugwatchContractError("INVALID_SCHEMA", "external replay record envelope domain is invalid");
	const keyring =
		record.kind === "registry"
			? keyrings.registry
			: record.kind === "rollback"
				? keyrings.rollback
				: record.kind === "artifact"
					? keyrings.snapshot
					: keyrings.fatal;
	const key = requireRetainedSnapshotKey(keyring, record.keyId, `${record.kind}_replay_key`);
	verifyMac(record as unknown as JsonValue, record.domain, key.keyBytes);
}
function parseFrontierEntries(
	value: JsonValue,
	scopeId: string,
	cutoffAt: string,
	keys: readonly string[],
	context: string,
	identity: (entry: { [key: string]: JsonValue }) => string,
	validate: (entry: { [key: string]: JsonValue }) => void,
	validateRecord: (record: SnapshotFrontierRecordV1, entry: { [key: string]: JsonValue }) => void,
): void {
	const frontier = exactObject(value, ["scopeId", "entries"], context);
	if (
		stringField(frontier, "scopeId") !== scopeId ||
		!Array.isArray(frontier.entries) ||
		frontier.entries.length > 16_384
	)
		throw new BugwatchContractError("INVALID_SCHEMA", `${context} scope or entries are invalid`);
	let previousIdentity: string | null = null;
	for (const value of frontier.entries) {
		const entry = exactObject(value, [...keys, "records"], `${context} entry`);
		validate(entry);
		const entryIdentity = identity(entry);
		if (previousIdentity !== null && entryIdentity <= previousIdentity)
			throw new BugwatchContractError("INVALID_SCHEMA", `${context} entries must be unique and canonical ordered`);
		previousIdentity = entryIdentity;
		for (const record of parseFrontierRecords(entry.records, cutoffAt, context)) validateRecord(record, entry);
	}
}
function verifySnapshotFrontierEvidence(
	cutoff: SnapshotCutoffV1,
	evidence: AuthoritySnapshotFrontierEvidenceV1 | undefined,
	scopeId: string,
	keyrings: AuthoritySnapshotPackKeyringsV1,
): void {
	if (evidence === undefined)
		throw new BugwatchContractError("AUTHORITY_MISSING", "authority_missing:cutoff_frontiers");
	const cutoffAt = cutoff.cutoffAt;
	canonicalUtcTimestamp(cutoffAt, "snapshot cutoff");
	const sqlite = exactObject(
		evidence.sqliteBackup as unknown as JsonValue,
		[
			"scopeId",
			"backupId",
			"backupBytes",
			"backupHash",
			"databaseHash",
			"dataVersionBefore",
			"dataVersionAfter",
			"createdAt",
		],
		"SQLite backup frontier",
	);
	const backupCreatedAt = stringField(sqlite, "createdAt");
	canonicalUtcTimestamp(backupCreatedAt, "backup createdAt");
	if (
		stringField(sqlite, "scopeId") !== scopeId ||
		boundedString(sqlite.backupId, "backupId").length === 0 ||
		parseHash(sqlite, "backupHash") !== sha256Hex(canonicalSnapshotBlob(sqlite.backupBytes, "SQLite backup bytes")) ||
		parseHash(sqlite, "databaseHash") !== parseHash(sqlite, "backupHash") ||
		numberField(sqlite, "dataVersionBefore") !== numberField(sqlite, "dataVersionAfter") ||
		backupCreatedAt > cutoffAt
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "SQLite backup frontier is invalid");
	const schemaMeta = exactObject(
		evidence.schemaMeta as unknown as JsonValue,
		[
			"id",
			"schema_major",
			"schema_minor",
			"log_schema_version",
			"redaction_version",
			"noise_version",
			"severity_version",
			"fingerprint_version",
			"fixture_manifest_hash",
			"schema_catalog_hash",
			"created_at_ms",
			"migrated_at_ms",
		],
		"schema metadata frontier",
	);
	const cutoffAtMs = Date.parse(cutoffAt);
	if (
		numberField(schemaMeta, "id") !== 1 ||
		numberField(schemaMeta, "schema_major") !== BUGWATCH_SCHEMA_MAJOR ||
		numberField(schemaMeta, "schema_minor") !== BUGWATCH_SCHEMA_MINOR ||
		numberField(schemaMeta, "log_schema_version") !== BUGWATCH_LOG_SCHEMA_VERSION ||
		numberField(schemaMeta, "redaction_version") !== BUGWATCH_REDACTION_VERSION ||
		numberField(schemaMeta, "noise_version") !== BUGWATCH_NOISE_VERSION ||
		numberField(schemaMeta, "severity_version") !== BUGWATCH_SEVERITY_VERSION ||
		numberField(schemaMeta, "fingerprint_version") !== BUGWATCH_FINGERPRINT_VERSION ||
		parseHash(schemaMeta, "fixture_manifest_hash") !== BUGWATCH_FIXTURE_MANIFEST_HASH ||
		parseHash(schemaMeta, "schema_catalog_hash") !== BUGWATCH_SCHEMA_CATALOG_HASH ||
		numberField(schemaMeta, "created_at_ms") > cutoffAtMs ||
		numberField(schemaMeta, "migrated_at_ms") > cutoffAtMs
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "schema metadata frontier is invalid");
	parseFrontierEntries(
		evidence.sourceWatermarks as unknown as JsonValue,
		scopeId,
		cutoffAt,
		["sourceId", "generation", "committedOffset"],
		"source watermark frontier",
		entry =>
			`${stringField(entry, "sourceId")}\u0000${numberField(entry, "generation").toString().padStart(16, "0")}\u0000${numberField(entry, "committedOffset").toString().padStart(20, "0")}`,
		entry => {
			if (boundedString(entry.sourceId, "sourceId").length === 0 || numberField(entry, "generation") < 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "source watermark is invalid");
			numberField(entry, "committedOffset");
		},
		(record, entry) => {
			if (
				record.kind !== "source" ||
				record.sourceId !== entry.sourceId ||
				record.generation !== entry.generation ||
				record.committedOffset !== entry.committedOffset
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"source frontier record does not match its composite entry identity",
				);
		},
	);
	parseFrontierEntries(
		evidence.registryFrontiers as unknown as JsonValue,
		scopeId,
		cutoffAt,
		["bootId", "transportEpoch"],
		"registry frontier",
		entry =>
			`${stringField(entry, "bootId")}\u0000${numberField(entry, "transportEpoch").toString().padStart(16, "0")}`,
		entry => {
			if (boundedString(entry.bootId, "bootId").length === 0 || numberField(entry, "transportEpoch") < 1)
				throw new BugwatchContractError("INVALID_SCHEMA", "registry frontier is invalid");
		},
		(record, entry) => {
			if (
				record.kind !== "registry" ||
				record.bootId !== entry.bootId ||
				record.transportEpoch !== entry.transportEpoch
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"registry frontier record does not match its composite entry identity",
				);
		},
	);
	parseFrontierEntries(
		evidence.inboxFrontier as unknown as JsonValue,
		scopeId,
		cutoffAt,
		["slot", "slotGeneration"],
		"inbox frontier",
		entry =>
			`${numberField(entry, "slot").toString().padStart(5, "0")}\u0000${numberField(entry, "slotGeneration").toString().padStart(16, "0")}`,
		entry => {
			if (numberField(entry, "slot") >= INBOX_SLOTS || numberField(entry, "slotGeneration") < 1)
				throw new BugwatchContractError("INVALID_SCHEMA", "inbox frontier is invalid");
		},
		(record, entry) => {
			if (record.kind !== "inbox" || record.slot !== entry.slot || record.slotGeneration !== entry.slotGeneration)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"inbox frontier record does not match its composite entry identity",
				);
		},
	);
	parseFrontierEntries(
		evidence.emergencyFrontier as unknown as JsonValue,
		scopeId,
		cutoffAt,
		["logicalSlot", "page", "pageGeneration"],
		"emergency frontier",
		entry =>
			`${numberField(entry, "logicalSlot").toString().padStart(5, "0")}\u0000${numberField(entry, "page").toString().padStart(5, "0")}\u0000${numberField(entry, "pageGeneration").toString().padStart(16, "0")}`,
		entry => {
			if (
				numberField(entry, "logicalSlot") >= EMERGENCY_LOGICAL_SLOTS ||
				numberField(entry, "page") >= EMERGENCY_PAGES_PER_LOGICAL_SLOT ||
				numberField(entry, "pageGeneration") < 1
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "emergency frontier is invalid");
		},
		(record, entry) => {
			if (
				record.kind !== "emergency" ||
				record.logicalSlot !== entry.logicalSlot ||
				record.page !== entry.page ||
				record.pageGeneration !== entry.pageGeneration
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"emergency frontier record does not match its composite entry identity",
				);
		},
	);
	parseFrontierEntries(
		evidence.rollbackSpoolFrontier as unknown as JsonValue,
		scopeId,
		cutoffAt,
		["epochId", "segmentIndex"],
		"rollback spool frontier",
		entry =>
			`${stringField(entry, "epochId")}\u0000${numberField(entry, "segmentIndex").toString().padStart(16, "0")}`,
		entry => {
			if (boundedString(entry.epochId, "epochId").length === 0)
				throw new BugwatchContractError("INVALID_SCHEMA", "rollback spool frontier is invalid");
			numberField(entry, "segmentIndex");
		},
		(record, entry) => {
			if (
				record.kind !== "rollback" ||
				record.epochId !== entry.epochId ||
				record.segmentIndex !== entry.segmentIndex
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"rollback frontier record does not match its composite entry identity",
				);
		},
	);
	parseFrontierEntries(
		evidence.artifactFrontier as unknown as JsonValue,
		scopeId,
		cutoffAt,
		["artifactId", "outboxSequence"],
		"artifact outbox frontier",
		entry => `${stringField(entry, "artifactId")}\u0000${stringField(entry, "outboxSequence").padStart(32, "0")}`,
		entry => {
			if (
				boundedString(entry.artifactId, "artifactId").length === 0 ||
				!/^(0|[1-9][0-9]*)$/.test(stringField(entry, "outboxSequence"))
			)
				throw new BugwatchContractError("INVALID_SCHEMA", "artifact frontier is invalid");
		},
		(record, entry) => {
			if (
				record.kind !== "artifact" ||
				record.artifactId !== entry.artifactId ||
				record.outboxSequence !== entry.outboxSequence
			)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"artifact frontier record does not match its composite entry identity",
				);
		},
	);
	for (const frontier of [
		evidence.registryFrontiers,
		evidence.inboxFrontier,
		evidence.emergencyFrontier,
		evidence.rollbackSpoolFrontier,
		evidence.artifactFrontier,
	]) {
		const entries = valueObject(frontier as unknown as JsonValue, "external replay frontier").entries;
		if (!Array.isArray(entries))
			throw new BugwatchContractError("INVALID_SCHEMA", "external replay frontier entries are invalid");
		for (const entry of entries) {
			const records = valueObject(entry, "external replay frontier entry").records;
			if (!Array.isArray(records) || records.length === 0)
				throw new BugwatchContractError(
					"INVALID_SCHEMA",
					"external replay frontier evidence entry must not be empty",
				);
			for (const record of parseFrontierRecords(records, cutoffAt, "external replay frontier"))
				verifyReplayFrontierRecord(record, keyrings);
		}
	}
	const expected: ReadonlyArray<readonly [Exclude<keyof SnapshotCutoffV1, "sqliteBackupHash">, JsonValue]> = [
		["schemaMetaHash", schemaMeta],
		["sourceWatermarksHash", evidence.sourceWatermarks as unknown as JsonValue],
		["registryFrontiersHash", evidence.registryFrontiers as unknown as JsonValue],
		["inboxFrontierHash", evidence.inboxFrontier as unknown as JsonValue],
		["emergencyFrontierHash", evidence.emergencyFrontier as unknown as JsonValue],
		["rollbackSpoolFrontierHash", evidence.rollbackSpoolFrontier as unknown as JsonValue],
		["artifactFrontierHash", evidence.artifactFrontier as unknown as JsonValue],
	];
	if (cutoff.sqliteBackupHash !== sqlite.backupHash)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot cutoff sqliteBackupHash does not match backup bytes");
	for (const [field, value] of expected)
		if (cutoff[field] !== sha256Hex(canonicalizeJson(value)))
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				`snapshot cutoff ${field} does not match authenticated evidence`,
			);
}

export function verifyAuthoritySnapshotPackV2(
	manifestInput: string | JsonValue,
	itemInputs: readonly (string | JsonValue)[],
	keyrings: AuthoritySnapshotPackKeyringsV1,
	previousManifest: AuthoritySnapshotManifestV2 | null = null,
	frontierEvidence: AuthoritySnapshotFrontierEvidenceV1 | undefined = undefined,
): AuthoritySnapshotPackVerificationV1 {
	const manifest = parseAuthoritySnapshotManifestV2(manifestInput);
	const snapshotKey = requireSnapshotKey(
		{ keyId: manifest.snapshotKeyId, keyDigest: manifest.snapshotKeyDigest },
		keyrings.snapshot,
		"snapshot_keyring",
	);
	requireSnapshotKey(
		{ keyId: manifest.policyKeyringId, keyDigest: manifest.policyKeyringDigest },
		keyrings.policy,
		"policy_keyring",
	);
	requireSnapshotKey(
		{ keyId: manifest.fatalKeyringId, keyDigest: manifest.fatalKeyringDigest },
		keyrings.fatal,
		"fatal_keyring",
	);
	requireSnapshotKey(
		{ keyId: manifest.registryKeyringId, keyDigest: manifest.registryKeyringDigest },
		keyrings.registry,
		"registry_keyring",
	);
	requireSnapshotKey(
		{ keyId: manifest.rollbackKeyringId, keyDigest: manifest.rollbackKeyringDigest },
		keyrings.rollback,
		"rollback_keyring",
	);
	verifySnapshotFrontierEvidence(manifest.cutoff, frontierEvidence, manifest.scopeId, keyrings);
	verifyMac(manifest as unknown as JsonValue, "gjc-bugwatch-authority-snapshot-v2", snapshotKey);
	if (manifest.previousSnapshotId === null) {
		if (previousManifest !== null)
			throw new BugwatchContractError("INVALID_SCHEMA", "genesis snapshot must not have a predecessor");
	} else if (
		previousManifest === null ||
		previousManifest.scopeId !== manifest.scopeId ||
		previousManifest.snapshotId !== manifest.previousSnapshotId ||
		authenticatedHash(previousManifest as unknown as JsonValue) !== manifest.previousManifestHash
	) {
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot manifest predecessor does not match");
	}
	const items = itemInputs.map(parseAuthoritySnapshotItemV1);
	for (const [index, item] of items.entries()) {
		if (
			item.index !== index ||
			item.previousItemHash !== (index === 0 ? null : authenticatedHash(items[index - 1] as unknown as JsonValue)) ||
			item.keyId !== manifest.snapshotKeyId
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "snapshot item chain is not deterministic");
		if (AUTHORITY_SNAPSHOT_POLICY[item.itemType].mode !== "payload")
			throw new BugwatchContractError("INVALID_SCHEMA", "snapshot items may only carry payload authority");
		validateSnapshotPayload(item, {
			scopeId: manifest.scopeId,
			items,
			policyKey: keyrings.policy,
			registryKey: keyrings.registry,
			fatalKey: keyrings.fatal,
			rollbackKey: keyrings.rollback,
		});
		requireSnapshotPayloadAtOrBefore(item.payload, manifest.cutoff.cutoffAt);
		verifyMac(item as unknown as JsonValue, "gjc-bugwatch-authority-item-v1", snapshotKey);
	}
	validateSnapshotGraph({
		scopeId: manifest.scopeId,
		items,
		policyKey: keyrings.policy,
		registryKey: keyrings.registry,
		fatalKey: keyrings.fatal,
		rollbackKey: keyrings.rollback,
	});
	if (items.filter(item => item.itemType === "schema_meta").length !== 1)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot must contain exactly one schema metadata record");
	const schemaMeta = items.find(item => item.itemType === "schema_meta");
	if (schemaMeta === undefined)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot must contain schema metadata");
	const metadata = valueObject(schemaMeta.payload, "snapshot schema metadata");
	if (
		numberField(metadata, "schema_major") !== manifest.storeSchemaMajor ||
		stringField(metadata, "fixture_manifest_hash") !== manifest.fixtureManifestHash ||
		schemaMeta.payloadHash !== manifest.cutoff.schemaMetaHash
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot schema metadata does not match its manifest");
	verifySnapshotScopePolicyGraph(items, manifest.scopeId, manifest.policyGeneration, keyrings.policy);
	const allBytes = snapshotItemBytes(items);
	if (
		items.length !== manifest.itemCount ||
		allBytes.byteLength !== manifest.byteCount ||
		sha256Hex(allBytes) !== manifest.itemsSha256 ||
		snapshotMerkleRoot(items) !== manifest.merkleRoot
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot pack digest does not match reconstructive items");
	for (const entry of manifest.classes) {
		const classItems = items.filter(item => item.itemType === entry.className);
		const classBytes = snapshotItemBytes(classItems);
		if (
			classItems.length !== entry.itemCount ||
			classBytes.byteLength !== entry.byteCount ||
			sha256Hex(classBytes) !== entry.itemsSha256 ||
			snapshotClassDigest(classItems) !== entry.classDigest
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				`snapshot class ${entry.className} digest does not match items`,
			);
	}
	return { manifest, items };
}
export function parseAuthoritySnapshotManifestV2(input: string | JsonValue): AuthoritySnapshotManifestV2 {
	const manifest = parseEnvelope<AuthoritySnapshotManifestV2>(input, "gjc-bugwatch-authority-snapshot/v2", [
		"schema",
		"scopeId",
		"snapshotId",
		"kind",
		"policyGeneration",
		"storeSchemaMajor",
		"fixtureManifestHash",
		"createdAt",
		"itemCount",
		"byteCount",
		"itemsSha256",
		"merkleRoot",
		"previousSnapshotId",
		"previousManifestHash",
		"cutoff",
		"classes",
		"snapshotKeyId",
		"snapshotKeyDigest",
		"policyKeyringId",
		"policyKeyringDigest",
		"policyKeyringSource",
		"fatalKeyringId",
		"fatalKeyringDigest",
		"fatalKeyringSource",
		"registryKeyringId",
		"registryKeyringDigest",
		"registryKeyringSource",
		"rollbackKeyringId",
		"rollbackKeyringDigest",
		"rollbackKeyringSource",
		"keyId",
		"mac",
	]);
	if (
		!["migration", "rebuild", "cutover", "rollback", "manual_authority"].includes(manifest.kind) ||
		manifest.policyGeneration < 1 ||
		manifest.storeSchemaMajor < 1 ||
		(manifest.previousSnapshotId === null) !== (manifest.previousManifestHash === null)
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "invalid authenticated snapshot manifest");
	if (
		manifest.snapshotKeyId !== manifest.keyId ||
		manifest.policyKeyringSource !== "protected_retained_policy_keyring" ||
		manifest.fatalKeyringSource !== "protected_retained_fatal_keyring" ||
		manifest.registryKeyringSource !== "protected_retained_registry_keyring" ||
		manifest.rollbackKeyringSource !== "protected_retained_rollback_keyring" ||
		[
			"snapshotKeyDigest",
			"policyKeyringDigest",
			"fatalKeyringDigest",
			"registryKeyringDigest",
			"rollbackKeyringDigest",
		].every(key => /^[0-9a-f]{64}$/.test(stringField(manifest as unknown as { [key: string]: JsonValue }, key))) ===
			false
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "invalid snapshot key references");
	if (
		manifest.storeSchemaMajor !== BUGWATCH_SCHEMA_MAJOR ||
		manifest.fixtureManifestHash !== BUGWATCH_FIXTURE_MANIFEST_HASH
	)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot manifest is incompatible with this contract");
	const classes = manifest.classes as unknown as JsonValue;
	if (!Array.isArray(classes) || classes.length !== AUTHORITY_CLASS_NAMES.length)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot must contain every authority class exactly once");
	for (const [index, entry] of classes.entries()) parseSnapshotClassEntryV1(entry, index);
	if (manifest.classes.reduce((total, entry) => total + entry.itemCount, 0) !== manifest.itemCount)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot item count does not match class counts");
	if (manifest.classes.reduce((total, entry) => total + entry.byteCount, 0) !== manifest.byteCount)
		throw new BugwatchContractError("INVALID_SCHEMA", "snapshot byte count does not match class byte counts");
	return manifest;
}
export type RootRenameActualStateV1 = "O" | "P" | "F" | "X";
export type RootRenameRecoveryV1 =
	| "abort"
	| "roll_forward_pending"
	| "apply_db"
	| "complete_baseline"
	| "finalize_first"
	| "finalize_second"
	| "commit"
	| "conflict";

export interface RootMutationDbStateV1 {
	schema: "gjc-bugwatch-root-mutation-db-state/v1";
	scopeId: string;
	mutationId: string;
	coreHash: string;
	phase: RootMutationDbPhaseV1;
	previousPhase: RootMutationDbPhaseV1 | null;
	previousStateHash: string | null;
	keyId: string;
	mac: string;
}

export interface RootMutationRestartEvidenceV2 {
	core: string | JsonValue;
	dbStates: readonly (string | JsonValue)[];
	steps: readonly (string | JsonValue)[];
	keyBytes: Uint8Array;
	outputs: readonly RootMutationOutputObservationV2[];
}

export interface RootMutationOutputObservationV2 {
	target: "old_root" | "new_root";
	destinationHash: string | null;
	pendingTempHash: string | null;
	finalTempHash: string | null;
}
export interface RootMutationAuthorityGraphV1 {
	core: string | JsonValue;
	outputs: readonly RootMutationOutputV2[];
	steps: readonly (string | JsonValue)[];
	dbStates: readonly (string | JsonValue)[];
	keyBytes: Uint8Array;
}

export interface StoreOperationRestartEvidenceV1 {
	core: string | JsonValue;
	steps: readonly (string | JsonValue)[];
	keyBytes: Uint8Array;
	member: "db" | "wal" | "shm";
	observedSourceHash: string | null;
	observedQuarantineHash: string | null;
}

export type StoreOperationRecoveryV1 =
	| "perform_move"
	| "append_complete"
	| "append_verified_absent"
	| "already_complete"
	| "conflict";

function authenticatedRootSteps(
	core: RootMutationCoreV1,
	steps: readonly (string | JsonValue)[],
	keyBytes: Uint8Array,
): RootMutationRenameStepV2[] {
	verifyMac(core as unknown as JsonValue, "gjc-bugwatch-root-mutation-core-v1", keyBytes);
	const coreHash = authenticatedHash(core as unknown as JsonValue);
	const parsed = steps.map(parseRootMutationRenameStepV2).sort((left, right) => left.stepIndex - right.stepIndex);
	const expected: Array<{
		target: "old_root" | "new_root";
		lifecycle: "pending" | "final";
		action: "rename_intent" | "rename_complete";
	}> = [];
	for (const lifecycle of ["pending", "final"] as const)
		for (const output of [...core.outputs].sort((left, right) => left.publicationOrder - right.publicationOrder))
			expected.push(
				{ target: output.target, lifecycle, action: "rename_intent" },
				{ target: output.target, lifecycle, action: "rename_complete" },
			);
	for (const [index, step] of parsed.entries()) {
		verifyMac(step as unknown as JsonValue, "gjc-bugwatch-root-rename-step-v2", keyBytes);
		const output = core.outputs.find(candidate => candidate.target === step.target);
		const desired = step.lifecycle === "pending" ? output?.pendingContentHash : output?.finalContentHash;
		const expectedDestination =
			step.lifecycle === "pending" ? output?.expectedOldContentHash : output?.pendingContentHash;
		const expectedStep = expected[index];
		if (
			output === undefined ||
			expectedStep === undefined ||
			step.scopeId !== core.scopeId ||
			step.mutationId !== core.mutationId ||
			step.coreHash !== coreHash ||
			step.keyId !== core.keyId ||
			step.stepIndex !== index ||
			step.previousStepHash !==
				(index === 0 ? null : authenticatedHash(parsed[index - 1] as unknown as JsonValue)) ||
			step.target !== expectedStep.target ||
			step.lifecycle !== expectedStep.lifecycle ||
			step.action !== expectedStep.action ||
			step.expectedDestinationHash !== expectedDestination ||
			step.sourceTempHash !== desired ||
			step.desiredDestinationHash !== desired ||
			(step.action === "rename_intent" && step.observedDestinationHash !== null) ||
			(step.action === "rename_complete" && step.observedDestinationHash !== desired)
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "root rename step is not authenticated core evidence");
	}
	return parsed;
}
function authenticatedRootDbStates(
	core: RootMutationCoreV1,
	states: readonly (string | JsonValue)[],
	keyBytes: Uint8Array,
): RootMutationDbStateV1[] {
	if (states.length === 0) throw new BugwatchContractError("INVALID_SCHEMA", "root database state chain is empty");
	const coreHash = authenticatedHash(core as unknown as JsonValue);
	const parsed = states.map(parseRootMutationDbStateV1);
	for (const [index, state] of parsed.entries()) {
		verifyMac(state as unknown as JsonValue, "gjc-bugwatch-root-mutation-db-state-v1", keyBytes);
		const previous = parsed[index - 1];
		const expectedPhase =
			index === 0
				? "prepared"
				: previous.phase === "conflict" || previous.phase === "aborted" || previous.phase === "committed"
					? null
					: ROOT_MUTATION_DB_PHASE_CHAIN[ROOT_MUTATION_DB_PHASE_CHAIN.indexOf(previous.phase) + 1];
		const terminalTransition =
			state.phase === "conflict" ||
			(state.phase === "aborted" && (previous?.phase === "prepared" || previous?.phase === "publishing"));
		if (
			state.scopeId !== core.scopeId ||
			state.mutationId !== core.mutationId ||
			state.coreHash !== coreHash ||
			state.keyId !== core.keyId ||
			(index === 0
				? state.phase !== "prepared" || state.previousPhase !== null || state.previousStateHash !== null
				: state.previousPhase !== previous.phase ||
					state.previousStateHash !== authenticatedHash(previous as unknown as JsonValue) ||
					(state.phase !== expectedPhase && !terminalTransition))
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "root database state is not an authenticated phase chain");
	}
	return parsed;
}
function requireRootRenameEvidenceForTerminalPhase(
	core: RootMutationCoreV1,
	steps: readonly RootMutationRenameStepV2[],
	terminalPhase: RootMutationDbPhaseV1,
): void {
	const pendingStepCount = core.outputs.length * 2;
	const allStepCount = core.outputs.length * 4;
	const legal =
		(terminalPhase === "prepared" && steps.length === 0) ||
		(terminalPhase === "publishing" && steps.length <= pendingStepCount) ||
		((terminalPhase === "files_published" || terminalPhase === "db_applied") && steps.length === pendingStepCount) ||
		(terminalPhase === "baseline_complete" && steps.length >= pendingStepCount && steps.length <= allStepCount) ||
		((terminalPhase === "files_finalized" || terminalPhase === "committed") && steps.length === allStepCount) ||
		(terminalPhase === "aborted" && steps.length <= 1) ||
		terminalPhase === "conflict";
	if (!legal)
		throw new BugwatchContractError(
			"INVALID_SCHEMA",
			"root mutation rename evidence is not legal for its terminal database phase",
		);
}

/**
 * Validates the complete persisted authority graph for one root mutation.
 * Callers must supply the retained registry key matching the core key ID.
 */
export function validateRootMutationAuthorityGraphV1(evidence: RootMutationAuthorityGraphV1): void {
	const core = parseRootMutationCoreV1(evidence.core);
	const suppliedSteps = evidence.steps.map(parseRootMutationRenameStepV2);
	if (suppliedSteps.some((step, index) => step.stepIndex !== index))
		throw new BugwatchContractError("INVALID_SCHEMA", "root mutation rename evidence is not in step order");
	verifyMac(core as unknown as JsonValue, "gjc-bugwatch-root-mutation-core-v1", evidence.keyBytes);
	if (
		evidence.outputs.length !== core.outputs.length ||
		new Set(evidence.outputs.map(output => output.target)).size !== evidence.outputs.length
	)
		throw new BugwatchContractError(
			"AUTHORITY_MISSING",
			"root mutation outputs do not completely cover core outputs",
		);
	for (const output of core.outputs) {
		const row = evidence.outputs.filter(candidate => candidate.target === output.target);
		if (
			row.length !== 1 ||
			row[0].pathHash !== output.pathHash ||
			row[0].precondition !== output.precondition ||
			row[0].expectedOldContentHash !== output.expectedOldContentHash ||
			row[0].pendingContentHash !== output.pendingContentHash ||
			row[0].finalContentHash !== output.finalContentHash ||
			row[0].desiredRootGeneration !== output.desiredRootGeneration ||
			row[0].publicationOrder !== output.publicationOrder
		)
			throw new BugwatchContractError(
				"INVALID_SCHEMA",
				"root mutation output does not project from authenticated core",
			);
	}
	const steps = authenticatedRootSteps(core, evidence.steps, evidence.keyBytes);
	const states = authenticatedRootDbStates(core, evidence.dbStates, evidence.keyBytes);
	requireRootRenameEvidenceForTerminalPhase(core, steps, states.at(-1)!.phase);
}

export function resolveRootMutationRestartV2(evidence: RootMutationRestartEvidenceV2): RootRenameRecoveryV1 {
	const core = parseRootMutationCoreV1(evidence.core);
	const dbStates = authenticatedRootDbStates(core, evidence.dbStates, evidence.keyBytes);
	const dbState = dbStates[dbStates.length - 1];
	const steps = authenticatedRootSteps(core, evidence.steps, evidence.keyBytes);
	if (evidence.outputs.length !== core.outputs.length)
		throw new BugwatchContractError("INVALID_SCHEMA", "root observations must cover each output exactly once");
	const observations = [...evidence.outputs].sort(
		(left, right) =>
			(core.outputs.find(output => output.target === left.target)?.publicationOrder ?? 0) -
			(core.outputs.find(output => output.target === right.target)?.publicationOrder ?? 0),
	);
	if (new Set(observations.map(observation => observation.target)).size !== observations.length)
		throw new BugwatchContractError("INVALID_SCHEMA", "root observations duplicate an output");
	const vector = observations.map(observation => {
		const output = core.outputs.find(candidate => candidate.target === observation.target);
		if (output === undefined)
			throw new BugwatchContractError("INVALID_SCHEMA", "root observation names an unknown output");
		const state: RootRenameActualStateV1 =
			observation.destinationHash === output.expectedOldContentHash
				? "O"
				: observation.destinationHash === output.pendingContentHash
					? "P"
					: observation.destinationHash === output.finalContentHash
						? "F"
						: "X";
		const pendingTempValid =
			(state === "O" && observation.pendingTempHash === output.pendingContentHash) ||
			(state === "P" && observation.pendingTempHash === null) ||
			(state === "F" && observation.pendingTempHash === null);
		const finalTempValid =
			(state === "O" && observation.finalTempHash === output.finalContentHash) ||
			(state === "P" && observation.finalTempHash === output.finalContentHash) ||
			(state === "F" && observation.finalTempHash === null);
		return pendingTempValid && finalTempValid ? state : "X";
	});
	const hasStep = (
		target: "old_root" | "new_root",
		lifecycle: "pending" | "final",
		action: "rename_intent" | "rename_complete",
	) => steps.some(step => step.target === target && step.lifecycle === lifecycle && step.action === action);
	const hasIntent = (index: number, lifecycle: "pending" | "final") =>
		hasStep(observations[index].target, lifecycle, "rename_intent");
	const hasCompletion = (index: number, lifecycle: "pending" | "final") =>
		hasStep(observations[index].target, lifecycle, "rename_complete");
	const allHaveCompletion = (lifecycle: "pending" | "final") =>
		vector.every((state, index) => state !== "O" && hasCompletion(index, lifecycle));
	const pendingEvidenceMatches = vector.every((state, index) =>
		state === "P" || state === "F"
			? hasIntent(index, "pending")
			: !hasStep(observations[index].target, "pending", "rename_complete"),
	);
	const firstPending = vector.findIndex(state => state !== "F");
	const finalEvidenceMatches = vector.every((state, index) =>
		state === "F"
			? hasIntent(index, "final")
			: !hasCompletion(index, "final") && (!hasIntent(index, "final") || index === firstPending),
	);
	if (dbState.phase === "prepared") {
		if (vector.every(state => state === "O") && steps.length === 0) return "abort";
		return "conflict";
	}
	if (dbState.phase === "publishing") {
		const firstOld = vector.indexOf("O");
		return vector.every(
			(state, index) => state === (index < (firstOld === -1 ? vector.length : firstOld) ? "P" : "O"),
		) && pendingEvidenceMatches
			? "roll_forward_pending"
			: "conflict";
	}
	if (dbState.phase === "files_published")
		return vector.every(state => state === "P") && pendingEvidenceMatches && allHaveCompletion("pending")
			? "apply_db"
			: "conflict";
	if (dbState.phase === "db_applied")
		return vector.every(state => state === "P") && pendingEvidenceMatches && allHaveCompletion("pending")
			? "complete_baseline"
			: "conflict";
	if (dbState.phase === "baseline_complete") {
		if (vector.every(state => state === "P") && pendingEvidenceMatches && allHaveCompletion("pending"))
			return "finalize_first";
		if (
			vector.length === 2 &&
			vector[0] === "F" &&
			vector[1] === "P" &&
			pendingEvidenceMatches &&
			allHaveCompletion("pending") &&
			finalEvidenceMatches
		)
			return "finalize_second";
		return vector.every(state => state === "F") &&
			pendingEvidenceMatches &&
			allHaveCompletion("pending") &&
			finalEvidenceMatches
			? "commit"
			: "conflict";
	}
	if (dbState.phase === "files_finalized" || dbState.phase === "committed")
		return vector.every(state => state === "F") &&
			pendingEvidenceMatches &&
			allHaveCompletion("pending") &&
			finalEvidenceMatches &&
			allHaveCompletion("final")
			? "commit"
			: "conflict";
	if (dbState.phase === "aborted")
		return vector.every(state => state === "O") && !steps.some(step => step.action === "rename_complete")
			? "abort"
			: "conflict";
	return "conflict";
}

export function classifyStoreOperationMemberRestartV1(
	evidence: StoreOperationRestartEvidenceV1,
): StoreOperationRecoveryV1 {
	const core = parseStoreOperationCoreV1(evidence.core);
	verifyMac(core as unknown as JsonValue, "gjc-bugwatch-store-operation-core-v1", evidence.keyBytes);
	const coreHash = authenticatedHash(core as unknown as JsonValue);
	const member = core.members.find(candidate => candidate.member === evidence.member);
	if (member === undefined) throw new BugwatchContractError("INVALID_SCHEMA", "store member is not declared by core");
	const steps = evidence.steps.map(parseStoreOperationStepV1).sort((left, right) => left.stepIndex - right.stepIndex);
	let intent = false;
	let completion = false;
	let absentCompletion = false;
	for (const [index, step] of steps.entries()) {
		verifyMac(step as unknown as JsonValue, "gjc-bugwatch-store-operation-step-v1", evidence.keyBytes);
		if (
			step.scopeId !== core.scopeId ||
			step.operationId !== core.operationId ||
			step.coreHash !== coreHash ||
			step.keyId !== core.keyId ||
			step.stepIndex !== index ||
			step.previousStepHash !== (index === 0 ? null : authenticatedHash(steps[index - 1] as unknown as JsonValue))
		)
			throw new BugwatchContractError("INVALID_SCHEMA", "store operation step is not authenticated core evidence");
		if (step.member !== evidence.member) continue;
		if (step.action === "verified_absent") {
			if (member.expectedPresence || intent || completion || absentCompletion)
				throw new BugwatchContractError("INVALID_SCHEMA", "verified absent conflicts with member evidence");
			absentCompletion = true;
			continue;
		}
		if (step.expectedSourceHash !== member.expectedHash)
			throw new BugwatchContractError("INVALID_SCHEMA", "store step expected hash does not match core");
		if (step.action === "move_intent") {
			if (intent || completion)
				throw new BugwatchContractError("INVALID_SCHEMA", "store member has duplicate move intent");
			intent = true;
		} else {
			if (!intent || completion || step.observedDestinationHash !== member.expectedHash)
				throw new BugwatchContractError("INVALID_SCHEMA", "store completion is not bound to its core move");
			completion = true;
		}
	}
	if (!member.expectedPresence) {
		if (evidence.observedSourceHash !== null || evidence.observedQuarantineHash !== null) return "conflict";
		return absentCompletion ? "already_complete" : "append_verified_absent";
	}
	if (absentCompletion) return "conflict";
	if (completion)
		return evidence.observedSourceHash === null && evidence.observedQuarantineHash === member.expectedHash
			? "already_complete"
			: "conflict";
	if (evidence.observedSourceHash === member.expectedHash && evidence.observedQuarantineHash === null)
		return intent ? "perform_move" : "conflict";
	if (evidence.observedSourceHash === null && evidence.observedQuarantineHash === member.expectedHash)
		return intent ? "append_complete" : "conflict";
	return "conflict";
}
