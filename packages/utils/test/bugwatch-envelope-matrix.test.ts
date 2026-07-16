import { describe, expect, it } from "bun:test";
import {
	AUTHORITY_CLASS_NAMES,
	AUTHORITY_SNAPSHOT_POLICY,
	type AuthoritySnapshotFrontierEvidenceV1,
	authenticatedHash,
	BUGWATCH_FIXTURE_MANIFEST_HASH,
	BUGWATCH_SCHEMA_CATALOG_HASH,
	BUGWATCH_SCHEMA_MINOR,
	canonicalizeJson,
	classifyStoreOperationMemberRestartV1,
	computeEventId,
	fatalCoreHash,
	hmacSha256Hex,
	type JsonValue,
	macPayload,
	parseArchiveAliasV1,
	parseAttachmentV1,
	parseAuthoritySnapshotItemV1,
	parseAuthoritySnapshotManifestV2,
	parseBootCoreV1,
	parseBootFinalV1,
	parseBootTransportCloseV1,
	parseBootTransportStartV1,
	parseCaptureAuthorityV1,
	parseFatalEnvelopeV1,
	parseFatalKeyringV1,
	parseLeaseV1,
	parseMonitorDisableActionV1,
	parseMonitorDisableAuthorizationV1,
	parseMonitorDisableReceiptV1,
	parseMonitorInventoryV1,
	parsePolicySemanticV1,
	parseRollbackBundleV1,
	parseRollbackInboxAckV1,
	parseRollbackSpoolItemV1,
	parseRollbackSpoolManifestV1,
	parseRootControlV1,
	parseRootMutationCoreV1,
	parseRootMutationRenameStepV2,
	parseScopePolicyHeadV2,
	parseScopePolicyRevisionV2,
	parseSourceAuthorityV1,
	parseSourceCheckpointV1,
	parseStoreOperationCoreV1,
	parseStoreOperationStepV1,
	type RollbackItemTypeV1,
	resolveRootMutationRestartV2,
	type SnapshotFrontierRecordV1,
	sha256Hex,
	verifyAuthoritySnapshotPackV2,
	verifyRollbackBundleV1,
	verifyRollbackSpoolSegmentV1,
} from "@gajae-code/utils/bugwatch-contract";

type JsonObject = { [key: string]: JsonValue };
type Parser = (input: JsonValue) => unknown;

const hash = "a".repeat(64);
const pendingContentHash = "b".repeat(64);
const finalContentHash = "c".repeat(64);
const timestamp = "2026-01-02T03:04:05.678Z";
const derivedKeyId = "0123456789abcdef0123456789abcdef";
const retainedKeyId = "fedcba9876543210fedcba9876543210";
const envelope = (schema: string, fields: JsonObject): JsonObject => ({ schema, ...fields });
const withUnknown = (value: JsonObject): JsonObject => ({ ...value, unknown: true });

function policySemantic(): JsonObject {
	return envelope("gjc-bugwatch-policy-semantics/v1", {
		scopeId: "scope",
		daemon: { enabled: true, pollMs: 250 },
		ingest: {
			maxFilesPerTick: 1,
			maxBytesPerTick: 65_536,
			maxRowsPerTick: 1,
			maxWorkMsPerTick: 5,
			maxRowBytes: 16_384,
			maxPartialBytes: 16_384,
			maxDiscardBytes: 262_144,
			partialMaxAgeMs: 10_000,
		},
		inbox: {},
		archive: { filesPerCycle: 0, compressedBytesPerCycle: 0, decompressedBytesPerCycle: 0, workMsPerCycle: 0 },
		coverage: {},
		store: { maxDbBytes: 1, maxWalBytes: 1, maxOutboxBytes: 1 },
		candidate: { highFatalPerRoot: 100, mediumPerRoot: 0, lowPerRoot: 0 },
		jobs: { activeGlobal: 1, activePerRoot: 1, maxAttempts: 1, wallMs: 10_000 },
		context: { persistedGlobalBytes: 1, ttlDays: 1 },
		triage: { upstreamEnabled: true },
		retention: { observationDays: 7, jobDays: 7, runDays: 7 },
	});
}

const bootCore = () =>
	envelope("gjc-bugwatch-boot-core/v1", {
		scopeId: "scope",
		bootId: "boot",
		bootTokenHash: hash,
		pid: 1,
		pidStartToken: "token",
		producer: "daemon",
		startedAt: timestamp,
		initialPolicyGeneration: 1,
		initialPolicyHash: hash,
		fatalKeyId: derivedKeyId,
		gjcVersion: "1",
		buildSha: null,
		sequenceOrigin: "1",
		maxSequence: "9223372036854775807",
		keyId: derivedKeyId,
		mac: hash,
	});
const rollbackRootPayload = (): JsonObject => ({
	scopeId: "scope",
	rootId: "root",
	kind: "project",
	canonicalPath: "/root",
	enabled: true,
	revision: 1,
	projectPolicyHash: hash,
	registeredAtMs: 1,
	disabledAtMs: null,
	persistContext: true,
	baselineEpochId: null,
	activeMutationId: null,
});

type RootMutationAction = "enable" | "disable" | "set_context" | "move";

const rootMutation = (action: RootMutationAction = "move") => {
	const oldRootId = action === "enable" ? null : "old-root";
	const newRootId = action === "disable" ? null : action === "set_context" ? "old-root" : "new-root";
	const newRootOutput: JsonObject = {
		target: "new_root",
		pathHash: hash,
		precondition: action === "set_context" ? "present" : "missing",
		expectedOldContentHash: action === "set_context" ? hash : null,
		pendingContentHash,
		finalContentHash,
		desiredRootGeneration: 1,
		publicationOrder: 1,
	};
	const oldRootOutput: JsonObject = {
		target: "old_root",
		pathHash: hash,
		precondition: "present",
		expectedOldContentHash: hash,
		pendingContentHash,
		finalContentHash,
		desiredRootGeneration: 1,
		publicationOrder: action === "move" ? 2 : 1,
	};
	return envelope("gjc-bugwatch-root-mutation-core/v1", {
		scopeId: "scope",
		mutationId: "mutation",
		action,
		expectedPolicyGeneration: 1,
		expectedPolicyHash: hash,
		oldRootId,
		newRootId,
		outputs:
			action === "move" ? [newRootOutput, oldRootOutput] : [action === "disable" ? oldRootOutput : newRootOutput],
		createdAt: timestamp,
		actorPid: 1,
		actorPidStartToken: "token",
		keyId: "key",
		mac: hash,
	});
};

function snapshot(): JsonObject {
	return envelope("gjc-bugwatch-authority-snapshot/v2", {
		scopeId: "scope",
		snapshotId: "snapshot",
		kind: "rebuild",
		policyGeneration: 1,
		storeSchemaMajor: 1,
		fixtureManifestHash: BUGWATCH_FIXTURE_MANIFEST_HASH,
		createdAt: timestamp,
		itemCount: 0,
		byteCount: 0,
		itemsSha256: hash,
		merkleRoot: hash,
		previousSnapshotId: null,
		previousManifestHash: null,
		cutoff: {
			operationId: "operation",
			quiesceTokenHash: hash,
			cutoffAt: timestamp,
			sqliteBackupHash: hash,
			schemaMetaHash: hash,
			sourceWatermarksHash: hash,
			registryFrontiersHash: hash,
			inboxFrontierHash: hash,
			emergencyFrontierHash: hash,
			rollbackSpoolFrontierHash: hash,
			artifactFrontierHash: hash,
		},
		classes: AUTHORITY_CLASS_NAMES.map(className => {
			const policy = AUTHORITY_SNAPSHOT_POLICY[className];
			return {
				className,
				mode: policy.mode,
				itemCount: 0,
				byteCount: 0,
				itemsSha256: sha256Hex(""),
				classDigest: hash,
				reconstructiveSource: policy.reconstructiveSource,
			};
		}),
		snapshotKeyId: "key",
		snapshotKeyDigest: sha256Hex(new Uint8Array([1])),
		policyKeyringId: "policy",
		policyKeyringDigest: sha256Hex(new Uint8Array([5])),
		policyKeyringSource: "protected_retained_policy_keyring",
		fatalKeyringId: "fatal",
		fatalKeyringDigest: sha256Hex(new Uint8Array([2])),
		fatalKeyringSource: "protected_retained_fatal_keyring",
		registryKeyringId: "registry",
		registryKeyringDigest: sha256Hex(new Uint8Array([3])),
		registryKeyringSource: "protected_retained_registry_keyring",
		rollbackKeyringId: "rollback",
		rollbackKeyringDigest: sha256Hex(new Uint8Array([4])),
		rollbackKeyringSource: "protected_retained_rollback_keyring",
		keyId: "key",
		mac: hash,
	});
}

const fixtures: Array<{ name: string; parser: Parser; valid: JsonObject; field: string; expected: JsonValue }> = [
	{
		name: "policy semantic",
		parser: parsePolicySemanticV1,
		valid: policySemantic(),
		field: "schema",
		expected: "gjc-bugwatch-policy-semantics/v1",
	},
	{
		name: "policy revision",
		parser: parseScopePolicyRevisionV2,
		valid: envelope("gjc-bugwatch-policy-revision/v2", {
			scopeId: "scope",
			generation: 1,
			semantic: policySemantic(),
			contentHash: hash,
			previousGeneration: null,
			previousRevisionHash: null,
			previousContentHash: null,
			casTokenHash: hash,
			createdAt: timestamp,
			writerId: "writer",
			keyId: "key",
			mac: hash,
		}),
		field: "generation",
		expected: 1,
	},
	{
		name: "policy head",
		parser: parseScopePolicyHeadV2,
		valid: envelope("gjc-bugwatch-policy-head/v2", {
			scopeId: "scope",
			generation: 1,
			revisionHash: hash,
			contentHash: hash,
			casToken: "token",
			updatedAt: timestamp,
			keyId: "key",
			mac: hash,
		}),
		field: "generation",
		expected: 1,
	},
	{
		name: "lease",
		parser: parseLeaseV1,
		valid: envelope("gjc-bugwatch-lease/v1", {
			scopeId: "scope",
			claimTokenHash: hash,
			ownerId: "owner",
			role: "daemon",
			pid: 1,
			pidStartToken: "token",
			executableFingerprint: hash,
			protocolMajor: 1,
			storeMin: 1,
			storeMax: 1,
			phase: "published",
			heartbeatAt: timestamp,
			policyGeneration: 1,
			policyHash: hash,
			rollbackState: "none",
			keyId: "key",
			mac: hash,
		}),
		field: "pid",
		expected: 1,
	},
	{
		name: "root",
		parser: parseRootControlV1,
		valid: envelope("gjc-bugwatch-root/v1", {
			scopeId: "scope",
			rootId: "root",
			canonicalPath: "/root",
			enabled: true,
			persistContext: true,
			generation: 1,
			projectPolicyHash: hash,
			baselineEpochId: null,
			activeMutationId: null,
			updatedAt: timestamp,
			nonce: "nonce",
			keyId: "key",
			mac: hash,
		}),
		field: "enabled",
		expected: true,
	},
	{ name: "boot core", parser: parseBootCoreV1, valid: bootCore(), field: "bootId", expected: "boot" },
	{
		name: "transport start",
		parser: parseBootTransportStartV1,
		valid: envelope("gjc-bugwatch-transport-start/v1", {
			scopeId: "scope",
			bootId: "boot",
			bootCoreHash: hash,
			transportEpoch: 1,
			policyGeneration: 1,
			policyHash: hash,
			startSequence: "1",
			startedAt: timestamp,
			fileEnabled: true,
			keyId: "key",
			previousRecordHash: null,
			mac: hash,
		}),
		field: "fileEnabled",
		expected: true,
	},
	{
		name: "transport close",
		parser: parseBootTransportCloseV1,
		valid: envelope("gjc-bugwatch-transport-close/v1", {
			scopeId: "scope",
			bootId: "boot",
			bootCoreHash: hash,
			transportEpoch: 1,
			startRecordHash: hash,
			endSequenceInclusive: "1",
			endedAt: timestamp,
			outcome: "closed",
			keyId: "key",
			previousRecordHash: hash,
			mac: hash,
		}),
		field: "outcome",
		expected: "closed",
	},
	{
		name: "boot final",
		parser: parseBootFinalV1,
		valid: envelope("gjc-bugwatch-boot-final/v1", {
			scopeId: "scope",
			bootId: "boot",
			bootCoreHash: hash,
			finalSequence: "1",
			endedAt: timestamp,
			state: "clean",
			lastTransportRecordHash: hash,
			attachmentSnapshotHash: hash,
			keyId: "key",
			previousRecordHash: hash,
			mac: hash,
		}),
		field: "state",
		expected: "clean",
	},
	{
		name: "attachment",
		parser: parseAttachmentV1,
		valid: envelope("gjc-bugwatch-attachment/v1", {
			scopeId: "scope",
			attachmentId: "attachment",
			attachmentTokenHash: hash,
			bootId: "boot",
			bootCoreHash: hash,
			rootId: "root",
			sessionId: null,
			startedAt: timestamp,
			endedAt: null,
			state: "prepared",
			managedSessionRoot: null,
			sessionFile: null,
			rootGeneration: 1,
			baselineEpochId: "epoch",
			publishSequence: null,
			retireSequence: null,
			keyId: "key",
			mac: hash,
		}),
		field: "sessionId",
		expected: null,
	},
	{
		name: "fatal",
		parser: parseFatalEnvelopeV1,
		valid: (() => {
			const fatal = envelope("gjc-bugwatch-fatal/v1", {
				scopeId: "scope",
				keyId: derivedKeyId,
				bootId: "boot",
				recordSeq: "1",
				eventId: computeEventId("boot", "1"),
				crashCorrelationId: "crash",
				kind: "uncaught_exception",
				occurredAt: timestamp,
				producer: "daemon",
				attachmentId: null,
				rootId: null,
				sessionId: null,
				severity: "fatal",
				message: "failure",
				stackTop: null,
				redactionVersion: 1,
				category: "gjc-internal",
				mac: hash,
			});
			return { ...fatal, fatalCoreHash: fatalCoreHash(fatal) };
		})(),
		field: "severity",
		expected: "fatal",
	},
	{ name: "root mutation", parser: parseRootMutationCoreV1, valid: rootMutation(), field: "action", expected: "move" },
	{
		name: "root rename",
		parser: parseRootMutationRenameStepV2,
		valid: envelope("gjc-bugwatch-root-rename-step/v2", {
			scopeId: "scope",
			mutationId: "mutation",
			coreHash: hash,
			stepIndex: 0,
			target: "old_root",
			lifecycle: "pending",
			action: "rename_intent",
			expectedDestinationHash: null,
			sourceTempHash: hash,
			desiredDestinationHash: hash,
			observedDestinationHash: null,
			previousStepHash: null,
			occurredAt: timestamp,
			keyId: "key",
			mac: hash,
		}),
		field: "lifecycle",
		expected: "pending",
	},
	{
		name: "source",
		parser: parseSourceAuthorityV1,
		valid: envelope("gjc-bugwatch-source/v1", {
			scopeId: "scope",
			segmentId: "segment",
			generation: 0,
			sourceKind: "log",
			pathHash: hash,
			fileIdentityHint: "file",
			prefixAnchorLength: 0,
			prefixHash: hash,
			committedOffset: 0,
			boundaryHash: null,
			checkpointDigest: hash,
			state: "active",
			updatedAt: timestamp,
			keyId: "key",
			mac: hash,
		}),
		field: "boundaryHash",
		expected: null,
	},
	{
		name: "source checkpoint",
		parser: parseSourceCheckpointV1,
		valid: envelope("gjc-bugwatch-source-checkpoint/v1", {
			scopeId: "scope",
			segmentId: "segment",
			generation: 0,
			kind: "chunk",
			chunkIndex: 0,
			startOffset: 0,
			endOffset: 1,
			hash,
			keyId: "key",
			mac: hash,
		}),
		field: "kind",
		expected: "chunk",
	},
	{
		name: "archive alias",
		parser: parseArchiveAliasV1,
		valid: envelope("gjc-bugwatch-archive-alias/v1", {
			scopeId: "scope",
			archiveDigest: hash,
			uncompressedLength: 0,
			segmentId: "segment",
			generation: 0,
			lineageKind: "full",
			verifiedCheckpointDigest: hash,
			createdAt: timestamp,
			keyId: "key",
			mac: hash,
		}),
		field: "lineageKind",
		expected: "full",
	},
	{
		name: "monitor inventory",
		parser: parseMonitorInventoryV1,
		valid: envelope("gjc-bugwatch-monitor-inventory/v1", {
			scopeId: "scope",
			inventoryEpochId: "epoch",
			monitorId: "monitor",
			kind: "process",
			stableIdentifier: "stable",
			configHash: hash,
			coveredRootIds: ["root"],
			status: "active",
			observedAt: timestamp,
			adapterEvidenceHash: hash,
			keyId: "key",
			mac: hash,
		}),
		field: "status",
		expected: "active",
	},
	{
		name: "disable authorization",
		parser: parseMonitorDisableAuthorizationV1,
		valid: envelope("gjc-bugwatch-monitor-disable-auth/v1", {
			scopeId: "scope",
			authorizationId: "authorization",
			inventoryEpochId: "epoch",
			monitorId: "monitor",
			adapterKind: "process",
			stableIdentifier: "stable",
			expectedConfigHash: hash,
			allowedAction: {
				kind: "process",
				pid: 1,
				pidStartToken: "token",
				uid: "1000",
				executableHash: hash,
				argvHash: hash,
				signal: "TERM",
			},
			authorizedAt: timestamp,
			expiresAt: "2026-01-02T03:04:06.678Z",
			nonce: "nonce",
			keyId: "key",
			mac: hash,
		}),
		field: "authorizationId",
		expected: "authorization",
	},
	{
		name: "disable receipt",
		parser: parseMonitorDisableReceiptV1,
		valid: envelope("gjc-bugwatch-monitor-disable-receipt/v1", {
			scopeId: "scope",
			authorizationId: "authorization",
			actionHash: hash,
			inventoryEpochId: "epoch",
			monitorId: "monitor",
			adapterKind: "process",
			beforeHash: hash,
			afterHash: null,
			startedAt: timestamp,
			finishedAt: timestamp,
			result: "disabled",
			steps: [{ name: "signal", attempted: true, ok: true, evidenceHash: null, errorCode: null }],
			coveredRootIds: ["root"],
			keyId: "key",
			mac: hash,
		}),
		field: "afterHash",
		expected: null,
	},
	{
		name: "authority snapshot",
		parser: parseAuthoritySnapshotManifestV2,
		valid: snapshot(),
		field: "snapshotId",
		expected: "snapshot",
	},
];

describe("bugwatch envelope parser matrix", () => {
	it("accepts every exported envelope wrapper and rejects unknown fields", () => {
		for (const fixture of fixtures) {
			const parsed = fixture.parser(fixture.valid) as JsonObject;
			expect(parsed[fixture.field], fixture.name).toBe(fixture.expected);
			expect(() => fixture.parser(withUnknown(fixture.valid)), `${fixture.name} unknown field`).toThrow();
		}
	});

	it("enforces representative field type, range, nullability, and nested invariants", () => {
		const policy = policySemantic();
		const invalid: Array<{ name: string; parser: Parser; value: JsonObject }> = [
			{
				name: "policy nested range",
				parser: parsePolicySemanticV1,
				value: { ...policy, daemon: { enabled: true, pollMs: 249 } },
			},
			{
				name: "revision predecessor",
				parser: parseScopePolicyRevisionV2,
				value: { ...fixtures[1].valid, previousGeneration: 1 },
			},
			{ name: "head generation", parser: parseScopePolicyHeadV2, value: { ...fixtures[2].valid, generation: 0 } },
			{ name: "lease pid", parser: parseLeaseV1, value: { ...fixtures[3].valid, pid: 0 } },
			{
				name: "root nullable field",
				parser: parseRootControlV1,
				value: { ...fixtures[4].valid, baselineEpochId: 1 },
			},
			{ name: "boot pid range", parser: parseBootCoreV1, value: { ...bootCore(), pid: 2_147_483_648 } },
			{
				name: "start sequence",
				parser: parseBootTransportStartV1,
				value: { ...fixtures[6].valid, startSequence: "0" },
			},
			{ name: "close enum", parser: parseBootTransportCloseV1, value: { ...fixtures[7].valid, outcome: "open" } },
			{ name: "final sequence type", parser: parseBootFinalV1, value: { ...fixtures[8].valid, finalSequence: 1 } },
			{ name: "attachment state", parser: parseAttachmentV1, value: { ...fixtures[9].valid, state: "open" } },
			{ name: "fatal event", parser: parseFatalEnvelopeV1, value: { ...fixtures[10].valid, eventId: hash } },
			{
				name: "rename nullable hash",
				parser: parseRootMutationRenameStepV2,
				value: { ...fixtures[12].valid, expectedDestinationHash: "bad" },
			},
			{ name: "source hash", parser: parseSourceAuthorityV1, value: { ...fixtures[13].valid, boundaryHash: "bad" } },
			{
				name: "checkpoint offset",
				parser: parseSourceCheckpointV1,
				value: { ...fixtures[14].valid, endOffset: -1 },
			},
			{
				name: "archive integer",
				parser: parseArchiveAliasV1,
				value: { ...fixtures[15].valid, uncompressedLength: -1 },
			},
			{
				name: "inventory nested type",
				parser: parseMonitorInventoryV1,
				value: { ...fixtures[16].valid, coveredRootIds: [1] },
			},
			{
				name: "receipt nested object",
				parser: parseMonitorDisableReceiptV1,
				value: {
					...fixtures[17].valid,
					steps: [{ name: "signal", attempted: true, ok: true, evidenceHash: null }],
				},
			},
			{
				name: "snapshot class invariant",
				parser: parseAuthoritySnapshotManifestV2,
				value: { ...snapshot(), classes: [] },
			},
		];
		for (const entry of invalid) expect(() => entry.parser(entry.value), entry.name).toThrow();
	});

	it("enforces root mutation output identity and precondition invariants", () => {
		const valid = rootMutation();
		const outputs = valid.outputs as JsonObject[];
		const cases: JsonObject[] = [
			{ ...valid, outputs: [{ ...outputs[0], target: "old_root" }, outputs[1]] },
			{ ...valid, outputs: [outputs[0], { ...outputs[1], publicationOrder: 1 }] },
			{ ...valid, outputs: [{ ...outputs[0], expectedOldContentHash: hash }, outputs[1]] },
			{ ...valid, outputs: [outputs[0], { ...outputs[1], expectedOldContentHash: null }] },
			{ ...valid, outputs: [outputs[0], { ...outputs[1], expectedOldContentHash: "bad" }] },
		];
		for (const value of cases) expect(() => parseRootMutationCoreV1(value)).toThrow();
	});
	it("parses every root mutation action and rejects cross-action identities", () => {
		const enable = rootMutation("enable");
		const disable = rootMutation("disable");
		const setContext = rootMutation("set_context");
		const move = rootMutation("move");

		for (const mutation of [enable, disable, setContext, move])
			expect(parseRootMutationCoreV1(mutation)).toBeDefined();

		const disableOutput = disable.outputs as JsonObject[];
		const cases: JsonObject[] = [
			{ ...enable, oldRootId: "old-root" },
			{ ...disable, newRootId: "new-root" },
			{ ...disable, outputs: [{ ...disableOutput[0], target: "new_root" }] },
			{ ...setContext, newRootId: "different-root" },
			{ ...move, newRootId: "old-root" },
		];
		for (const value of cases) expect(() => parseRootMutationCoreV1(value)).toThrow();
	});
	it("rejects root mutation outputs with equal pending and final content hashes", () => {
		const valid = rootMutation();
		const outputs = valid.outputs as JsonObject[];
		expect(() =>
			parseRootMutationCoreV1({
				...valid,
				outputs: [{ ...outputs[0], finalContentHash: outputs[0].pendingContentHash }, outputs[1]],
			}),
		).toThrow();
	});

	const markerLine = "# gjc-bugwatch monitor-id\n";
	const jobLine = "* * * * * gjc-bugwatch-run\n";
	it("parses every monitor action and bounds process identifiers", () => {
		const actions: JsonObject[] = [
			{
				kind: "gjc_cron",
				ownerSessionId: "session",
				ownerPid: 1,
				ownerPidStartToken: "token",
				cronId: "cron",
				expression: "* * * * *",
				promptHash: hash,
			},
			{
				kind: "user_cron",
				expectedCrontabHash: hash,
				markerLineHash: sha256Hex(markerLine),
				jobLineHash: sha256Hex(jobLine),
				markerLineBytesBase64: Buffer.from(markerLine).toString("base64"),
				jobLineBytesBase64: Buffer.from(jobLine).toString("base64"),
			},
			{
				kind: "systemd_user",
				units: [{ name: "gjc-bugwatch.service", expectedPropertiesHash: hash, expectedFragmentPathHash: hash }],
				operation: "disable_now",
			},
			{
				kind: "process",
				pid: 1,
				pidStartToken: "token",
				uid: "1000",
				executableHash: hash,
				argvHash: hash,
				signal: "TERM",
			},
			{
				kind: "process_force",
				pid: 1,
				pidStartToken: "token",
				uid: "1000",
				executableHash: hash,
				argvHash: hash,
				signal: "KILL",
			},
			{
				kind: "tmux_pane",
				serverIdentityHash: hash,
				paneId: "%1",
				sessionId: "session",
				tagHash: hash,
				commandHash: hash,
			},
			{
				kind: "tmux_session",
				serverIdentityHash: hash,
				sessionId: "session",
				paneIds: ["%1"],
				allPaneTagsHash: hash,
			},
			{
				kind: "plugin_feature",
				pluginName: "plugin",
				pluginVersion: "1",
				pluginPathHash: hash,
				manifestHash: hash,
				expectedRuntimeConfigGeneration: 1,
				expectedRuntimeConfigHash: hash,
				feature: "bugwatchAutomation.enabled",
				from: true,
				to: false,
			},
		];
		for (const action of actions) expect((parseMonitorDisableActionV1(action) as JsonObject).kind).toBe(action.kind);
		for (const pid of [0, -1, 2_147_483_648]) {
			expect(() => parseMonitorDisableActionV1({ ...actions[0], ownerPid: pid })).toThrow();
			expect(() => parseMonitorDisableActionV1({ ...actions[3], pid })).toThrow();
		}
		expect(() => parseMonitorDisableActionV1(withUnknown(actions[2]))).toThrow();
		expect(() =>
			parseMonitorDisableActionV1({
				...actions[2],
				units: [{ ...(actions[2].units as JsonObject[])[0], name: "other.service" }],
			}),
		).toThrow();
	});

	it("parses capture variants and rejects invalid capture discriminants", () => {
		const captured = envelope("gjc-bugwatch-capture/v1", {
			state: "captured",
			scopeId: "scope",
			policyGeneration: 1,
			policyHash: hash,
			bootCoreHash: hash,
			transportEpoch: 1,
			transportStartHash: hash,
			durableChannel: "file",
			keyId: "key",
		});
		const unavailable = envelope("gjc-bugwatch-capture/v1", { state: "disabled", reason: "daemon_disabled" });
		expect((parseCaptureAuthorityV1(captured) as JsonObject).state).toBe("captured");
		expect((parseCaptureAuthorityV1(unavailable) as JsonObject).reason).toBe("daemon_disabled");
		for (const value of [
			{ ...captured, policyGeneration: 0 },
			{ ...captured, durableChannel: "files" },
			withUnknown(captured),
			{ ...unavailable, reason: "other" },
		])
			expect(() => parseCaptureAuthorityV1(value)).toThrow();
	});
	it("derives every root restart action from an authenticated phase chain", () => {
		const key = new Uint8Array([7]);
		const unsignedCore = rootMutation();
		const signedCore = {
			...unsignedCore,
			mac: hmacSha256Hex(key, "gjc-bugwatch-root-mutation-core-v1", macPayload(unsignedCore)),
		};
		const coreHash = authenticatedHash(signedCore);
		const phases = [
			"prepared",
			"publishing",
			"files_published",
			"db_applied",
			"baseline_complete",
			"files_finalized",
			"committed",
		] as const;
		const dbStates = (phase: (typeof phases)[number]) => {
			const states: JsonObject[] = [];
			for (const current of phases.slice(0, phases.indexOf(phase) + 1)) {
				const previous = states.at(-1);
				const unsigned = envelope("gjc-bugwatch-root-mutation-db-state/v1", {
					scopeId: "scope",
					mutationId: "mutation",
					coreHash,
					phase: current,
					previousPhase: previous?.phase ?? null,
					previousStateHash: previous === undefined ? null : authenticatedHash(previous),
					keyId: "key",
				});
				states.push({
					...unsigned,
					mac: hmacSha256Hex(key, "gjc-bugwatch-root-mutation-db-state-v1", macPayload(unsigned)),
				});
			}
			return states;
		};
		const output = (target: "new_root" | "old_root", destinationHash: string | null) => ({
			target,
			destinationHash,
			pendingTempHash:
				destinationHash === pendingContentHash || destinationHash === finalContentHash ? null : pendingContentHash,
			finalTempHash: destinationHash === finalContentHash ? null : finalContentHash,
		});
		const old = output("old_root", hash);
		const fresh = output("new_root", null);
		const steps = (
			entries: Array<{
				target: "new_root" | "old_root";
				lifecycle: "pending" | "final";
				action: "rename_intent" | "rename_complete";
			}>,
		): JsonObject[] => {
			const signed: JsonObject[] = [];
			for (const entry of entries) {
				const target =
					entry.target === "new_root"
						? { old: null, pending: pendingContentHash, final: finalContentHash }
						: { old: hash, pending: pendingContentHash, final: finalContentHash };
				const desired = entry.lifecycle === "pending" ? target.pending : target.final;
				const unsigned = envelope("gjc-bugwatch-root-rename-step/v2", {
					scopeId: "scope",
					mutationId: "mutation",
					coreHash,
					stepIndex: signed.length,
					target: entry.target,
					lifecycle: entry.lifecycle,
					action: entry.action,
					expectedDestinationHash: entry.lifecycle === "pending" ? target.old : target.pending,
					sourceTempHash: desired,
					desiredDestinationHash: desired,
					observedDestinationHash: entry.action === "rename_complete" ? desired : null,
					previousStepHash: signed.length === 0 ? null : authenticatedHash(signed[signed.length - 1]),
					occurredAt: timestamp,
					keyId: "key",
				});
				signed.push({
					...unsigned,
					mac: hmacSha256Hex(key, "gjc-bugwatch-root-rename-step-v2", macPayload(unsigned)),
				});
			}
			return signed;
		};
		const pendingSteps = steps([
			{ target: "new_root", lifecycle: "pending", action: "rename_intent" },
			{ target: "new_root", lifecycle: "pending", action: "rename_complete" },
			{ target: "old_root", lifecycle: "pending", action: "rename_intent" },
			{ target: "old_root", lifecycle: "pending", action: "rename_complete" },
		]);
		const firstFinalSteps = steps([
			...[
				{ target: "new_root" as const, lifecycle: "pending" as const, action: "rename_intent" as const },
				{ target: "new_root" as const, lifecycle: "pending" as const, action: "rename_complete" as const },
				{ target: "old_root" as const, lifecycle: "pending" as const, action: "rename_intent" as const },
				{ target: "old_root" as const, lifecycle: "pending" as const, action: "rename_complete" as const },
				{ target: "new_root" as const, lifecycle: "final" as const, action: "rename_intent" as const },
				{ target: "new_root" as const, lifecycle: "final" as const, action: "rename_complete" as const },
			],
		]);
		const finalIntentBeforeRename = steps([
			...firstFinalSteps.map(step => ({
				target: step.target as "new_root" | "old_root",
				lifecycle: step.lifecycle as "pending" | "final",
				action: step.action as "rename_intent" | "rename_complete",
			})),
			{ target: "old_root", lifecycle: "final", action: "rename_intent" },
		]);
		const finalSteps = steps([
			...finalIntentBeforeRename.map(step => ({
				target: step.target as "new_root" | "old_root",
				lifecycle: step.lifecycle as "pending" | "final",
				action: step.action as "rename_intent" | "rename_complete",
			})),
			{ target: "old_root", lifecycle: "final", action: "rename_complete" },
		]);
		const resolve = (
			phase: (typeof phases)[number],
			renameSteps: readonly JsonObject[],
			outputs: readonly {
				target: "new_root" | "old_root";
				destinationHash: string | null;
				pendingTempHash: string | null;
				finalTempHash: string | null;
			}[],
		) =>
			resolveRootMutationRestartV2({
				dbStates: dbStates(phase),
				core: signedCore,
				steps: renameSteps,
				keyBytes: key,
				outputs,
			});
		const pendingOutputs = [output("new_root", pendingContentHash), output("old_root", pendingContentHash)];
		const firstFinalOutputs = [output("new_root", finalContentHash), output("old_root", pendingContentHash)];
		const finalOutputs = [output("new_root", finalContentHash), output("old_root", finalContentHash)];
		expect(resolve("prepared", [], [fresh, old])).toBe("abort");
		expect(resolve("publishing", pendingSteps.slice(0, 2), [output("new_root", pendingContentHash), old])).toBe(
			"roll_forward_pending",
		);
		expect(resolve("files_published", pendingSteps, pendingOutputs)).toBe("apply_db");
		expect(resolve("db_applied", pendingSteps, pendingOutputs)).toBe("complete_baseline");
		expect(resolve("baseline_complete", pendingSteps, pendingOutputs)).toBe("finalize_first");
		expect(resolve("baseline_complete", firstFinalSteps.slice(0, -1), pendingOutputs)).toBe("finalize_first");
		expect(resolve("baseline_complete", firstFinalSteps, firstFinalOutputs)).toBe("finalize_second");
		expect(resolve("baseline_complete", finalIntentBeforeRename, firstFinalOutputs)).toBe("finalize_second");
		expect(resolve("baseline_complete", finalSteps, finalOutputs)).toBe("commit");
		expect(resolve("files_finalized", finalSteps, finalOutputs)).toBe("commit");
		expect(resolve("files_finalized", finalIntentBeforeRename, finalOutputs)).toBe("conflict");
		expect(resolve("committed", finalSteps, finalOutputs)).toBe("commit");
		expect(resolve("baseline_complete", finalIntentBeforeRename, [pendingOutputs[0], finalOutputs[1]])).toBe(
			"conflict",
		);
		expect(resolve("baseline_complete", pendingSteps, firstFinalOutputs)).toBe("conflict");
		const brokenChain = dbStates("baseline_complete");
		const brokenUnsigned = { ...brokenChain[2], phase: "db_applied" };
		brokenChain[2] = {
			...brokenUnsigned,
			mac: hmacSha256Hex(key, "gjc-bugwatch-root-mutation-db-state-v1", macPayload(brokenUnsigned)),
		};
		expect(() =>
			resolveRootMutationRestartV2({
				dbStates: brokenChain,
				core: signedCore,
				steps: pendingSteps,
				keyBytes: key,
				outputs: pendingOutputs,
			}),
		).toThrow();
		const missingPredecessor = dbStates("publishing");
		const missingUnsigned = {
			...missingPredecessor[1],
			previousStateHash: null,
			previousPhase: null,
		};
		missingPredecessor[1] = {
			...missingUnsigned,
			mac: hmacSha256Hex(key, "gjc-bugwatch-root-mutation-db-state-v1", macPayload(missingUnsigned)),
		};
		expect(() =>
			resolveRootMutationRestartV2({
				dbStates: missingPredecessor,
				core: signedCore,
				steps: [],
				keyBytes: key,
				outputs: [fresh, old],
			}),
		).toThrow();
	});
	it("classifies each durable store restart row idempotently", () => {
		const key = new Uint8Array([9]);
		const unsignedCore = envelope("gjc-bugwatch-store-operation-core/v1", {
			scopeId: "scope",
			operationId: "operation",
			ownerId: "owner",
			claimTokenHash: hash,
			kind: "migrate",
			fromVersion: 1,
			toVersion: 2,
			members: [
				{
					member: "db",
					sourcePathHash: "1".repeat(64),
					expectedPresence: true,
					expectedSize: 1,
					expectedHash: hash,
					quarantinePathHash: "4".repeat(64),
				},
				{
					member: "wal",
					sourcePathHash: "2".repeat(64),
					expectedPresence: false,
					expectedSize: null,
					expectedHash: null,
					quarantinePathHash: "5".repeat(64),
				},
				{
					member: "shm",
					sourcePathHash: "3".repeat(64),
					expectedPresence: false,
					expectedSize: null,
					expectedHash: null,
					quarantinePathHash: "6".repeat(64),
				},
			],
			startedAt: timestamp,
			keyId: "key",
		});
		const core = {
			...unsignedCore,
			mac: hmacSha256Hex(key, "gjc-bugwatch-store-operation-core-v1", macPayload(unsignedCore)),
		};
		const coreHash = authenticatedHash(core);
		const steps = (
			member: "db" | "wal" | "shm",
			actions: Array<"move_intent" | "move_complete" | "verified_absent">,
		): JsonObject[] => {
			const signed: JsonObject[] = [];
			for (const action of actions) {
				const unsigned = envelope("gjc-bugwatch-store-operation-step/v1", {
					scopeId: "scope",
					operationId: "operation",
					coreHash,
					stepIndex: signed.length,
					member,
					action,
					expectedSourceHash: action === "verified_absent" ? null : hash,
					observedDestinationHash: action === "move_complete" ? hash : null,
					previousStepHash: signed.length === 0 ? null : authenticatedHash(signed[signed.length - 1]),
					occurredAt: timestamp,
					keyId: "key",
				});
				signed.push({
					...unsigned,
					mac: hmacSha256Hex(key, "gjc-bugwatch-store-operation-step-v1", macPayload(unsigned)),
				});
			}
			return signed;
		};
		const rows: Array<{
			member: "db" | "wal" | "shm";
			actions: Array<"move_intent" | "move_complete" | "verified_absent">;
			source: string | null;
			quarantine: string | null;
			expected: "perform_move" | "append_complete" | "append_verified_absent" | "already_complete" | "conflict";
		}> = [
			{ member: "db", actions: [], source: hash, quarantine: null, expected: "conflict" },
			{ member: "db", actions: ["move_intent"], source: hash, quarantine: null, expected: "perform_move" },
			{ member: "db", actions: [], source: null, quarantine: hash, expected: "conflict" },
			{ member: "db", actions: ["move_intent"], source: null, quarantine: hash, expected: "append_complete" },
			{
				member: "db",
				actions: ["move_intent", "move_complete"],
				source: null,
				quarantine: hash,
				expected: "already_complete",
			},
			{ member: "db", actions: ["move_intent"], source: hash, quarantine: hash, expected: "conflict" },
			{ member: "db", actions: ["move_intent"], source: null, quarantine: null, expected: "conflict" },
			{ member: "wal", actions: [], source: null, quarantine: null, expected: "append_verified_absent" },
			{ member: "wal", actions: ["verified_absent"], source: null, quarantine: null, expected: "already_complete" },
			{ member: "shm", actions: [], source: hash, quarantine: null, expected: "conflict" },
			{ member: "shm", actions: ["verified_absent"], source: null, quarantine: hash, expected: "conflict" },
		];
		for (const row of rows) {
			const evidence = {
				core,
				steps: steps(row.member, row.actions),
				keyBytes: key,
				member: row.member,
				observedSourceHash: row.source,
				observedQuarantineHash: row.quarantine,
			};
			expect(classifyStoreOperationMemberRestartV1(evidence)).toBe(row.expected);
			expect(classifyStoreOperationMemberRestartV1(evidence)).toBe(row.expected);
		}
		expect(
			classifyStoreOperationMemberRestartV1({
				core,
				steps: steps("wal", ["verified_absent"]),
				keyBytes: key,
				member: "db",
				observedSourceHash: hash,
				observedQuarantineHash: null,
			}),
		).toBe("conflict");
		const mismatchedCompletion = steps("db", ["move_intent", "move_complete"]);
		mismatchedCompletion[1] = { ...mismatchedCompletion[1], observedDestinationHash: finalContentHash };
		expect(() =>
			classifyStoreOperationMemberRestartV1({
				core,
				steps: mismatchedCompletion,
				keyBytes: key,
				member: "db",
				observedSourceHash: null,
				observedQuarantineHash: hash,
			}),
		).toThrow();
	});
	it("enforces authenticated keyring, store, and rollback authorities", () => {
		const keyring = envelope("gjc-bugwatch-fatal-keyring/v1", {
			scopeId: "scope",
			currentKeyId: derivedKeyId,
			previousKeyIds: [retainedKeyId],
			casToken: "token",
			revision: 1,
			updatedAt: timestamp,
		});
		const members = ["db", "wal", "shm"].map((member, index) => ({
			member,
			sourcePathHash: `${index + 1}`.repeat(64),
			expectedPresence: member === "db",
			expectedSize: member === "db" ? 1 : null,
			expectedHash: member === "db" ? hash : null,
			quarantinePathHash: `${index + 4}`.repeat(64),
		}));
		const core = envelope("gjc-bugwatch-store-operation-core/v1", {
			scopeId: "scope",
			operationId: "operation",
			ownerId: "owner",
			claimTokenHash: hash,
			kind: "migrate",
			fromVersion: 1,
			toVersion: 2,
			members,
			startedAt: timestamp,
			keyId: "key",
			mac: hash,
		});
		const step = envelope("gjc-bugwatch-store-operation-step/v1", {
			scopeId: "scope",
			operationId: "operation",
			coreHash: hash,
			stepIndex: 0,
			member: "db",
			action: "move_intent",
			expectedSourceHash: hash,
			observedDestinationHash: null,
			previousStepHash: null,
			occurredAt: timestamp,
			keyId: "key",
			mac: hash,
		});
		const bundle = envelope("gjc-bugwatch-rollback-bundle/v1", {
			scopeId: "scope",
			epochId: "epoch",
			roleTransitionTokenHash: hash,
			bundleVersion: 1,
			state: "exported",
			manifestHash: hash,
			itemCount: 1,
			byteCount: 1,
			itemsDigest: hash,
			sourceWatermarkHash: hash,
			createdAt: timestamp,
			exportedAt: timestamp,
			keyId: "key",
			mac: hash,
		});
		const manifest = envelope("gjc-bugwatch-rollback-spool-manifest/v1", {
			scopeId: "scope",
			epochId: "epoch",
			segmentIndex: 0,
			state: "closed",
			itemCount: 1,
			byteCount: 1,
			itemsDigest: hash,
			previousManifestHash: null,
			closedAt: timestamp,
			keyId: "key",
			mac: hash,
		});
		const itemPayload = rollbackRootPayload();
		const itemWithoutHash = {
			schema: "gjc-bugwatch-rollback-spool-item/v1",
			scopeId: "scope",
			epochId: "epoch",
			segmentIndex: 0,
			itemIndex: 0,
			itemType: "root",
			payload: itemPayload,
			payloadHash: authenticatedHash(itemPayload),
			previousItemHash: null,
			createdAt: timestamp,
			keyId: "key",
		};
		const item = envelope("gjc-bugwatch-rollback-spool-item/v1", {
			...itemWithoutHash,
			itemHash: authenticatedHash(itemWithoutHash),
			mac: hash,
		});
		const ack = envelope("gjc-bugwatch-rollback-inbox-ack/v1", {
			scopeId: "scope",
			epochId: "epoch",
			slot: 0,
			slotGeneration: 1,
			eventId: hash,
			segmentIndex: 0,
			spoolItemHash: hash,
			acknowledgedAt: timestamp,
			keyId: "key",
			mac: hash,
		});
		for (const [parser, value] of [
			[parseFatalKeyringV1, keyring],
			[parseStoreOperationCoreV1, core],
			[parseStoreOperationStepV1, step],
			[parseRollbackBundleV1, bundle],
			[parseRollbackSpoolManifestV1, manifest],
			[parseRollbackSpoolItemV1, item],
			[parseRollbackInboxAckV1, ack],
		] as const) {
			expect(parser(value)).toBeDefined();
			expect(() => parser(withUnknown(value))).toThrow();
		}
		expect(() => parseFatalKeyringV1({ ...keyring, previousKeyIds: [derivedKeyId] })).toThrow();
		expect(() => parseFatalKeyringV1({ ...keyring, previousKeyIds: [1] })).toThrow();
		expect(() => parseFatalKeyringV1({ ...keyring, currentKeyId: derivedKeyId.toUpperCase() })).toThrow();
		expect(() => parseFatalKeyringV1({ ...keyring, currentKeyId: derivedKeyId.slice(0, -1) })).toThrow();
		expect(() => parseFatalKeyringV1({ ...keyring, previousKeyIds: [retainedKeyId.toUpperCase()] })).toThrow();
		expect(parseFatalKeyringV1(keyring).previousKeyIds).toEqual([retainedKeyId]);
		expect(() => parseBootCoreV1({ ...bootCore(), fatalKeyId: derivedKeyId.toUpperCase() })).toThrow();
		expect(() => parseBootCoreV1({ ...bootCore(), keyId: derivedKeyId.toUpperCase() })).toThrow();
		expect(() => parseFatalEnvelopeV1({ ...fixtures[10].valid, keyId: derivedKeyId.toUpperCase() })).toThrow();
		expect(() => parseStoreOperationStepV1({ ...step, observedDestinationHash: hash })).toThrow();
		expect(() => parseRollbackBundleV1({ ...bundle, byteCount: 67_108_865 })).toThrow();
		expect(() => parseRollbackSpoolManifestV1({ ...manifest, state: "open" })).toThrow();
		expect(() => parseRollbackInboxAckV1({ ...ack, slot: 8192 })).toThrow();
	});
	it("verifies authenticated rollback reconstruction and closed spool acknowledgement evidence", () => {
		const key = new Uint8Array([11]);
		const wrongKey = new Uint8Array([12]);
		const keyForId = (keyId: string): Uint8Array | undefined => (keyId === "rollback" ? key : undefined);
		const sign = (value: JsonObject, domain: string, signingKey = key): JsonObject => ({
			...value,
			mac: hmacSha256Hex(signingKey, domain, macPayload(value)),
		});
		const bundleItem = (itemIndex: number, previousItemHash: string | null, payload: JsonValue): JsonObject => {
			const withoutHash: JsonObject = {
				schema: "gjc-bugwatch-rollback-bundle-item/v1",
				scopeId: "scope",
				epochId: "epoch",
				itemIndex,
				itemType: "root",
				payload,
				payloadHash: authenticatedHash(payload),
				previousItemHash,
				createdAt: timestamp,
				keyId: "rollback",
			};
			return sign(
				{ ...withoutHash, itemHash: authenticatedHash(withoutHash) },
				"gjc-bugwatch-rollback-bundle-item-v1",
			);
		};
		const bundleItems = [bundleItem(0, null, rollbackRootPayload())];
		const bundleDigest = sha256Hex(bundleItems.map(item => item.itemHash).join("\n"));
		const bundle = sign(
			{
				schema: "gjc-bugwatch-rollback-bundle/v1",
				scopeId: "scope",
				epochId: "epoch",
				roleTransitionTokenHash: hash,
				bundleVersion: 1,
				state: "exported",
				manifestHash: bundleDigest,
				itemCount: bundleItems.length,
				byteCount: bundleItems.reduce(
					(total, item) => total + new TextEncoder().encode(canonicalizeJson(item)).byteLength + 1,
					0,
				),
				itemsDigest: bundleDigest,
				sourceWatermarkHash: hash,
				createdAt: timestamp,
				exportedAt: timestamp,
				keyId: "rollback",
			},
			"gjc-bugwatch-rollback-bundle-v1",
		);
		expect(() => verifyRollbackBundleV1(bundle, bundleItems, keyForId)).not.toThrow();

		const acknowledgementPayload: JsonObject = {
			scopeId: "scope",
			epochId: "epoch",
			slot: 0,
			slotGeneration: 1,
			eventId: hash,
			segmentIndex: 0,
			acknowledgedAt: timestamp,
		};
		const spoolItem = (
			itemIndex: number,
			previousItemHash: string | null,
			itemType: "root" | "inbox_ack",
			payload: JsonValue,
		): JsonObject => {
			const withoutHash: JsonObject = {
				schema: "gjc-bugwatch-rollback-spool-item/v1",
				scopeId: "scope",
				epochId: "epoch",
				segmentIndex: 0,
				itemIndex,
				itemType,
				payload,
				payloadHash: authenticatedHash(payload),
				previousItemHash,
				createdAt: timestamp,
				keyId: "rollback",
			};
			return sign(
				{ ...withoutHash, itemHash: authenticatedHash(withoutHash) },
				"gjc-bugwatch-rollback-spool-item-v1",
			);
		};
		const spoolItems = [
			spoolItem(0, null, "root", rollbackRootPayload()),
			spoolItem(1, "", "inbox_ack", acknowledgementPayload),
		];
		spoolItems[1] = spoolItem(1, spoolItems[0].itemHash as string, "inbox_ack", acknowledgementPayload);
		const spoolDigest = sha256Hex(spoolItems.map(item => item.itemHash).join("\n"));
		const manifest = sign(
			{
				schema: "gjc-bugwatch-rollback-spool-manifest/v1",
				scopeId: "scope",
				epochId: "epoch",
				segmentIndex: 0,
				state: "closed",
				itemCount: spoolItems.length,
				byteCount: spoolItems.reduce(
					(total, item) => total + new TextEncoder().encode(canonicalizeJson(item)).byteLength + 1,
					0,
				),
				itemsDigest: spoolDigest,
				previousManifestHash: null,
				closedAt: timestamp,
				keyId: "rollback",
			},
			"gjc-bugwatch-rollback-spool-manifest-v1",
		);
		const acknowledgement = sign(
			{
				schema: "gjc-bugwatch-rollback-inbox-ack/v1",
				...acknowledgementPayload,
				spoolItemHash: spoolItems[1].itemHash,
				keyId: "rollback",
			},
			"gjc-bugwatch-rollback-inbox-ack-v1",
		);
		expect(() => verifyRollbackSpoolSegmentV1(manifest, spoolItems, [acknowledgement], keyForId)).not.toThrow();

		expect(() => verifyRollbackBundleV1(bundle, bundleItems, () => wrongKey)).toThrow();
		const forgedBundle = sign(bundle, "gjc-bugwatch-rollback-bundle-v1", wrongKey);
		expect(() => verifyRollbackBundleV1(forgedBundle, bundleItems, keyForId)).toThrow();
		expect(() =>
			verifyRollbackBundleV1(bundle, [{ ...bundleItems[0], payload: { rootId: "corrupt" } }], keyForId),
		).toThrow();
		expect(() => verifyRollbackBundleV1(bundle, bundleItems, () => undefined)).toThrow();
		expect(() => verifyRollbackBundleV1(bundle, [bundleItems[0], bundleItems[0]], keyForId)).toThrow();
		expect(() => verifyRollbackBundleV1(canonicalizeJson(bundle), bundleItems, keyForId)).not.toThrow();
		expect(() => verifyRollbackBundleV1("{", bundleItems, keyForId)).toThrow();
		expect(() => verifyRollbackBundleV1({ ...bundle, itemCount: 100_001 }, bundleItems, keyForId)).toThrow();
		expect(() => verifyRollbackSpoolSegmentV1(manifest, spoolItems, [], keyForId)).toThrow();
		expect(() =>
			verifyRollbackSpoolSegmentV1(
				manifest,
				spoolItems,
				[{ ...acknowledgement, spoolItemHash: spoolItems[0].itemHash }],
				keyForId,
			),
		).toThrow();
		expect(() => verifyRollbackSpoolSegmentV1(manifest, spoolItems, [acknowledgement], () => wrongKey)).toThrow();
		const forgedManifest = sign(manifest, "gjc-bugwatch-rollback-spool-manifest-v1", wrongKey);
		expect(() => verifyRollbackSpoolSegmentV1(forgedManifest, spoolItems, [acknowledgement], keyForId)).toThrow();
		expect(() =>
			verifyRollbackSpoolSegmentV1(
				{ ...manifest, state: "open", itemsDigest: null, closedAt: null },
				spoolItems,
				[acknowledgement],
				keyForId,
			),
		).toThrow();
		expect(() =>
			verifyRollbackSpoolSegmentV1({ ...manifest, itemCount: 100_001 }, spoolItems, [acknowledgement], keyForId),
		).toThrow();
	});
	it("requires closed reconstructive payloads for every rollback item type", () => {
		const payloads: Record<RollbackItemTypeV1, JsonObject> = {
			root: rollbackRootPayload(),
			root_alias: {
				scopeId: "scope",
				oldRootId: "old-root",
				newRootId: "root",
				moveEpochId: "move",
				oldPathHash: hash,
				newPathHash: hash,
				createdAtMs: 1,
			},
			boot: {
				scopeId: "scope",
				bootId: "boot",
				bootCoreHash: hash,
				pid: 1,
				pidStartToken: "token",
				producer: "daemon",
				startedAtMs: 1,
				initialPolicyGeneration: 1,
				initialPolicyHash: hash,
				fatalKeyId: "fatal",
				gjcVersion: "1",
				buildSha: null,
				finalSeq: null,
				finalState: null,
				finalRecordHash: null,
			},
			attachment: {
				scopeId: "scope",
				attachmentId: "attachment",
				attachmentTokenHash: hash,
				bootId: "boot",
				bootCoreHash: hash,
				rootId: "root",
				sessionId: null,
				startedAtMs: 1,
				endedAtMs: null,
				state: "active",
				managedSessionRoot: null,
				sessionFile: null,
				rootGeneration: 1,
				baselineEpochId: "epoch",
				publishSeq: null,
				retireSeq: null,
				currentTransitionHash: hash,
			},
			coverage_range: { scopeId: "scope", bootId: "boot", startSeq: 1, endSeq: 1 },
			source: {
				scopeId: "scope",
				segmentId: "segment",
				generation: 0,
				sourceKind: "log",
				path: "/log",
				fileIdentityHint: "identity",
				prefixAnchorLength: 0,
				prefixHash: hash,
				committedOffset: 0,
				boundaryHash: null,
				checkpointDigest: hash,
				validationState: "valid",
				state: "active",
				blockId: null,
				updatedAtMs: 1,
			},
			source_checkpoint: {
				scopeId: "scope",
				segmentId: "segment",
				generation: 0,
				kind: "chunk",
				chunkIndex: 0,
				startOffset: 0,
				endOffset: 1,
				hash,
				validatedAtMs: null,
			},
			archive_alias: {
				scopeId: "scope",
				archiveDigest: hash,
				uncompressedLength: 0,
				segmentId: "segment",
				generation: 0,
				lineageKind: "full",
				verifiedCheckpointDigest: hash,
				createdAtMs: 1,
			},
			physical_row: {
				scopeId: "scope",
				segmentId: "segment",
				generation: 0,
				endOffset: 1,
				rawHash: hash,
				bootId: null,
				recordSeq: null,
				eventId: null,
				disposition: "candidate",
			},
			overflow: {
				scopeId: "scope",
				rootId: "root",
				severity: "low",
				windowStartMs: 0,
				count: 1,
				firstAtMs: 0,
				lastAtMs: 1,
				firstRawHash: hash,
				lastRawHash: hash,
			},
			observation: {
				scopeId: "scope",
				eventId: "event",
				rootId: "root",
				bootId: null,
				attachmentId: null,
				correlationId: null,
				recordSeq: null,
				fingerprintVersion: 1,
				fingerprintHash: hash,
				fingerprintText: "fingerprint",
				severity: "high",
				category: "error",
				message: "message",
				stackTop: null,
				occurredAtMs: null,
				createdAtMs: 1,
			},
			candidate: {
				scopeId: "scope",
				rootId: "root",
				fingerprintVersion: 1,
				fingerprintHash: hash,
				count: 1,
				severity: "high",
				category: "error",
				sampleEventId: null,
				policyState: "open",
				latestRevision: 0,
				nextEligibleAtMs: null,
			},
			cursor_watermark: {
				scopeId: "scope",
				epochId: "epoch",
				segmentId: "segment",
				generation: 0,
				offset: 0,
				boundaryHash: null,
				checkpointDigest: null,
				sourceState: "active",
			},
			inbox_ack: {
				scopeId: "scope",
				epochId: "epoch",
				slot: 0,
				slotGeneration: 1,
				eventId: hash,
				segmentIndex: 0,
				acknowledgedAt: timestamp,
			},
		};
		for (const itemType of Object.keys(payloads) as RollbackItemTypeV1[]) {
			const payload = payloads[itemType];
			const withoutHash = {
				schema: "gjc-bugwatch-rollback-spool-item/v1",
				scopeId: "scope",
				epochId: "epoch",
				segmentIndex: 0,
				itemIndex: 0,
				itemType,
				payload,
				payloadHash: authenticatedHash(payload),
				previousItemHash: null,
				createdAt: timestamp,
				keyId: "rollback",
			};
			const item = { ...withoutHash, itemHash: authenticatedHash(withoutHash), mac: hash };
			expect(parseRollbackSpoolItemV1(item).payload).toEqual(payload);
			const unknownPayload = { ...payload, unknown: true };
			const invalid = {
				...item,
				payload: unknownPayload,
				payloadHash: authenticatedHash(unknownPayload),
			};
			expect(() => parseRollbackSpoolItemV1(invalid)).toThrow();
			const missingPayload = { scopeId: "scope" };
			expect(() =>
				parseRollbackSpoolItemV1({
					...item,
					payload: missingPayload,
					payloadHash: authenticatedHash(missingPayload),
				}),
			).toThrow();
			const corruptPayload = { ...payload, scopeId: "other" };
			expect(() =>
				parseRollbackSpoolItemV1({
					...item,
					payload: corruptPayload,
					payloadHash: authenticatedHash(corruptPayload),
				}),
			).toThrow();
		}
		const hashOnlyPayload = { scopeId: "scope", rawHash: hash };
		expect(() =>
			parseRollbackSpoolItemV1({
				schema: "gjc-bugwatch-rollback-spool-item/v1",
				scopeId: "scope",
				epochId: "epoch",
				segmentIndex: 0,
				itemIndex: 0,
				itemType: "physical_row",
				payload: hashOnlyPayload,
				payloadHash: authenticatedHash(hashOnlyPayload),
				itemHash: authenticatedHash({
					schema: "gjc-bugwatch-rollback-spool-item/v1",
					scopeId: "scope",
					epochId: "epoch",
					segmentIndex: 0,
					itemIndex: 0,
					itemType: "physical_row",
					payload: hashOnlyPayload,
					payloadHash: authenticatedHash(hashOnlyPayload),
					previousItemHash: null,
					createdAt: timestamp,
					keyId: "rollback",
				}),
				previousItemHash: null,
				createdAt: timestamp,
				keyId: "rollback",
				mac: hash,
			}),
		).toThrow();
		const root = payloads.root;
		const crossType = {
			schema: "gjc-bugwatch-rollback-spool-item/v1",
			scopeId: "scope",
			epochId: "epoch",
			segmentIndex: 0,
			itemIndex: 0,
			itemType: "boot",
			payload: root,
			payloadHash: authenticatedHash(root),
			previousItemHash: null,
			createdAt: timestamp,
			keyId: "rollback",
		};
		expect(() =>
			parseRollbackSpoolItemV1({ ...crossType, itemHash: authenticatedHash(crossType), mac: hash }),
		).toThrow();
	});
});
describe("authority snapshot reconstructive pack verification", () => {
	const snapshotKey = new Uint8Array([1]);
	const policyKey = new Uint8Array([5]);
	const fatalKey = new Uint8Array([2]);
	const registryKey = new Uint8Array([3]);
	const rollbackKey = new Uint8Array([4]);
	const retainedPolicyKey = new Uint8Array([6]);
	const retainedFatalKey = new Uint8Array([7]);
	const retainedRegistryKey = new Uint8Array([8]);
	const retainedRollbackKey = new Uint8Array([9]);
	function snapshotFrontierEvidence(schemaMeta: JsonValue): AuthoritySnapshotFrontierEvidenceV1 {
		const frontierRecord = (kind: string, fields: JsonObject): SnapshotFrontierRecordV1 => {
			const identity = { sequence: 0, kind, ...fields, occurredAt: timestamp, previousRecordHash: null };
			return {
				...identity,
				recordHash: sha256Hex(canonicalizeJson(identity)),
			} as unknown as SnapshotFrontierRecordV1;
		};
		const evidence: AuthoritySnapshotFrontierEvidenceV1 = {
			sqliteBackup: {
				scopeId: "scope",
				backupId: "backup",
				backupBytes: "base64:c25hcHNob3Q=",
				backupHash: sha256Hex(new TextEncoder().encode("snapshot")),
				databaseHash: sha256Hex(new TextEncoder().encode("snapshot")),
				dataVersionBefore: 1,
				dataVersionAfter: 1,
				createdAt: timestamp,
			},
			schemaMeta: schemaMeta as unknown as AuthoritySnapshotFrontierEvidenceV1["schemaMeta"],
			sourceWatermarks: {
				scopeId: "scope",
				entries: [
					{
						sourceId: "source",
						generation: 0,
						committedOffset: 1,
						records: [
							frontierRecord("source", {
								itemType: "sources",
								authorityId: "source",
								payloadHash: hash,
								sourceId: "source",
								generation: 0,
								committedOffset: 1,
								boundaryHash: null,
								checkpointDigest: hash,
							}),
						],
					},
				],
			},
			registryFrontiers: {
				scopeId: "scope",
				entries: [
					{
						bootId: "boot",
						transportEpoch: 1,
						records: [
							frontierRecord("registry", {
								itemType: "producer_boots",
								authorityId: "boot",
								payloadHash: hash,
								bootId: "boot",
								transportEpoch: 1,
							}),
						],
					},
				],
			},
			inboxFrontier: {
				scopeId: "scope",
				entries: [
					{
						slot: 1,
						slotGeneration: 1,
						records: [
							frontierRecord("inbox", {
								itemType: "inbox_emergency_replay",
								authorityId: "inbox",
								payloadHash: hash,
								slot: 1,
								slotGeneration: 1,
							}),
						],
					},
				],
			},
			emergencyFrontier: {
				scopeId: "scope",
				entries: [
					{
						logicalSlot: 1,
						page: 1,
						pageGeneration: 1,
						records: [
							frontierRecord("emergency", {
								itemType: "inbox_emergency_replay",
								authorityId: "emergency",
								payloadHash: hash,
								logicalSlot: 1,
								page: 1,
								pageGeneration: 1,
							}),
						],
					},
				],
			},
			rollbackSpoolFrontier: {
				scopeId: "scope",
				entries: [
					{
						epochId: "epoch",
						segmentIndex: 1,
						records: [
							frontierRecord("rollback", {
								itemType: "rollback_spool_replay",
								authorityId: "epoch",
								payloadHash: hash,
								epochId: "epoch",
								segmentIndex: 1,
							}),
						],
					},
				],
			},
			artifactFrontier: {
				scopeId: "scope",
				entries: [
					{
						artifactId: "artifact",
						outboxSequence: "1",
						records: [
							frontierRecord("artifact", {
								itemType: "artifact_outbox",
								authorityId: "artifact",
								payloadHash: hash,
								artifactId: "artifact",
								outboxSequence: "1",
							}),
						],
					},
				],
			},
		};
		for (const frontier of [
			evidence.sourceWatermarks,
			evidence.registryFrontiers,
			evidence.inboxFrontier,
			evidence.emergencyFrontier,
			evidence.rollbackSpoolFrontier,
			evidence.artifactFrontier,
		])
			frontier.entries = [];
		return evidence;
	}

	function signed(value: JsonObject, domain: string, key: Uint8Array): JsonObject {
		return { ...value, mac: hmacSha256Hex(key, domain, macPayload(value)) };
	}
	function verifiedPack(
		payload: JsonObject = {
			id: 1,
			schema_major: 1,
			schema_minor: BUGWATCH_SCHEMA_MINOR,
			log_schema_version: 2,
			redaction_version: 1,
			noise_version: 1,
			severity_version: 1,
			fingerprint_version: 1,
			fixture_manifest_hash: BUGWATCH_FIXTURE_MANIFEST_HASH,
			schema_catalog_hash: BUGWATCH_SCHEMA_CATALOG_HASH,
			created_at_ms: 1_767_323_045_000,
			migrated_at_ms: 1_767_323_045_000,
		},
		authorityId = "1",
		itemType = "schema_meta",
		extraRecords: Array<{ itemType: string; authorityId: string; payload: JsonObject }> = [],
		policyAuthority: { keyId: string; keyBytes: Uint8Array } = { keyId: "policy", keyBytes: policyKey },
	): {
		manifest: JsonObject;
		items: JsonObject[];
		classes: JsonObject[];
		frontierEvidence: AuthoritySnapshotFrontierEvidenceV1;
	} {
		const casToken = "snapshot-cas-token-v1";
		const semantic = policySemantic();
		const revision = signed(
			{
				schema: "gjc-bugwatch-policy-revision/v2",
				scopeId: "scope",
				generation: 1,
				semantic,
				contentHash: sha256Hex(canonicalizeJson(semantic)),
				previousGeneration: null,
				previousRevisionHash: null,
				previousContentHash: null,
				casTokenHash: sha256Hex(casToken),
				createdAt: timestamp,
				writerId: "writer",
				keyId: policyAuthority.keyId,
			},
			"gjc-bugwatch-policy-revision-v2",
			policyAuthority.keyBytes,
		);
		const head = signed(
			{
				schema: "gjc-bugwatch-policy-head/v2",
				scopeId: "scope",
				generation: 1,
				revisionHash: authenticatedHash(revision),
				contentHash: revision.contentHash,
				casToken,
				updatedAt: timestamp,
				keyId: policyAuthority.keyId,
			},
			"gjc-bugwatch-policy-head-v2",
			policyAuthority.keyBytes,
		);
		const revisionRow = {
			scope_id: revision.scopeId,
			generation: revision.generation,
			revision_hash: authenticatedHash(revision),
			semantic_json: canonicalizeJson(revision.semantic as JsonValue),
			content_hash: revision.contentHash,
			previous_generation: revision.previousGeneration,
			previous_revision_hash: revision.previousRevisionHash,
			previous_content_hash: revision.previousContentHash,
			cas_token_hash: revision.casTokenHash,
			created_at_ms: Date.parse(revision.createdAt as string),
			writer_id: revision.writerId,
			key_id: revision.keyId,
			mac: revision.mac,
		};
		const headRow = {
			scope_id: head.scopeId,
			generation: head.generation,
			revision_hash: head.revisionHash,
			content_hash: head.contentHash,
			cas_token_hash: sha256Hex(head.casToken as string),
			head_json: canonicalizeJson(head),
			updated_at_ms: Date.parse(head.updatedAt as string),
			key_id: head.keyId,
			mac: head.mac,
		};
		const records: Array<{ itemType: string; authorityId: string; payload: JsonObject }> = [
			{ itemType, authorityId, payload },
			{ itemType: "scope_policies", authorityId: "scope", payload: revisionRow },
			{ itemType: "scope_policy_heads", authorityId: "scope", payload: headRow },
			...extraRecords,
		];
		const items: JsonObject[] = [];
		for (const [index, record] of records.entries()) {
			items.push(
				signed(
					{
						schema: "gjc-bugwatch-authority-item/v1",
						index,
						itemType: record.itemType,
						authorityId: record.authorityId,
						payload: record.payload,
						payloadHash: sha256Hex(canonicalizeJson(record.payload)),
						previousItemHash: index === 0 ? null : authenticatedHash(items[index - 1]),
						keyId: "snapshot",
					},
					"gjc-bugwatch-authority-item-v1",
					snapshotKey,
				),
			);
		}
		const itemBytes = items.map(item => `${canonicalizeJson(item)}\n`).join("");
		let merkleLevel = items.map(item => authenticatedHash(item));
		while (merkleLevel.length > 1) {
			const next: string[] = [];
			for (let index = 0; index < merkleLevel.length; index += 2)
				next.push(sha256Hex(`${merkleLevel[index]}${merkleLevel[index + 1] ?? merkleLevel[index]}`));
			merkleLevel = next;
		}
		const merkleRoot = merkleLevel[0];
		const classes = AUTHORITY_CLASS_NAMES.map(className => {
			const classItems = items.filter(item => item.itemType === className);
			const classBytes = classItems.map(value => `${canonicalizeJson(value)}\n`).join("");
			return {
				className,
				mode: AUTHORITY_SNAPSHOT_POLICY[className].mode,
				itemCount: classItems.length,
				byteCount: Buffer.byteLength(classBytes),
				itemsSha256: sha256Hex(classBytes),
				classDigest: sha256Hex(canonicalizeJson(classItems.map(value => sha256Hex(canonicalizeJson(value))))),
				reconstructiveSource: AUTHORITY_SNAPSHOT_POLICY[className].reconstructiveSource,
			};
		});
		const frontierEvidence = snapshotFrontierEvidence(items[0].payload);
		const cutoff = {
			...(snapshot().cutoff as JsonObject),
			sqliteBackupHash: frontierEvidence.sqliteBackup.backupHash,
			schemaMetaHash: sha256Hex(canonicalizeJson(frontierEvidence.schemaMeta as unknown as JsonValue)),
			sourceWatermarksHash: sha256Hex(canonicalizeJson(frontierEvidence.sourceWatermarks as unknown as JsonValue)),
			registryFrontiersHash: sha256Hex(canonicalizeJson(frontierEvidence.registryFrontiers as unknown as JsonValue)),
			inboxFrontierHash: sha256Hex(canonicalizeJson(frontierEvidence.inboxFrontier as unknown as JsonValue)),
			emergencyFrontierHash: sha256Hex(canonicalizeJson(frontierEvidence.emergencyFrontier as unknown as JsonValue)),
			rollbackSpoolFrontierHash: sha256Hex(
				canonicalizeJson(frontierEvidence.rollbackSpoolFrontier as unknown as JsonValue),
			),
			artifactFrontierHash: sha256Hex(canonicalizeJson(frontierEvidence.artifactFrontier as unknown as JsonValue)),
		};
		const manifest = signed(
			{
				...snapshot(),
				itemCount: items.length,
				byteCount: Buffer.byteLength(itemBytes),
				itemsSha256: sha256Hex(itemBytes),
				merkleRoot,
				cutoff,
				classes,
				snapshotKeyId: "snapshot",
				snapshotKeyDigest: sha256Hex(snapshotKey),
				policyKeyringId: "policy",
				policyKeyringDigest: sha256Hex(policyKey),
				policyKeyringSource: "protected_retained_policy_keyring",
				fatalKeyringId: "fatal",
				fatalKeyringDigest: sha256Hex(fatalKey),
				fatalKeyringSource: "protected_retained_fatal_keyring",
				registryKeyringId: "registry",
				registryKeyringDigest: sha256Hex(registryKey),
				registryKeyringSource: "protected_retained_registry_keyring",
				rollbackKeyringId: "rollback",
				rollbackKeyringDigest: sha256Hex(rollbackKey),
				rollbackKeyringSource: "protected_retained_rollback_keyring",
				keyId: "snapshot",
			},
			"gjc-bugwatch-authority-snapshot-v2",
			snapshotKey,
		);
		return { manifest, items, classes, frontierEvidence };
	}
	const keyrings = {
		snapshot: { keyId: "snapshot", keyBytes: snapshotKey },
		policy: { keyId: "policy", keyBytes: policyKey },
		fatal: { keyId: "fatal", keyBytes: fatalKey },
		registry: { keyId: "registry", keyBytes: registryKey },
		rollback: { keyId: "rollback", keyBytes: rollbackKey },
	};

	it("authenticates root mutation core snapshots through retained registry graph keys", () => {
		const retainedRegistry = { keyId: "registry-old", keyBytes: retainedRegistryKey };
		const rootKey = retainedRegistry.keyBytes;
		const unsignedCore = {
			schema: "gjc-bugwatch-root-mutation-core/v1",
			scopeId: "scope",
			mutationId: "mutation",
			action: "set_context",
			expectedPolicyGeneration: 1,
			expectedPolicyHash: hash,
			oldRootId: "root",
			newRootId: "root",
			outputs: [
				{
					target: "new_root",
					pathHash: hash,
					precondition: "present",
					expectedOldContentHash: hash,
					pendingContentHash,
					finalContentHash,
					desiredRootGeneration: 1,
					publicationOrder: 1,
				},
			],
			createdAt: "2026-01-02T03:04:05.000Z",
			actorPid: 1,
			actorPidStartToken: "pid-start",
			keyId: retainedRegistry.keyId,
		};
		const core = signed(unsignedCore, "gjc-bugwatch-root-mutation-core-v1", rootKey);
		const coreHash = authenticatedHash(core);
		const unsignedPrepared = {
			schema: "gjc-bugwatch-root-mutation-db-state/v1",
			scopeId: "scope",
			mutationId: "mutation",
			coreHash,
			phase: "prepared",
			previousPhase: null,
			previousStateHash: null,
			keyId: retainedRegistry.keyId,
		};
		const prepared = signed(unsignedPrepared, "gjc-bugwatch-root-mutation-db-state-v1", rootKey);
		const publishing = signed(
			{
				...unsignedPrepared,
				phase: "publishing",
				previousPhase: "prepared",
				previousStateHash: authenticatedHash(prepared),
			},
			"gjc-bugwatch-root-mutation-db-state-v1",
			rootKey,
		);
		const renameSteps: JsonObject[] = [];
		for (const [lifecycle, action] of [
			["pending", "rename_intent"],
			["pending", "rename_complete"],
			["final", "rename_intent"],
			["final", "rename_complete"],
		] as const) {
			const desired = lifecycle === "pending" ? pendingContentHash : finalContentHash;
			const expectedDestination = lifecycle === "pending" ? hash : pendingContentHash;
			const unsigned = {
				schema: "gjc-bugwatch-root-rename-step/v2",
				scopeId: "scope",
				mutationId: "mutation",
				coreHash,
				stepIndex: renameSteps.length,
				target: "new_root",
				lifecycle,
				action,
				expectedDestinationHash: expectedDestination,
				sourceTempHash: desired,
				desiredDestinationHash: desired,
				observedDestinationHash: action === "rename_complete" ? desired : null,
				previousStepHash: renameSteps.length === 0 ? null : authenticatedHash(renameSteps[renameSteps.length - 1]),
				occurredAt: timestamp,
				keyId: retainedRegistry.keyId,
			};
			renameSteps.push(signed(unsigned, "gjc-bugwatch-root-rename-step-v2", rootKey));
		}
		const renameRow = (step: JsonObject): JsonObject => ({
			mutation_id: step.mutationId,
			step_index: step.stepIndex,
			target: step.target,
			lifecycle: step.lifecycle,
			action: step.action,
			expected_destination_hash: step.expectedDestinationHash,
			source_temp_hash: step.sourceTempHash,
			desired_destination_hash: step.desiredDestinationHash,
			observed_destination_hash: step.observedDestinationHash,
			previous_step_hash: step.previousStepHash,
			step_hash: authenticatedHash(step),
			occurred_at_ms: Date.parse(String(step.occurredAt)),
			key_id: step.keyId,
			mac: step.mac,
		});
		const stateRow = (state: JsonObject, stepIndex: number): JsonObject => ({
			scope_id: state.scopeId,
			mutation_id: state.mutationId,
			core_hash: state.coreHash,
			step_index: stepIndex,
			phase: state.phase,
			previous_phase: state.previousPhase,
			previous_state_hash: state.previousStateHash,
			key_id: state.keyId,
			mac: state.mac,
			record_hash: authenticatedHash(state),
			created_at_ms: 1_767_323_045_000,
			recorded_at_ms: 1_767_323_045_000,
		});
		const summary = {
			mutation_id: "mutation",
			scope_id: "scope",
			action: "set_context",
			core_hash: coreHash,
			core_json: canonicalizeJson(core),
			expected_policy_generation: 1,
			expected_policy_hash: hash,
			old_root_id: "root",
			new_root_id: "root",
			phase: "publishing",
			step_index: 1,
			current_step_hash: authenticatedHash(publishing),
			created_at_ms: 1_767_323_045_000,
			updated_at_ms: 1_767_323_045_000,
		};
		const rootAuthority = signed(
			{
				schema: "gjc-bugwatch-root/v1",
				scopeId: "scope",
				rootId: "root",
				canonicalPath: "/root",
				enabled: true,
				persistContext: true,
				generation: 1,
				projectPolicyHash: hash,
				baselineEpochId: null,
				activeMutationId: null,
				updatedAt: timestamp,
				nonce: "nonce",
				keyId: retainedRegistry.keyId,
			},
			"gjc-bugwatch-root-v1",
			rootKey,
		);
		const records = [
			{
				itemType: "roots",
				authorityId: "root",
				payload: {
					root_id: "root",
					kind: "project",
					canonical_path: "/root",
					enabled: 1,
					revision: 1,
					project_policy_hash: hash,
					registered_at_ms: 1,
					disabled_at_ms: 0,
					persist_context: 1,
					baseline_epoch_id: null,
					active_mutation_id: null,
					root_json: canonicalizeJson(rootAuthority),
				},
			},
			{ itemType: "root_mutations", authorityId: "mutation", payload: summary },
			{
				itemType: "root_mutation_outputs",
				authorityId: "mutation",
				payload: {
					mutation_id: "mutation",
					target: "new_root",
					path_hash: hash,
					precondition: "present",
					expected_old_content_hash: hash,
					pending_content_hash: pendingContentHash,
					final_content_hash: finalContentHash,
					desired_root_generation: 1,
					publication_order: 1,
					pending_state: "prepared",
					final_state: "prepared",
				},
			},
			{ itemType: "root_mutation_steps", authorityId: "mutation", payload: stateRow(prepared, 0) },
			{ itemType: "root_mutation_steps", authorityId: "mutation", payload: stateRow(publishing, 1) },
			...renameSteps.slice(0, 2).map(step => ({
				itemType: "root_mutation_rename_steps",
				authorityId: "mutation",
				payload: renameRow(step),
			})),
		];
		const pack = verifiedPack(undefined, undefined, undefined, records);
		expect(
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...keyrings, registry: [keyrings.registry, retainedRegistry] },
				null,
				pack.frontierEvidence,
			).items,
		).toHaveLength(10);
		for (const invalid of [
			records.filter(record => record !== records[1]),
			records.map(record =>
				record.itemType === "root_mutation_steps" && record.payload.step_index === 1
					? { ...record, payload: { ...record.payload, phase: "files_published" } }
					: record,
			),
			records.map(record =>
				record.itemType === "root_mutations"
					? { ...record, payload: { ...record.payload, core_json: canonicalizeJson({ ...core, mac: hash }) } }
					: record,
			),
			records.map(record =>
				record.itemType === "roots"
					? {
							...record,
							payload: { ...record.payload, root_json: canonicalizeJson({ ...rootAuthority, mac: hash }) },
						}
					: record,
			),
			records.map(record =>
				record.itemType === "roots"
					? { ...record, payload: { ...record.payload, canonical_path: "/other" } }
					: record,
			),
			records.map(record =>
				record.itemType === "roots" ? { ...record, payload: { ...record.payload, persist_context: 0 } } : record,
			),
			records.map(record =>
				record.itemType === "root_mutations"
					? { ...record, payload: { ...record.payload, action: "move" } }
					: record,
			),
		]) {
			const invalidPack = verifiedPack(undefined, undefined, undefined, invalid);
			expect(() =>
				verifyAuthoritySnapshotPackV2(
					invalidPack.manifest,
					invalidPack.items,
					{ ...keyrings, registry: [keyrings.registry, retainedRegistry] },
					null,
					invalidPack.frontierEvidence,
				),
			).toThrow();
		}
		expect(() =>
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...keyrings, registry: [keyrings.registry] },
				null,
				pack.frontierEvidence,
			),
		).toThrow("authority_missing:registry_keyring:registry-old");
		expect(() =>
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...keyrings, registry: { keyId: "registry", keyBytes: new Uint8Array([9]) } },
				null,
				pack.frontierEvidence,
			),
		).toThrow();
		expect(() =>
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...keyrings, registry: { keyId: "wrong-registry", keyBytes: rootKey } },
				null,
				pack.frontierEvidence,
			),
		).toThrow();
	});
	it("rejects policy evidence authenticated by the snapshot signing key", () => {
		const pack = verifiedPack();
		expect(() =>
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...keyrings, policy: { keyId: "policy", keyBytes: snapshotKey } },
				null,
				pack.frontierEvidence,
			),
		).toThrow();
	});
	it("resolves retained policy material through the revision and head graph rather than manifest preflight", () => {
		const retainedPolicy = { keyId: "policy-old", keyBytes: retainedPolicyKey };
		const pack = verifiedPack(undefined, undefined, undefined, [], retainedPolicy);
		const retainedKeyrings = { ...keyrings, policy: [keyrings.policy, retainedPolicy] };
		expect(
			verifyAuthoritySnapshotPackV2(pack.manifest, pack.items, retainedKeyrings, null, pack.frontierEvidence).items,
		).toHaveLength(pack.items.length);
		expect(() =>
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...retainedKeyrings, policy: [keyrings.policy] },
				null,
				pack.frontierEvidence,
			),
		).toThrow("authority_missing:policy_keyring:policy-old");
	});
	it("enforces per-class SQLite checks and complete composite snapshot references", () => {
		const retainedRegistry = { keyId: "registry-old", keyBytes: retainedRegistryKey };
		const source = {
			segment_id: "segment",
			generation: 0,
			source_kind: "log",
			path: "/tmp/log",
			file_identity_hint: "identity",
			prefix_anchor_length: 0,
			prefix_hash: hash,
			committed_offset: 0,
			boundary_hash: null,
			checkpoint_digest: hash,
			validation_state: "valid",
			state: "active",
			block_id: null,
			updated_at_ms: 1,
		};
		const checkpoint = {
			segment_id: "segment",
			generation: 0,
			kind: "chunk",
			chunk_index: 0,
			start_offset: 0,
			end_offset: 1,
			hash,
			validated_at_ms: 1,
		};
		const inventory = {
			inventory_epoch_id: "inventory",
			scope_id: "scope",
			state: "complete",
			started_at_ms: 1,
			completed_at_ms: 1,
			receipt_hash: hash,
		};
		const monitorAuthority = signed(
			{
				schema: "gjc-bugwatch-monitor-inventory/v1",
				scopeId: "scope",
				inventoryEpochId: "inventory",
				monitorId: "monitor",
				kind: "process",
				stableIdentifier: "pid:1",
				configHash: hash,
				coveredRootIds: [],
				status: "active",
				observedAt: timestamp,
				adapterEvidenceHash: hash,
				keyId: retainedRegistry.keyId,
			},
			"gjc-bugwatch-monitor-inventory-v1",
			retainedRegistry.keyBytes,
		);
		const monitor = {
			inventory_epoch_id: "inventory",
			monitor_id: "monitor",
			kind: "process",
			stable_identifier: "pid:1",
			owner: "owner",
			config_hash: hash,
			status: "active",
			observed_at_ms: Date.parse(timestamp),
			inventory_json: canonicalizeJson(monitorAuthority),
		};
		const records = [
			{ itemType: "sources", authorityId: "segment", payload: source },
			{ itemType: "source_checkpoints", authorityId: "segment", payload: checkpoint },
			{ itemType: "old_monitor_inventory_epochs", authorityId: "inventory", payload: inventory },
			{ itemType: "old_monitors", authorityId: "monitor", payload: monitor },
		];
		const pack = verifiedPack(undefined, undefined, undefined, records);
		expect(
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...keyrings, registry: [keyrings.registry, retainedRegistry] },
				null,
				pack.frontierEvidence,
			).items,
		).toHaveLength(7);
		for (const invalid of [
			records.map(record =>
				record.itemType === "source_checkpoints"
					? { ...record, payload: { ...record.payload, generation: 1 } }
					: record,
			),
			records.map(record =>
				record.itemType === "old_monitors"
					? { ...record, payload: { ...record.payload, observed_at_ms: -1 } }
					: record,
			),
			records.map(record =>
				record.itemType === "old_monitors"
					? {
							...record,
							payload: {
								...record.payload,
								inventory_json: canonicalizeJson(
									signed(
										{ ...monitorAuthority, coveredRootIds: ["root"] },
										"gjc-bugwatch-monitor-inventory-v1",
										retainedRegistry.keyBytes,
									),
								),
							},
						}
					: record,
			),
		]) {
			const invalidPack = verifiedPack(undefined, undefined, undefined, invalid);
			expect(() =>
				verifyAuthoritySnapshotPackV2(
					invalidPack.manifest,
					invalidPack.items,
					{ ...keyrings, registry: [keyrings.registry, retainedRegistry] },
					null,
					invalidPack.frontierEvidence,
				),
			).toThrow();
		}
		expect(() =>
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...keyrings, registry: [keyrings.registry] },
				null,
				pack.frontierEvidence,
			),
		).toThrow("authority_missing:registry_keyring:registry-old");
	});
	it("reconstructs and authenticates every digest from payload-bearing items", () => {
		const pack = verifiedPack();
		expect(parseAuthoritySnapshotItemV1(pack.items[0]).authorityId).toBe("1");
		const head = pack.items[2].payload as JsonObject;
		const authenticatedHead = JSON.parse(head.head_json as string) as JsonObject;
		expect(pack.items[2].itemType).toBe("scope_policy_heads");
		expect(authenticatedHead.casToken).toBe("snapshot-cas-token-v1");
		expect(head.cas_token_hash).toBe(sha256Hex(authenticatedHead.casToken as string));
		expect(head.cas_token_hash).not.toBe(authenticatedHead.casToken);
		expect(
			verifyAuthoritySnapshotPackV2(pack.manifest, pack.items, keyrings, null, pack.frontierEvidence).items,
		).toHaveLength(3);
	});
	it("rejects missing or mismatched frontier evidence", () => {
		const pack = verifiedPack();
		expect(() => verifyAuthoritySnapshotPackV2(pack.manifest, pack.items, keyrings)).toThrow(
			"authority_missing:cutoff_frontiers",
		);
		expect(() =>
			verifyAuthoritySnapshotPackV2(pack.manifest, pack.items, keyrings, null, {
				...pack.frontierEvidence,
				inboxFrontier: {
					scopeId: "scope",
					entries: [{ slot: 2, slotGeneration: 1, records: [] }],
				},
			}),
		).toThrow();
	});
	it("accepts generation zero source frontiers and rejects negative or fractional generations", () => {
		const pack = verifiedPack();
		const withGeneration = (generation: number) => {
			const sourceWatermarks = {
				...pack.frontierEvidence.sourceWatermarks,
				entries: [{ sourceId: "source", generation, committedOffset: 1, records: [] }],
			};
			const frontierEvidence = { ...pack.frontierEvidence, sourceWatermarks };
			const cutoff = {
				...(pack.manifest.cutoff as JsonObject),
				sourceWatermarksHash: sha256Hex(canonicalizeJson(sourceWatermarks as unknown as JsonValue)),
			};
			return {
				frontierEvidence,
				manifest: signed({ ...pack.manifest, cutoff }, "gjc-bugwatch-authority-snapshot-v2", snapshotKey),
			};
		};
		const zero = withGeneration(0);
		expect(
			verifyAuthoritySnapshotPackV2(zero.manifest, pack.items, keyrings, null, zero.frontierEvidence).items,
		).toHaveLength(3);
		for (const generation of [-1, 0.5]) {
			const invalid = withGeneration(generation);
			expect(() =>
				verifyAuthoritySnapshotPackV2(invalid.manifest, pack.items, keyrings, null, invalid.frontierEvidence),
			).toThrow();
		}
	});
	it("rejects incomplete, gapped, wrong-scope, and conflicting typed cutoff frontiers", () => {
		const pack = verifiedPack();
		const invalidEvidence = [
			{ ...pack.frontierEvidence, sqliteBackup: { ...pack.frontierEvidence.sqliteBackup, dataVersionAfter: 2 } },
			{ ...pack.frontierEvidence, sqliteBackup: { ...pack.frontierEvidence.sqliteBackup, backupBytes: "snapshot" } },
			{ ...pack.frontierEvidence, sqliteBackup: { ...pack.frontierEvidence.sqliteBackup, backupHash: hash } },
			{
				...pack.frontierEvidence,
				sourceWatermarks: { ...pack.frontierEvidence.sourceWatermarks, scopeId: "other" },
			},
			{
				...pack.frontierEvidence,
				registryFrontiers: {
					...pack.frontierEvidence.registryFrontiers,
					entries: [{ bootId: "boot", transportEpoch: 1, records: [] }],
				},
			},
			{
				...pack.frontierEvidence,
				inboxFrontier: {
					...pack.frontierEvidence.inboxFrontier,
					entries: [{ slot: 1, slotGeneration: 1, records: [] }],
				},
			},
			{
				...pack.frontierEvidence,
				emergencyFrontier: {
					...pack.frontierEvidence.emergencyFrontier,
					entries: [{ logicalSlot: 1, page: 2, pageGeneration: 1, records: [] }],
				},
			},
			{
				...pack.frontierEvidence,
				rollbackSpoolFrontier: {
					...pack.frontierEvidence.rollbackSpoolFrontier,
					entries: [{ epochId: "", segmentIndex: 1, records: [] }],
				},
			},
			{
				...pack.frontierEvidence,
				artifactFrontier: {
					...pack.frontierEvidence.artifactFrontier,
					entries: [{ artifactId: "artifact", outboxSequence: "01", records: [] }],
				},
			},
		];
		for (const evidence of invalidEvidence)
			expect(() => verifyAuthoritySnapshotPackV2(pack.manifest, pack.items, keyrings, null, evidence)).toThrow();
	});
	it("rejects digest-consistent non-reconstructive snapshot payloads", () => {
		const invalidPayloads: Array<{ payload: JsonObject; authorityId?: string; itemType?: string }> = [
			{ payload: { version: 1 } },
			{ payload: { ...(verifiedPack().items[0].payload as JsonObject), unexpected: true } },
			{
				payload: {
					schema: "gjc-bugwatch-schema-meta/v1",
					id: 1,
					schemaMajor: 1,
					schemaMinor: 1,
					logSchemaVersion: 1,
					redactionVersion: 1,
					noiseVersion: 1,
					severityVersion: 1,
					fingerprintVersion: 1,
					fixtureManifestHash: hash,
					schemaCatalogHash: hash,
					createdAt: timestamp,
				},
			},
			{ payload: verifiedPack().items[0].payload as JsonObject, authorityId: "wrong" },
			{ payload: verifiedPack().items[0].payload as JsonObject, itemType: "roots" },
			{ payload: verifiedPack().items[0].payload as JsonObject, itemType: "upstream_cache" },
		];
		for (const vector of invalidPayloads) {
			const pack = verifiedPack(vector.payload, vector.authorityId, vector.itemType);
			expect(() =>
				verifyAuthoritySnapshotPackV2(pack.manifest, pack.items, keyrings, null, pack.frontierEvidence),
			).toThrow();
		}
	});

	it("rejects item omission, duplication, reordering, corruption, count, byte, digest, Merkle, predecessor, and keyring faults", () => {
		const pack = verifiedPack();
		const cases: Array<{ manifest?: JsonObject; items?: JsonObject[] }> = [
			{ items: [] },
			{ items: [pack.items[0], pack.items[0]] },
			{ items: [{ ...pack.items[0], index: 1 }] },
			{ items: [{ ...pack.items[0], payload: { version: 2 } }] },
			{ manifest: { ...pack.manifest, itemCount: 2 } },
			{ manifest: { ...pack.manifest, byteCount: 0 } },
			{
				manifest: {
					...pack.manifest,
					classes: pack.classes.map((entry, index) => (index === 0 ? { ...entry, classDigest: hash } : entry)),
				},
			},
			{
				manifest: {
					...pack.manifest,
					classes: pack.classes.map((entry, index) => (index === 0 ? { ...entry, itemsSha256: hash } : entry)),
				},
			},
			{ manifest: { ...pack.manifest, merkleRoot: hash } },
		];
		for (const entry of cases)
			expect(() =>
				verifyAuthoritySnapshotPackV2(
					entry.manifest ?? pack.manifest,
					entry.items ?? pack.items,
					keyrings,
					null,
					pack.frontierEvidence,
				),
			).toThrow();
		expect(() =>
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...keyrings, snapshot: undefined },
				null,
				pack.frontierEvidence,
			),
		).toThrow();
		expect(() =>
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...keyrings, fatal: undefined },
				null,
				pack.frontierEvidence,
			),
		).toThrow();
		expect(() =>
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{
					...keyrings,
					registry: { keyId: "registry", keyBytes: new Uint8Array([9]) },
				},
				null,
				pack.frontierEvidence,
			),
		).toThrow();
		const predecessor = signed(
			{ ...pack.manifest, previousSnapshotId: "previous", previousManifestHash: hash },
			"gjc-bugwatch-authority-snapshot-v2",
			snapshotKey,
		);
		expect(() =>
			verifyAuthoritySnapshotPackV2(predecessor, pack.items, keyrings, null, pack.frontierEvidence),
		).toThrow();
	});
	it("rejects schema table CHECK violations before graph reconstruction", () => {
		const invalidRows: Array<{ itemType: string; authorityId: string; payload: JsonObject }> = [
			{
				itemType: "producer_coverage",
				authorityId: "boot",
				payload: {
					boot_id: "boot",
					contiguous_through: 1,
					max_seen: 0,
					final_seq: 0,
					state: "open",
					updated_at_ms: 1,
				},
			},
			{
				itemType: "job_inputs",
				authorityId: "job",
				payload: {
					job_id: "job",
					root_id: "root",
					fingerprint_version: 1,
					fingerprint_hash: hash,
					revision: 0,
					policy_version: "policy",
					input_json: "{}",
					input_hash: sha256Hex("{}"),
					input_byte_count: 2,
					created_at_ms: 1,
				},
			},
			{
				itemType: "triage_results",
				authorityId: "result",
				payload: {
					result_id: "result",
					job_id: "job",
					attempt: 0,
					lease_token: "lease",
					result_kind: "draft",
					result_json: "{}",
					input_hash: hash,
					context_hash: null,
					evidence_hash: hash,
					output_hash: sha256Hex("{}"),
					output_byte_count: 2,
					upstream_sha: null,
					created_at_ms: 1,
				},
			},
			{
				itemType: "fingerprint_prefix_aliases",
				authorityId: "root",
				payload: {
					root_id: "root",
					fingerprint_version: 1,
					full_hash: hash,
					prefix_len: 7,
					prefix: "aaaaaaa",
					source: "generated",
					artifact_id: null,
				},
			},
			{
				itemType: "sources",
				authorityId: "segment",
				payload: {
					segment_id: "segment",
					generation: 0,
					source_kind: "log",
					path: "/log",
					file_identity_hint: "identity",
					prefix_anchor_length: -1,
					prefix_hash: hash,
					committed_offset: 0,
					boundary_hash: null,
					checkpoint_digest: hash,
					validation_state: "valid",
					state: "active",
					block_id: null,
					updated_at_ms: 1,
				},
			},
			{
				itemType: "attachment_transitions",
				authorityId: "attachment",
				payload: {
					attachment_id: "attachment",
					step_index: 0,
					transition_hash: hash,
					state: "prepared",
					previous_transition_hash: null,
					occurred_at_ms: 1,
					record_json: "{}",
					record_byte_count: 2,
					key_id: "",
					mac: hash,
				},
			},
			{
				itemType: "store_operation_members",
				authorityId: "operation",
				payload: {
					operation_id: "operation",
					member: "db",
					source_path_hash: hash,
					expected_presence: 1,
					expected_size: 1,
					expected_hash: hash,
					quarantine_path_hash: pendingContentHash,
					state: "intent_recorded",
					observed_source_hash: null,
					observed_quarantine_hash: null,
					step_json: "{ }",
					updated_at_ms: 1,
				},
			},
		];
		for (const row of invalidRows) {
			const pack = verifiedPack(undefined, undefined, undefined, [row]);
			expect(() =>
				verifyAuthoritySnapshotPackV2(pack.manifest, pack.items, keyrings, null, pack.frontierEvidence),
			).toThrow();
		}
	});
	it("reconstructs retained fatal boot, transport, final, and attachment authorities", () => {
		const retainedFatal = { keyId: "1".repeat(32), keyBytes: retainedFatalKey };
		const fatalCore = signed(
			{
				...bootCore(),
				fatalKeyId: retainedFatal.keyId,
				keyId: retainedFatal.keyId,
				mac: undefined,
			} as unknown as JsonObject,
			"gjc-bugwatch-boot-core-v1",
			retainedFatal.keyBytes,
		);
		delete fatalCore.mac;
		const core = signed(fatalCore, "gjc-bugwatch-boot-core-v1", retainedFatal.keyBytes);
		const coreHash = authenticatedHash(core);
		const transportStart = signed(
			{
				schema: "gjc-bugwatch-transport-start/v1",
				scopeId: "scope",
				bootId: "boot",
				bootCoreHash: coreHash,
				transportEpoch: 1,
				policyGeneration: 1,
				policyHash: hash,
				startSequence: "1",
				startedAt: timestamp,
				fileEnabled: true,
				keyId: retainedFatal.keyId,
				previousRecordHash: null,
			},
			"gjc-bugwatch-transport-start-v1",
			retainedFatal.keyBytes,
		);
		const transportClose = signed(
			{
				schema: "gjc-bugwatch-transport-close/v1",
				scopeId: "scope",
				bootId: "boot",
				bootCoreHash: coreHash,
				transportEpoch: 1,
				startRecordHash: authenticatedHash(transportStart),
				endSequenceInclusive: "1",
				endedAt: timestamp,
				outcome: "closed",
				keyId: retainedFatal.keyId,
				previousRecordHash: authenticatedHash(transportStart),
			},
			"gjc-bugwatch-transport-close-v1",
			retainedFatal.keyBytes,
		);
		const final = signed(
			{
				schema: "gjc-bugwatch-boot-final/v1",
				scopeId: "scope",
				bootId: "boot",
				bootCoreHash: coreHash,
				finalSequence: "1",
				endedAt: timestamp,
				state: "clean",
				lastTransportRecordHash: authenticatedHash(transportClose),
				attachmentSnapshotHash: hash,
				keyId: retainedFatal.keyId,
				previousRecordHash: authenticatedHash(transportClose),
			},
			"gjc-bugwatch-boot-final-v1",
			retainedFatal.keyBytes,
		);
		const root = signed(
			{
				schema: "gjc-bugwatch-root/v1",
				scopeId: "scope",
				rootId: "root",
				canonicalPath: "/root",
				enabled: true,
				persistContext: true,
				generation: 1,
				projectPolicyHash: hash,
				baselineEpochId: "baseline",
				activeMutationId: null,
				updatedAt: timestamp,
				nonce: "nonce",
				keyId: "registry",
			},
			"gjc-bugwatch-root-v1",
			registryKey,
		);
		const attachment = signed(
			{
				schema: "gjc-bugwatch-attachment/v1",
				scopeId: "scope",
				attachmentId: "attachment",
				attachmentTokenHash: hash,
				bootId: "boot",
				bootCoreHash: coreHash,
				rootId: "root",
				sessionId: null,
				startedAt: timestamp,
				endedAt: null,
				state: "prepared",
				managedSessionRoot: null,
				sessionFile: null,
				rootGeneration: 1,
				baselineEpochId: "baseline",
				publishSequence: null,
				retireSequence: null,
				keyId: retainedFatal.keyId,
			},
			"gjc-bugwatch-attachment-v1",
			retainedFatal.keyBytes,
		);
		const records: { itemType: string; authorityId: string; payload: JsonObject }[] = [
			{
				itemType: "roots",
				authorityId: "root",
				payload: {
					root_id: "root",
					kind: "project",
					canonical_path: "/root",
					enabled: 1,
					revision: 1,
					project_policy_hash: hash,
					registered_at_ms: 1,
					disabled_at_ms: null,
					persist_context: 1,
					baseline_epoch_id: "baseline",
					active_mutation_id: null,
					root_json: canonicalizeJson(root),
				},
			},
			{
				itemType: "producer_boots",
				authorityId: "boot",
				payload: {
					boot_id: "boot",
					scope_id: "scope",
					boot_core_hash: coreHash,
					pid: 1,
					pid_start_token: "token",
					producer: "daemon",
					started_at_ms: Date.parse(timestamp),
					initial_policy_generation: 1,
					initial_policy_hash: hash,
					fatal_key_id: retainedFatal.keyId,
					gjc_version: "1",
					build_sha: null,
					final_seq: 1,
					final_state: "clean",
					final_record_hash: authenticatedHash(final),
					boot_core_json: canonicalizeJson(core),
				},
			},
			{
				itemType: "boot_transport_records",
				authorityId: "boot",
				payload: {
					boot_id: "boot",
					transport_epoch: 1,
					record_kind: "start",
					record_hash: authenticatedHash(transportStart),
					start_record_hash: null,
					policy_generation: 1,
					policy_hash: hash,
					start_seq: 1,
					end_seq: null,
					file_enabled: 1,
					outcome: null,
					previous_record_hash: null,
					record_json: canonicalizeJson(transportStart),
					created_at_ms: Date.parse(timestamp),
				},
			},
			{
				itemType: "boot_transport_records",
				authorityId: "boot",
				payload: {
					boot_id: "boot",
					transport_epoch: 1,
					record_kind: "close",
					record_hash: authenticatedHash(transportClose),
					start_record_hash: authenticatedHash(transportStart),
					policy_generation: 1,
					policy_hash: hash,
					start_seq: null,
					end_seq: 1,
					file_enabled: null,
					outcome: "closed",
					previous_record_hash: authenticatedHash(transportStart),
					record_json: canonicalizeJson(transportClose),
					created_at_ms: Date.parse(timestamp),
				},
			},
			{
				itemType: "boot_final_records",
				authorityId: "boot",
				payload: {
					boot_id: "boot",
					record_hash: authenticatedHash(final),
					final_seq: 1,
					state: "clean",
					last_transport_record_hash: authenticatedHash(transportClose),
					attachment_snapshot_hash: hash,
					previous_record_hash: authenticatedHash(transportClose),
					record_json: canonicalizeJson(final),
					created_at_ms: Date.parse(timestamp),
				},
			},
			{
				itemType: "session_attachments",
				authorityId: "attachment",
				payload: {
					attachment_id: "attachment",
					scope_id: "scope",
					attachment_token_hash: hash,
					boot_id: "boot",
					boot_core_hash: coreHash,
					root_id: "root",
					session_id: null,
					started_at_ms: Date.parse(timestamp),
					ended_at_ms: null,
					state: "prepared",
					managed_session_root: null,
					session_file: null,
					root_generation: 1,
					baseline_epoch_id: "baseline",
					publish_seq: null,
					retire_seq: null,
					current_transition_hash: authenticatedHash(attachment),
					attachment_json: canonicalizeJson(attachment),
				},
			},
			{
				itemType: "attachment_transitions",
				authorityId: "attachment",
				payload: {
					attachment_id: "attachment",
					step_index: 0,
					transition_hash: authenticatedHash(attachment),
					state: "prepared",
					previous_transition_hash: null,
					occurred_at_ms: Date.parse(timestamp),
					record_json: canonicalizeJson(attachment),
					record_byte_count: Buffer.byteLength(canonicalizeJson(attachment)),
					key_id: retainedFatal.keyId,
					mac: attachment.mac,
				},
			},
		];
		const pack = verifiedPack(undefined, undefined, undefined, records);
		const retainedKeyrings = { ...keyrings, fatal: [keyrings.fatal, retainedFatal] };
		expect(
			verifyAuthoritySnapshotPackV2(pack.manifest, pack.items, retainedKeyrings, null, pack.frontierEvidence).items,
		).toHaveLength(10);
		expect(() =>
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...retainedKeyrings, fatal: [keyrings.fatal] },
				null,
				pack.frontierEvidence,
			),
		).toThrow(`authority_missing:fatal_keyring:${retainedFatal.keyId}`);
	});
	it("reconstructs retained registry store core and complete member-step chain", () => {
		const retainedRegistry = { keyId: "registry-old", keyBytes: retainedRegistryKey };
		const members = [
			{
				member: "db",
				sourcePathHash: "1".repeat(64),
				expectedPresence: true,
				expectedSize: 1,
				expectedHash: hash,
				quarantinePathHash: "4".repeat(64),
			},
			{
				member: "wal",
				sourcePathHash: "2".repeat(64),
				expectedPresence: false,
				expectedSize: null,
				expectedHash: null,
				quarantinePathHash: "5".repeat(64),
			},
			{
				member: "shm",
				sourcePathHash: "3".repeat(64),
				expectedPresence: false,
				expectedSize: null,
				expectedHash: null,
				quarantinePathHash: "6".repeat(64),
			},
		];
		const core = signed(
			{
				schema: "gjc-bugwatch-store-operation-core/v1",
				scopeId: "scope",
				operationId: "operation",
				ownerId: "owner",
				claimTokenHash: hash,
				kind: "migrate",
				fromVersion: 1,
				toVersion: 2,
				members,
				startedAt: timestamp,
				keyId: retainedRegistry.keyId,
			},
			"gjc-bugwatch-store-operation-core-v1",
			retainedRegistry.keyBytes,
		);
		const coreHash = authenticatedHash(core);
		const steps: JsonObject[] = [];
		for (const member of members)
			steps.push(
				signed(
					{
						schema: "gjc-bugwatch-store-operation-step/v1",
						scopeId: "scope",
						operationId: "operation",
						coreHash,
						stepIndex: steps.length,
						member: member.member,
						action: member.expectedPresence ? "move_intent" : "verified_absent",
						expectedSourceHash: member.expectedHash,
						observedDestinationHash: null,
						previousStepHash: steps.length === 0 ? null : authenticatedHash(steps[steps.length - 1]),
						occurredAt: timestamp,
						keyId: retainedRegistry.keyId,
					},
					"gjc-bugwatch-store-operation-step-v1",
					retainedRegistry.keyBytes,
				),
			);
		const records = [
			{
				itemType: "store_operations",
				authorityId: "operation",
				payload: {
					operation_id: "operation",
					owner_id: "owner",
					claim_token_hash: hash,
					kind: "migrate",
					from_version: 1,
					to_version: 2,
					phase: "prepared",
					core_hash: coreHash,
					current_step: 2,
					current_step_hash: authenticatedHash(steps[2]),
					backup_path: null,
					quarantine_path: null,
					watermark_hash: null,
					core_json: canonicalizeJson(core),
					started_at_ms: Date.parse(timestamp),
					updated_at_ms: Date.parse(timestamp),
				},
			},
			...members.map((member, index) => ({
				itemType: "store_operation_members",
				authorityId: "operation",
				payload: {
					operation_id: "operation",
					member: member.member,
					source_path_hash: member.sourcePathHash,
					expected_presence: member.expectedPresence ? 1 : 0,
					expected_size: member.expectedSize,
					expected_hash: member.expectedHash,
					quarantine_path_hash: member.quarantinePathHash,
					state: member.expectedPresence ? "intent_recorded" : "verified_absent",
					observed_source_hash: null,
					observed_quarantine_hash: null,
					step_json: canonicalizeJson(steps[index]),
					updated_at_ms: Date.parse(timestamp),
				},
			})),
		];
		const pack = verifiedPack(undefined, undefined, undefined, records);
		const retainedKeyrings = { ...keyrings, registry: [keyrings.registry, retainedRegistry] };
		expect(
			verifyAuthoritySnapshotPackV2(pack.manifest, pack.items, retainedKeyrings, null, pack.frontierEvidence).items,
		).toHaveLength(7);
		expect(() =>
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...retainedKeyrings, registry: [keyrings.registry] },
				null,
				pack.frontierEvidence,
			),
		).toThrow("authority_missing:registry_keyring:registry-old");
	});
	it("reconstructs retained rollback bundle, spool manifest, and acknowledgement authorities", () => {
		const retainedRollback = { keyId: "rollback-old", keyBytes: retainedRollbackKey };
		const bundle = signed(
			{
				schema: "gjc-bugwatch-rollback-bundle/v1",
				scopeId: "scope",
				epochId: "epoch",
				roleTransitionTokenHash: hash,
				bundleVersion: 1,
				state: "exported",
				manifestHash: hash,
				itemCount: 1,
				byteCount: 1,
				itemsDigest: hash,
				sourceWatermarkHash: hash,
				createdAt: timestamp,
				exportedAt: timestamp,
				keyId: retainedRollback.keyId,
			},
			"gjc-bugwatch-rollback-bundle-v1",
			retainedRollback.keyBytes,
		);
		const spool = signed(
			{
				schema: "gjc-bugwatch-rollback-spool-manifest/v1",
				scopeId: "scope",
				epochId: "epoch",
				segmentIndex: 0,
				state: "closed",
				itemCount: 1,
				byteCount: 1,
				itemsDigest: hash,
				previousManifestHash: null,
				closedAt: timestamp,
				keyId: retainedRollback.keyId,
			},
			"gjc-bugwatch-rollback-spool-manifest-v1",
			retainedRollback.keyBytes,
		);
		const ack = signed(
			{
				schema: "gjc-bugwatch-rollback-inbox-ack/v1",
				scopeId: "scope",
				epochId: "epoch",
				slot: 0,
				slotGeneration: 1,
				eventId: hash,
				segmentIndex: 0,
				spoolItemHash: hash,
				acknowledgedAt: timestamp,
				keyId: retainedRollback.keyId,
			},
			"gjc-bugwatch-rollback-inbox-ack-v1",
			retainedRollback.keyBytes,
		);
		const itemPayload = rollbackRootPayload();
		const itemWithoutHash: JsonObject = {
			schema: "gjc-bugwatch-rollback-bundle-item/v1",
			scopeId: "scope",
			epochId: "epoch",
			itemIndex: 0,
			itemType: "root",
			payload: itemPayload,
			payloadHash: authenticatedHash(itemPayload),
			previousItemHash: null,
			createdAt: timestamp,
			keyId: retainedRollback.keyId,
		};
		const item = signed(
			{ ...itemWithoutHash, itemHash: authenticatedHash(itemWithoutHash) },
			"gjc-bugwatch-rollback-bundle-item-v1",
			retainedRollback.keyBytes,
		);
		const payloadBytes = Buffer.from(canonicalizeJson(itemPayload));
		const payloadBlob = `base64:${payloadBytes.toString("base64")}`;
		const records: { itemType: string; authorityId: string; payload: JsonObject }[] = [
			{
				itemType: "rollback_epochs",
				authorityId: "epoch",
				payload: {
					epoch_id: "epoch",
					scope_id: "scope",
					role_transition_token: "token",
					bundle_version: 1,
					state: "exported",
					manifest_hash: hash,
					limits_json: "{}",
					bundle_json: canonicalizeJson(bundle),
					spool_manifest_json: canonicalizeJson(spool),
					inbox_ack_json: canonicalizeJson(ack),
					created_at_ms: Date.parse(timestamp),
					exported_at_ms: Date.parse(timestamp),
					released_at_ms: null,
					completed_at_ms: null,
				},
			},
			{
				itemType: "rollback_items",
				authorityId: "epoch",
				payload: {
					epoch_id: "epoch",
					item_index: 0,
					item_type: "root",
					item_hash: item.itemHash,
					payload_hash: item.payloadHash,
					payload_byte_count: payloadBytes.byteLength,
					state: "pending",
					payload: payloadBlob,
					item_schema: "gjc-bugwatch-rollback-bundle-item/v1",
					key_id: retainedRollback.keyId,
					mac: item.mac,
					item_json: canonicalizeJson(item),
				},
			},
		];
		const pack = verifiedPack(undefined, undefined, undefined, records);
		const retainedKeyrings = { ...keyrings, rollback: [keyrings.rollback, retainedRollback] };
		expect(
			verifyAuthoritySnapshotPackV2(pack.manifest, pack.items, retainedKeyrings, null, pack.frontierEvidence).items,
		).toHaveLength(5);
		expect(() =>
			verifyAuthoritySnapshotPackV2(
				pack.manifest,
				pack.items,
				{ ...retainedKeyrings, rollback: [keyrings.rollback] },
				null,
				pack.frontierEvidence,
			),
		).toThrow("authority_missing:rollback_keyring:rollback-old");
	});
	it("accepts authenticated external replay evidence without forbidden snapshot items and rejects each replay family tampering", () => {
		const pack = verifiedPack();
		const retainedFatal = { keyId: "fatal-old", keyBytes: retainedFatalKey };
		const retainedRegistry = { keyId: "registry-old", keyBytes: retainedRegistryKey };
		const retainedRollback = { keyId: "rollback-old", keyBytes: retainedRollbackKey };
		const retainedKeyrings = {
			...keyrings,
			fatal: [keyrings.fatal, retainedFatal],
			registry: [keyrings.registry, retainedRegistry],
			rollback: [keyrings.rollback, retainedRollback],
		};
		const replayRecord = (
			kind: "registry" | "inbox" | "emergency" | "rollback" | "artifact",
			fields: JsonObject,
			keyId: string,
			key: Uint8Array,
		): SnapshotFrontierRecordV1 => {
			const domain = `gjc-bugwatch-external-replay-${kind}-v1`;
			const unsigned = {
				sequence: 0,
				schema: "gjc-bugwatch-external-replay-record/v1",
				domain,
				kind,
				...fields,
				occurredAt: timestamp,
				previousRecordHash: null,
				keyId,
			};
			return signed(
				{ ...unsigned, recordHash: sha256Hex(canonicalizeJson(unsigned)) },
				domain,
				key,
			) as unknown as SnapshotFrontierRecordV1;
		};
		const evidence = structuredClone(pack.frontierEvidence);
		evidence.registryFrontiers.entries = [
			{
				bootId: "boot",
				transportEpoch: 1,
				records: [
					replayRecord(
						"registry",
						{
							itemType: "attachment_transitions",
							authorityId: "attachment",
							payloadHash: hash,
							bootId: "boot",
							transportEpoch: 1,
							attachmentId: "attachment",
							transitionStep: 0,
						},
						retainedRegistry.keyId,
						retainedRegistry.keyBytes,
					),
				],
			},
		];
		evidence.inboxFrontier.entries = [
			{
				slot: 1,
				slotGeneration: 1,
				records: [
					replayRecord(
						"inbox",
						{
							itemType: "inbox_emergency_replay",
							authorityId: "inbox",
							payloadHash: hash,
							slot: 1,
							slotGeneration: 1,
						},
						retainedFatal.keyId,
						retainedFatal.keyBytes,
					),
				],
			},
		];
		evidence.emergencyFrontier.entries = [
			{
				logicalSlot: 1,
				page: 1,
				pageGeneration: 1,
				records: [
					replayRecord(
						"emergency",
						{
							itemType: "inbox_emergency_replay",
							authorityId: "emergency",
							payloadHash: hash,
							logicalSlot: 1,
							page: 1,
							pageGeneration: 1,
						},
						retainedFatal.keyId,
						retainedFatal.keyBytes,
					),
				],
			},
		];
		evidence.rollbackSpoolFrontier.entries = [
			{
				epochId: "epoch",
				segmentIndex: 1,
				records: [
					replayRecord(
						"rollback",
						{
							itemType: "rollback_spool_replay",
							authorityId: "epoch",
							payloadHash: hash,
							epochId: "epoch",
							segmentIndex: 1,
						},
						retainedRollback.keyId,
						retainedRollback.keyBytes,
					),
				],
			},
		];
		evidence.artifactFrontier.entries = [
			{
				artifactId: "artifact",
				outboxSequence: "1",
				records: [
					replayRecord(
						"artifact",
						{
							itemType: "artifact_outbox",
							authorityId: "artifact",
							payloadHash: hash,
							artifactId: "artifact",
							outboxSequence: "1",
						},
						"snapshot",
						snapshotKey,
					),
				],
			},
		];
		const resealed = (candidate: AuthoritySnapshotFrontierEvidenceV1): JsonObject => {
			const cutoff = {
				...(pack.manifest.cutoff as JsonObject),
				registryFrontiersHash: sha256Hex(canonicalizeJson(candidate.registryFrontiers as unknown as JsonValue)),
				inboxFrontierHash: sha256Hex(canonicalizeJson(candidate.inboxFrontier as unknown as JsonValue)),
				emergencyFrontierHash: sha256Hex(canonicalizeJson(candidate.emergencyFrontier as unknown as JsonValue)),
				rollbackSpoolFrontierHash: sha256Hex(
					canonicalizeJson(candidate.rollbackSpoolFrontier as unknown as JsonValue),
				),
				artifactFrontierHash: sha256Hex(canonicalizeJson(candidate.artifactFrontier as unknown as JsonValue)),
			};
			return signed({ ...pack.manifest, cutoff }, "gjc-bugwatch-authority-snapshot-v2", snapshotKey);
		};
		expect(
			verifyAuthoritySnapshotPackV2(resealed(evidence), pack.items, retainedKeyrings, null, evidence).items,
		).toHaveLength(3);
		const frontiers = [
			"registryFrontiers",
			"inboxFrontier",
			"emergencyFrontier",
			"rollbackSpoolFrontier",
			"artifactFrontier",
		] as const;
		for (const frontier of frontiers) {
			const wrongKey = structuredClone(evidence);
			(wrongKey[frontier].entries[0].records[0] as { keyId: string; mac: string }).keyId = "wrong";
			expect(() =>
				verifyAuthoritySnapshotPackV2(resealed(wrongKey), pack.items, retainedKeyrings, null, wrongKey),
			).toThrow();
			const wrongMac = structuredClone(evidence);
			(wrongMac[frontier].entries[0].records[0] as { keyId: string; mac: string }).mac = hash;
			expect(() =>
				verifyAuthoritySnapshotPackV2(resealed(wrongMac), pack.items, retainedKeyrings, null, wrongMac),
			).toThrow();
			const compositeMismatch = structuredClone(evidence);
			if (frontier === "registryFrontiers") compositeMismatch[frontier].entries[0].bootId = "other";
			else if (frontier === "inboxFrontier") compositeMismatch[frontier].entries[0].slot = 2;
			else if (frontier === "emergencyFrontier") compositeMismatch[frontier].entries[0].page = 2;
			else if (frontier === "rollbackSpoolFrontier") compositeMismatch[frontier].entries[0].segmentIndex = 2;
			else compositeMismatch[frontier].entries[0].artifactId = "other";
			expect(() =>
				verifyAuthoritySnapshotPackV2(
					resealed(compositeMismatch),
					pack.items,
					retainedKeyrings,
					null,
					compositeMismatch,
				),
			).toThrow();
			const gap = structuredClone(evidence);
			gap[frontier].entries[0].records[0].sequence = 1;
			expect(() => verifyAuthoritySnapshotPackV2(resealed(gap), pack.items, retainedKeyrings, null, gap)).toThrow();
		}
		for (const [expected, keyring] of [
			["authority_missing:inbox_replay_key:fatal-old", { ...retainedKeyrings, fatal: [keyrings.fatal] }],
			["authority_missing:registry_replay_key:registry-old", { ...retainedKeyrings, registry: [keyrings.registry] }],
			["authority_missing:rollback_replay_key:rollback-old", { ...retainedKeyrings, rollback: [keyrings.rollback] }],
		] as const)
			expect(() => verifyAuthoritySnapshotPackV2(resealed(evidence), pack.items, keyring, null, evidence)).toThrow(
				expected,
			);
	});
});
