import { describe, expect, it } from "bun:test";
import {
	AUTHORITY_CLASS_NAMES,
	AUTHORITY_SNAPSHOT_POLICY,
	authenticatedHash,
	BUGWATCH_CONTRACT_VERSION,
	BUGWATCH_FINGERPRINT_VERSION,
	BUGWATCH_FIXTURE_MANIFEST_HASH,
	BUGWATCH_LOG_SCHEMA_VERSION,
	BUGWATCH_NOISE_VERSION,
	BUGWATCH_REDACTION_VERSION,
	BUGWATCH_SCHEMA_CATALOG_HASH,
	BUGWATCH_SCHEMA_MAJOR,
	BUGWATCH_SCHEMA_MINOR,
	BUGWATCH_SEVERITY_VERSION,
	type BugwatchSignalAuthorityV1,
	CONTEXT_CUMULATIVE_BYTES_PER_JOB,
	canonicalizeBugwatchFixtureManifestIdentity,
	classifyBugwatchNoise,
	classifyBugwatchSeverity,
	createPolicySemanticV1,
	EMERGENCY_FILE_BYTES,
	EMERGENCY_LOGICAL_SLOTS,
	EMERGENCY_PAGE_BYTES,
	EMERGENCY_PAGES_PER_LOGICAL_SLOT,
	fingerprintBugwatchSignal,
	INBOX_ENVELOPE_BYTES,
	INBOX_PROBES,
	INBOX_SLOTS,
	isBugwatchTextRedacted,
	type JsonValue,
	MAX_GAP_SPAN,
	MAX_RANGES_PER_BOOT,
	parseBootTransportStartV1,
	parseLeaseV1,
	parseMonitorDisableActionV1,
	parseRollbackBundleItemV1,
	parseSourceAuthorityV1,
	parseSourceCheckpointV1,
	policyContentHash,
	redactBugwatchText,
	SNAPSHOT_PAYLOAD_FIELD_SETS,
	SNAPSHOT_PAYLOAD_VALIDATORS,
	type SnapshotPayloadClassV1,
	sha256Hex,
} from "@gajae-code/utils/bugwatch-contract";
import fixture from "./fixtures/bugwatch-contract-v1.json" with { type: "json" };

const hash = "0".repeat(64);
const timestamp = "2026-01-02T03:04:05.000Z";
const SNAPSHOT_PAYLOAD_CLASSES = [
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

describe("bugwatch Phase-0 plan compliance", () => {
	it("freezes default-off semantics, manifest, and versioned signal vectors", () => {
		const policy = createPolicySemanticV1("scope-fixture");
		expect(policy.daemon.enabled).toBe(false);
		expect(policyContentHash(policy)).toBe(fixture.expected.defaultSemanticHash);
		expect(fixture.compatibility.contractVersion).toBe(BUGWATCH_CONTRACT_VERSION);
		expect(fixture.compatibility.schemaMajor).toBe(BUGWATCH_SCHEMA_MAJOR);
		expect(fixture.compatibility.schemaMinor).toBe(BUGWATCH_SCHEMA_MINOR);
		expect(fixture.compatibility.schemaCatalogHash).toBe(BUGWATCH_SCHEMA_CATALOG_HASH);
		expect(fixture.compatibility.logSchemaVersion).toBe(BUGWATCH_LOG_SCHEMA_VERSION);
		expect(fixture.compatibility.redactionVersion).toBe(BUGWATCH_REDACTION_VERSION);
		expect(fixture.compatibility.noiseVersion).toBe(BUGWATCH_NOISE_VERSION);
		expect(fixture.compatibility.severityVersion).toBe(BUGWATCH_SEVERITY_VERSION);
		expect(fixture.compatibility.fingerprintVersion).toBe(BUGWATCH_FINGERPRINT_VERSION);
		expect(fixture.compatibility.maxRangesPerBoot).toBe(MAX_RANGES_PER_BOOT);
		expect(fixture.compatibility.maxGapSpan).toBe(MAX_GAP_SPAN);
		expect(fixture.compatibility.inboxSlots).toBe(INBOX_SLOTS);
		expect(fixture.compatibility.inboxEnvelopeBytes).toBe(INBOX_ENVELOPE_BYTES);
		expect(fixture.compatibility.inboxProbes).toBe(INBOX_PROBES);
		expect(fixture.compatibility.contextCumulativeBytesPerJob).toBe(CONTEXT_CUMULATIVE_BYTES_PER_JOB);
		expect(fixture.compatibility.emergencyFileBytes).toBe(EMERGENCY_FILE_BYTES);
		expect(fixture.compatibility.emergencyPageBytes).toBe(EMERGENCY_PAGE_BYTES);
		expect(fixture.compatibility.emergencyLogicalSlots).toBe(EMERGENCY_LOGICAL_SLOTS);
		expect(fixture.compatibility.emergencyPagesPerLogicalSlot).toBe(EMERGENCY_PAGES_PER_LOGICAL_SLOT);
		expect(sha256Hex(canonicalizeBugwatchFixtureManifestIdentity(fixture as unknown as JsonValue))).toBe(
			BUGWATCH_FIXTURE_MANIFEST_HASH,
		);
		expect(redactBugwatchText(fixture.vectors.redaction.input)).toBe(fixture.vectors.redaction.output);
		{
			const identity = (value: JsonValue): string => sha256Hex(canonicalizeBugwatchFixtureManifestIdentity(value));
			const base = fixture as unknown as JsonValue;
			const typed = structuredClone(fixture) as unknown as {
				envelopes: {
					snapshot: {
						classes: Array<{ className: string }>;
						merkleRoot: string;
					};
					snapshotItems: Array<{ payload: { id?: number }; mac: string }>;
					snapshotFrontierEvidence: {
						sourceWatermarks: {
							entries: Array<{ committedOffset: number }>;
						};
					};
				};
			};

			const classMutation = structuredClone(typed);
			classMutation.envelopes.snapshot.classes[0].className = "roots";
			expect(identity(classMutation as unknown as JsonValue)).not.toBe(identity(base));

			const payloadMutation = structuredClone(typed);
			payloadMutation.envelopes.snapshotItems[0].payload.id = 2;
			expect(identity(payloadMutation as unknown as JsonValue)).not.toBe(identity(base));

			const frontierMutation = structuredClone(typed);
			frontierMutation.envelopes.snapshotFrontierEvidence.sourceWatermarks.entries[0].committedOffset = 101;
			expect(identity(frontierMutation as unknown as JsonValue)).not.toBe(identity(base));

			const derivedMutation = structuredClone(typed);
			derivedMutation.envelopes.snapshot.merkleRoot = hash;
			derivedMutation.envelopes.snapshotItems[0].mac = hash;
			expect(identity(derivedMutation as unknown as JsonValue)).toBe(identity(base));
		}
		for (const vector of fixture.vectors.redactionAdversarial) {
			const redacted = redactBugwatchText(vector.input);
			expect(redacted).toBe(vector.output);
			expect(isBugwatchTextRedacted(vector.input)).toBe(false);
			expect(isBugwatchTextRedacted(redacted)).toBe(true);
		}
		expect(
			fingerprintBugwatchSignal(
				fixture.vectors.fingerprint.category,
				fixture.vectors.fingerprint.message,
				fixture.vectors.fingerprint.stack,
			),
		).toBe(fixture.vectors.fingerprint.hash);
		for (const vector of fixture.vectors.fingerprintCollisions) {
			const fingerprint = fingerprintBugwatchSignal(vector.category, vector.message, vector.stack);
			expect(fingerprint).toBe(vector.hash);
			expect(fingerprint === fixture.vectors.fingerprint.hash).toBe(vector.relation === "same");
		}
		expect(classifyBugwatchNoise("debug heartbeat")).toBe("signal");
		for (const vector of fixture.vectors.noise)
			expect(classifyBugwatchNoise(vector.input)).toBe(vector.output as "noise" | "signal");
		expect(
			classifyBugwatchSeverity({
				category: "warn",
				hook: null,
				level: "warn",
				message: "token refresh failed",
				stackTop: null,
			}),
		).toBe("low");
		for (const vector of fixture.vectors.severity)
			expect(classifyBugwatchSeverity(vector.authority as BugwatchSignalAuthorityV1)).toBe(
				vector.output as "diagnostic" | "fatal" | "high" | "low" | "medium",
			);
	});

	it("rejects incompatible lease, signal cross-pairs, and DDL boundary violations", () => {
		const lease = fixture.envelopes.lease;
		expect(parseLeaseV1(lease).phase).toBe("published");
		for (const invalid of [{ protocolMajor: 0 }, { storeMax: 0 }, { phase: "dead" }])
			expect(() => parseLeaseV1({ ...lease, ...invalid })).toThrow();
		const action = fixture.envelopes.monitorAction;
		const parsedAction = parseMonitorDisableActionV1(action);
		expect(parsedAction.kind).toBe("process");
		if (parsedAction.kind !== "process") throw new Error("fixture action must be a process action");
		expect(parsedAction.signal).toBe("TERM");
		expect(() => parseMonitorDisableActionV1({ ...action, signal: "KILL" })).toThrow();
		const transport = {
			schema: "gjc-bugwatch-transport-start/v1",
			scopeId: "scope",
			bootId: "boot",
			bootCoreHash: hash,
			transportEpoch: 1,
			policyGeneration: 1,
			policyHash: hash,
			startSequence: "1",
			startedAt: timestamp,
			fileEnabled: false,
			keyId: "key",
			previousRecordHash: null,
			mac: hash,
		};
		expect(() => parseBootTransportStartV1({ ...transport, transportEpoch: 0 })).toThrow();
		const checkpoint = {
			schema: "gjc-bugwatch-source-checkpoint/v1",
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
		};
		expect(() => parseSourceCheckpointV1({ ...checkpoint, endOffset: 0 })).toThrow();
		const source = {
			schema: "gjc-bugwatch-source/v1",
			scopeId: "scope",
			segmentId: "segment",
			generation: 0,
			sourceKind: "log",
			pathHash: hash,
			fileIdentityHint: "identity",
			prefixAnchorLength: 0,
			prefixHash: hash,
			committedOffset: 0,
			boundaryHash: null,
			checkpointDigest: hash,
			state: "active",
			updatedAt: timestamp,
			keyId: "key",
			mac: hash,
		};
		expect(parseSourceAuthorityV1(source).generation).toBe(0);
		for (const generation of [-1, 0.5]) expect(() => parseSourceAuthorityV1({ ...source, generation })).toThrow();
		const rollbackPayload = {
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
		};
		const rollbackItemWithoutHash = {
			schema: "gjc-bugwatch-rollback-bundle-item/v1",
			scopeId: "scope",
			epochId: "epoch",
			itemIndex: 0,
			itemType: "root",
			payload: rollbackPayload,
			payloadHash: authenticatedHash(rollbackPayload),
			previousItemHash: null,
			createdAt: timestamp,
			keyId: "key",
		};
		expect(
			parseRollbackBundleItemV1({
				...rollbackItemWithoutHash,
				itemHash: authenticatedHash(rollbackItemWithoutHash),
				mac: hash,
			}).previousItemHash,
		).toBeNull();
	});

	it("publishes the exhaustive canonical authority class policy", () => {
		expect(Object.keys(AUTHORITY_SNAPSHOT_POLICY)).toEqual([...AUTHORITY_CLASS_NAMES]);
		expect(AUTHORITY_SNAPSHOT_POLICY.roots.mode).toBe("payload");
		expect(AUTHORITY_SNAPSHOT_POLICY.sqlite_wal_shm.mode).toBe("excluded_safe");
		expect(authenticatedHash(fixture.envelopes.monitorAction)).toHaveLength(64);
		expect(AUTHORITY_SNAPSHOT_POLICY.upstream_cache.mode).toBe("excluded_safe");
		expect(AUTHORITY_SNAPSHOT_POLICY.daemon_runs.mode).toBe("excluded_safe");
		expect(AUTHORITY_SNAPSHOT_POLICY.authority_snapshot_packs.mode).toBe("external_replay");
		expect(AUTHORITY_SNAPSHOT_POLICY.authority_snapshot_items.mode).toBe("external_replay");
		expect(AUTHORITY_SNAPSHOT_POLICY.store_operation_journal.mode).toBe("external_replay");
		expect(AUTHORITY_SNAPSHOT_POLICY.source_archive_replay.mode).toBe("external_replay");
		expect(AUTHORITY_SNAPSHOT_POLICY.inbox_emergency_replay.mode).toBe("external_replay");
		expect(AUTHORITY_SNAPSHOT_POLICY.rollback_spool_replay.mode).toBe("external_replay");
		expect(AUTHORITY_SNAPSHOT_POLICY.registry_replay.mode).toBe("external_replay");
		expect(AUTHORITY_CLASS_NAMES).toContain("root_mutation_steps");
		const payloadClasses = AUTHORITY_CLASS_NAMES.filter(
			(className): className is SnapshotPayloadClassV1 => AUTHORITY_SNAPSHOT_POLICY[className].mode === "payload",
		);
		expect(payloadClasses).toEqual([...SNAPSHOT_PAYLOAD_CLASSES]);
		const registeredClasses = Object.keys(SNAPSHOT_PAYLOAD_VALIDATORS).sort();
		const expectedClasses: string[] = [...SNAPSHOT_PAYLOAD_CLASSES].sort();
		expect(
			registeredClasses,
			`payload validator coverage mismatch; missing: ${expectedClasses.filter(className => !registeredClasses.includes(className)).join(", ") || "none"}; unexpected: ${registeredClasses.filter(className => !expectedClasses.includes(className)).join(", ") || "none"}`,
		).toEqual(expectedClasses);
	});
	it("keeps the schema-1.6 row inventory aligned with the closed validator registry", () => {
		const schema16Inventory = {
			attachment_transitions:
				"attachment_id step_index transition_hash state previous_transition_hash occurred_at_ms record_json record_byte_count key_id mac",
			legacy_disable_receipts: "receipt_id root_id receipt_hash payload payload_json created_at_ms",
			store_operation_members:
				"operation_id member source_path_hash expected_presence expected_size expected_hash quarantine_path_hash state observed_source_hash observed_quarantine_hash step_json updated_at_ms",
			import_epochs:
				"epoch_id root_id kind source_path_hash source_content_hash byte_count item_count state started_at_ms completed_at_ms",
		} as const;
		for (const [className, columns] of Object.entries(schema16Inventory)) {
			expect(SNAPSHOT_PAYLOAD_FIELD_SETS[className as SnapshotPayloadClassV1]).toEqual(columns.split(" "));
			expect(SNAPSHOT_PAYLOAD_VALIDATORS[className as SnapshotPayloadClassV1]).toBeDefined();
		}
		expect(SNAPSHOT_PAYLOAD_FIELD_SETS.attachment_transitions).toContain("key_id");
		expect(SNAPSHOT_PAYLOAD_FIELD_SETS.attachment_transitions).toContain("mac");
	});
});
