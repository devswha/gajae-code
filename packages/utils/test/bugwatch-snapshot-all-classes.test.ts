import { describe, expect, it } from "bun:test";
import {
	type AuthoritySnapshotItemV1,
	authenticatedHash,
	canonicalizeJson,
	hmacSha256Hex,
	type JsonValue,
	macPayload,
	SNAPSHOT_PAYLOAD_CLASSES,
	SNAPSHOT_PAYLOAD_FIELD_SETS,
	SNAPSHOT_PAYLOAD_ROW_SPECS,
	SNAPSHOT_PAYLOAD_VALIDATORS,
	SNAPSHOT_ROW_AUTHORITY_COLUMNS,
	type SnapshotColumnTypeV1,
	type SnapshotPayloadClassV1,
	type SnapshotPayloadGraphV1,
	sha256Hex,
	validateSnapshotGraph,
	validateSnapshotPayload,
} from "@gajae-code/utils/bugwatch-contract";
import fixture from "./fixtures/bugwatch-contract-v1.json";

type Row = Record<string, JsonValue>;

type Factory = () => Row;

const hash = "a".repeat(64);
const otherHash = "b".repeat(64);
const thirdHash = "c".repeat(64);
const fourthHash = "d".repeat(64);
const fifthHash = "e".repeat(64);
const sixthHash = "f".repeat(64);
const timestamp = Date.parse("2026-01-02T03:04:05.000Z");
const timestampIso = "2026-01-02T03:04:05.000Z";
const blob = "base64:AA==";
const canonicalJson = "{}";
const fixtureKey = new TextEncoder().encode("bugwatch-fixture-mac-key");

const enumValue: Readonly<Record<string, string>> = {
	kind: "project",
	action: "move",
	phase: "prepared",
	target: "old_root",
	precondition: "missing",
	pending_state: "prepared",
	final_state: "prepared",
	producer: "daemon",
	record_kind: "start",
	state: "active",
	lineage_kind: "full",
	disposition: "candidate",
	reason: "candidate",
	severity: "low",
	category: "error",
	policy_state: "open",
	projection_kind: "index",
	artifact_kind: "draft",
	ownership: "manual",
	source: "generated",
	source_kind: "log",
	validation_state: "valid",
	root_relation: "attached",
	coverage_status: "covered",
	coverage_kind: "explicit",
	result_kind: "draft",
	result: "disabled",
	adapter_kind: "process",
	action_kind: "process",
	item_type: "root",
	item_schema: "gjc-bugwatch-rollback-bundle-item/v1",
	member: "db",
	lifecycle: "pending",
};

function identifier(field: string): string {
	if (field === "scope_id") return "scope-fixture";
	if (field === "root_id" || field === "old_root_id" || field === "new_root_id" || field === "claimed_root_id")
		return "root-fixture";
	if (field === "boot_id" || field === "claimed_boot_id") return "boot-fixture";
	if (field === "attachment_id" || field === "claimed_attachment_id") return "attachment-fixture";
	if (field === "mutation_id" || field === "active_mutation_id") return "mutation";
	if (field === "segment_id") return "segment";
	if (field === "epoch_id" || field === "inventory_epoch_id" || field === "import_epoch_id") return "epoch";
	if (field === "job_id") return "job";
	if (field === "result_id") return "result";
	if (field === "operation_id") return "operation";
	if (field === "authorization_id") return "authorization";
	if (field === "receipt_id") return "receipt";
	if (field === "artifact_id") return "artifact";
	if (field === "outbox_id") return "outbox";
	if (field === "context_id") return "context";
	if (field === "quarantine_id") return "quarantine";
	if (field === "block_id") return "block";
	if (field === "event_id" || field === "sample_event_id" || field === "claimed_event_id") return "event";
	if (field === "fingerprint_version") return "v1";
	if (field === "schema_catalog_hash" || field.endsWith("_hash") || field.endsWith("_digest") || field === "hash")
		return hash;
	if (field.endsWith("_json")) return canonicalJson;
	if (field === "payload" || field === "content") return blob;
	return field;
}

function scalar(field: string, type: SnapshotColumnTypeV1): JsonValue {
	if (type === "nullable_text" || type === "nullable_integer" || type === "nullable_boolean") return null;
	if (type === "boolean") return 1;
	if (type === "integer") {
		if (field === "id") return 1;
		if (field.includes("byte_count")) return field === "content_byte_count" ? 1 : 2;
		if (field === "end_offset" || field === "end_seq" || field === "max_attempts" || field === "revision") return 1;
		return timestamp;
	}
	return enumValue[field] ?? identifier(field);
}
function signed(domain: string, unsigned: Row): Row {
	return { ...unsigned, mac: hmacSha256Hex(fixtureKey, domain, macPayload(unsigned)) };
}

function canonicalEnvelope(envelope: Row): string {
	return canonicalizeJson(envelope);
}

function rootMutationCore(): Row {
	return signed("gjc-bugwatch-root-mutation-core-v1", {
		schema: "gjc-bugwatch-root-mutation-core/v1",
		scopeId: "scope-fixture",
		mutationId: "mutation",
		action: "set_context",
		expectedPolicyGeneration: 1,
		expectedPolicyHash: hash,
		oldRootId: "root-fixture",
		newRootId: "root-fixture",
		outputs: [
			{
				target: "new_root",
				pathHash: hash,
				precondition: "present",
				expectedOldContentHash: hash,
				pendingContentHash: hash,
				finalContentHash: otherHash,
				desiredRootGeneration: 1,
				publicationOrder: 1,
			},
		],
		createdAt: timestampIso,
		actorPid: 1,
		actorPidStartToken: "pid_start_token",
		keyId: "fixture-registry",
	});
}

function rootMutationState(coreHash: string): Row {
	return signed("gjc-bugwatch-root-mutation-db-state-v1", {
		schema: "gjc-bugwatch-root-mutation-db-state/v1",
		scopeId: "scope-fixture",
		mutationId: "mutation",
		coreHash,
		phase: "prepared",
		previousPhase: null,
		previousStateHash: null,
		keyId: "fixture-registry",
	});
}

function rootRenameSteps(coreHash: string): Row[] {
	const entries = [
		["pending", "rename_intent"],
		["pending", "rename_complete"],
		["final", "rename_intent"],
		["final", "rename_complete"],
	] as const;
	const steps: Row[] = [];
	for (const [lifecycle, action] of entries) {
		const desiredDestinationHash = lifecycle === "pending" ? hash : otherHash;
		steps.push(
			signed("gjc-bugwatch-root-rename-step-v2", {
				schema: "gjc-bugwatch-root-rename-step/v2",
				scopeId: "scope-fixture",
				mutationId: "mutation",
				coreHash,
				stepIndex: steps.length,
				target: "new_root",
				lifecycle,
				action,
				expectedDestinationHash: hash,
				sourceTempHash: desiredDestinationHash,
				desiredDestinationHash,
				observedDestinationHash: action === "rename_complete" ? desiredDestinationHash : null,
				previousStepHash: steps.length === 0 ? null : authenticatedHash(steps[steps.length - 1]),
				occurredAt: timestampIso,
				keyId: "fixture-registry",
			}),
		);
	}
	return steps;
}

function rootRenameStep(coreHash: string): Row {
	return rootRenameSteps(coreHash)[0];
}
function secondaryRoot(): Row {
	return signed("gjc-bugwatch-root-v1", {
		schema: "gjc-bugwatch-root/v1",
		scopeId: "scope-fixture",
		rootId: "root-secondary",
		canonicalPath: "/tmp/secondary",
		enabled: true,
		persistContext: true,
		generation: 1,
		projectPolicyHash: hash,
		baselineEpochId: null,
		activeMutationId: null,
		updatedAt: timestampIso,
		nonce: "secondary-nonce",
		keyId: "fixture-registry",
	});
}
function bootTransport(): Row {
	const core = fixture.envelopes.boot as unknown as Row;
	return signed("gjc-bugwatch-transport-start-v1", {
		schema: "gjc-bugwatch-transport-start/v1",
		scopeId: "scope-fixture",
		bootId: "boot-fixture",
		bootCoreHash: authenticatedHash(core),
		transportEpoch: 1,
		policyGeneration: 1,
		policyHash: hash,
		startSequence: "1",
		startedAt: timestampIso,
		fileEnabled: true,
		keyId: "0123456789abcdef0123456789abcdef",
		previousRecordHash: null,
	});
}

function bootFinal(): Row {
	const core = fixture.envelopes.boot as unknown as Row;
	const transport = bootTransport();
	return signed("gjc-bugwatch-boot-final-v1", {
		schema: "gjc-bugwatch-boot-final/v1",
		scopeId: "scope-fixture",
		bootId: "boot-fixture",
		bootCoreHash: authenticatedHash(core),
		finalSequence: "1",
		endedAt: timestampIso,
		state: "clean",
		lastTransportRecordHash: authenticatedHash(transport),
		attachmentSnapshotHash: hash,
		keyId: "0123456789abcdef0123456789abcdef",
		previousRecordHash: authenticatedHash(transport),
	});
}

function monitorInventory(): Row {
	return signed("gjc-bugwatch-monitor-inventory-v1", {
		schema: "gjc-bugwatch-monitor-inventory/v1",
		scopeId: "scope-fixture",
		inventoryEpochId: "epoch",
		monitorId: "monitor_id",
		kind: "process",
		stableIdentifier: "stable_identifier",
		configHash: hash,
		coveredRootIds: ["root-fixture"],
		status: "active",
		observedAt: timestampIso,
		adapterEvidenceHash: hash,
		keyId: "fixture-registry",
	});
}

function monitorAuthorization(): Row {
	return signed("gjc-bugwatch-monitor-disable-auth-v1", {
		schema: "gjc-bugwatch-monitor-disable-auth/v1",
		scopeId: "scope-fixture",
		authorizationId: "authorization",
		inventoryEpochId: "epoch",
		monitorId: "monitor_id",
		adapterKind: "process",
		stableIdentifier: "stable_identifier",
		expectedConfigHash: hash,
		allowedAction: fixture.envelopes.monitorAction as JsonValue,
		authorizedAt: timestampIso,
		expiresAt: "2026-01-02T03:04:06.000Z",
		nonce: "nonce",
		keyId: "fixture-registry",
	});
}

function monitorReceipt(): Row {
	const actionJson = canonicalizeJson(fixture.envelopes.monitorAction);
	return signed("gjc-bugwatch-monitor-disable-receipt-v1", {
		schema: "gjc-bugwatch-monitor-disable-receipt/v1",
		scopeId: "scope-fixture",
		authorizationId: "authorization",
		actionHash: sha256Hex(actionJson),
		inventoryEpochId: "epoch",
		monitorId: "monitor_id",
		adapterKind: "process",
		beforeHash: hash,
		afterHash: null,
		startedAt: timestampIso,
		finishedAt: timestampIso,
		result: "disabled",
		steps: [{ name: "signal", attempted: true, ok: true, evidenceHash: null, errorCode: null }],
		coveredRootIds: ["root-fixture"],
		keyId: "fixture-registry",
	});
}

function storeCore(): Row {
	return signed("gjc-bugwatch-store-operation-core-v1", {
		schema: "gjc-bugwatch-store-operation-core/v1",
		scopeId: "scope-fixture",
		operationId: "operation",
		ownerId: "owner_id",
		claimTokenHash: hash,
		kind: "migrate",
		fromVersion: 1,
		toVersion: 2,
		members: [
			{
				member: "db",
				sourcePathHash: hash,
				expectedPresence: true,
				expectedSize: timestamp,
				expectedHash: hash,
				quarantinePathHash: otherHash,
			},
			{
				member: "wal",
				sourcePathHash: thirdHash,
				expectedPresence: false,
				expectedSize: null,
				expectedHash: null,
				quarantinePathHash: fourthHash,
			},
			{
				member: "shm",
				sourcePathHash: fifthHash,
				expectedPresence: false,
				expectedSize: null,
				expectedHash: null,
				quarantinePathHash: sixthHash,
			},
		],
		startedAt: timestampIso,
		keyId: "fixture-registry",
	});
}

function storeStep(
	coreHash: string,
	member: "db" | "wal" | "shm",
	stepIndex: number,
	action: "move_intent" | "verified_absent",
	expectedSourceHash: string | null,
	previousStepHash: string | null,
): Row {
	return signed("gjc-bugwatch-store-operation-step-v1", {
		schema: "gjc-bugwatch-store-operation-step/v1",
		scopeId: "scope-fixture",
		operationId: "operation",
		coreHash,
		stepIndex,
		member,
		action,
		expectedSourceHash,
		observedDestinationHash: null,
		previousStepHash,
		occurredAt: timestampIso,
		keyId: "fixture-registry",
	});
}

function storeSteps(coreHash: string): readonly Row[] {
	const db = storeStep(coreHash, "db", 0, "move_intent", hash, null);
	const wal = storeStep(coreHash, "wal", 1, "verified_absent", null, authenticatedHash(db));
	const shm = storeStep(coreHash, "shm", 2, "verified_absent", null, authenticatedHash(wal));
	return [db, wal, shm];
}
function rollbackItem(): Row {
	const payload: Row = {
		scopeId: "scope-fixture",
		rootId: "root-fixture",
		kind: "project",
		canonicalPath: "/tmp/project",
		enabled: true,
		revision: 1,
		projectPolicyHash: hash,
		registeredAtMs: timestamp,
		disabledAtMs: null,
		persistContext: true,
		baselineEpochId: null,
		activeMutationId: null,
	};
	return signed("gjc-bugwatch-rollback-bundle-item-v1", {
		schema: "gjc-bugwatch-rollback-bundle-item/v1",
		scopeId: "scope-fixture",
		epochId: "epoch",
		itemIndex: 0,
		itemType: "root",
		payload,
		payloadHash: sha256Hex(canonicalizeJson(payload)),
		itemHash: hash,
		previousItemHash: null,
		createdAt: timestampIso,
		keyId: "fixture-rollback",
	});
}

function rollbackBundle(): Row {
	return signed("gjc-bugwatch-rollback-bundle-v1", {
		schema: "gjc-bugwatch-rollback-bundle/v1",
		scopeId: "scope-fixture",
		epochId: "epoch",
		roleTransitionTokenHash: hash,
		bundleVersion: 1,
		state: "quiescing",
		manifestHash: null,
		itemCount: 0,
		byteCount: 0,
		itemsDigest: null,
		sourceWatermarkHash: null,
		createdAt: timestampIso,
		exportedAt: null,
		keyId: "fixture-rollback",
	});
}

function rollbackManifest(): Row {
	return signed("gjc-bugwatch-rollback-spool-manifest-v1", {
		schema: "gjc-bugwatch-rollback-spool-manifest/v1",
		scopeId: "scope-fixture",
		epochId: "epoch",
		segmentIndex: 0,
		state: "open",
		itemCount: 0,
		byteCount: 0,
		itemsDigest: null,
		previousManifestHash: null,
		closedAt: null,
		keyId: "fixture-rollback",
	});
}

function rollbackAck(): Row {
	return signed("gjc-bugwatch-rollback-inbox-ack-v1", {
		schema: "gjc-bugwatch-rollback-inbox-ack/v1",
		scopeId: "scope-fixture",
		epochId: "epoch",
		slot: 0,
		slotGeneration: 1,
		eventId: hash,
		segmentIndex: 0,
		spoolItemHash: hash,
		acknowledgedAt: timestampIso,
		keyId: "fixture-rollback",
	});
}

/**
 * Exact rows are intentionally owned by this test.  A field may receive a
 * type-derived default only before this map overrides every DDL coupling,
 * foreign key, signed-envelope projection, JSON byte count, and BLOB hash.
 */
function row(className: SnapshotPayloadClassV1): Row {
	if (className === "schema_meta" || className === "scope_policies" || className === "scope_policy_heads") {
		const item = fixture.envelopes.snapshotItems.find(candidate => candidate.itemType === className);
		if (item === undefined) throw new Error(`missing fixture row for ${className}`);
		return structuredClone(item.payload) as unknown as Row;
	}
	const spec = SNAPSHOT_PAYLOAD_ROW_SPECS[className];
	const value = Object.fromEntries(
		spec.fields.map((field, index) => [field, scalar(field, spec.types[index])]),
	) as Row;
	const blobHash = sha256Hex(new Uint8Array([0]));
	const jsonHash = sha256Hex("{}");
	switch (className) {
		case "roots": {
			const authority = fixture.envelopes.root as unknown as Row;
			Object.assign(value, {
				root_id: authority.rootId,
				canonical_path: authority.canonicalPath,
				enabled: authority.enabled ? 1 : 0,
				revision: authority.generation,
				project_policy_hash: authority.projectPolicyHash,
				registered_at_ms: timestamp,
				disabled_at_ms: null,
				persist_context: authority.persistContext ? 1 : 0,
				baseline_epoch_id: authority.baselineEpochId,
				active_mutation_id: authority.activeMutationId,
				root_json: canonicalEnvelope(authority),
			});
			break;
		}
		case "root_aliases":
			Object.assign(value, { old_root_id: "root-fixture", new_root_id: "root-secondary" });
			break;
		case "root_mutations": {
			const core = rootMutationCore();
			const state = rootMutationState(authenticatedHash(core));
			Object.assign(value, {
				scope_id: "scope-fixture",
				action: "set_context",
				core_hash: authenticatedHash(core),
				core_json: canonicalEnvelope(core),
				expected_policy_generation: 1,
				expected_policy_hash: hash,
				old_root_id: "root-fixture",
				new_root_id: "root-fixture",
				phase: "prepared",
				step_index: 0,
				current_step_hash: authenticatedHash(state),
			});
			break;
		}
		case "root_mutation_outputs":
			Object.assign(value, {
				target: "new_root",
				precondition: "present",
				expected_old_content_hash: hash,
				pending_content_hash: hash,
				final_content_hash: otherHash,
				desired_root_generation: 1,
				publication_order: 1,
				pending_state: "prepared",
				final_state: "prepared",
			});
			break;
		case "root_mutation_steps": {
			const core = rootMutationCore();
			const state = rootMutationState(authenticatedHash(core));
			Object.assign(value, {
				scope_id: "scope-fixture",
				mutation_id: "mutation",
				core_hash: authenticatedHash(core),
				step_index: 0,
				phase: "prepared",
				previous_phase: null,
				previous_state_hash: null,
				key_id: state.keyId,
				mac: state.mac,
				record_hash: authenticatedHash(state),
			});
			break;
		}
		case "root_mutation_rename_steps": {
			const core = rootMutationCore();
			const step = rootRenameStep(authenticatedHash(core));
			Object.assign(value, {
				mutation_id: "mutation",
				step_index: 0,
				target: "new_root",
				lifecycle: "pending",
				action: "rename_intent",
				expected_destination_hash: hash,
				source_temp_hash: hash,
				desired_destination_hash: hash,
				observed_destination_hash: null,
				previous_step_hash: null,
				step_hash: authenticatedHash(step),
				occurred_at_ms: timestamp,
				key_id: step.keyId,
				mac: step.mac,
			});
			break;
		}
		case "producer_boots": {
			const authority = fixture.envelopes.boot as unknown as Row;
			const final = bootFinal();
			Object.assign(value, {
				boot_id: authority.bootId,
				scope_id: authority.scopeId,
				boot_core_hash: authenticatedHash(authority),
				pid: authority.pid,
				pid_start_token: authority.pidStartToken,
				producer: authority.producer,
				started_at_ms: timestamp,
				initial_policy_generation: authority.initialPolicyGeneration,
				initial_policy_hash: authority.initialPolicyHash,
				fatal_key_id: authority.fatalKeyId,
				gjc_version: authority.gjcVersion,
				build_sha: authority.buildSha,
				final_seq: 1,
				final_state: "clean",
				final_record_hash: authenticatedHash(final),
				boot_core_json: canonicalEnvelope(authority),
			});
			break;
		}
		case "boot_transport_records": {
			const transport = bootTransport();
			Object.assign(value, {
				boot_id: "boot-fixture",
				transport_epoch: 1,
				record_kind: "start",
				record_hash: authenticatedHash(transport),
				start_record_hash: null,
				policy_generation: 1,
				policy_hash: hash,
				start_seq: 1,
				end_seq: null,
				file_enabled: 1,
				outcome: null,
				previous_record_hash: null,
				record_json: canonicalEnvelope(transport),
				created_at_ms: timestamp,
			});
			break;
		}
		case "boot_final_records": {
			const final = bootFinal();
			Object.assign(value, {
				boot_id: "boot-fixture",
				record_hash: authenticatedHash(final),
				final_seq: 1,
				state: "clean",
				last_transport_record_hash: authenticatedHash(bootTransport()),
				attachment_snapshot_hash: hash,
				previous_record_hash: authenticatedHash(bootTransport()),
				record_json: canonicalEnvelope(final),
				created_at_ms: timestamp,
			});
			break;
		}
		case "session_attachments": {
			const authority = fixture.envelopes.attachment as unknown as Row;
			Object.assign(value, {
				attachment_id: authority.attachmentId,
				scope_id: authority.scopeId,
				attachment_token_hash: authority.attachmentTokenHash,
				boot_id: authority.bootId,
				boot_core_hash: authority.bootCoreHash,
				root_id: authority.rootId,
				session_id: authority.sessionId,
				started_at_ms: timestamp,
				ended_at_ms: null,
				state: authority.state,
				managed_session_root: authority.managedSessionRoot,
				session_file: authority.sessionFile,
				root_generation: authority.rootGeneration,
				baseline_epoch_id: authority.baselineEpochId,
				publish_seq: 1,
				retire_seq: null,
				current_transition_hash: authenticatedHash(authority),
				attachment_json: canonicalEnvelope(authority),
			});
			break;
		}
		case "attachment_transitions": {
			const authority = fixture.envelopes.attachment as unknown as Row;
			Object.assign(value, {
				attachment_id: authority.attachmentId,
				step_index: 0,
				transition_hash: authenticatedHash(authority),
				state: authority.state,
				previous_transition_hash: null,
				occurred_at_ms: timestamp,
				record_json: canonicalEnvelope(authority),
				record_byte_count: new TextEncoder().encode(canonicalEnvelope(authority)).byteLength,
				key_id: authority.keyId,
				mac: authority.mac,
			});
			break;
		}
		case "producer_coverage":
			Object.assign(value, { contiguous_through: 0, max_seen: 0, final_seq: null, state: "open" });
			break;
		case "producer_ranges":
		case "coverage_boot_ranges":
			Object.assign(value, { start_seq: 1, end_seq: 1 });
			break;
		case "sources":
			Object.assign(value, { generation: 0, prefix_anchor_length: 0, boundary_hash: null });
			break;
		case "source_checkpoints":
			Object.assign(value, { generation: 0, kind: "chunk", chunk_index: 0, start_offset: 0, end_offset: 1 });
			break;
		case "archive_aliases":
		case "physical_rows":
			Object.assign(value, { generation: 0 });
			break;
		case "identity_quarantines":
			Object.assign(value, {
				generation: 0,
				expected_offset: 0,
				reason: "missing_boot",
				state: "active",
				resolved_at_ms: null,
			});
			break;
		case "capacity_blocks":
			Object.assign(value, { generation: 0 });
			break;
		case "job_inputs":
			Object.assign(value, { revision: 1, input_json: "{}", input_hash: jsonHash, input_byte_count: 2 });
			break;
		case "triage_jobs":
			Object.assign(value, {
				state: "queued",
				attempts: 0,
				max_attempts: 1,
				lease_token: null,
				lease_expires_at_ms: null,
			});
			break;
		case "triage_results":
			Object.assign(value, {
				attempt: 1,
				result_kind: "draft",
				result_json: "{}",
				output_hash: jsonHash,
				output_byte_count: 2,
			});
			break;
		case "artifact_outbox":
			Object.assign(value, {
				artifact_kind: "draft",
				immutable: 1,
				required: 1,
				projection_kind: null,
				required_projection_generation: null,
				content: blob,
				content_hash: blobHash,
				content_byte_count: 1,
				state: "pending",
				attempts: 0,
			});
			break;
		case "projection_heads":
			Object.assign(value, {
				projection_kind: "index",
				next_generation: 0,
				dirty_through_generation: 0,
				applied_generation: 0,
				state: "clean",
			});
			break;
		case "manual_artifacts":
			Object.assign(value, {
				kind: "draft",
				content: blob,
				content_hash: blobHash,
				content_byte_count: 1,
				ownership: "manual",
			});
			break;
		case "fingerprint_prefix_aliases":
			Object.assign(value, { prefix_len: 8, prefix: hash.slice(0, 8), source: "generated" });
			break;
		case "import_epochs":
			Object.assign(value, { kind: "manual_refresh", byte_count: 0, item_count: 0, state: "complete" });
			break;
		case "context_records":
			Object.assign(value, { byte_count: 1, state: "present", deleted_at_ms: null, delete_proof_hash: null });
			break;
		case "coverage_source_watermarks":
			Object.assign(value, { generation: 0 });
			break;
		case "coverage_epochs":
			Object.assign(value, { kind: "shadow", state: "open", coverage_status: "covered" });
			break;
		case "rollback_epochs": {
			const bundle = rollbackBundle();
			const manifest = rollbackManifest();
			const ack = rollbackAck();
			Object.assign(value, {
				scope_id: "scope-fixture",
				bundle_version: 1,
				state: "quiescing",
				manifest_hash: null,
				bundle_json: canonicalEnvelope(bundle),
				spool_manifest_json: canonicalEnvelope(manifest),
				inbox_ack_json: canonicalEnvelope(ack),
			});
			break;
		}
		case "rollback_items": {
			const authority = rollbackItem();
			const payload = canonicalizeJson(authority.payload);
			Object.assign(value, {
				epoch_id: "epoch",
				item_index: 0,
				item_type: "root",
				item_hash: authority.itemHash,
				payload: `base64:${btoa(payload)}`,
				payload_hash: authority.payloadHash,
				payload_byte_count: new TextEncoder().encode(payload).byteLength,
				state: "pending",
				item_schema: "gjc-bugwatch-rollback-bundle-item/v1",
				key_id: authority.keyId,
				mac: authority.mac,
				item_json: canonicalEnvelope(authority),
			});
			break;
		}
		case "old_monitor_inventory_epochs":
			Object.assign(value, {
				scope_id: "scope-fixture",
				state: "collecting",
				completed_at_ms: null,
				receipt_hash: null,
			});
			break;
		case "old_monitors": {
			const authority = monitorInventory();
			Object.assign(value, {
				inventory_epoch_id: authority.inventoryEpochId,
				monitor_id: authority.monitorId,
				kind: authority.kind,
				stable_identifier: authority.stableIdentifier,
				config_hash: authority.configHash,
				status: authority.status,
				observed_at_ms: timestamp,
				inventory_json: canonicalEnvelope(authority),
			});
			break;
		}
		case "old_monitor_root_coverage":
			Object.assign(value, { inventory_epoch_id: "epoch", monitor_id: "monitor_id", root_id: "root-fixture" });
			break;
		case "legacy_disable_receipts":
			Object.assign(value, { payload: blob, receipt_hash: blobHash, payload_json: "{}" });
			break;
		case "monitor_disable_authorizations": {
			const authority = monitorAuthorization();
			const actionJson = canonicalizeJson(fixture.envelopes.monitorAction);
			Object.assign(value, {
				authorization_id: "authorization",
				scope_id: "scope-fixture",
				inventory_epoch_id: authority.inventoryEpochId,
				monitor_id: authority.monitorId,
				action_kind: authority.adapterKind,
				action_json: actionJson,
				action_hash: sha256Hex(actionJson),
				expected_config_hash: authority.expectedConfigHash,
				consume_nonce_hash: sha256Hex(String(authority.nonce)),
				state: "authorized",
				authorized_at_ms: timestamp,
				expires_at_ms: timestamp + 1_000,
				consumed_at_ms: null,
				authorization_json: canonicalEnvelope(authority),
				key_id: authority.keyId,
				mac: authority.mac,
			});
			break;
		}
		case "monitor_disable_receipts": {
			const authority = monitorReceipt();
			Object.assign(value, {
				receipt_id: "receipt",
				authorization_id: authority.authorizationId,
				scope_id: authority.scopeId,
				inventory_epoch_id: authority.inventoryEpochId,
				monitor_id: authority.monitorId,
				adapter_kind: authority.adapterKind,
				action_hash: authority.actionHash,
				before_hash: authority.beforeHash,
				after_hash: authority.afterHash,
				result: authority.result,
				steps_json: canonicalizeJson(authority.steps),
				covered_roots_json: canonicalizeJson(authority.coveredRootIds),
				receipt_json: canonicalEnvelope(authority),
				started_at_ms: timestamp,
				finished_at_ms: timestamp,
				receipt_hash: authenticatedHash(authority),
				key_id: authority.keyId,
				mac: authority.mac,
			});
			break;
		}
		case "store_operations": {
			const core = storeCore();
			const step = storeSteps(authenticatedHash(core))[2];
			Object.assign(value, {
				operation_id: core.operationId,
				owner_id: core.ownerId,
				claim_token_hash: core.claimTokenHash,
				kind: core.kind,
				from_version: core.fromVersion,
				to_version: core.toVersion,
				phase: "prepared",
				core_hash: authenticatedHash(core),
				current_step: 2,
				current_step_hash: authenticatedHash(step),
				core_json: canonicalEnvelope(core),
				started_at_ms: timestamp,
			});
			break;
		}
		case "store_operation_members": {
			const core = storeCore();
			const step = storeSteps(authenticatedHash(core))[0];
			Object.assign(value, {
				operation_id: "operation",
				member: "db",
				source_path_hash: hash,
				expected_presence: 1,
				expected_size: timestamp,
				expected_hash: hash,
				quarantine_path_hash: otherHash,
				state: "intent_recorded",
				observed_source_hash: null,
				observed_quarantine_hash: null,
				step_json: canonicalEnvelope(step),
				updated_at_ms: timestamp,
			});
			break;
		}
	}
	return value;
}

const exactRows: Readonly<Record<SnapshotPayloadClassV1, Factory>> = Object.freeze(
	Object.fromEntries(SNAPSHOT_PAYLOAD_CLASSES.map(className => [className, () => row(className)])) as Record<
		SnapshotPayloadClassV1,
		Factory
	>,
);

describe("schema-1.7 snapshot payload matrix", () => {
	it("owns one exact factory for every production payload class and keeps its fields aligned", () => {
		const factoryNames = Object.keys(exactRows).sort();
		const classNames = [...SNAPSHOT_PAYLOAD_CLASSES].sort();
		expect(
			factoryNames,
			`missing factories: ${classNames.filter(name => !factoryNames.includes(name)).join(", ")}`,
		).toEqual(classNames);
		for (const className of SNAPSHOT_PAYLOAD_CLASSES) {
			const value = exactRows[className]();
			expect(Object.keys(value).sort()).toEqual([...SNAPSHOT_PAYLOAD_FIELD_SETS[className]].sort());
		}
	});

	it("keeps one meaningful required-field mutation per class", () => {
		for (const className of SNAPSHOT_PAYLOAD_CLASSES) {
			const fields = SNAPSHOT_PAYLOAD_FIELD_SETS[className];
			const requiredField = fields.find(
				(_field, index) => !SNAPSHOT_PAYLOAD_ROW_SPECS[className].types[index].startsWith("nullable_"),
			);
			expect(requiredField, `${className} has no required field`).toBeDefined();
			const valid = exactRows[className]();
			const invalid = { ...valid, [requiredField as string]: otherHash };
			expect(invalid[requiredField as string]).not.toBe(valid[requiredField as string]);
		}
	});

	it("accepts exact rows and rejects required-field loss through production validators", () => {
		const items: AuthoritySnapshotItemV1[] = SNAPSHOT_PAYLOAD_CLASSES.filter(
			className => className !== "root_mutation_rename_steps",
		).map((className, index) => {
			const payload = exactRows[className]();
			return {
				schema: "gjc-bugwatch-authority-item/v1",
				index,
				itemType: className,
				authorityId:
					className === "schema_meta"
						? "1"
						: SNAPSHOT_ROW_AUTHORITY_COLUMNS[className] === undefined
							? `${className}-authority`
							: String(payload[SNAPSHOT_ROW_AUTHORITY_COLUMNS[className] as string]),
				payload,
				payloadHash: sha256Hex(canonicalizeJson(payload)),
				previousItemHash: null,
				keyId: "fixture-key",
				mac: hash,
			};
		});
		const secondaryAuthority = secondaryRoot();
		const secondaryPayload: Row = {
			...exactRows.roots(),
			root_id: secondaryAuthority.rootId,
			canonical_path: secondaryAuthority.canonicalPath,
			enabled: 1,
			revision: secondaryAuthority.generation,
			project_policy_hash: secondaryAuthority.projectPolicyHash,
			baseline_epoch_id: secondaryAuthority.baselineEpochId,
			active_mutation_id: secondaryAuthority.activeMutationId,
			root_json: canonicalEnvelope(secondaryAuthority),
		};
		items.push({
			schema: "gjc-bugwatch-authority-item/v1",
			index: items.length,
			itemType: "roots",
			authorityId: "root-secondary",
			payload: secondaryPayload,
			payloadHash: sha256Hex(canonicalizeJson(secondaryPayload)),
			previousItemHash: null,
			keyId: "fixture-key",
			mac: hash,
		});

		const storeCoreHash = authenticatedHash(storeCore());
		const supportingStoreMembers = [
			{
				member: "wal",
				sourcePathHash: thirdHash,
				quarantinePathHash: fourthHash,
				step: storeSteps(storeCoreHash)[1],
			},
			{
				member: "shm",
				sourcePathHash: fifthHash,
				quarantinePathHash: sixthHash,
				step: storeSteps(storeCoreHash)[2],
			},
		] as const;
		for (const supporting of supportingStoreMembers) {
			const payload: Row = {
				...exactRows.store_operation_members(),
				member: supporting.member,
				source_path_hash: supporting.sourcePathHash,
				expected_presence: 0,
				expected_size: null,
				expected_hash: null,
				quarantine_path_hash: supporting.quarantinePathHash,
				state: "verified_absent",
				observed_source_hash: null,
				observed_quarantine_hash: null,
				step_json: canonicalEnvelope(supporting.step),
				updated_at_ms: timestamp,
			};
			items.push({
				schema: "gjc-bugwatch-authority-item/v1",
				index: items.length,
				itemType: "store_operation_members",
				authorityId: "operation",
				payload,
				payloadHash: sha256Hex(canonicalizeJson(payload)),
				previousItemHash: null,
				keyId: "fixture-key",
				mac: hash,
			});
		}
		const graph: SnapshotPayloadGraphV1 = {
			scopeId: "scope-fixture",
			items,
			policyKey: { keyId: "fixture-policy", keyBytes: fixtureKey },
			registryKey: { keyId: "fixture-registry", keyBytes: fixtureKey },
			fatalKey: { keyId: "0123456789abcdef0123456789abcdef", keyBytes: fixtureKey },
			rollbackKey: { keyId: "fixture-rollback", keyBytes: fixtureKey },
		};
		const failures: string[] = [];
		for (const item of items) {
			try {
				SNAPSHOT_PAYLOAD_VALIDATORS[item.itemType as SnapshotPayloadClassV1](item, graph);
			} catch (error) {
				failures.push(`${item.itemType}: ${error instanceof Error ? error.message : String(error)}`);
			}
		}
		expect(failures).toEqual([]);
		expect(() => validateSnapshotGraph(graph)).not.toThrow();
		const reservedRoot = {
			...exactRows.roots(),
			root_id: "service",
			kind: "service",
			canonical_path: null,
			enabled: 1,
			revision: 1,
			project_policy_hash: "0".repeat(64),
			disabled_at_ms: null,
			persist_context: 0,
			baseline_epoch_id: null,
			active_mutation_id: null,
			root_json: null,
		};
		expect(() =>
			SNAPSHOT_PAYLOAD_VALIDATORS.roots(
				{
					...items.find(item => item.itemType === "roots")!,
					authorityId: "service",
					payload: reservedRoot,
					payloadHash: sha256Hex(canonicalizeJson(reservedRoot)),
				},
				graph,
			),
		).not.toThrow();
		const copiedProjectScalars = { ...reservedRoot, root_id: "root-fixture", project_policy_hash: hash };
		expect(() =>
			SNAPSHOT_PAYLOAD_VALIDATORS.roots(
				{
					...items.find(item => item.itemType === "roots")!,
					payload: copiedProjectScalars,
					payloadHash: sha256Hex(canonicalizeJson(copiedProjectScalars)),
				},
				graph,
			),
		).toThrow();

		const projectRoot = items.find(item => item.itemType === "roots")!;
		const tamperedRoot = {
			...projectRoot,
			payload: { ...(projectRoot.payload as Row), root_json: "{}" },
		};
		expect(() =>
			validateSnapshotPayload(
				{
					...tamperedRoot,
					payloadHash: sha256Hex(canonicalizeJson(tamperedRoot.payload)),
				},
				graph,
			),
		).toThrow();
		const wrongRegistryKey: SnapshotPayloadGraphV1 = {
			...graph,
			registryKey: { keyId: "fixture-registry", keyBytes: new Uint8Array([1]) },
		};
		expect(() => validateSnapshotGraph(wrongRegistryKey)).toThrow();
		const withoutOutput: SnapshotPayloadGraphV1 = {
			...graph,
			items: items.filter(item => item.itemType !== "root_mutation_outputs"),
		};
		expect(() => validateSnapshotGraph(withoutOutput)).toThrow();
		const preparedRenamePayload = exactRows.root_mutation_rename_steps();
		const illegalPreparedRename: SnapshotPayloadGraphV1 = {
			...graph,
			items: [
				...items,
				{
					schema: "gjc-bugwatch-authority-item/v1",
					index: items.length,
					itemType: "root_mutation_rename_steps",
					authorityId: "mutation",
					payload: preparedRenamePayload,
					payloadHash: sha256Hex(canonicalizeJson(preparedRenamePayload)),
					previousItemHash: null,
					keyId: "fixture-key",
					mac: hash,
				},
			],
		};
		expect(() => validateSnapshotGraph(illegalPreparedRename)).toThrow();
		const substitutedReceipt: SnapshotPayloadGraphV1 = {
			...graph,
			items: items.map(item =>
				item.itemType !== "monitor_disable_receipts"
					? item
					: { ...item, payload: { ...(item.payload as Row), authorization_id: "substituted" } },
			),
		};
		expect(() => validateSnapshotGraph(substitutedReceipt)).toThrow();
		const receiptProjectionMismatch: SnapshotPayloadGraphV1 = {
			...graph,
			items: items.map(item =>
				item.itemType !== "monitor_disable_receipts"
					? item
					: { ...item, payload: { ...(item.payload as Row), scope_id: "substituted-scope" } },
			),
		};
		expect(() => validateSnapshotGraph(receiptProjectionMismatch)).toThrow();
		const duplicateMonitorInventory: SnapshotPayloadGraphV1 = {
			...graph,
			items: [...items, { ...items.find(item => item.itemType === "old_monitors")! }],
		};
		expect(() => validateSnapshotGraph(duplicateMonitorInventory)).toThrow();

		for (const item of items) {
			const spec = SNAPSHOT_PAYLOAD_ROW_SPECS[item.itemType as SnapshotPayloadClassV1];
			const requiredIndex = spec.types.findIndex(type => !type.startsWith("nullable_"));
			const field = spec.fields[requiredIndex];
			const invalid = { ...item, payload: { ...(item.payload as Row), [field]: null } };
			expect(() => SNAPSHOT_PAYLOAD_VALIDATORS[item.itemType as SnapshotPayloadClassV1](invalid, graph)).toThrow();
		}
	});
});
