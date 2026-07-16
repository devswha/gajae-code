import type { Database } from "bun:sqlite";
import {
	authenticatedHash,
	BUGWATCH_FINGERPRINT_VERSION,
	BUGWATCH_FIXTURE_MANIFEST_HASH,
	BUGWATCH_LOG_SCHEMA_VERSION,
	BUGWATCH_NOISE_VERSION,
	BUGWATCH_REDACTION_VERSION,
	BUGWATCH_SCHEMA_CATALOG_HASH,
	BUGWATCH_SCHEMA_MAJOR,
	BUGWATCH_SCHEMA_MINOR,
	BUGWATCH_SEVERITY_VERSION,
	canonicalizeJson,
	type JsonValue,
	parseMonitorDisableAuthorizationV1,
	parseMonitorDisableReceiptV1,
	parseMonitorInventoryV1,
	parseRootControlV1,
	parseRootMutationCoreV1,
	parseRootMutationDbStateV1,
	parseRootMutationRenameStepV2,
	parseScopePolicyHeadV2,
	type RootMutationCoreV1,
	type RootMutationOutputObservationV2,
	resolveRootMutationRestartV2,
	type ScopePolicyHeadV2,
	verifyMac,
} from "@gajae-code/utils/bugwatch-contract";
import { BUGWATCH_PERSISTED_TABLE_NAMES, BUGWATCH_SCHEMA_SQL } from "./schema";

export interface BugwatchSchemaMetadata {
	logSchemaVersion: number;
	redactionVersion: number;
	noiseVersion: number;
	severityVersion: number;
	fingerprintVersion: number;
	fixtureManifestHash: string;
	createdAtMs: number;
}

export function createBugwatchSchemaMetadata(createdAtMs: number): BugwatchSchemaMetadata {
	return {
		logSchemaVersion: BUGWATCH_LOG_SCHEMA_VERSION,
		redactionVersion: BUGWATCH_REDACTION_VERSION,
		noiseVersion: BUGWATCH_NOISE_VERSION,
		severityVersion: BUGWATCH_SEVERITY_VERSION,
		fingerprintVersion: BUGWATCH_FINGERPRINT_VERSION,
		fixtureManifestHash: BUGWATCH_FIXTURE_MANIFEST_HASH,
		createdAtMs,
	};
}

type SchemaMetaRow = {
	schema_major: number;
	schema_minor: number;
	log_schema_version: number;
	redaction_version: number;
	noise_version: number;
	severity_version: number;
	fingerprint_version: number;
	fixture_manifest_hash: string;
	schema_catalog_hash: string;
};
type SchemaVersionRow = {
	schema_major: number;
	schema_minor: number;
};

type CatalogRow = {
	type: "table" | "index" | "trigger" | "view";
	name: string;
	sql: string | null;
};

type ExpectedCatalogEntry = {
	type: "table" | "index" | "trigger";
	name: string;
	sql: string;
};

type QuickCheckRow = {
	quick_check: string;
};
type PolicyHeadRow = {
	scope_id: string;
	generation: number;
	revision_hash: string;
	content_hash: string;
	cas_token_hash: string;
	updated_at_ms: number;
	key_id: string;
	mac: string;
	head_json: string;
};
type RootMutationRow = {
	mutation_id: string;
	scope_id: string;
	action: string;
	core_hash: string;
	core_json: string;
	expected_policy_generation: number;
	expected_policy_hash: string;
	old_root_id: string | null;
	new_root_id: string | null;
	created_at_ms: number;
	phase: string;
};
export type BugwatchPersistedAuthorityKeyResolver = (keyId: string) => Uint8Array | undefined;

type RootAuthorityRow = {
	root_id: string;
	kind: "project" | "unattributed" | "service";
	canonical_path: string | null;
	enabled: number;
	revision: number;
	project_policy_hash: string;
	persist_context: number;
	baseline_epoch_id: string | null;
	active_mutation_id: string | null;
	root_json: string | null;
};
type AuthorityJsonRow = {
	scope_id: string;
	mutation_id: string;
	core_hash: string;
	step_index: number;
	phase: string;
	previous_phase: string | null;
	previous_state_hash: string | null;
	key_id: string;
	mac: string;
	record_hash: string;
	record_json: string;
	step_hash: string;
	target: string;
	lifecycle: string;
	action: string;
	expected_destination_hash: string | null;
	source_temp_hash: string;
	desired_destination_hash: string;
	observed_destination_hash: string | null;
	previous_step_hash: string | null;
	occurred_at_ms: number;
};
type MonitorAuthorityRow = {
	authorization_id: string;
	scope_id: string;
	inventory_epoch_id: string;
	monitor_id: string;
	action_kind: string;
	action_hash: string;
	expected_config_hash: string;
	consume_nonce_hash: string;
	state: string;
	authorized_at_ms: number;
	expires_at_ms: number;
	consumed_at_ms: number | null;
	action_json: string;
	authorization_json: string;
	key_id: string;
	mac: string;
	stable_identifier: string | null;
	monitor_config_hash: string | null;
	monitor_kind: string | null;
	inventory_scope_id: string | null;
	inventory_json: string | null;
};
type ReceiptAuthorityRow = {
	authorization_id: string;
	scope_id: string;
	inventory_epoch_id: string;
	monitor_id: string;
	adapter_kind: string;
	action_hash: string;
	before_hash: string;
	after_hash: string | null;
	result: string;
	steps_json: string;
	covered_roots_json: string;
	receipt_json: string;
	started_at_ms: number;
	finished_at_ms: number;
	receipt_hash: string;
	key_id: string;
	mac: string;
};
type RootMutationOutputRow = {
	target: "old_root" | "new_root";
	path_hash: string;
	precondition: "missing" | "present";
	expected_old_content_hash: string | null;
	pending_content_hash: string;
	final_content_hash: string;
	desired_root_generation: number;
	publication_order: number;
	pending_state: string;
	final_state: string;
};

function authorityKey(resolver: BugwatchPersistedAuthorityKeyResolver, keyId: string): Uint8Array {
	const key = resolver(keyId);
	if (key === undefined || key.byteLength === 0)
		throw new BugwatchSchemaIntegrityError("INTEGRITY", `missing retained authority key ${keyId}`);
	return key;
}
function authorityAssert(value: boolean, detail: string): void {
	if (!value) throw new BugwatchSchemaIntegrityError("INTEGRITY", detail);
}

/** Verifies MAC-backed persisted authority before an existing store is trusted. */
export function validateBugwatchPersistedAuthorities(
	db: Database,
	keyForId: BugwatchPersistedAuthorityKeyResolver,
): void {
	for (const row of db
		.prepare<RootAuthorityRow, []>(
			"SELECT root_id, kind, canonical_path, enabled, revision, project_policy_hash, persist_context, baseline_epoch_id, active_mutation_id, root_json FROM roots",
		)
		.all()) {
		if (row.kind !== "project") {
			authorityAssert(
				row.root_id === row.kind &&
					row.canonical_path === null &&
					row.root_json === null &&
					row.enabled === 1 &&
					row.revision === 1 &&
					row.persist_context === 0 &&
					row.baseline_epoch_id === null &&
					row.active_mutation_id === null,
				"reserved root authority projection mismatch",
			);
			continue;
		}
		try {
			if (row.root_json === null)
				throw new BugwatchSchemaIntegrityError("INTEGRITY", "project root is missing authority");
			const root = parseRootControlV1(row.root_json);
			verifyMac(root as unknown as JsonValue, "gjc-bugwatch-root-v1", authorityKey(keyForId, root.keyId));
			authorityAssert(
				root.rootId === row.root_id &&
					root.canonicalPath === row.canonical_path &&
					root.enabled === (row.enabled === 1) &&
					root.persistContext === (row.persist_context === 1) &&
					root.generation === row.revision &&
					root.projectPolicyHash === row.project_policy_hash &&
					root.baselineEpochId === row.baseline_epoch_id &&
					root.activeMutationId === row.active_mutation_id,
				"root authority projection mismatch",
			);
		} catch (error) {
			if (error instanceof BugwatchSchemaIntegrityError) throw error;
			throw new BugwatchSchemaIntegrityError("INTEGRITY", "invalid root authority envelope");
		}
	}
	for (const row of db
		.prepare<RootMutationRow, []>(
			"SELECT mutation_id, scope_id, action, core_hash, core_json, expected_policy_generation, expected_policy_hash, old_root_id, new_root_id, phase, created_at_ms FROM root_mutations",
		)
		.all()) {
		try {
			const core = parseRootMutationCoreV1(row.core_json);
			verifyMac(
				core as unknown as JsonValue,
				"gjc-bugwatch-root-mutation-core-v1",
				authorityKey(keyForId, core.keyId),
			);
			authorityAssert(
				authenticatedHash(core as unknown as JsonValue) === row.core_hash &&
					core.mutationId === row.mutation_id &&
					core.scopeId === row.scope_id &&
					core.action === row.action &&
					core.expectedPolicyGeneration === row.expected_policy_generation &&
					core.expectedPolicyHash === row.expected_policy_hash &&
					core.oldRootId === row.old_root_id &&
					core.newRootId === row.new_root_id &&
					core.createdAt === new Date(row.created_at_ms).toISOString(),
				"root mutation core projection mismatch",
			);
		} catch (error) {
			if (error instanceof BugwatchSchemaIntegrityError) throw error;
			throw new BugwatchSchemaIntegrityError("INTEGRITY", "invalid root mutation authority envelope");
		}
	}
	const stateHeads = new Map<string, { index: number; hash: string; phase: string }>();
	for (const row of db
		.prepare<AuthorityJsonRow, []>(
			"SELECT scope_id, mutation_id, core_hash, step_index, phase, previous_phase, previous_state_hash, key_id, mac, record_hash, '' AS record_json, '' AS step_hash, '' AS target, '' AS lifecycle, '' AS action, NULL AS expected_destination_hash, '' AS source_temp_hash, '' AS desired_destination_hash, NULL AS observed_destination_hash, NULL AS previous_step_hash, 0 AS occurred_at_ms FROM root_mutation_steps ORDER BY mutation_id, step_index",
		)
		.all()) {
		try {
			const state = parseRootMutationDbStateV1(
				canonicalizeJson({
					schema: "gjc-bugwatch-root-mutation-db-state/v1",
					scopeId: row.scope_id,
					mutationId: row.mutation_id,
					coreHash: row.core_hash,
					phase: row.phase,
					previousPhase: row.previous_phase,
					previousStateHash: row.previous_state_hash,
					keyId: row.key_id,
					mac: row.mac,
				}),
			);
			verifyMac(
				state as unknown as JsonValue,
				"gjc-bugwatch-root-mutation-db-state-v1",
				authorityKey(keyForId, state.keyId),
			);
			const previous = stateHeads.get(row.mutation_id);
			authorityAssert(
				authenticatedHash(state as unknown as JsonValue) === row.record_hash &&
					row.step_index === (previous?.index ?? -1) + 1 &&
					state.previousStateHash === (previous?.hash ?? null) &&
					state.previousPhase === (previous?.phase ?? null),
				"root mutation state chain or hash mismatch",
			);
			stateHeads.set(row.mutation_id, { index: row.step_index, hash: row.record_hash, phase: row.phase });
		} catch {
			throw new BugwatchSchemaIntegrityError("INTEGRITY", "invalid root mutation state envelope");
		}
	}
	const renameHeads = new Map<string, { index: number; hash: string }>();
	for (const row of db
		.prepare<AuthorityJsonRow, []>(
			"SELECT scope_id, mutation_id, core_hash, step_index, '' AS phase, NULL AS previous_phase, NULL AS previous_state_hash, key_id, mac, '' AS record_hash, record_json, step_hash, target, lifecycle, action, expected_destination_hash, source_temp_hash, desired_destination_hash, observed_destination_hash, previous_step_hash, occurred_at_ms FROM root_mutation_rename_steps ORDER BY mutation_id, step_index",
		)
		.all()) {
		try {
			const step = parseRootMutationRenameStepV2(row.record_json);
			verifyMac(
				step as unknown as JsonValue,
				"gjc-bugwatch-root-rename-step-v2",
				authorityKey(keyForId, step.keyId),
			);
			const previous = renameHeads.get(row.mutation_id);
			authorityAssert(
				authenticatedHash(step as unknown as JsonValue) === row.step_hash &&
					step.scopeId === row.scope_id &&
					step.mutationId === row.mutation_id &&
					step.coreHash === row.core_hash &&
					step.stepIndex === row.step_index &&
					step.target === row.target &&
					step.lifecycle === row.lifecycle &&
					step.action === row.action &&
					step.expectedDestinationHash === row.expected_destination_hash &&
					step.sourceTempHash === row.source_temp_hash &&
					step.desiredDestinationHash === row.desired_destination_hash &&
					step.observedDestinationHash === row.observed_destination_hash &&
					step.previousStepHash === row.previous_step_hash &&
					step.previousStepHash === (previous?.hash ?? null) &&
					step.stepIndex === (previous?.index ?? -1) + 1 &&
					step.occurredAt === new Date(row.occurred_at_ms).toISOString() &&
					step.keyId === row.key_id &&
					step.mac === row.mac,
				"root rename authority projection or chain mismatch",
			);
			renameHeads.set(row.mutation_id, { index: row.step_index, hash: row.step_hash });
		} catch {
			throw new BugwatchSchemaIntegrityError("INTEGRITY", "invalid root rename authority envelope");
		}
	}
	for (const mutation of db
		.prepare<RootMutationRow, []>(
			"SELECT mutation_id, scope_id, action, core_hash, core_json, expected_policy_generation, expected_policy_hash, old_root_id, new_root_id, phase, created_at_ms FROM root_mutations",
		)
		.all()) {
		try {
			const core = parseRootMutationCoreV1(mutation.core_json);
			const coreOutputs = [...core.outputs].sort((left, right) => left.publicationOrder - right.publicationOrder);
			const states = db
				.prepare<AuthorityJsonRow, [string]>(
					"SELECT scope_id, mutation_id, core_hash, step_index, phase, previous_phase, previous_state_hash, key_id, mac, record_hash, '' AS record_json, '' AS step_hash, '' AS target, '' AS lifecycle, '' AS action, NULL AS expected_destination_hash, '' AS source_temp_hash, '' AS desired_destination_hash, NULL AS observed_destination_hash, NULL AS previous_step_hash, 0 AS occurred_at_ms FROM root_mutation_steps WHERE mutation_id=? ORDER BY step_index",
				)
				.all(mutation.mutation_id)
				.map(row =>
					canonicalizeJson({
						schema: "gjc-bugwatch-root-mutation-db-state/v1",
						scopeId: row.scope_id,
						mutationId: row.mutation_id,
						coreHash: row.core_hash,
						phase: row.phase,
						previousPhase: row.previous_phase,
						previousStateHash: row.previous_state_hash,
						keyId: row.key_id,
						mac: row.mac,
					}),
				);
			const steps = db
				.prepare<{ record_json: string }, [string]>(
					"SELECT record_json FROM root_mutation_rename_steps WHERE mutation_id=? ORDER BY step_index",
				)
				.all(mutation.mutation_id)
				.map(row => row.record_json);
			const pendingRenameStepCount = core.outputs.length * 2;
			const completeRenameStepCount = pendingRenameStepCount * 2;
			const renamePrefixIsLegal =
				mutation.phase === "prepared"
					? steps.length === 0
					: mutation.phase === "publishing"
						? steps.length <= pendingRenameStepCount
						: mutation.phase === "files_published" ||
								mutation.phase === "db_applied" ||
								mutation.phase === "baseline_complete"
							? steps.length === pendingRenameStepCount
							: mutation.phase === "files_finalized" || mutation.phase === "committed"
								? steps.length === completeRenameStepCount
								: steps.length <= completeRenameStepCount;
			authorityAssert(renamePrefixIsLegal, "root mutation rename evidence is incompatible with DB phase");
			const outputs = db
				.prepare<RootMutationOutputRow, [string]>(
					"SELECT target, path_hash, precondition, expected_old_content_hash, pending_content_hash, final_content_hash, desired_root_generation, publication_order, pending_state, final_state FROM root_mutation_outputs WHERE mutation_id=? ORDER BY publication_order",
				)
				.all(mutation.mutation_id);
			authorityAssert(
				outputs.length === coreOutputs.length &&
					outputs.every(
						(output, index) =>
							output.target === coreOutputs[index]?.target &&
							output.path_hash === coreOutputs[index]?.pathHash &&
							output.precondition === coreOutputs[index]?.precondition &&
							output.expected_old_content_hash === coreOutputs[index]?.expectedOldContentHash &&
							output.pending_content_hash === coreOutputs[index]?.pendingContentHash &&
							output.final_content_hash === coreOutputs[index]?.finalContentHash &&
							output.desired_root_generation === coreOutputs[index]?.desiredRootGeneration &&
							output.publication_order === coreOutputs[index]?.publicationOrder,
					),
				"root mutation outputs do not exactly project authenticated core",
			);
			const outputsForRecovery: RootMutationOutputObservationV2[] = outputs.map(output => {
				const final = output.final_state === "verified";
				const pending = output.pending_state === "verified";
				return {
					target: output.target,
					destinationHash: final
						? output.final_content_hash
						: pending
							? output.pending_content_hash
							: output.expected_old_content_hash,
					pendingTempHash: final || pending ? null : output.pending_content_hash,
					finalTempHash: final ? null : output.final_content_hash,
				};
			});
			const recovery = resolveRootMutationRestartV2({
				core: mutation.core_json,
				dbStates: states,
				steps,
				keyBytes: authorityKey(keyForId, core.keyId),
				outputs: outputsForRecovery,
			});
			authorityAssert(recovery !== "conflict", "root mutation restart evidence is incomplete or contradictory");
			if (mutation.phase === "files_finalized" || mutation.phase === "committed")
				authorityAssert(
					steps.length === core.outputs.length * 4 && recovery === "commit",
					"terminal root mutation lacks complete rename evidence",
				);
		} catch (error) {
			if (error instanceof BugwatchSchemaIntegrityError) throw error;
			throw new BugwatchSchemaIntegrityError("INTEGRITY", "invalid root mutation restart evidence");
		}
	}
	const authorizations = new Map<string, MonitorAuthorityRow>();
	for (const row of db
		.prepare<MonitorAuthorityRow, []>(
			`SELECT authorization.authorization_id, authorization.scope_id, authorization.inventory_epoch_id,
		        authorization.monitor_id, authorization.action_kind, authorization.action_hash,
		        authorization.expected_config_hash, authorization.consume_nonce_hash, authorization.state,
		        authorization.authorized_at_ms, authorization.expires_at_ms, authorization.consumed_at_ms,
		        authorization.action_json, authorization.authorization_json, authorization.key_id, authorization.mac,
		        monitor.stable_identifier, monitor.config_hash AS monitor_config_hash
		        , monitor.kind AS monitor_kind, epoch.scope_id AS inventory_scope_id, monitor.inventory_json
		   FROM monitor_disable_authorizations AS authorization
		   LEFT JOIN old_monitors AS monitor
		     ON monitor.inventory_epoch_id=authorization.inventory_epoch_id
		    AND monitor.monitor_id=authorization.monitor_id
		   LEFT JOIN old_monitor_inventory_epochs AS epoch
		     ON epoch.inventory_epoch_id=authorization.inventory_epoch_id`,
		)
		.all()) {
		try {
			const authorization = parseMonitorDisableAuthorizationV1(row.authorization_json);
			verifyMac(
				authorization as unknown as JsonValue,
				"gjc-bugwatch-monitor-disable-auth-v1",
				authorityKey(keyForId, authorization.keyId),
			);
			authorityAssert(
				authorization.authorizationId === row.authorization_id &&
					authorization.scopeId === row.scope_id &&
					authorization.inventoryEpochId === row.inventory_epoch_id &&
					authorization.monitorId === row.monitor_id &&
					authorization.adapterKind === row.action_kind &&
					row.stable_identifier !== null &&
					row.monitor_config_hash !== null &&
					row.monitor_kind !== null &&
					row.inventory_scope_id !== null &&
					row.inventory_json !== null &&
					authorization.stableIdentifier === row.stable_identifier &&
					authorization.adapterKind === row.monitor_kind &&
					authorization.scopeId === row.inventory_scope_id &&
					authorization.expectedConfigHash === row.expected_config_hash &&
					authorization.expectedConfigHash === row.monitor_config_hash &&
					authorization.authorizedAt === new Date(row.authorized_at_ms).toISOString() &&
					authorization.expiresAt === new Date(row.expires_at_ms).toISOString() &&
					authorization.keyId === row.key_id &&
					authorization.mac === row.mac &&
					canonicalizeJson(authorization.allowedAction as unknown as JsonValue) === row.action_json &&
					authenticatedHash(authorization.allowedAction as unknown as JsonValue) === row.action_hash &&
					new Bun.CryptoHasher("sha256").update(authorization.nonce).digest("hex") === row.consume_nonce_hash &&
					(row.state === "consumed") === (row.consumed_at_ms !== null) &&
					(() => {
						const inventory = parseMonitorInventoryV1(row.inventory_json);
						return (
							inventory.scopeId === row.inventory_scope_id &&
							inventory.inventoryEpochId === row.inventory_epoch_id &&
							inventory.monitorId === row.monitor_id &&
							inventory.kind === row.monitor_kind &&
							inventory.stableIdentifier === row.stable_identifier &&
							inventory.configHash === row.monitor_config_hash
						);
					})(),
				"monitor authorization projection mismatch",
			);
			authorizations.set(row.authorization_id, row);
		} catch {
			throw new BugwatchSchemaIntegrityError("INTEGRITY", "invalid monitor authorization envelope");
		}
	}
	const receiptAuthorizations = new Set<string>();
	for (const row of db
		.prepare<ReceiptAuthorityRow, []>(
			"SELECT authorization_id, scope_id, inventory_epoch_id, monitor_id, adapter_kind, action_hash, before_hash, after_hash, result, steps_json, covered_roots_json, receipt_json, started_at_ms, finished_at_ms, receipt_hash, key_id, mac FROM monitor_disable_receipts",
		)
		.all()) {
		try {
			const receipt = parseMonitorDisableReceiptV1(row.receipt_json);
			verifyMac(
				receipt as unknown as JsonValue,
				"gjc-bugwatch-monitor-disable-receipt-v1",
				authorityKey(keyForId, receipt.keyId),
			);
			const authorization = authorizations.get(row.authorization_id);
			authorityAssert(
				authorization !== undefined &&
					authorization.state === "consumed" &&
					authorization.consumed_at_ms === row.finished_at_ms &&
					receipt.scopeId === authorization.scope_id &&
					receipt.scopeId === row.scope_id &&
					receipt.authorizationId === row.authorization_id &&
					receipt.inventoryEpochId === row.inventory_epoch_id &&
					receipt.monitorId === row.monitor_id &&
					receipt.adapterKind === row.adapter_kind &&
					receipt.actionHash === row.action_hash &&
					receipt.beforeHash === row.before_hash &&
					receipt.afterHash === row.after_hash &&
					receipt.result === row.result &&
					receipt.keyId === row.key_id &&
					receipt.mac === row.mac &&
					receipt.startedAt === new Date(row.started_at_ms).toISOString() &&
					receipt.finishedAt === new Date(row.finished_at_ms).toISOString() &&
					canonicalizeJson(receipt.steps as unknown as JsonValue) === row.steps_json &&
					canonicalizeJson(receipt.coveredRootIds as unknown as JsonValue) === row.covered_roots_json &&
					authenticatedHash(receipt as unknown as JsonValue) === row.receipt_hash &&
					authorization.action_hash === row.action_hash &&
					(() => {
						if (authorization.inventory_json === null) return false;
						const inventory = parseMonitorInventoryV1(authorization.inventory_json);
						const coveredRoots = [...inventory.coveredRootIds].sort();
						return (
							receipt.scopeId === inventory.scopeId &&
							receipt.adapterKind === inventory.kind &&
							receipt.coveredRootIds.length === coveredRoots.length &&
							[...receipt.coveredRootIds].sort().every((rootId, index) => rootId === coveredRoots[index])
						);
					})(),
				"monitor receipt projection or consumption mismatch",
			);
			receiptAuthorizations.add(row.authorization_id);
		} catch (error) {
			if (error instanceof BugwatchSchemaIntegrityError) throw error;
			throw new BugwatchSchemaIntegrityError("INTEGRITY", "invalid monitor receipt envelope");
		}
	}
	for (const authorization of authorizations.values()) {
		const hasReceipt = receiptAuthorizations.has(authorization.authorization_id);
		authorityAssert(
			authorization.state === "consumed"
				? hasReceipt && authorization.consumed_at_ms !== null
				: !hasReceipt && authorization.consumed_at_ms === null,
			"monitor authorization and receipt are not a complete bijection",
		);
	}
}

export type BugwatchSchemaIncompatibilityKind = "OLDER_MAJOR" | "NEWER_MAJOR" | "OLDER_MINOR" | "NEWER_MINOR";

export class BugwatchSchemaIncompatibilityError extends Error {
	readonly name = "BugwatchSchemaIncompatibilityError";

	constructor(
		readonly kind: BugwatchSchemaIncompatibilityKind,
		readonly foundVersion: number,
		readonly supportedVersion: number,
	) {
		super(
			kind === "OLDER_MAJOR"
				? `Bugwatch database schema major ${foundVersion} is older than supported ${supportedVersion}`
				: kind === "NEWER_MAJOR"
					? `Bugwatch database schema major ${foundVersion} is newer than supported ${supportedVersion}`
					: kind === "OLDER_MINOR"
						? `Bugwatch database schema minor ${foundVersion} is older than supported ${supportedVersion}; an explicit migration is required`
						: `Bugwatch database schema minor ${foundVersion} is newer than supported ${supportedVersion}`,
		);
	}
}

export type BugwatchSchemaIntegrityKind = "SCHEMA_DRIFT" | "INTEGRITY";

export class BugwatchSchemaIntegrityError extends Error {
	readonly name = "BugwatchSchemaIntegrityError";

	constructor(
		readonly kind: BugwatchSchemaIntegrityKind,
		detail: string,
	) {
		super(`Bugwatch ${kind === "SCHEMA_DRIFT" ? "schema drift" : "integrity check failed"}: ${detail}`);
	}
}

type MinorSchemaMigration = {
	fromMinor: number;
	toMinor: number;
	apply: (db: Database, metadata: BugwatchSchemaMetadata) => void;
};

const BUGWATCH_MINOR_SCHEMA_MIGRATIONS: readonly MinorSchemaMigration[] = [
	{
		fromMinor: 0,
		toMinor: 1,
		apply: migrateMinorSchema0To1,
	},
	{
		fromMinor: 1,
		toMinor: 2,
		apply: migrateMinorSchema1To2,
	},
	{
		fromMinor: 2,
		toMinor: 3,
		apply: migrateMinorSchema2To3,
	},
	{
		fromMinor: 3,
		toMinor: 4,
		apply: migrateMinorSchema3To4,
	},
	{
		fromMinor: 4,
		toMinor: 5,
		apply: migrateMinorSchema4To5,
	},
	{
		fromMinor: 5,
		toMinor: 6,
		apply: migrateMinorSchema5To6,
	},
	{
		fromMinor: 6,
		toMinor: 7,
		apply: migrateMinorSchema6To7,
	},
	{
		fromMinor: 7,
		toMinor: 8,
		apply: migrateMinorSchema7To8,
	},
	{
		fromMinor: 8,
		toMinor: 9,
		apply: migrateMinorSchema8To9,
	},
	{
		fromMinor: 9,
		toMinor: 10,
		apply: migrateMinorSchema9To10,
	},
	{
		fromMinor: 10,
		toMinor: 11,
		apply: migrateMinorSchema10To11,
	},
	{
		fromMinor: 11,
		toMinor: 12,
		apply: migrateMinorSchema11To12,
	},
];

const EXPECTED_CATALOG = extractExpectedCatalog(BUGWATCH_SCHEMA_SQL);
const MINOR_1_ADDED_CATALOG_OBJECT_NAMES = new Set([
	"root_mutation_steps",
	"root_mutation_step_chain_insert",
	"root_mutation_step_immutable_insert",
	"root_mutation_step_immutable_update",
	"root_mutation_step_immutable_delete",
	"root_mutation_summary_insert",
	"root_mutation_summary_update",
]);
const EXPECTED_MINOR_1_CATALOG = EXPECTED_CATALOG.filter(entry => !MINOR_1_ADDED_CATALOG_OBJECT_NAMES.has(entry.name));

function assertMetadata(metadata: BugwatchSchemaMetadata): void {
	for (const value of [
		metadata.logSchemaVersion,
		metadata.redactionVersion,
		metadata.noiseVersion,
		metadata.severityVersion,
		metadata.fingerprintVersion,
		metadata.createdAtMs,
	]) {
		if (!Number.isSafeInteger(value) || value < 0) throw new Error("Invalid bugwatch schema metadata");
	}
	if (
		metadata.logSchemaVersion !== BUGWATCH_LOG_SCHEMA_VERSION ||
		metadata.redactionVersion !== BUGWATCH_REDACTION_VERSION ||
		metadata.noiseVersion !== BUGWATCH_NOISE_VERSION ||
		metadata.severityVersion !== BUGWATCH_SEVERITY_VERSION ||
		metadata.fingerprintVersion !== BUGWATCH_FINGERPRINT_VERSION ||
		metadata.fixtureManifestHash !== BUGWATCH_FIXTURE_MANIFEST_HASH
	) {
		throw new Error("Bugwatch schema metadata must match the compiled semantic contract");
	}
}

function extractExpectedCatalog(sql: string): readonly ExpectedCatalogEntry[] {
	const entries: ExpectedCatalogEntry[] = [];
	const expression = /CREATE\s+(TABLE|INDEX)\s+IF\s+NOT\s+EXISTS\s+([A-Za-z_][A-Za-z0-9_]*)\s+([\s\S]*?);/gi;
	for (const match of sql.matchAll(expression)) {
		const type = match[1].toLowerCase();
		if (type !== "table" && type !== "index") throw new Error("Invalid Bugwatch catalog entry");
		entries.push({ type, name: match[2], sql: `${match[0].slice(0, -1)}` });
	}
	const triggerExpression = /CREATE\s+TRIGGER\s+IF\s+NOT\s+EXISTS\s+([A-Za-z_][A-Za-z0-9_]*)\s+[\s\S]*?\bEND;/gi;
	for (const match of sql.matchAll(triggerExpression)) {
		entries.push({ type: "trigger", name: match[1], sql: `${match[0].slice(0, -1)}` });
	}
	return entries;
}

function normalizeCatalogSql(sql: string): string {
	let normalized = "";
	let index = 0;
	let pendingSpace = false;

	const append = (text: string): void => {
		if (pendingSpace && normalized.length > 0) normalized += " ";
		normalized += text;
		pendingSpace = false;
	};

	while (index < sql.length) {
		const character = sql[index];
		if (/\s/.test(character)) {
			pendingSpace = true;
			index += 1;
			continue;
		}
		if (character === "'" || character === '"' || character === "`" || character === "[") {
			const terminator = character === "[" ? "]" : character;
			let quoted = character;
			index += 1;
			while (index < sql.length) {
				const quotedCharacter = sql[index];
				quoted += quotedCharacter;
				index += 1;
				if (quotedCharacter !== terminator) continue;
				if (terminator !== "]" && sql[index] === terminator) {
					quoted += terminator;
					index += 1;
					continue;
				}
				break;
			}
			append(quoted);
			continue;
		}
		const ifNotExists = sql.slice(index).match(/^IF\s+NOT\s+EXISTS(?=\s)/i);
		if (ifNotExists !== null) {
			index += ifNotExists[0].length;
			pendingSpace = true;
			continue;
		}
		append(character);
		index += 1;
	}
	return normalized.trim();
}

function isStoreEmpty(db: Database): boolean {
	const row = db
		.prepare<{ count: number }, []>(
			"SELECT count(*) AS count FROM sqlite_master WHERE type IN ('table','index','trigger','view') AND name NOT LIKE 'sqlite_%'",
		)
		.get();
	return row?.count === 0;
}

function readCatalog(db: Database): readonly CatalogRow[] {
	return db
		.prepare<CatalogRow, []>(
			"SELECT type, name, sql FROM sqlite_master WHERE type IN ('table','index','trigger','view') AND name NOT LIKE 'sqlite_%' ORDER BY type, name",
		)
		.all();
}

function assertCatalogMatchesExpected(
	db: Database,
	expectedCatalog: readonly ExpectedCatalogEntry[],
	description: string,
): void {
	const actual = readCatalog(db);
	const expected = [...expectedCatalog].sort((left, right) =>
		`${left.type}:${left.name}`.localeCompare(`${right.type}:${right.name}`),
	);
	if (actual.length !== expected.length) {
		throw new BugwatchSchemaIntegrityError(
			"SCHEMA_DRIFT",
			`${description} object count differs from the approved contract`,
		);
	}
	for (const [index, expectedEntry] of expected.entries()) {
		const actualEntry = actual[index];
		if (
			actualEntry.type !== expectedEntry.type ||
			actualEntry.name !== expectedEntry.name ||
			actualEntry.sql === null ||
			normalizeCatalogSql(actualEntry.sql) !== normalizeCatalogSql(expectedEntry.sql)
		) {
			throw new BugwatchSchemaIntegrityError(
				"SCHEMA_DRIFT",
				`${description} object ${expectedEntry.type}:${expectedEntry.name} differs from the approved contract`,
			);
		}
	}
}

function assertCatalogMatches(db: Database): void {
	assertCatalogMatchesExpected(db, EXPECTED_CATALOG, "catalog");
}

function assertMinorSchema1CatalogMatches(db: Database): void {
	assertCatalogMatchesExpected(db, EXPECTED_MINOR_1_CATALOG, "legacy 1.1 catalog");
}

function assertStoreIntegrity(db: Database): void {
	const foreignKeyViolations = db.prepare("PRAGMA foreign_key_check").all();
	if (foreignKeyViolations.length > 0) {
		throw new BugwatchSchemaIntegrityError("INTEGRITY", "foreign_key_check reported violations");
	}
	const quickCheck = db.prepare<QuickCheckRow, []>("PRAGMA quick_check").get();
	if (quickCheck?.quick_check !== "ok") {
		throw new BugwatchSchemaIntegrityError("INTEGRITY", "quick_check did not return ok");
	}
}
function assertPolicyHeadEnvelopes(db: Database): void {
	const heads = db
		.prepare<PolicyHeadRow, []>(
			"SELECT scope_id, generation, revision_hash, content_hash, cas_token_hash, updated_at_ms, key_id, mac, head_json FROM scope_policy_heads",
		)
		.all();
	for (const head of heads) {
		let parsed: ScopePolicyHeadV2;
		try {
			parsed = parseScopePolicyHeadV2(head.head_json);
		} catch {
			throw new BugwatchSchemaIntegrityError(
				"INTEGRITY",
				"policy head envelope is not a canonical shared-contract envelope",
			);
		}
		if (
			parsed.scopeId !== head.scope_id ||
			parsed.generation !== head.generation ||
			parsed.revisionHash !== head.revision_hash ||
			parsed.contentHash !== head.content_hash ||
			parsed.updatedAt !== new Date(head.updated_at_ms).toISOString() ||
			parsed.keyId !== head.key_id ||
			parsed.mac !== head.mac
		) {
			throw new BugwatchSchemaIntegrityError("INTEGRITY", "policy head envelope projection mismatch");
		}
		const casTokenHash = new Bun.CryptoHasher("sha256").update(parsed.casToken).digest("hex");
		if (casTokenHash !== head.cas_token_hash) {
			throw new BugwatchSchemaIntegrityError("INTEGRITY", "policy head CAS token hash mismatch");
		}
	}
}
function assertRootMutationCores(db: Database): void {
	const mutations = db
		.prepare<RootMutationRow, []>(
			"SELECT mutation_id, scope_id, action, core_hash, core_json, expected_policy_generation, expected_policy_hash, old_root_id, new_root_id, phase, created_at_ms FROM root_mutations",
		)
		.all();
	for (const mutation of mutations) {
		let core: RootMutationCoreV1;
		try {
			core = parseRootMutationCoreV1(mutation.core_json);
		} catch {
			throw new BugwatchSchemaIntegrityError(
				"INTEGRITY",
				"root mutation core is not a canonical shared-contract envelope",
			);
		}
		if (canonicalizeJson(core as unknown as JsonValue) !== mutation.core_json) {
			throw new BugwatchSchemaIntegrityError("INTEGRITY", "root mutation core JSON is not canonical");
		}
		if (
			authenticatedHash(core as unknown as JsonValue) !== mutation.core_hash ||
			core.mutationId !== mutation.mutation_id ||
			core.scopeId !== mutation.scope_id ||
			core.action !== mutation.action ||
			core.expectedPolicyGeneration !== mutation.expected_policy_generation ||
			core.expectedPolicyHash !== mutation.expected_policy_hash ||
			core.oldRootId !== mutation.old_root_id ||
			core.newRootId !== mutation.new_root_id ||
			new Date(mutation.created_at_ms).toISOString() !== core.createdAt
		) {
			throw new BugwatchSchemaIntegrityError("INTEGRITY", "root mutation core projection or hash mismatch");
		}
	}
}

function hasMatchingSemanticMetadata(row: SchemaMetaRow, metadata: BugwatchSchemaMetadata): boolean {
	return (
		row.log_schema_version === metadata.logSchemaVersion &&
		row.redaction_version === metadata.redactionVersion &&
		row.noise_version === metadata.noiseVersion &&
		row.severity_version === metadata.severityVersion &&
		row.fingerprint_version === metadata.fingerprintVersion &&
		row.fixture_manifest_hash === metadata.fixtureManifestHash &&
		row.schema_catalog_hash === BUGWATCH_SCHEMA_CATALOG_HASH
	);
}

function migrateMinorSchema(db: Database, schemaMinor: number, metadata: BugwatchSchemaMetadata): void {
	let currentMinor = schemaMinor;
	while (currentMinor < BUGWATCH_SCHEMA_MINOR) {
		const migration = BUGWATCH_MINOR_SCHEMA_MIGRATIONS.find(
			candidate => candidate.fromMinor === currentMinor && candidate.toMinor === currentMinor + 1,
		);
		if (migration === undefined) {
			throw new BugwatchSchemaIncompatibilityError("OLDER_MINOR", schemaMinor, BUGWATCH_SCHEMA_MINOR);
		}
		db.exec("BEGIN IMMEDIATE");
		try {
			migration.apply(db, metadata);
			currentMinor = migration.toMinor;
			db.prepare(
				"UPDATE schema_meta SET schema_minor = ?, schema_catalog_hash = ?, migrated_at_ms = ? WHERE id = 1",
			).run(currentMinor, BUGWATCH_SCHEMA_CATALOG_HASH, metadata.createdAtMs);
			db.exec("COMMIT");
		} catch (error: unknown) {
			db.exec("ROLLBACK");
			throw error;
		}
	}
}

function migrateMinorSchema0To1(db: Database, _metadata: BugwatchSchemaMetadata): void {
	let rollbackItemCount: number | undefined;
	let invalidMemberCount: number | undefined;
	try {
		rollbackItemCount = db
			.prepare<{ count: number }, []>("SELECT count(*) AS count FROM rollback_items")
			.get()?.count;
		invalidMemberCount = db
			.prepare<{ count: number }, []>(
				`SELECT count(*) AS count
				 FROM store_operation_members AS current
				 LEFT JOIN store_operation_members AS other
				   ON other.operation_id=current.operation_id AND other.member>current.member
				 WHERE current.source_path_hash=current.quarantine_path_hash
				    OR (
				     other.operation_id IS NOT NULL AND (
				      current.source_path_hash=other.source_path_hash OR
				      current.source_path_hash=other.quarantine_path_hash OR
				      current.quarantine_path_hash=other.source_path_hash OR
				      current.quarantine_path_hash=other.quarantine_path_hash
				     )
				    )`,
			)
			.get()?.count;
	} catch {
		throw new BugwatchSchemaIncompatibilityError("OLDER_MINOR", 0, BUGWATCH_SCHEMA_MINOR);
	}
	if (rollbackItemCount === undefined) {
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "legacy rollback_items table is unreadable");
	}
	if (rollbackItemCount > 0) {
		throw new BugwatchSchemaIntegrityError(
			"SCHEMA_DRIFT",
			"legacy rollback items cannot prove mandatory payload hash and byte bindings",
		);
	}
	if (invalidMemberCount === undefined) {
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "legacy store_operation_members table is unreadable");
	}
	if (invalidMemberCount > 0) {
		throw new BugwatchSchemaIntegrityError(
			"SCHEMA_DRIFT",
			"legacy store operation member paths violate the active contract",
		);
	}
	db.exec(`
		ALTER TABLE rollback_items RENAME TO rollback_items_legacy;
		CREATE TABLE rollback_items (
			epoch_id TEXT NOT NULL REFERENCES rollback_epochs(epoch_id), item_index INTEGER NOT NULL CHECK(item_index>=0), item_type TEXT NOT NULL,
			item_hash TEXT NOT NULL, payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64 AND payload_hash NOT GLOB '*[^0-9a-f]*'),
			payload_byte_count INTEGER NOT NULL CHECK(payload_byte_count>=0), state TEXT NOT NULL CHECK(state IN('pending','applied','duplicate','failed')),
			payload BLOB NOT NULL CHECK(payload_byte_count=length(payload)), PRIMARY KEY(epoch_id,item_index)
		) STRICT;
		DROP TABLE rollback_items_legacy;
		ALTER TABLE store_operation_members RENAME TO store_operation_members_legacy;
		CREATE TABLE store_operation_members (
			operation_id TEXT NOT NULL REFERENCES store_operations(operation_id) ON DELETE CASCADE,
			member TEXT NOT NULL CHECK(member IN('db','wal','shm')), source_path_hash TEXT NOT NULL,
			expected_presence INTEGER NOT NULL CHECK(expected_presence IN(0,1)), expected_size INTEGER, expected_hash TEXT,
			quarantine_path_hash TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN('pending','intent_recorded','moved','verified_absent','mismatch','conflict')),
			observed_source_hash TEXT, observed_quarantine_hash TEXT, updated_at_ms INTEGER NOT NULL,
			PRIMARY KEY(operation_id,member), CHECK(source_path_hash<>quarantine_path_hash)
		) STRICT;
		INSERT INTO store_operation_members(
			operation_id, member, source_path_hash, expected_presence, expected_size, expected_hash,
			quarantine_path_hash, state, observed_source_hash, observed_quarantine_hash, updated_at_ms
		)
		SELECT
			operation_id, member, source_path_hash, expected_presence, expected_size, expected_hash,
			quarantine_path_hash, state, observed_source_hash, observed_quarantine_hash, updated_at_ms
		FROM store_operation_members_legacy;
		DROP TABLE store_operation_members_legacy;
		CREATE TRIGGER store_operation_member_paths_insert
		BEFORE INSERT ON store_operation_members
		WHEN EXISTS(
			SELECT 1 FROM store_operation_members AS existing
			WHERE existing.operation_id=NEW.operation_id
				AND (
					existing.source_path_hash=NEW.source_path_hash OR
					existing.source_path_hash=NEW.quarantine_path_hash OR
					existing.quarantine_path_hash=NEW.source_path_hash OR
					existing.quarantine_path_hash=NEW.quarantine_path_hash
				)
		)
		BEGIN
			SELECT RAISE(ABORT, 'store operation member paths must be distinct');
		END;
		CREATE TRIGGER store_operation_member_identity_immutable_update
		BEFORE UPDATE OF operation_id, member, source_path_hash, quarantine_path_hash ON store_operation_members
		WHEN NEW.operation_id!=OLD.operation_id OR NEW.member!=OLD.member
			OR NEW.source_path_hash!=OLD.source_path_hash OR NEW.quarantine_path_hash!=OLD.quarantine_path_hash
		BEGIN
			SELECT RAISE(ABORT, 'store operation member identities are immutable');
		END;
		CREATE INDEX idx_store_member_state ON store_operation_members(state, updated_at_ms);
	`);
}
function migrateMinorSchema1To2(db: Database, _metadata: BugwatchSchemaMetadata): void {
	assertMinorSchema1CatalogMatches(db);
	const mutationCount = db.prepare<{ count: number }, []>("SELECT count(*) AS count FROM root_mutations").get()?.count;
	if (mutationCount === undefined)
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "legacy root_mutations table is unreadable");
	if (mutationCount > 0)
		throw new BugwatchSchemaIntegrityError(
			"SCHEMA_DRIFT",
			"legacy root mutations cannot prove mandatory immutable phase-chain evidence",
		);
	db.exec(`
		CREATE TABLE root_mutation_steps (
			scope_id TEXT NOT NULL, mutation_id TEXT NOT NULL, core_hash TEXT NOT NULL,
			step_index INTEGER NOT NULL CHECK(step_index>=0),
			phase TEXT NOT NULL CHECK(phase IN('prepared','publishing','files_published','db_applied','baseline_complete','files_finalized','committed','aborted','conflict')),
			previous_phase TEXT CHECK(previous_phase IS NULL OR previous_phase IN('prepared','publishing','files_published','db_applied','baseline_complete','files_finalized','committed','aborted','conflict')),
			previous_state_hash TEXT, key_id TEXT NOT NULL, mac TEXT NOT NULL, record_hash TEXT NOT NULL,
			created_at_ms INTEGER NOT NULL, recorded_at_ms INTEGER NOT NULL,
			PRIMARY KEY(scope_id,mutation_id,step_index), UNIQUE(record_hash),
			UNIQUE(scope_id,mutation_id,core_hash,phase,record_hash),
			CHECK((step_index=0 AND previous_phase IS NULL AND previous_state_hash IS NULL) OR
				(step_index>0 AND previous_phase IS NOT NULL AND previous_state_hash IS NOT NULL)),
			CHECK(recorded_at_ms>=created_at_ms)
		) STRICT;
		CREATE TRIGGER root_mutation_step_chain_insert
		BEFORE INSERT ON root_mutation_steps
		WHEN
			(NEW.step_index=0 AND NEW.phase!='prepared') OR
			(NEW.step_index>0 AND NOT EXISTS(
				SELECT 1 FROM root_mutation_steps AS predecessor
				WHERE predecessor.scope_id=NEW.scope_id
					AND predecessor.mutation_id=NEW.mutation_id
					AND predecessor.core_hash=NEW.core_hash
					AND predecessor.step_index=NEW.step_index-1
					AND predecessor.phase=NEW.previous_phase
					AND predecessor.record_hash=NEW.previous_state_hash
			)) OR
			(NEW.step_index>0 AND NOT EXISTS(
				SELECT 1 FROM root_mutation_steps AS predecessor
				WHERE predecessor.scope_id=NEW.scope_id
					AND predecessor.mutation_id=NEW.mutation_id
					AND predecessor.step_index=NEW.step_index-1
					AND (
						(predecessor.phase='prepared' AND NEW.phase IN('publishing','aborted','conflict')) OR
						(predecessor.phase='publishing' AND NEW.phase IN('files_published','aborted','conflict')) OR
						(predecessor.phase='files_published' AND NEW.phase IN('db_applied','conflict')) OR
						(predecessor.phase='db_applied' AND NEW.phase IN('baseline_complete','conflict')) OR
						(predecessor.phase='baseline_complete' AND NEW.phase IN('files_finalized','conflict')) OR
						(predecessor.phase='files_finalized' AND NEW.phase IN('committed','conflict'))
					)
			))
		BEGIN
			SELECT RAISE(ABORT, 'root mutation step phase chain mismatch');
		END;
		CREATE TRIGGER root_mutation_step_immutable_insert
		BEFORE INSERT ON root_mutation_steps
		WHEN EXISTS(
			SELECT 1 FROM root_mutation_steps AS existing
			WHERE existing.scope_id=NEW.scope_id AND existing.mutation_id=NEW.mutation_id AND existing.step_index=NEW.step_index
		)
		BEGIN
			SELECT RAISE(ABORT, 'root mutation steps are immutable');
		END;
		CREATE TRIGGER root_mutation_step_immutable_update
		BEFORE UPDATE ON root_mutation_steps
		BEGIN
			SELECT RAISE(ABORT, 'root mutation steps are immutable');
		END;
		CREATE TRIGGER root_mutation_step_immutable_delete
		BEFORE DELETE ON root_mutation_steps
		BEGIN
			SELECT RAISE(ABORT, 'root mutation steps are immutable');
		END;
		CREATE TRIGGER root_mutation_summary_insert
		BEFORE INSERT ON root_mutations
		WHEN NOT EXISTS(
			SELECT 1 FROM root_mutation_steps AS step
			WHERE step.scope_id=NEW.scope_id
				AND step.mutation_id=NEW.mutation_id
				AND step.core_hash=NEW.core_hash
				AND step.phase=NEW.phase
				AND step.record_hash=NEW.current_step_hash
				AND step.step_index=NEW.step_index
				AND NOT EXISTS(
					SELECT 1 FROM root_mutation_steps AS successor
					WHERE successor.scope_id=step.scope_id
						AND successor.mutation_id=step.mutation_id
						AND successor.step_index=step.step_index+1
				)
		)
		BEGIN
			SELECT RAISE(ABORT, 'root mutation summary terminal step mismatch');
		END;
		CREATE TRIGGER root_mutation_summary_update
		BEFORE UPDATE ON root_mutations
		WHEN NOT EXISTS(
			SELECT 1 FROM root_mutation_steps AS step
			WHERE step.scope_id=NEW.scope_id
				AND step.mutation_id=NEW.mutation_id
				AND step.core_hash=NEW.core_hash
				AND step.phase=NEW.phase
				AND step.record_hash=NEW.current_step_hash
				AND step.step_index=NEW.step_index
				AND NOT EXISTS(
					SELECT 1 FROM root_mutation_steps AS successor
					WHERE successor.scope_id=step.scope_id
						AND successor.mutation_id=step.mutation_id
						AND successor.step_index=step.step_index+1
				)
		)
		BEGIN
			SELECT RAISE(ABORT, 'root mutation summary terminal step mismatch');
		END;
	`);
}
function migrateMinorSchema3To4(db: Database, _metadata: BugwatchSchemaMetadata): void {
	const mutationCount = db.prepare<{ count: number }, []>("SELECT count(*) AS count FROM root_mutations").get()?.count;
	if (mutationCount === undefined)
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "legacy root_mutations table is unreadable");
	if (mutationCount > 0) {
		throw new BugwatchSchemaIntegrityError(
			"SCHEMA_DRIFT",
			"legacy root mutations lack mandatory canonical authenticated core bytes",
		);
	}
	const outputCount = db
		.prepare<{ count: number }, []>("SELECT count(*) AS count FROM root_mutation_outputs")
		.get()?.count;
	if (outputCount === undefined)
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "legacy root_mutation_outputs table is unreadable");
	if (outputCount > 0)
		throw new BugwatchSchemaIntegrityError(
			"SCHEMA_DRIFT",
			"legacy root mutation outputs have no retained core authority",
		);
	db.exec(`
		DROP TRIGGER IF EXISTS root_mutation_summary_insert;
		DROP TRIGGER IF EXISTS root_mutation_summary_update;
		ALTER TABLE root_mutation_outputs RENAME TO root_mutation_outputs_legacy;
		ALTER TABLE root_mutations RENAME TO root_mutations_legacy;
		CREATE TABLE root_mutations (
			mutation_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN('enable','disable','set_context','move')),
			core_hash TEXT NOT NULL UNIQUE CHECK(length(core_hash)=64 AND core_hash NOT GLOB '*[^0-9a-f]*'), core_json TEXT NOT NULL CHECK(json_valid(core_json)),
			expected_policy_generation INTEGER NOT NULL CHECK(expected_policy_generation>=1), expected_policy_hash TEXT NOT NULL CHECK(length(expected_policy_hash)=64 AND expected_policy_hash NOT GLOB '*[^0-9a-f]*'),
			old_root_id TEXT REFERENCES roots(root_id), new_root_id TEXT REFERENCES roots(root_id),
			phase TEXT NOT NULL CHECK(phase IN('prepared','publishing','files_published','db_applied','baseline_complete','files_finalized','committed','aborted','conflict')),
			step_index INTEGER NOT NULL, current_step_hash TEXT NOT NULL, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
		) STRICT;
		DROP TABLE root_mutation_outputs_legacy;
		DROP TABLE root_mutations_legacy;
	`);
	db.exec(BUGWATCH_SCHEMA_SQL);
}
function migrateMinorSchema4To5(db: Database, _metadata: BugwatchSchemaMetadata): void {
	const authoritativeTables = [
		"roots",
		"producer_boots",
		"session_attachments",
		"attachment_transitions",
		"rollback_epochs",
		"rollback_items",
		"old_monitors",
		"monitor_disable_authorizations",
		"monitor_disable_receipts",
		"legacy_disable_receipts",
		"store_operations",
		"store_operation_members",
		"job_inputs",
		"triage_results",
		"artifact_outbox",
	] as const;
	for (const table of authoritativeTables) {
		const count = db.prepare<{ count: number }, []>(`SELECT count(*) AS count FROM ${table}`).get()?.count;
		if (count === undefined)
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		if (count > 0)
			throw new BugwatchSchemaIntegrityError(
				"SCHEMA_DRIFT",
				`legacy ${table} rows lack mandatory lossless canonical authority`,
			);
	}
	for (const table of [...BUGWATCH_PERSISTED_TABLE_NAMES].reverse()) {
		if (table !== "schema_meta") db.exec(`DROP TABLE ${table}`);
	}
	db.exec(BUGWATCH_SCHEMA_SQL);
}
function migrateMinorSchema5To6(db: Database, _metadata: BugwatchSchemaMetadata): void {
	const authoritativeTables = [
		"attachment_transitions",
		"rollback_items",
		"monitor_disable_authorizations",
		"job_inputs",
		"triage_results",
		"artifact_outbox",
		"manual_artifacts",
	] as const;
	for (const table of authoritativeTables) {
		let count: number | undefined;
		try {
			count = db.prepare<{ count: number }, []>(`SELECT count(*) AS count FROM ${table}`).get()?.count;
		} catch {
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		}
		if (count === undefined)
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		if (count > 0)
			throw new BugwatchSchemaIntegrityError(
				"SCHEMA_DRIFT",
				`legacy ${table} rows lack mandatory signed or lossless content authority`,
			);
	}
	for (const table of [...BUGWATCH_PERSISTED_TABLE_NAMES].reverse()) {
		if (table !== "schema_meta") db.exec(`DROP TABLE ${table}`);
	}
	db.exec(BUGWATCH_SCHEMA_SQL);
}
function migrateMinorSchema6To7(db: Database, _metadata: BugwatchSchemaMetadata): void {
	let transitionCount: number | undefined;
	try {
		transitionCount = db
			.prepare<{ count: number }, []>("SELECT count(*) AS count FROM attachment_transitions")
			.get()?.count;
	} catch {
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "legacy attachment_transitions table is unreadable");
	}
	if (transitionCount === undefined)
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "legacy attachment_transitions table is unreadable");
	if (transitionCount > 0)
		throw new BugwatchSchemaIntegrityError(
			"SCHEMA_DRIFT",
			"legacy attachment transitions lack mandatory authenticated key and MAC bytes",
		);
	db.exec(`
		DROP TRIGGER IF EXISTS attachment_transition_immutable_update;
		DROP TRIGGER IF EXISTS attachment_transition_immutable_delete;
		DROP TABLE attachment_transitions;
	`);
	db.exec(BUGWATCH_SCHEMA_SQL);
}
function migrateMinorSchema7To8(db: Database, _metadata: BugwatchSchemaMetadata): void {
	const tableNames = ["root_mutation_rename_steps", "monitor_disable_authorizations"] as const;
	for (const table of tableNames) {
		let count: number | undefined;
		try {
			count = db.prepare<{ count: number }, []>(`SELECT count(*) AS count FROM ${table}`).get()?.count;
		} catch {
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		}
		if (count === undefined)
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		if (count > 0)
			throw new BugwatchSchemaIntegrityError(
				"SCHEMA_DRIFT",
				`legacy ${table} rows lack mandatory authenticated transition authority`,
			);
	}
	let invalidRootCount: number | undefined;
	try {
		invalidRootCount = db
			.prepare<{ count: number }, []>(
				`SELECT count(*) AS count FROM roots
				 WHERE json_extract(root_json,'$.schema')!='gjc-bugwatch-root/v1'
				    OR json_extract(root_json,'$.rootId')!=root_id
				    OR json_extract(root_json,'$.canonicalPath') IS NOT canonical_path
				    OR json_type(root_json,'$.keyId') IS NULL
				    OR json_type(root_json,'$.mac') IS NULL
				    OR json_extract(root_json,'$.enabled')!=enabled
				    OR json_extract(root_json,'$.persistContext')!=persist_context
				    OR json_extract(root_json,'$.generation')!=revision
				    OR json_extract(root_json,'$.projectPolicyHash')!=project_policy_hash
				    OR json_extract(root_json,'$.baselineEpochId') IS NOT baseline_epoch_id
				    OR json_extract(root_json,'$.activeMutationId') IS NOT active_mutation_id
				    OR (enabled=1 AND disabled_at_ms IS NOT NULL)
				    OR (enabled=0 AND disabled_at_ms IS NULL)`,
			)
			.get()?.count;
	} catch {
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "legacy roots table is unreadable");
	}
	if (invalidRootCount === undefined)
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "legacy roots table is unreadable");
	if (invalidRootCount > 0)
		throw new BugwatchSchemaIntegrityError(
			"SCHEMA_DRIFT",
			"legacy roots lack mandatory canonical authenticated revision projections",
		);
	db.exec(`
		DROP TRIGGER IF EXISTS root_authority_projection_insert;
		DROP TRIGGER IF EXISTS root_authority_immutable_update;
		DROP TRIGGER IF EXISTS root_authority_revision_cas;
		DROP TRIGGER IF EXISTS monitor_authorization_authority_projection_insert;
		DROP TRIGGER IF EXISTS monitor_authorization_immutable_update;
		DROP TRIGGER IF EXISTS monitor_authorization_consume_cas;
		DROP TRIGGER IF EXISTS monitor_authorization_immutable_delete;
		DROP TRIGGER IF EXISTS monitor_authorization_projection_insert;
		DROP TABLE root_mutation_rename_steps;
	`);
	db.exec(BUGWATCH_SCHEMA_SQL);
}
function migrateMinorSchema8To9(db: Database, _metadata: BugwatchSchemaMetadata): void {
	const authoritativeTables = [
		"roots",
		"root_mutations",
		"root_mutation_steps",
		"root_mutation_rename_steps",
		"monitor_disable_authorizations",
		"monitor_disable_receipts",
	] as const;
	for (const table of authoritativeTables) {
		let count: number | undefined;
		try {
			count = db.prepare<{ count: number }, []>(`SELECT count(*) AS count FROM ${table}`).get()?.count;
		} catch {
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		}
		if (count === undefined)
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		if (count > 0)
			throw new BugwatchSchemaIntegrityError(
				"SCHEMA_DRIFT",
				`legacy ${table} rows cannot prove schema-1.9 persisted authority binding`,
			);
	}
	db.exec(`
		DROP TRIGGER IF EXISTS root_authority_projection_insert;
		DROP TRIGGER IF EXISTS root_authority_revision_cas;
		DROP TRIGGER IF EXISTS monitor_authorization_authority_projection_insert;
		DROP TRIGGER IF EXISTS monitor_authorization_consume_cas;
		DROP TRIGGER IF EXISTS monitor_authorization_immutable_delete;
		DROP TRIGGER IF EXISTS monitor_receipt_consume_authorization;
		DROP TRIGGER IF EXISTS monitor_receipt_consume_authorization_after;
		DROP TABLE monitor_disable_receipts;
		DROP TABLE monitor_disable_authorizations;
		DROP TABLE root_mutation_rename_steps;
	`);
	db.exec(BUGWATCH_SCHEMA_SQL);
}
function migrateMinorSchema9To10(db: Database, _metadata: BugwatchSchemaMetadata): void {
	for (const table of ["monitor_disable_authorizations", "monitor_disable_receipts"] as const) {
		let count: number | undefined;
		try {
			count = db.prepare<{ count: number }, []>(`SELECT count(*) AS count FROM ${table}`).get()?.count;
		} catch {
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		}
		if (count === undefined)
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		if (count > 0)
			throw new BugwatchSchemaIntegrityError(
				"SCHEMA_DRIFT",
				`legacy ${table} rows cannot prove receipt-backed schema-1.10 consumption`,
			);
	}
	db.exec(`
		DROP TRIGGER IF EXISTS monitor_authorization_authority_projection_insert;
		DROP TRIGGER IF EXISTS monitor_authorization_consume_cas;
		DROP TRIGGER IF EXISTS monitor_authorization_immutable_delete;
		DROP TRIGGER IF EXISTS monitor_receipt_consume_authorization;
		DROP TRIGGER IF EXISTS monitor_receipt_consume_authorization_after;
	`);
	db.exec(BUGWATCH_SCHEMA_SQL);
}
function migrateMinorSchema11To12(db: Database, _metadata: BugwatchSchemaMetadata): void {
	const authorityTables = [
		"roots",
		"root_mutations",
		"root_mutation_steps",
		"root_mutation_outputs",
		"root_mutation_rename_steps",
		"monitor_disable_authorizations",
		"monitor_disable_receipts",
	] as const;
	for (const table of authorityTables) {
		let count: number | undefined;
		try {
			count = db.prepare<{ count: number }, []>(`SELECT count(*) AS count FROM ${table}`).get()?.count;
		} catch {
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		}
		if (count === undefined)
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		if (count > 0)
			throw new BugwatchSchemaIntegrityError(
				"SCHEMA_DRIFT",
				`legacy ${table} rows cannot prove schema-1.12 durable authority bindings`,
			);
	}
	db.exec(`
		DROP TRIGGER IF EXISTS root_authority_projection_insert;
		DROP TRIGGER IF EXISTS root_authority_revision_cas;
		DROP TABLE roots;
		DROP TRIGGER IF EXISTS monitor_authorization_authority_projection_insert;
		DROP TRIGGER IF EXISTS monitor_authorization_consume_cas;
		DROP TRIGGER IF EXISTS monitor_authorization_immutable_delete;
		DROP TRIGGER IF EXISTS monitor_authorization_projection_insert;
		DROP TRIGGER IF EXISTS monitor_receipt_consume_authorization;
		DROP TRIGGER IF EXISTS monitor_receipt_consume_authorization_after;
		DROP TRIGGER IF EXISTS monitor_receipt_projection_insert;
		DROP TRIGGER IF EXISTS monitor_receipt_immutable_update;
		DROP TRIGGER IF EXISTS monitor_receipt_immutable_delete;
		DROP TABLE monitor_disable_receipts;
		DROP TABLE monitor_disable_authorizations;
	`);
	db.exec(BUGWATCH_SCHEMA_SQL);
}
function migrateMinorSchema10To11(db: Database, _metadata: BugwatchSchemaMetadata): void {
	for (const table of ["roots", "monitor_disable_authorizations", "monitor_disable_receipts"] as const) {
		let count: number | undefined;
		try {
			count = db.prepare<{ count: number }, []>(`SELECT count(*) AS count FROM ${table}`).get()?.count;
		} catch {
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		}
		if (count === undefined)
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy ${table} table is unreadable`);
		if (count > 0)
			throw new BugwatchSchemaIntegrityError(
				"SCHEMA_DRIFT",
				`legacy ${table} rows cannot prove schema-1.11 reserved-root and receipt authority bindings`,
			);
	}
	db.exec(`
		DROP TRIGGER IF EXISTS root_authority_projection_insert;
		DROP TRIGGER IF EXISTS root_authority_revision_cas;
		DROP TABLE roots;
	`);
	db.exec(BUGWATCH_SCHEMA_SQL);
}

function assertMinorSchema2TablesPresent(db: Database): void {
	const tableNames = new Set(
		readCatalog(db)
			.filter(entry => entry.type === "table")
			.map(entry => entry.name),
	);
	for (const tableName of BUGWATCH_PERSISTED_TABLE_NAMES)
		if (!tableNames.has(tableName))
			throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", `legacy 1.2 table ${tableName} is missing`);
}
function migrateMinorSchema2To3(db: Database, _metadata: BugwatchSchemaMetadata): void {
	assertMinorSchema2TablesPresent(db);
	const headCount = db.prepare<{ count: number }, []>("SELECT count(*) AS count FROM scope_policy_heads").get()?.count;
	if (headCount === undefined) {
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "legacy scope_policy_heads table is unreadable");
	}
	if (headCount > 0) {
		throw new BugwatchSchemaIntegrityError(
			"SCHEMA_DRIFT",
			"legacy policy heads cannot reconstruct their authenticated raw CAS tokens",
		);
	}
	db.exec(`
		DROP TRIGGER scope_policy_head_insert;
		DROP TRIGGER scope_policy_head_immutable_insert;
		DROP TRIGGER scope_policy_head_cas;
		DROP TRIGGER scope_policy_head_immutable_delete;
		DROP TABLE scope_policy_heads;
	`);
	db.exec(BUGWATCH_SCHEMA_SQL);
}
function readSchemaVersion(db: Database): SchemaVersionRow {
	try {
		const row = db
			.prepare<SchemaVersionRow, []>("SELECT schema_major, schema_minor FROM schema_meta WHERE id = 1")
			.get();
		if (row === null) throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "schema_meta row is missing");
		return row;
	} catch (error: unknown) {
		if (error instanceof BugwatchSchemaIntegrityError) throw error;
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "schema_meta version columns are missing or unreadable");
	}
}

function readSchemaMetadata(db: Database): SchemaMetaRow {
	const row = db
		.prepare<SchemaMetaRow, []>(
			"SELECT schema_major, schema_minor, log_schema_version, redaction_version, noise_version, severity_version, fingerprint_version, fixture_manifest_hash, schema_catalog_hash FROM schema_meta WHERE id = 1",
		)
		.get();
	if (row === null) throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "schema_meta row is missing");
	return row;
}

/**
 * Installs the literal Phase-0 authority schema. Existing stores are validated
 * without DDL or data writes; migration/rebuild workflows must explicitly own
 * backup and quarantine before changing an existing catalog.
 */
export function migrateBugwatchSchema(db: Database, metadata: BugwatchSchemaMetadata): void {
	assertMetadata(metadata);
	db.exec("PRAGMA foreign_keys = ON");
	db.exec("PRAGMA recursive_triggers = ON");
	if (isStoreEmpty(db)) {
		db.exec("PRAGMA journal_mode = WAL");
		db.exec("PRAGMA synchronous = FULL");
		db.exec("BEGIN IMMEDIATE");
		try {
			db.exec(BUGWATCH_SCHEMA_SQL);
			db.prepare(
				"INSERT INTO schema_meta(id, schema_major, schema_minor, log_schema_version, redaction_version, noise_version, severity_version, fingerprint_version, fixture_manifest_hash, schema_catalog_hash, created_at_ms, migrated_at_ms) VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			).run(
				BUGWATCH_SCHEMA_MAJOR,
				BUGWATCH_SCHEMA_MINOR,
				metadata.logSchemaVersion,
				metadata.redactionVersion,
				metadata.noiseVersion,
				metadata.severityVersion,
				metadata.fingerprintVersion,
				metadata.fixtureManifestHash,
				BUGWATCH_SCHEMA_CATALOG_HASH,
				metadata.createdAtMs,
				metadata.createdAtMs,
			);
			db.exec("COMMIT");
		} catch (error: unknown) {
			db.exec("ROLLBACK");
			throw error;
		}
		return;
	}

	const catalog = readCatalog(db);
	if (!catalog.some(entry => entry.type === "table" && entry.name === "schema_meta")) {
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "schema_meta table is missing");
	}
	const version = readSchemaVersion(db);
	if (version.schema_major > BUGWATCH_SCHEMA_MAJOR) {
		throw new BugwatchSchemaIncompatibilityError("NEWER_MAJOR", version.schema_major, BUGWATCH_SCHEMA_MAJOR);
	}
	if (version.schema_major < BUGWATCH_SCHEMA_MAJOR) {
		throw new BugwatchSchemaIncompatibilityError("OLDER_MAJOR", version.schema_major, BUGWATCH_SCHEMA_MAJOR);
	}
	if (version.schema_minor > BUGWATCH_SCHEMA_MINOR) {
		throw new BugwatchSchemaIncompatibilityError("NEWER_MINOR", version.schema_minor, BUGWATCH_SCHEMA_MINOR);
	}
	if (version.schema_minor < BUGWATCH_SCHEMA_MINOR) {
		migrateMinorSchema(db, version.schema_minor, metadata);
	}
	assertCatalogMatches(db);
	const existing = readSchemaMetadata(db);
	if (!hasMatchingSemanticMetadata(existing, metadata)) {
		throw new BugwatchSchemaIntegrityError("SCHEMA_DRIFT", "schema metadata does not match the active contract");
	}
	assertStoreIntegrity(db);
	assertPolicyHeadEnvelopes(db);
	assertRootMutationCores(db);
}
