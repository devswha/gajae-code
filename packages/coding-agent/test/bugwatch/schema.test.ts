import { Database } from "bun:sqlite";
import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	AUTHORITY_CLASS_NAMES,
	AUTHORITY_LOGICAL_SOURCE_MAPPING,
	authenticatedHash,
	canonicalizeJson,
	hmacSha256Hex,
	type JsonValue,
	macPayload,
	parseAttachmentV1,
	parseRootMutationCoreV1,
	parseScopePolicyHeadV2,
	BUGWATCH_FINGERPRINT_VERSION as SHARED_BUGWATCH_FINGERPRINT_VERSION,
	BUGWATCH_FIXTURE_MANIFEST_HASH as SHARED_BUGWATCH_FIXTURE_MANIFEST_HASH,
	BUGWATCH_LOG_SCHEMA_VERSION as SHARED_BUGWATCH_LOG_SCHEMA_VERSION,
	BUGWATCH_NOISE_VERSION as SHARED_BUGWATCH_NOISE_VERSION,
	BUGWATCH_REDACTION_VERSION as SHARED_BUGWATCH_REDACTION_VERSION,
	BUGWATCH_SCHEMA_CATALOG_HASH as SHARED_BUGWATCH_SCHEMA_CATALOG_HASH,
	BUGWATCH_SCHEMA_MAJOR as SHARED_BUGWATCH_SCHEMA_MAJOR,
	BUGWATCH_SCHEMA_MINOR as SHARED_BUGWATCH_SCHEMA_MINOR,
	BUGWATCH_SEVERITY_VERSION as SHARED_BUGWATCH_SEVERITY_VERSION,
} from "@gajae-code/utils/bugwatch-contract";
import {
	BugwatchSchemaIncompatibilityError,
	BugwatchSchemaIntegrityError,
	type BugwatchSchemaMetadata,
	createBugwatchSchemaMetadata,
	migrateBugwatchSchema,
	validateBugwatchPersistedAuthorities,
} from "../../src/bugwatch/migrations";
import {
	BUGWATCH_FINGERPRINT_VERSION,
	BUGWATCH_FIXTURE_MANIFEST_HASH,
	BUGWATCH_LOG_SCHEMA_VERSION,
	BUGWATCH_NOISE_VERSION,
	BUGWATCH_PERSISTED_TABLE_NAMES,
	BUGWATCH_REDACTION_VERSION,
	BUGWATCH_SCHEMA_CATALOG_HASH,
	BUGWATCH_SCHEMA_HELPER_TABLE_MAPPING,
	BUGWATCH_SCHEMA_MAJOR,
	BUGWATCH_SCHEMA_MINOR,
	BUGWATCH_SCHEMA_SQL,
	BUGWATCH_SEVERITY_VERSION,
} from "../../src/bugwatch/schema";

const metadata: BugwatchSchemaMetadata = createBugwatchSchemaMetadata(1_700_000_000_000);

const temporaryDirectories: string[] = [];

async function createDatabase(): Promise<{ db: Database; directory: string }> {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-bugwatch-schema-"));
	temporaryDirectories.push(directory);
	return { db: new Database(path.join(directory, "authority.sqlite")), directory };
}

function installRawSchema(db: Database, sql: string): void {
	db.exec("PRAGMA foreign_keys = ON");
	db.exec(sql);
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
}

afterEach(async () => {
	await Promise.all(
		temporaryDirectories.splice(0).map(directory => fs.rm(directory, { recursive: true, force: true })),
	);
});

type CountRow = { count: number };
type MetaRow = {
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
type VersionMetaRow = {
	schema_major: number;
	schema_minor: number;
	log_schema_version: number;
	fixture_manifest_hash: string;
	schema_catalog_hash: string;
};
type ForeignKeyRow = { foreign_keys: number };
type RecursiveTriggerRow = { recursive_triggers: number };
type TableRow = { name: string };

function insertSource(db: Database, generation: number): void {
	db.prepare(
		"INSERT INTO sources(segment_id, generation, source_kind, path, file_identity_hint, prefix_anchor_length, prefix_hash, committed_offset, checkpoint_digest, validation_state, state, updated_at_ms) VALUES(?, ?, 'log', '/tmp/log', 'hint', 0, 'prefix', 0, 'checkpoint', 'valid', 'active', 1)",
	).run("segment", generation);
}
type PolicyRevisionInput = {
	generation: number;
	revisionHash: string;
	contentHash: string;
	previousGeneration?: number | null;
	previousRevisionHash?: string | null;
	previousContentHash?: string | null;
	casToken?: string;
};

function casTokenHash(casToken: string): string {
	return new Bun.CryptoHasher("sha256").update(casToken).digest("hex");
}

function policyHeadJson(
	generation: number,
	revisionHash: string,
	contentHash: string,
	casToken: string,
	updatedAtMs: number,
	keyId = "key",
	mac = new Bun.CryptoHasher("sha256").update("mac").digest("hex"),
): string {
	return `{"casToken":${JSON.stringify(casToken)},"contentHash":${JSON.stringify(contentHash)},"generation":${generation},"keyId":${JSON.stringify(keyId)},"mac":${JSON.stringify(mac)},"revisionHash":${JSON.stringify(revisionHash)},"schema":"gjc-bugwatch-policy-head/v2","scopeId":"scope","updatedAt":${JSON.stringify(new Date(updatedAtMs).toISOString())}}`;
}
const hash = (seed: string): string => new Bun.CryptoHasher("sha256").update(seed).digest("hex");
function rootAuthorityJson(
	rootId: string,
	projectPolicyHash: string,
	canonicalPath: string | null = "/tmp/root",
): string {
	return canonicalizeJson({
		activeMutationId: null,
		baselineEpochId: null,
		canonicalPath,
		enabled: true,
		generation: 1,
		persistContext: false,
		keyId: "key",
		mac: hash("mac"),
		nonce: "nonce",
		projectPolicyHash,
		rootId,
		schema: "gjc-bugwatch-root/v1",
		updatedAt: new Date(1).toISOString(),
	} as unknown as JsonValue);
}
function bootCoreJson(bootId: string): string {
	return canonicalizeJson({
		bootId,
		buildSha: null,
		fatalKeyId: "key",
		gjcVersion: "version",
		initialPolicyGeneration: 1,
		initialPolicyHash: "policy",
		pid: 1,
		pidStartToken: "start",
		producer: "producer",
		schema: "gjc-bugwatch-boot-core/v1",
		scopeId: "scope",
	} as unknown as JsonValue);
}
function attachmentTransitionJson(
	state: "prepared" | "active" | "ended" | "unknown" | "aborted" = "prepared",
	keyId = "fatal-key",
	mac = hash("attachment-mac"),
): string {
	return canonicalizeJson({
		attachmentId: "attachment",
		attachmentTokenHash: hash("token"),
		baselineEpochId: "epoch",
		bootCoreHash: hash("valid-core"),
		bootId: "valid-boot",
		endedAt: null,
		keyId,
		mac,
		managedSessionRoot: null,
		publishSequence: null,
		retireSequence: null,
		rootGeneration: 1,
		rootId: "root",
		schema: "gjc-bugwatch-attachment/v1",
		scopeId: "scope",
		sessionFile: null,
		sessionId: null,
		startedAt: new Date(1).toISOString(),
		state,
	} as unknown as JsonValue);
}
function insertAttachmentTransitionPrerequisites(db: Database): void {
	db.prepare(
		"INSERT INTO roots(root_id, kind, canonical_path, enabled, revision, project_policy_hash, registered_at_ms, root_json) VALUES('root', 'project', '/tmp/root', 1, 1, 'policy', 1, ?)",
	).run(rootAuthorityJson("root", "policy"));
	db.prepare(
		"INSERT INTO coverage_epochs(epoch_id, root_id, kind, state, policy_revision, coverage_status, started_at_ms) VALUES('epoch', 'root', 'enable_baseline', 'open', 'policy', 'unknown', 1)",
	).run();
	db.prepare(
		"INSERT INTO producer_boots(boot_id, scope_id, boot_core_hash, pid, pid_start_token, producer, started_at_ms, initial_policy_generation, initial_policy_hash, fatal_key_id, gjc_version, boot_core_json) VALUES('valid-boot', 'scope', ?, 1, 'start', 'producer', 1, 1, 'policy', 'key', 'version', ?)",
	).run(hash("valid-core"), bootCoreJson("valid-boot"));
	db.prepare(
		"INSERT INTO session_attachments(attachment_id, scope_id, attachment_token_hash, boot_id, boot_core_hash, root_id, started_at_ms, state, root_generation, baseline_epoch_id, current_transition_hash, attachment_json) VALUES('attachment', 'scope', ?, 'valid-boot', ?, 'root', 1, 'prepared', 1, 'epoch', 'transition', ?)",
	).run(hash("token"), hash("valid-core"), attachmentTransitionJson());
}
function storeOperationCoreJson(operationId: string, claimTokenHash: string): string {
	return canonicalizeJson({
		claimTokenHash,
		fromVersion: 1,
		kind: "quarantine",
		operationId,
		ownerId: "owner",
		schema: "gjc-bugwatch-store-operation-core/v1",
		toVersion: null,
	} as unknown as JsonValue);
}
function rootMutationCoreJson(mutationId: string): string {
	return canonicalizeJson({
		action: "enable",
		actorPid: 1,
		actorPidStartToken: "pid-start",
		createdAt: new Date(1).toISOString(),
		expectedPolicyGeneration: 1,
		expectedPolicyHash: hash("policy"),
		keyId: "key",
		mac: hash("root-core-mac"),
		mutationId,
		newRootId: "root",
		oldRootId: null,
		outputs: [
			{
				desiredRootGeneration: 1,
				expectedOldContentHash: null,
				finalContentHash: hash("final"),
				pathHash: hash("path"),
				pendingContentHash: hash("pending"),
				precondition: "missing",
				publicationOrder: 1,
				target: "new_root",
			},
		],
		schema: "gjc-bugwatch-root-mutation-core/v1",
		scopeId: "scope",
	} as unknown as JsonValue);
}

function insertPolicyRevision(db: Database, input: PolicyRevisionInput): void {
	const casToken = input.casToken ?? `raw-token-${input.generation}`;
	db.prepare(
		"INSERT INTO scope_policies(scope_id, generation, revision_hash, semantic_json, content_hash, previous_generation, previous_revision_hash, previous_content_hash, cas_token_hash, created_at_ms, writer_id, key_id, mac) VALUES('scope', ?, ?, ?, ?, ?, ?, ?, ?, 1, 'writer', 'key', 'mac')",
	).run(
		input.generation,
		input.revisionHash,
		`{"policy":"${input.contentHash}"}`,
		input.contentHash,
		input.previousGeneration ?? null,
		input.previousRevisionHash ?? null,
		input.previousContentHash ?? null,
		casTokenHash(casToken),
	);
}

function insertPolicyHead(
	db: Database,
	generation: number,
	revisionHash: string,
	contentHash: string,
	casToken = `raw-token-${generation}`,
	updatedAtMs = 1,
): void {
	db.prepare(
		"INSERT INTO scope_policy_heads(scope_id, generation, revision_hash, content_hash, cas_token_hash, updated_at_ms, key_id, mac, head_json) VALUES('scope', ?, ?, ?, ?, ?, 'key', ?, ?)",
	).run(
		generation,
		revisionHash,
		contentHash,
		casTokenHash(casToken),
		updatedAtMs,
		new Bun.CryptoHasher("sha256").update("mac").digest("hex"),
		policyHeadJson(
			generation,
			revisionHash,
			contentHash,
			casToken,
			updatedAtMs,
			"key",
			new Bun.CryptoHasher("sha256").update("mac").digest("hex"),
		),
	);
}

function createSchemaMetaOnlyDatabase(
	db: Database,
	schemaMajor: number,
	schemaMinor: number,
	semanticMetadata: BugwatchSchemaMetadata = metadata,
): void {
	db.exec(`
		CREATE TABLE schema_meta (
			id INTEGER PRIMARY KEY CHECK(id=1), schema_major INTEGER NOT NULL, schema_minor INTEGER NOT NULL,
			log_schema_version INTEGER NOT NULL, redaction_version INTEGER NOT NULL, noise_version INTEGER NOT NULL,
			severity_version INTEGER NOT NULL, fingerprint_version INTEGER NOT NULL,
			fixture_manifest_hash TEXT NOT NULL, schema_catalog_hash TEXT NOT NULL, created_at_ms INTEGER NOT NULL, migrated_at_ms INTEGER NOT NULL
		);
	`);
	db.prepare("INSERT INTO schema_meta VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
		schemaMajor,
		schemaMinor,
		semanticMetadata.logSchemaVersion,
		semanticMetadata.redactionVersion,
		semanticMetadata.noiseVersion,
		semanticMetadata.severityVersion,
		semanticMetadata.fingerprintVersion,
		semanticMetadata.fixtureManifestHash,
		BUGWATCH_SCHEMA_CATALOG_HASH,
		1,
		1,
	);
}
function createMinorOneDatabase(db: Database): void {
	installRawSchema(db, BUGWATCH_SCHEMA_SQL);
	db.exec(`
		DROP TRIGGER root_mutation_summary_update;
		DROP TRIGGER root_mutation_summary_insert;
		DROP TRIGGER root_mutation_step_immutable_delete;
		DROP TRIGGER root_mutation_step_immutable_update;
		DROP TRIGGER root_mutation_step_immutable_insert;
		DROP TRIGGER root_mutation_step_chain_insert;
		DROP TABLE root_mutation_steps;
	`);
	db.prepare("UPDATE schema_meta SET schema_minor = 1").run();
}
function createMinorThreeDatabase(db: Database): void {
	installRawSchema(db, BUGWATCH_SCHEMA_SQL);
	db.exec(`
		DROP TRIGGER root_mutation_summary_update;
		DROP TRIGGER root_mutation_summary_insert;
		DROP TRIGGER root_mutation_core_immutable_update;
		DROP TRIGGER root_mutation_core_projection_insert;
		DROP TABLE root_mutation_outputs;
		DROP TABLE root_mutations;
		CREATE TABLE root_mutations (
			mutation_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN('enable','disable','set_context','move')),
			core_hash TEXT NOT NULL UNIQUE, expected_policy_generation INTEGER NOT NULL CHECK(expected_policy_generation>=1), expected_policy_hash TEXT NOT NULL,
			old_root_id TEXT REFERENCES roots(root_id), new_root_id TEXT REFERENCES roots(root_id),
			phase TEXT NOT NULL CHECK(phase IN('prepared','publishing','files_published','db_applied','baseline_complete','files_finalized','committed','aborted','conflict')),
			step_index INTEGER NOT NULL, current_step_hash TEXT NOT NULL, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
		) STRICT;
		CREATE TABLE root_mutation_outputs (
			mutation_id TEXT NOT NULL REFERENCES root_mutations(mutation_id) ON DELETE CASCADE,
			target TEXT NOT NULL CHECK(target IN('old_root','new_root')), path_hash TEXT NOT NULL,
			precondition TEXT NOT NULL CHECK(precondition IN('missing','present')), expected_old_content_hash TEXT,
			pending_content_hash TEXT NOT NULL, final_content_hash TEXT NOT NULL,
			desired_root_generation INTEGER NOT NULL CHECK(desired_root_generation>=1), publication_order INTEGER NOT NULL CHECK(publication_order IN(1,2)),
			pending_state TEXT NOT NULL CHECK(pending_state IN('prepared','intent','published','verified','conflict')),
			final_state TEXT NOT NULL CHECK(final_state IN('prepared','intent','published','verified','conflict')),
			PRIMARY KEY(mutation_id,target), UNIQUE(mutation_id,publication_order), CHECK(pending_content_hash<>final_content_hash),
			CHECK((precondition='missing' AND expected_old_content_hash IS NULL) OR (precondition='present' AND expected_old_content_hash IS NOT NULL))
		) STRICT;
	`);
	db.prepare("UPDATE schema_meta SET schema_minor = 3").run();
}
function createMinorSixDatabase(db: Database): void {
	installRawSchema(db, BUGWATCH_SCHEMA_SQL);
	db.exec(`
		ALTER TABLE attachment_transitions RENAME TO attachment_transitions_legacy;
		CREATE TABLE attachment_transitions (
			attachment_id TEXT NOT NULL REFERENCES session_attachments(attachment_id), step_index INTEGER NOT NULL CHECK(step_index>=0),
			transition_hash TEXT NOT NULL UNIQUE CHECK(length(transition_hash)=64 AND transition_hash NOT GLOB '*[^0-9a-f]*'), state TEXT NOT NULL CHECK(state IN('prepared','active','ended','unknown','aborted')),
			previous_transition_hash TEXT, occurred_at_ms INTEGER NOT NULL,
			record_json TEXT NOT NULL CHECK(json_valid(record_json) AND record_json=json(record_json)), record_byte_count INTEGER NOT NULL CHECK(record_byte_count=length(CAST(record_json AS BLOB))),
			PRIMARY KEY(attachment_id,step_index)
		) STRICT;
		DROP TABLE attachment_transitions_legacy;
	`);
	db.prepare("UPDATE schema_meta SET schema_minor = 6").run();
}
function createMinorSevenDatabase(db: Database): void {
	installRawSchema(db, BUGWATCH_SCHEMA_SQL);
	db.prepare("UPDATE schema_meta SET schema_minor = 7").run();
}

function getCatalogTableNames(db: Database): string[] {
	return db
		.prepare<TableRow, []>("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
		.all()
		.map(row => row.name);
}

function expectIncompatibility(callback: () => void, kind: BugwatchSchemaIncompatibilityError["kind"]): void {
	let thrown: unknown;
	try {
		callback();
	} catch (error: unknown) {
		thrown = error;
	}
	expect(thrown).toBeInstanceOf(BugwatchSchemaIncompatibilityError);
	if (!(thrown instanceof BugwatchSchemaIncompatibilityError)) {
		throw new Error("Expected a typed bugwatch schema incompatibility error");
	}
	expect(thrown.kind).toBe(kind);
}
function expectSchemaIntegrity(callback: () => void, kind: BugwatchSchemaIntegrityError["kind"]): void {
	let thrown: unknown;
	try {
		callback();
	} catch (error: unknown) {
		thrown = error;
	}
	expect(thrown).toBeInstanceOf(BugwatchSchemaIntegrityError);
	if (!(thrown instanceof BugwatchSchemaIntegrityError)) {
		throw new Error("Expected a typed bugwatch schema integrity error");
	}
	expect(thrown.kind).toBe(kind);
}

describe("bugwatch Phase-0 authority schema", () => {
	it("creates the frozen authority catalog and covers every persisted snapshot class", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			const schemaMeta = db
				.prepare<MetaRow, []>(
					"SELECT schema_major, schema_minor, log_schema_version, redaction_version, noise_version, severity_version, fingerprint_version, fixture_manifest_hash, schema_catalog_hash FROM schema_meta WHERE id = 1",
				)
				.get();
			const foreignKeys = db.prepare<ForeignKeyRow, []>("PRAGMA foreign_keys").get();
			const recursiveTriggers = db.prepare<RecursiveTriggerRow, []>("PRAGMA recursive_triggers").get();
			expect(getCatalogTableNames(db)).toEqual([...BUGWATCH_PERSISTED_TABLE_NAMES].sort());
			expect(schemaMeta).toEqual({
				schema_major: BUGWATCH_SCHEMA_MAJOR,
				schema_minor: BUGWATCH_SCHEMA_MINOR,
				log_schema_version: metadata.logSchemaVersion,
				redaction_version: metadata.redactionVersion,
				noise_version: metadata.noiseVersion,
				severity_version: metadata.severityVersion,
				fingerprint_version: metadata.fingerprintVersion,
				fixture_manifest_hash: metadata.fixtureManifestHash,
				schema_catalog_hash: BUGWATCH_SCHEMA_CATALOG_HASH,
			});
			expect(foreignKeys?.foreign_keys).toBe(1);
			expect(recursiveTriggers?.recursive_triggers).toBe(1);
			expect(BUGWATCH_SCHEMA_MAJOR).toBe(SHARED_BUGWATCH_SCHEMA_MAJOR);
			expect(BUGWATCH_SCHEMA_MINOR).toBe(SHARED_BUGWATCH_SCHEMA_MINOR);
			expect(BUGWATCH_SCHEMA_CATALOG_HASH).toBe(SHARED_BUGWATCH_SCHEMA_CATALOG_HASH);
			expect(new Bun.CryptoHasher("sha256").update(BUGWATCH_SCHEMA_SQL).digest("hex")).toBe(
				SHARED_BUGWATCH_SCHEMA_CATALOG_HASH,
			);
			expect(BUGWATCH_LOG_SCHEMA_VERSION).toBe(SHARED_BUGWATCH_LOG_SCHEMA_VERSION);
			expect(BUGWATCH_REDACTION_VERSION).toBe(SHARED_BUGWATCH_REDACTION_VERSION);
			expect(BUGWATCH_NOISE_VERSION).toBe(SHARED_BUGWATCH_NOISE_VERSION);
			expect(BUGWATCH_SEVERITY_VERSION).toBe(SHARED_BUGWATCH_SEVERITY_VERSION);
			expect(BUGWATCH_FINGERPRINT_VERSION).toBe(SHARED_BUGWATCH_FINGERPRINT_VERSION);
			expect(BUGWATCH_FIXTURE_MANIFEST_HASH).toBe(SHARED_BUGWATCH_FIXTURE_MANIFEST_HASH);

			const logicalClassNames = new Set<string>(Object.keys(AUTHORITY_LOGICAL_SOURCE_MAPPING));
			const helperTableNames = new Set<string>(Object.keys(BUGWATCH_SCHEMA_HELPER_TABLE_MAPPING));
			const persistedTableNames = new Set<string>(BUGWATCH_PERSISTED_TABLE_NAMES);
			const persistedAuthorityClasses: string[] = BUGWATCH_PERSISTED_TABLE_NAMES.filter(
				tableName => !helperTableNames.has(tableName),
			).sort();
			const persistedSnapshotClasses: string[] = AUTHORITY_CLASS_NAMES.filter(
				className => persistedTableNames.has(className) && !helperTableNames.has(className),
			).sort();

			expect(persistedAuthorityClasses).toEqual(persistedSnapshotClasses);
			expect(AUTHORITY_CLASS_NAMES).toContain("store_operation_journal");
			expect(persistedTableNames.has("store_operation_journal")).toBe(false);
			expect(
				AUTHORITY_CLASS_NAMES.filter(
					className => logicalClassNames.has(className) && persistedTableNames.has(className),
				),
			).toEqual([]);
			for (const ownerClassName of Object.values(BUGWATCH_SCHEMA_HELPER_TABLE_MAPPING)) {
				expect(AUTHORITY_CLASS_NAMES).toContain(ownerClassName);
			}
		} finally {
			db.close();
		}
	});
	it("stores root mutation restart evidence as an immutable phase chain", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			db.prepare(
				"INSERT INTO roots(root_id, kind, canonical_path, enabled, revision, project_policy_hash, registered_at_ms, root_json) VALUES('root', 'project', '/tmp/root', 1, 1, ?, 1, ?)",
			).run(hash("policy"), rootAuthorityJson("root", hash("policy")));
			const coreJson = rootMutationCoreJson("mutation");
			const core = parseRootMutationCoreV1(coreJson);
			const coreHash = authenticatedHash(core as unknown as JsonValue);
			db.prepare(
				"INSERT INTO root_mutation_steps(scope_id, mutation_id, core_hash, step_index, phase, previous_phase, previous_state_hash, key_id, mac, record_hash, created_at_ms, recorded_at_ms) VALUES('scope', 'mutation', ?, 0, 'prepared', NULL, NULL, 'key', 'mac', 'prepared-step', 1, 1)",
			).run(coreHash);
			db.prepare(
				"INSERT INTO root_mutations(mutation_id, scope_id, action, core_hash, core_json, expected_policy_generation, expected_policy_hash, old_root_id, new_root_id, phase, step_index, current_step_hash, created_at_ms, updated_at_ms) VALUES('mutation', 'scope', 'enable', ?, ?, 1, ?, NULL, 'root', 'prepared', 0, 'prepared-step', 1, 1)",
			).run(coreHash, coreJson, hash("policy"));
			migrateBugwatchSchema(db, metadata);
			const mismatchJson = rootMutationCoreJson("mismatch");
			db.prepare(
				"INSERT INTO root_mutation_steps(scope_id, mutation_id, core_hash, step_index, phase, previous_phase, previous_state_hash, key_id, mac, record_hash, created_at_ms, recorded_at_ms) VALUES('scope', 'mismatch', ?, 0, 'prepared', NULL, NULL, 'key', 'mac', 'mismatch-step', 1, 1)",
			).run(hash("wrong-core"));
			db.prepare(
				"INSERT INTO root_mutations(mutation_id, scope_id, action, core_hash, core_json, expected_policy_generation, expected_policy_hash, old_root_id, new_root_id, phase, step_index, current_step_hash, created_at_ms, updated_at_ms) VALUES('mismatch', 'scope', 'enable', ?, ?, 1, ?, NULL, 'root', 'prepared', 0, 'mismatch-step', 1, 1)",
			).run(hash("wrong-core"), mismatchJson, hash("policy"));
			expectSchemaIntegrity(() => migrateBugwatchSchema(db, metadata), "INTEGRITY");
			expect(() =>
				db.prepare("UPDATE root_mutation_steps SET mac='replacement' WHERE mutation_id='mutation'").run(),
			).toThrow("root mutation steps are immutable");
			expect(() =>
				db.prepare("UPDATE root_mutations SET core_json='{}' WHERE mutation_id='mutation'").run(),
			).toThrow("root mutation core identity is immutable");
			expect(() =>
				db.prepare("UPDATE root_mutations SET current_step_hash='other-step' WHERE mutation_id='mutation'").run(),
			).toThrow("root mutation summary terminal step mismatch");
			const renameIntent = canonicalizeJson({
				action: "rename_intent",
				coreHash,
				desiredDestinationHash: hash("pending"),
				expectedDestinationHash: null,
				keyId: "key",
				lifecycle: "pending",
				mac: hash("rename-mac"),
				mutationId: "mutation",
				occurredAt: new Date(1).toISOString(),
				observedDestinationHash: null,
				previousStepHash: null,
				schema: "gjc-bugwatch-root-rename-step/v2",
				scopeId: "scope",
				sourceTempHash: hash("temp"),
				stepIndex: 0,
				target: "new_root",
			} as unknown as JsonValue);
			db.prepare(
				"INSERT INTO root_mutation_rename_steps(scope_id, mutation_id, core_hash, step_index, target, lifecycle, action, expected_destination_hash, source_temp_hash, desired_destination_hash, observed_destination_hash, previous_step_hash, step_hash, occurred_at_ms, record_json, record_byte_count, key_id, mac) VALUES('scope', 'mutation', ?, 0, 'new_root', 'pending', 'rename_intent', NULL, ?, ?, NULL, NULL, ?, 1, ?, ?, 'key', ?)",
			).run(
				coreHash,
				hash("temp"),
				hash("pending"),
				hash("rename-intent"),
				renameIntent,
				Buffer.byteLength(renameIntent),
				hash("rename-mac"),
			);
			expect(() =>
				db.prepare("UPDATE root_mutation_rename_steps SET mac='replacement' WHERE mutation_id='mutation'").run(),
			).toThrow("root mutation rename steps are immutable");
			expect(() =>
				db
					.prepare(
						"INSERT INTO root_mutation_rename_steps(scope_id, mutation_id, core_hash, step_index, target, lifecycle, action, expected_destination_hash, source_temp_hash, desired_destination_hash, observed_destination_hash, previous_step_hash, step_hash, occurred_at_ms, record_json, record_byte_count, key_id, mac) VALUES('scope', 'mutation', ?, 2, 'new_root', 'pending', 'rename_complete', NULL, ?, ?, ?, ?, ?, 2, ?, ?, 'key', ?)",
					)
					.run(
						coreHash,
						hash("temp"),
						hash("pending"),
						hash("pending"),
						hash("rename-intent"),
						hash("rename-complete"),
						canonicalizeJson({
							action: "rename_complete",
							coreHash,
							desiredDestinationHash: hash("pending"),
							expectedDestinationHash: null,
							keyId: "key",
							lifecycle: "pending",
							mac: hash("rename-mac"),
							mutationId: "mutation",
							occurredAt: new Date(2).toISOString(),
							observedDestinationHash: hash("pending"),
							previousStepHash: hash("rename-intent"),
							schema: "gjc-bugwatch-root-rename-step/v2",
							scopeId: "scope",
							sourceTempHash: hash("temp"),
							stepIndex: 2,
							target: "new_root",
						} as unknown as JsonValue),
						1,
						hash("rename-mac"),
					),
			).toThrow("root mutation rename step chain mismatch");
		} finally {
			db.close();
		}
	});
	it("persists distinct snapshot records for repeated parent authority IDs while constraining their chain", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			db.prepare(
				"INSERT INTO authority_snapshot_packs(snapshot_id, scope_id, kind, manifest_hash, merkle_root, item_count, byte_count, created_at_ms, state) VALUES('snapshot', 'scope', 'manual_authority', 'manifest', 'merkle', 9, 9, 1, 'writing')",
			).run();
			const insertItem = db.prepare(
				"INSERT INTO authority_snapshot_items(snapshot_id, item_index, item_type, authority_id, item_hash, payload_hash, previous_item_hash, payload) VALUES('snapshot', ?, ?, ?, ?, ?, ?, ?)",
			);
			const payload = new Uint8Array([1]);
			insertItem.run(0, "schema_meta", "schema", "item-0", "payload-0", null, payload);
			insertItem.run(1, "scope_policies", "scope", "item-1", "policy-revision-1", "item-0", payload);
			insertItem.run(2, "scope_policies", "scope", "item-2", "policy-revision-2", "item-1", payload);
			insertItem.run(3, "root_mutation_rename_steps", "mutation", "item-3", "rename-step-1", "item-2", payload);
			insertItem.run(4, "root_mutation_rename_steps", "mutation", "item-4", "rename-step-2", "item-3", payload);
			insertItem.run(5, "boot_transport_records", "boot", "item-5", "transport-1", "item-4", payload);
			insertItem.run(6, "boot_transport_records", "boot", "item-6", "transport-2", "item-5", payload);
			insertItem.run(7, "source_checkpoints", "source", "item-7", "checkpoint-1", "item-6", payload);
			insertItem.run(8, "source_checkpoints", "source", "item-8", "checkpoint-2", "item-7", payload);

			expect(() =>
				insertItem.run(9, "scope_policies", "scope", "item-9", "policy-revision-2", "item-8", payload),
			).toThrow();
			expect(() =>
				insertItem.run(8, "source_checkpoints", "source", "duplicate-order", "checkpoint-3", "item-7", payload),
			).toThrow();
			expect(() =>
				insertItem.run(9, "source_checkpoints", "source", "item-9", "checkpoint-3", "wrong-predecessor", payload),
			).toThrow("snapshot item predecessor must be the preceding item");
			expect(() =>
				db
					.prepare(
						"INSERT INTO authority_snapshot_items(snapshot_id, item_index, item_type, authority_id, item_hash, payload_hash, previous_item_hash, payload) VALUES('missing-snapshot', 0, 'schema_meta', 'schema', 'missing-item', 'missing-payload', NULL, ?)",
					)
					.run(payload),
			).toThrow();

			expect(
				db
					.prepare<CountRow, []>(
						"SELECT COUNT(*) AS count FROM authority_snapshot_items WHERE snapshot_id='snapshot'",
					)
					.get()?.count,
			).toBe(9);
		} finally {
			db.close();
		}
	});
	it("retains immutable policy revisions and authenticates the per-scope head", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			insertPolicyRevision(db, { generation: 1, revisionHash: "revision-a1", contentHash: "content-a" });
			insertPolicyRevision(db, {
				generation: 2,
				revisionHash: "revision-b2",
				contentHash: "content-b",
				previousGeneration: 1,
				previousRevisionHash: "revision-a1",
				previousContentHash: "content-a",
			});
			insertPolicyRevision(db, {
				generation: 3,
				revisionHash: "revision-a3",
				contentHash: "content-a",
				previousGeneration: 2,
				previousRevisionHash: "revision-b2",
				previousContentHash: "content-b",
			});
			insertPolicyHead(db, 1, "revision-a1", "content-a");
			db.prepare(
				"UPDATE scope_policy_heads SET generation=2, revision_hash='revision-b2', content_hash='content-b', cas_token_hash=?, updated_at_ms=2, head_json=? WHERE scope_id='scope'",
			).run(casTokenHash("raw-token-2"), policyHeadJson(2, "revision-b2", "content-b", "raw-token-2", 2));
			db.prepare(
				"UPDATE scope_policy_heads SET generation=3, revision_hash='revision-a3', content_hash='content-a', cas_token_hash=?, updated_at_ms=3, head_json=? WHERE scope_id='scope'",
			).run(casTokenHash("raw-token-3"), policyHeadJson(3, "revision-a3", "content-a", "raw-token-3", 3));

			const revisions = db
				.prepare<{ generation: number; revision_hash: string; content_hash: string }, []>(
					"SELECT generation, revision_hash, content_hash FROM scope_policies WHERE scope_id='scope' ORDER BY generation",
				)
				.all();
			expect(revisions).toEqual([
				{ generation: 1, revision_hash: "revision-a1", content_hash: "content-a" },
				{ generation: 2, revision_hash: "revision-b2", content_hash: "content-b" },
				{ generation: 3, revision_hash: "revision-a3", content_hash: "content-a" },
			]);

			expect(() =>
				insertPolicyRevision(db, {
					generation: 4,
					revisionHash: "fork",
					contentHash: "content-c",
					previousGeneration: 3,
					previousRevisionHash: "wrong-predecessor",
					previousContentHash: "content-a",
				}),
			).toThrow("scope policy predecessor mismatch");
			expect(() =>
				insertPolicyRevision(db, {
					generation: 5,
					revisionHash: "orphan",
					contentHash: "content-c",
					previousGeneration: 4,
					previousRevisionHash: "missing",
					previousContentHash: "content-c",
				}),
			).toThrow("scope policy predecessor mismatch");
			expect(() =>
				insertPolicyRevision(db, {
					generation: 4,
					revisionHash: "generation-mismatch",
					contentHash: "content-c",
					previousGeneration: 2,
					previousRevisionHash: "revision-b2",
					previousContentHash: "content-b",
				}),
			).toThrow();
			insertPolicyRevision(db, {
				generation: 4,
				revisionHash: "revision-c4",
				contentHash: "content-c",
				previousGeneration: 3,
				previousRevisionHash: "revision-a3",
				previousContentHash: "content-a",
			});
			expect(() =>
				db
					.prepare(
						"UPDATE scope_policy_heads SET generation=4, revision_hash='wrong-revision', content_hash='content-c', cas_token_hash=?, head_json=? WHERE scope_id='scope'",
					)
					.run(casTokenHash("raw-token-4"), policyHeadJson(4, "wrong-revision", "content-c", "raw-token-4", 3)),
			).toThrow("scope policy head CAS mismatch");
			expect(() =>
				db.prepare("UPDATE scope_policies SET semantic_json='{}' WHERE scope_id='scope' AND generation=1").run(),
			).toThrow("scope policy revisions are immutable");
			expect(() => db.prepare("DELETE FROM scope_policies WHERE scope_id='scope' AND generation=1").run()).toThrow(
				"scope policy revisions are immutable",
			);
			db.exec("PRAGMA recursive_triggers = OFF");
			expect(() =>
				db
					.prepare(
						"INSERT OR REPLACE INTO scope_policies(scope_id, generation, revision_hash, semantic_json, content_hash, previous_generation, previous_revision_hash, previous_content_hash, cas_token_hash, created_at_ms, writer_id, key_id, mac) VALUES('scope', 1, 'replaced', '{}', 'replaced', NULL, NULL, NULL, 'token-1', 1, 'writer', 'key', 'mac')",
					)
					.run(),
			).toThrow("scope policy revisions are immutable");
			db.exec("PRAGMA recursive_triggers = ON");
			expect(() =>
				db
					.prepare(
						"INSERT OR REPLACE INTO scope_policy_heads(scope_id, generation, revision_hash, content_hash, cas_token_hash, updated_at_ms, key_id, mac, head_json) VALUES('scope', 3, 'revision-a3', 'content-a', ?, 3, 'key', 'mac', ?)",
					)
					.run(casTokenHash("raw-token-3"), policyHeadJson(3, "revision-a3", "content-a", "raw-token-3", 3)),
			).toThrow("scope policy head must be updated by CAS");
			expect(() => db.prepare("DELETE FROM scope_policy_heads WHERE scope_id='scope'").run()).toThrow(
				"scope policy head cannot be deleted",
			);
			expect(
				db
					.prepare<{ generation: number; revision_hash: string; content_hash: string }, []>(
						"SELECT generation, revision_hash, content_hash FROM scope_policy_heads WHERE scope_id='scope'",
					)
					.get(),
			).toEqual({ generation: 3, revision_hash: "revision-a3", content_hash: "content-a" });
		} finally {
			db.close();
		}
	});
	it("requires a lossless canonical policy head envelope and a real CAS-token hash", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			insertPolicyRevision(db, { generation: 1, revisionHash: "revision-1", contentHash: "content-1" });

			expect(() =>
				db
					.prepare(
						"INSERT INTO scope_policy_heads(scope_id, generation, revision_hash, content_hash, cas_token_hash, updated_at_ms, key_id, mac, head_json) VALUES('scope', 1, 'revision-1', 'content-1', ?, 1, 'key', 'mac', ?)",
					)
					.run(
						casTokenHash("raw-token-1"),
						'{"schema":"gjc-bugwatch-policy-head/v2","scopeId":"scope","generation":1,"revisionHash":"revision-1","contentHash":"content-1","casToken":"raw-token-1","updatedAt":"1","keyId":"key","mac":"mac"}',
					),
			).toThrow("scope policy head envelope mismatch");
			expect(() =>
				db
					.prepare(
						"INSERT INTO scope_policy_heads(scope_id, generation, revision_hash, content_hash, cas_token_hash, updated_at_ms, key_id, mac, head_json) VALUES('scope', 1, 'revision-1', 'content-1', ?, 1, 'key', 'mac', ?)",
					)
					.run(casTokenHash("raw-token-1"), "{not-json}"),
			).toThrow();

			expect(() =>
				db
					.prepare(
						"INSERT INTO scope_policy_heads(scope_id, generation, revision_hash, content_hash, cas_token_hash, updated_at_ms, key_id, mac, head_json) VALUES('scope', 1, 'revision-1', 'content-1', ?, 1, 'key', 'mac', ?)",
					)
					.run(casTokenHash("raw-token-1"), policyHeadJson(1, "revision-1", "content-1", "wrong-token", 1)),
			).toThrow("scope policy head envelope mismatch");

			db.prepare(
				"INSERT INTO scope_policies(scope_id, generation, revision_hash, semantic_json, content_hash, previous_generation, previous_revision_hash, previous_content_hash, cas_token_hash, created_at_ms, writer_id, key_id, mac) VALUES('masquerade', 1, 'masquerade-revision', '{}', 'masquerade-content', NULL, NULL, NULL, 'masquerade', 1, 'writer', 'key', 'mac')",
			).run();
			expect(() =>
				db
					.prepare(
						"INSERT INTO scope_policy_heads(scope_id, generation, revision_hash, content_hash, cas_token_hash, updated_at_ms, key_id, mac, head_json) VALUES('masquerade', 1, 'masquerade-revision', 'masquerade-content', 'masquerade', 1, 'key', 'mac', ?)",
					)
					.run(
						'{"casToken":"masquerade","contentHash":"masquerade-content","generation":1,"keyId":"key","mac":"mac","revisionHash":"masquerade-revision","schema":"gjc-bugwatch-policy-head/v2","scopeId":"masquerade","updatedAt":"1"}',
					),
			).toThrow("scope policy head envelope mismatch");
		} finally {
			db.close();
		}
	});

	it("projects policy-head timestamps as canonical UTC strings accepted by the shared parser", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			const revisionHash = hash("revision");
			const contentHash = hash("content");
			const timestamp = 1_767_323_045_678;
			insertPolicyRevision(db, { generation: 1, revisionHash, contentHash, casToken: "raw-token" });
			insertPolicyHead(db, 1, revisionHash, contentHash, "raw-token", timestamp);
			const row = db
				.prepare<{ head_json: string }, []>("SELECT head_json FROM scope_policy_heads WHERE scope_id='scope'")
				.get();
			expect(row).not.toBeNull();
			expect(parseScopePolicyHeadV2(row?.head_json ?? "")).toEqual(JSON.parse(row?.head_json ?? ""));
			expect(JSON.parse(row?.head_json ?? "").updatedAt).toBe(new Date(timestamp).toISOString());
		} finally {
			db.close();
		}
	});
	it("stores only canonical shared-parser attachment transition envelopes", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			insertAttachmentTransitionPrerequisites(db);
			const record = attachmentTransitionJson();
			const parsed = parseAttachmentV1(record);
			const transitionHash = authenticatedHash(parsed as unknown as JsonValue);
			db.prepare(
				"INSERT INTO attachment_transitions(attachment_id, step_index, transition_hash, state, previous_transition_hash, occurred_at_ms, record_json, record_byte_count, key_id, mac) VALUES('attachment', 0, ?, 'prepared', NULL, 1, ?, ?, 'fatal-key', ?)",
			).run(transitionHash, record, Buffer.byteLength(record), parsed.mac);
			expect(parseAttachmentV1(record)).toEqual(JSON.parse(record));
			expect(() =>
				db
					.prepare(
						"INSERT INTO attachment_transitions(attachment_id, step_index, transition_hash, state, previous_transition_hash, occurred_at_ms, record_json, record_byte_count, key_id, mac) VALUES('attachment', 1, ?, 'prepared', ?, 1, ?, ?, 'wrong-key', ?)",
					)
					.run(transitionHash, transitionHash, record, Buffer.byteLength(record), parsed.mac),
			).toThrow("attachment transition envelope or chain mismatch");
			expect(() =>
				db
					.prepare(
						"INSERT INTO attachment_transitions(attachment_id, step_index, transition_hash, state, previous_transition_hash, occurred_at_ms, record_json, record_byte_count, key_id, mac) VALUES('attachment', 1, ?, 'prepared', ?, 1, ?, ?, 'fatal-key', 'wrong-mac')",
					)
					.run(transitionHash, transitionHash, record, Buffer.byteLength(record)),
			).toThrow();
			const wrongProjection = record.replace('"attachmentId":"attachment"', '"attachmentId":"other"');
			expect(() =>
				db
					.prepare(
						"INSERT INTO attachment_transitions(attachment_id, step_index, transition_hash, state, previous_transition_hash, occurred_at_ms, record_json, record_byte_count, key_id, mac) VALUES('attachment', 1, ?, 'prepared', ?, 1, ?, ?, 'fatal-key', ?)",
					)
					.run(transitionHash, transitionHash, wrongProjection, Buffer.byteLength(wrongProjection), parsed.mac),
			).toThrow("attachment transition envelope or chain mismatch");
			const nonCanonical = record.replace(',"attachmentTokenHash"', ', "attachmentTokenHash"');
			expect(() =>
				db
					.prepare(
						"INSERT INTO attachment_transitions(attachment_id, step_index, transition_hash, state, previous_transition_hash, occurred_at_ms, record_json, record_byte_count, key_id, mac) VALUES('attachment', 1, ?, 'prepared', ?, 1, ?, ?, 'fatal-key', ?)",
					)
					.run(transitionHash, transitionHash, nonCanonical, Buffer.byteLength(nonCanonical), parsed.mac),
			).toThrow();
			expect(() =>
				db
					.prepare(
						"INSERT INTO attachment_transitions(attachment_id, step_index, transition_hash, state, previous_transition_hash, occurred_at_ms, record_json, record_byte_count, key_id) VALUES('attachment', 1, ?, 'prepared', ?, 1, ?, ?, 'fatal-key')",
					)
					.run(transitionHash, transitionHash, record, Buffer.byteLength(record)),
			).toThrow();
			expect(() =>
				db
					.prepare(
						"INSERT INTO attachment_transitions(attachment_id, step_index, transition_hash, state, previous_transition_hash, occurred_at_ms, record_json, record_byte_count, mac) VALUES('attachment', 1, ?, 'prepared', ?, 1, ?, ?, ?)",
					)
					.run(transitionHash, transitionHash, record, Buffer.byteLength(record), parsed.mac),
			).toThrow();
		} finally {
			db.close();
		}
	});
	it("migrates an empty 1.7 catalog and refuses unauthenticated transition rows", async () => {
		const valid = await createDatabase();
		try {
			createMinorSevenDatabase(valid.db);
			migrateBugwatchSchema(valid.db, metadata);
			expect(
				valid.db.prepare<{ schema_minor: number }, []>("SELECT schema_minor FROM schema_meta WHERE id=1").get()
					?.schema_minor,
			).toBe(BUGWATCH_SCHEMA_MINOR);
		} finally {
			valid.db.close();
		}

		const blocked = await createDatabase();
		try {
			createMinorSevenDatabase(blocked.db);
			blocked.db.exec("PRAGMA foreign_keys = OFF");
			blocked.db.exec("DROP TRIGGER monitor_authorization_authority_projection_insert");
			blocked.db
				.prepare(
					"INSERT INTO monitor_disable_authorizations(authorization_id, scope_id, inventory_epoch_id, monitor_id, action_kind, action_hash, expected_config_hash, consume_nonce_hash, state, authorized_at_ms, expires_at_ms, consumed_at_ms, action_json, authorization_json, key_id, mac) VALUES('legacy', 'scope', 'epoch', 'monitor', 'process', ?, 'config', 'nonce', 'authorized', 1, 2, NULL, '{\"kind\":\"process\"}', '{}', 'key', ?)",
				)
				.run(hash("legacy-action"), hash("legacy-mac"));
			expectSchemaIntegrity(() => migrateBugwatchSchema(blocked.db, metadata), "SCHEMA_DRIFT");
		} finally {
			blocked.db.close();
		}
	});
	it("migrates empty 1.6 attachment transitions and refuses unauthenticated legacy rows", async () => {
		const valid = await createDatabase();
		try {
			createMinorSixDatabase(valid.db);
			migrateBugwatchSchema(valid.db, metadata);
			expect(
				valid.db
					.prepare<CountRow, []>(
						"SELECT count(*) AS count FROM pragma_table_info('attachment_transitions') WHERE name IN('key_id','mac')",
					)
					.get()?.count,
			).toBe(2);
			expect(
				valid.db.prepare<{ schema_minor: number }, []>("SELECT schema_minor FROM schema_meta WHERE id=1").get()
					?.schema_minor,
			).toBe(BUGWATCH_SCHEMA_MINOR);
		} finally {
			valid.db.close();
		}

		const blocked = await createDatabase();
		try {
			createMinorSixDatabase(blocked.db);
			blocked.db.exec("PRAGMA foreign_keys = OFF");
			blocked.db
				.prepare(
					"INSERT INTO attachment_transitions(attachment_id, step_index, transition_hash, state, previous_transition_hash, occurred_at_ms, record_json, record_byte_count) VALUES('legacy', 0, ?, 'prepared', NULL, 1, '{}', 2)",
				)
				.run(hash("legacy-transition"));
			blocked.db.exec("PRAGMA foreign_keys = ON");
			expectSchemaIntegrity(() => migrateBugwatchSchema(blocked.db, metadata), "SCHEMA_DRIFT");
			expect(
				blocked.db.prepare<{ schema_minor: number }, []>("SELECT schema_minor FROM schema_meta WHERE id=1").get()
					?.schema_minor,
			).toBe(6);
		} finally {
			blocked.db.close();
		}
	});
	it("migrates empty 1.3 root mutations and refuses legacy rows without authenticated cores", async () => {
		const valid = await createDatabase();
		try {
			createMinorThreeDatabase(valid.db);
			migrateBugwatchSchema(valid.db, metadata);
			expect(
				valid.db.prepare<{ schema_minor: number }, []>("SELECT schema_minor FROM schema_meta WHERE id=1").get()
					?.schema_minor,
			).toBe(BUGWATCH_SCHEMA_MINOR);
		} finally {
			valid.db.close();
		}

		const blocked = await createDatabase();
		try {
			createMinorThreeDatabase(blocked.db);
			blocked.db
				.prepare(
					"INSERT INTO root_mutations(mutation_id, scope_id, action, core_hash, expected_policy_generation, expected_policy_hash, phase, step_index, current_step_hash, created_at_ms, updated_at_ms) VALUES('legacy', 'scope', 'enable', 'legacy', 1, 'policy', 'prepared', 0, 'step', 1, 1)",
				)
				.run();
			expectSchemaIntegrity(() => migrateBugwatchSchema(blocked.db, metadata), "SCHEMA_DRIFT");
		} finally {
			blocked.db.close();
		}
	});
	it("is idempotent when reopening an authority database", async () => {
		const { db, directory } = await createDatabase();
		const databasePath = path.join(directory, "authority.sqlite");
		migrateBugwatchSchema(db, metadata);
		db.close();
		const reopened = new Database(databasePath);
		try {
			migrateBugwatchSchema(reopened, metadata);
			expect(reopened.prepare<CountRow, []>("SELECT COUNT(*) AS count FROM schema_meta").get()?.count).toBe(1);
		} finally {
			reopened.close();
		}
	});
	it("requires rollback payload bytes and preserves distinct store member identities", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			db.prepare(
				"INSERT INTO rollback_epochs(epoch_id, scope_id, role_transition_token, bundle_version, state, limits_json, bundle_json, spool_manifest_json, inbox_ack_json, created_at_ms) VALUES('epoch', 'scope', 'token', 1, 'exporting', '{}', '{}', '{}', '{}', 1)",
			).run();
			const insertRollbackItem = db.prepare(
				"INSERT INTO rollback_items(epoch_id, item_index, item_type, item_hash, payload_hash, payload_byte_count, state, payload, item_schema, key_id, mac, item_json) VALUES('epoch', ?, 'root', ?, ?, ?, 'pending', ?, 'gjc-bugwatch-rollback-bundle-item/v1', 'key', 'mac', ?)",
			);
			const payload = new Uint8Array([1, 2]);
			const payloadHash = hash("payload");
			const itemHash = hash("item");
			const itemJson = canonicalizeJson({
				epochId: "epoch",
				itemHash,
				itemIndex: 0,
				itemType: "root",
				keyId: "key",
				mac: "mac",
				payloadHash,
				schema: "gjc-bugwatch-rollback-bundle-item/v1",
			} as unknown as JsonValue);
			insertRollbackItem.run(0, itemHash, payloadHash, payload.byteLength, payload, itemJson);
			expect(() =>
				insertRollbackItem.run(1, hash("item-2"), hash("payload-2"), payload.byteLength, payload, itemJson),
			).toThrow("rollback item authority projection mismatch");

			const insertOperation = db.prepare(
				"INSERT INTO store_operations(operation_id, owner_id, claim_token_hash, kind, from_version, to_version, phase, core_hash, current_step, current_step_hash, backup_path, quarantine_path, watermark_hash, core_json, started_at_ms, updated_at_ms) VALUES(?, 'owner', ?, 'quarantine', 1, NULL, 'prepared', ?, 0, NULL, NULL, NULL, NULL, ?, 1, 1)",
			);
			const insertMember = db.prepare(
				"INSERT INTO store_operation_members(operation_id, member, source_path_hash, expected_presence, expected_size, expected_hash, quarantine_path_hash, state, observed_source_hash, observed_quarantine_hash, step_json, updated_at_ms) VALUES(?, ?, ?, 0, NULL, NULL, ?, 'pending', NULL, NULL, '{}', 1)",
			);
			insertOperation.run(
				"valid-operation",
				"claim-valid",
				"core-valid",
				storeOperationCoreJson("valid-operation", "claim-valid"),
			);
			insertMember.run("valid-operation", "db", "source-db", "quarantine-db");
			insertMember.run("valid-operation", "wal", "source-wal", "quarantine-wal");
			insertMember.run("valid-operation", "shm", "source-shm", "quarantine-shm");

			insertOperation.run(
				"duplicate-operation",
				"claim-duplicate",
				"core-duplicate",
				storeOperationCoreJson("duplicate-operation", "claim-duplicate"),
			);
			insertMember.run("duplicate-operation", "db", "source-db", "quarantine-db");
			expect(() => insertMember.run("duplicate-operation", "wal", "source-db", "quarantine-wal")).toThrow(
				"store operation member paths must be distinct",
			);

			insertOperation.run(
				"swapped-operation",
				"claim-swapped",
				"core-swapped",
				storeOperationCoreJson("swapped-operation", "claim-swapped"),
			);
			insertMember.run("swapped-operation", "db", "source-db", "quarantine-db");
			expect(() => insertMember.run("swapped-operation", "wal", "quarantine-db", "source-wal")).toThrow(
				"store operation member paths must be distinct",
			);

			insertOperation.run(
				"same-row-operation",
				"claim-same-row",
				"core-same-row",
				storeOperationCoreJson("same-row-operation", "claim-same-row"),
			);
			expect(() => insertMember.run("same-row-operation", "db", "same-path", "same-path")).toThrow();
		} finally {
			db.close();
		}
	});
	it("requires retained authority content and immutable remaining payload families", () => {
		const db = new Database(":memory:");
		try {
			db.exec(BUGWATCH_SCHEMA_SQL);
			insertAttachmentTransitionPrerequisites(db);
			const json = canonicalizeJson({ value: "content" } as unknown as JsonValue);
			const contentHash = hash(json);
			const transition = attachmentTransitionJson("prepared", "key", hash("mac"));
			db.prepare(
				"INSERT INTO attachment_transitions(attachment_id, step_index, transition_hash, state, previous_transition_hash, occurred_at_ms, record_json, record_byte_count, key_id, mac) VALUES('attachment', 0, ?, 'prepared', NULL, 1, ?, ?, 'key', ?)",
			).run(
				authenticatedHash(parseAttachmentV1(transition) as unknown as JsonValue),
				transition,
				Buffer.byteLength(transition),
				hash("mac"),
			);
			expect(() => db.prepare("UPDATE attachment_transitions SET state='active'").run()).toThrow(
				"attachment transitions are immutable",
			);

			const rollbackAuthority = canonicalizeJson({
				epochId: "epoch",
				itemHash: hash("item"),
				itemIndex: 0,
				itemType: "root",
				keyId: "key",
				mac: "mac",
				payloadHash: hash("payload"),
				schema: "gjc-bugwatch-rollback-bundle-item/v1",
			} as unknown as JsonValue);
			db.prepare(
				"INSERT INTO rollback_items(epoch_id, item_index, item_type, item_hash, payload_hash, payload_byte_count, state, payload, item_schema, key_id, mac, item_json) VALUES('epoch', 0, 'root', ?, ?, 1, 'pending', X'01', 'gjc-bugwatch-rollback-bundle-item/v1', 'key', 'mac', ?)",
			).run(hash("item"), hash("payload"), rollbackAuthority);
			expect(() =>
				db
					.prepare(
						"INSERT INTO rollback_items(epoch_id, item_index, item_type, item_hash, payload_hash, payload_byte_count, state, payload, item_schema, key_id, mac, item_json) VALUES('epoch', 1, 'root', ?, ?, 1, 'pending', X'01', 'gjc-bugwatch-rollback-bundle-item/v1', 'key', 'mac', ?)",
					)
					.run(hash("wrong-item"), hash("payload"), rollbackAuthority),
			).toThrow("rollback item authority projection mismatch");

			db.prepare(
				"INSERT INTO old_monitor_inventory_epochs(inventory_epoch_id, scope_id, state, started_at_ms, completed_at_ms, receipt_hash) VALUES('inventory', 'scope', 'complete', 1, 1, NULL)",
			).run();
			db.prepare(
				"INSERT INTO old_monitors(inventory_epoch_id, monitor_id, kind, stable_identifier, owner, config_hash, status, observed_at_ms, inventory_json) VALUES('inventory', 'monitor', 'process', 'stable', 'owner', 'config', 'active', 1, '{}')",
			).run();
			const actionJson = canonicalizeJson({ kind: "process" } as unknown as JsonValue);
			const authorization = canonicalizeJson({
				adapterKind: "process",
				allowedAction: { kind: "process" },
				authorizedAt: new Date(1).toISOString(),
				expiresAt: new Date(2).toISOString(),
				expectedConfigHash: "config",
				authorizationId: "auth",
				inventoryEpochId: "inventory",
				keyId: "key",
				mac: hash("monitor-mac"),
				monitorId: "monitor",
				nonce: "nonce",
				schema: "gjc-bugwatch-monitor-disable-auth/v1",
				scopeId: "scope",
				stableIdentifier: "stable",
			} as unknown as JsonValue);
			const insertAuthorization = db.prepare(
				"INSERT INTO monitor_disable_authorizations(authorization_id, scope_id, inventory_epoch_id, monitor_id, action_kind, action_hash, expected_config_hash, consume_nonce_hash, state, authorized_at_ms, expires_at_ms, consumed_at_ms, action_json, authorization_json, key_id, mac) VALUES(?, 'scope', 'inventory', 'monitor', 'process', ?, 'config', 'nonce', 'authorized', 1, 2, NULL, ?, ?, 'key', ?)",
			);
			expect(() =>
				insertAuthorization.run(
					"bad-auth",
					hash(actionJson),
					'{"kind":"process","extra":true}',
					authorization,
					hash("monitor-mac"),
				),
			).toThrow("monitor authorization authority projection mismatch");
			insertAuthorization.run("auth", hash(actionJson), actionJson, authorization, hash("monitor-mac"));
			db.prepare("UPDATE monitor_disable_authorizations SET state='executing' WHERE authorization_id='auth'").run();
			expect(() =>
				db
					.prepare(
						"UPDATE monitor_disable_authorizations SET state='consumed', consumed_at_ms=3 WHERE authorization_id='auth'",
					)
					.run(),
			).toThrow("monitor authorization consume CAS mismatch");
			expect(() =>
				db
					.prepare("UPDATE monitor_disable_authorizations SET state='executing' WHERE authorization_id='auth'")
					.run(),
			).toThrow("monitor authorization consume CAS mismatch");
			const disabledRootJson = canonicalizeJson({
				activeMutationId: null,
				baselineEpochId: null,
				canonicalPath: "/tmp/root",
				keyId: "key",
				mac: hash("root-disable-mac"),
				nonce: "disable-nonce",
				enabled: false,
				generation: 2,
				persistContext: false,
				projectPolicyHash: "policy",
				rootId: "root",
				schema: "gjc-bugwatch-root/v1",
				updatedAt: new Date(2).toISOString(),
			} as unknown as JsonValue);
			db.prepare("UPDATE roots SET enabled=0, revision=2, disabled_at_ms=2, root_json=? WHERE root_id='root'").run(
				disabledRootJson,
			);
			const mismatchedRootJson = canonicalizeJson({
				activeMutationId: null,
				baselineEpochId: null,
				canonicalPath: "/tmp/root",
				keyId: "key",
				mac: hash("root-mismatch-mac"),
				nonce: "mismatch-nonce",
				enabled: false,
				generation: 3,
				persistContext: false,
				projectPolicyHash: "policy",
				rootId: "root",
				schema: "gjc-bugwatch-root/v1",
				updatedAt: new Date(3).toISOString(),
			} as unknown as JsonValue);
			expect(() =>
				db
					.prepare("UPDATE roots SET persist_context=1, revision=3, root_json=? WHERE root_id='root'")
					.run(mismatchedRootJson),
			).toThrow("root authority revision CAS mismatch");

			expect(() =>
				db
					.prepare(
						"INSERT INTO job_inputs(job_id, root_id, fingerprint_version, fingerprint_hash, revision, policy_version, input_json, input_hash, input_byte_count, created_at_ms) VALUES('job', 'root', 1, 'fingerprint', 1, 'policy', ?, ?, 0, 1)",
					)
					.run(json, contentHash),
			).toThrow();
			db.prepare(
				"INSERT INTO job_inputs(job_id, root_id, fingerprint_version, fingerprint_hash, revision, policy_version, input_json, input_hash, input_byte_count, created_at_ms) VALUES('job', 'root', 1, 'fingerprint', 1, 'policy', ?, ?, ?, 1)",
			).run(json, contentHash, Buffer.byteLength(json));
			db.prepare(
				"INSERT INTO triage_jobs(job_id, state, attempts, max_attempts, lease_token, lease_expires_at_ms, next_attempt_at_ms, worker_protocol_major, updated_at_ms) VALUES('job', 'queued', 0, 1, NULL, NULL, NULL, 1, 1)",
			).run();
			db.prepare(
				"INSERT INTO triage_results(result_id, job_id, attempt, lease_token, result_kind, result_json, input_hash, context_hash, evidence_hash, output_hash, output_byte_count, upstream_sha, created_at_ms) VALUES('result', 'job', 1, 'lease', 'draft', ?, ?, NULL, 'evidence', ?, ?, NULL, 1)",
			).run(json, contentHash, contentHash, Buffer.byteLength(json));
			expect(() => db.prepare("UPDATE triage_results SET result_kind='matched'").run()).toThrow(
				"triage results are immutable",
			);
			db.prepare(
				"INSERT INTO artifact_outbox(outbox_id, job_id, result_id, artifact_kind, target_relpath, immutable, required, projection_kind, required_projection_generation, expected_prior_hash, content_hash, content, content_byte_count, state, attempts, updated_at_ms) VALUES('outbox', 'job', 'result', 'draft', 'draft.md', 1, 1, NULL, NULL, NULL, ?, X'01', 1, 'pending', 0, 1)",
			).run(hash("artifact"));
			expect(() => db.prepare("UPDATE artifact_outbox SET content=X'02'").run()).toThrow(
				"artifact outbox authority is immutable",
			);
			db.prepare(
				"INSERT INTO manual_artifacts(artifact_id, root_id, path, kind, fingerprint_version, full_fingerprint_hash, revision, content_hash, content, content_byte_count, ownership, import_epoch_id, created_at_ms) VALUES('manual', 'root', 'draft.md', 'draft', NULL, NULL, NULL, ?, X'01', 1, 'manual', NULL, 1)",
			).run(hash("manual"));
			expect(() => db.prepare("DELETE FROM manual_artifacts").run()).toThrow("manual artifacts are immutable");
		} finally {
			db.close();
		}
	});
	it("rejects caller semantic metadata mismatches before fresh or reopened catalog mutation", async () => {
		const suppliedMismatch = { ...metadata, fixtureManifestHash: "different-fixture" };
		const suppliedMismatches: readonly BugwatchSchemaMetadata[] = [
			{ ...metadata, logSchemaVersion: metadata.logSchemaVersion + 1 },
			{ ...metadata, redactionVersion: metadata.redactionVersion + 1 },
			{ ...metadata, noiseVersion: metadata.noiseVersion + 1 },
			{ ...metadata, severityVersion: metadata.severityVersion + 1 },
			{ ...metadata, fingerprintVersion: metadata.fingerprintVersion + 1 },
			suppliedMismatch,
		];
		const { db, directory } = await createDatabase();
		const databasePath = path.join(directory, "authority.sqlite");
		try {
			for (const mismatch of suppliedMismatches) {
				expect(() => migrateBugwatchSchema(db, mismatch)).toThrow(
					"Bugwatch schema metadata must match the compiled semantic contract",
				);
			}
			expect(getCatalogTableNames(db)).toEqual([]);
			migrateBugwatchSchema(db, metadata);
		} finally {
			db.close();
		}

		const reopened = new Database(databasePath);
		try {
			expect(() => migrateBugwatchSchema(reopened, suppliedMismatch)).toThrow(
				"Bugwatch schema metadata must match the compiled semantic contract",
			);
			expect(reopened.prepare<CountRow, []>("SELECT COUNT(*) AS count FROM schema_meta").get()?.count).toBe(1);
		} finally {
			reopened.close();
		}
	});

	it("keeps source generations and checkpoints composite-keyed", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			insertSource(db, 0);
			insertSource(db, 1);
			db.prepare(
				"INSERT INTO source_checkpoints(segment_id, generation, kind, chunk_index, start_offset, end_offset, hash) VALUES('segment', 1, 'chunk', 0, 0, 64, 'hash')",
			).run();
			expect(() =>
				db
					.prepare(
						"INSERT INTO source_checkpoints(segment_id, generation, kind, chunk_index, start_offset, end_offset, hash) VALUES('segment', 2, 'chunk', 0, 0, 64, 'hash')",
					)
					.run(),
			).toThrow();
			expect(
				db.prepare<CountRow, []>("SELECT COUNT(*) AS count FROM sources WHERE segment_id = 'segment'").get()?.count,
			).toBe(2);
		} finally {
			db.close();
		}
	});

	it("enforces root and source foreign-key constraints", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			expect(() =>
				db
					.prepare(
						"INSERT INTO roots(root_id, kind, canonical_path, enabled, revision, project_policy_hash, registered_at_ms) VALUES('bad-root', 'project', NULL, 1, 1, 'policy', 1)",
					)
					.run(),
			).toThrow();
			expect(() =>
				db
					.prepare(
						"INSERT INTO physical_rows(segment_id, generation, end_offset, raw_hash, disposition) VALUES('missing', 0, 1, 'raw', 'filtered')",
					)
					.run(),
			).toThrow();
		} finally {
			db.close();
		}
	});

	it("rejects incomplete older layouts without persisting partial DDL", async () => {
		const incompatibleVersions: {
			kind: BugwatchSchemaIncompatibilityError["kind"];
			schemaMajor: number;
			schemaMinor: number;
		}[] = [
			{ kind: "OLDER_MAJOR", schemaMajor: BUGWATCH_SCHEMA_MAJOR - 1, schemaMinor: BUGWATCH_SCHEMA_MINOR },
			{ kind: "NEWER_MAJOR", schemaMajor: BUGWATCH_SCHEMA_MAJOR + 1, schemaMinor: BUGWATCH_SCHEMA_MINOR },
			{ kind: "NEWER_MINOR", schemaMajor: BUGWATCH_SCHEMA_MAJOR, schemaMinor: BUGWATCH_SCHEMA_MINOR + 1 },
		];

		for (const version of incompatibleVersions) {
			const { db } = await createDatabase();
			try {
				createSchemaMetaOnlyDatabase(db, version.schemaMajor, version.schemaMinor);
				expectIncompatibility(() => migrateBugwatchSchema(db, metadata), version.kind);
				expect(getCatalogTableNames(db)).toEqual(["schema_meta"]);
			} finally {
				db.close();
			}
		}

		const { db } = await createDatabase();
		try {
			createSchemaMetaOnlyDatabase(db, BUGWATCH_SCHEMA_MAJOR, BUGWATCH_SCHEMA_MINOR - 1);
			expectSchemaIntegrity(() => migrateBugwatchSchema(db, metadata), "SCHEMA_DRIFT");
			expect(getCatalogTableNames(db)).toEqual(["schema_meta"]);
			expect(
				db
					.prepare<VersionMetaRow, []>(
						"SELECT schema_major, schema_minor, log_schema_version, fixture_manifest_hash, schema_catalog_hash FROM schema_meta WHERE id = 1",
					)
					.get(),
			).toEqual({
				schema_major: BUGWATCH_SCHEMA_MAJOR,
				schema_minor: BUGWATCH_SCHEMA_MINOR - 1,
				log_schema_version: metadata.logSchemaVersion,
				fixture_manifest_hash: metadata.fixtureManifestHash,
				schema_catalog_hash: BUGWATCH_SCHEMA_CATALOG_HASH,
			});
		} finally {
			db.close();
		}
	});

	it("migrates a complete empty 1.1 catalog and rejects malformed 1.1 catalogs before DDL", async () => {
		const { db: validDatabase } = await createDatabase();
		try {
			createMinorOneDatabase(validDatabase);
			migrateBugwatchSchema(validDatabase, metadata);
			expect(
				validDatabase
					.prepare<CountRow, []>(
						"SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'root_mutation_steps'",
					)
					.get()?.count,
			).toBe(1);
			expect(
				validDatabase
					.prepare<VersionMetaRow, []>(
						"SELECT schema_major, schema_minor, log_schema_version, fixture_manifest_hash, schema_catalog_hash FROM schema_meta WHERE id = 1",
					)
					.get(),
			).toEqual({
				schema_major: BUGWATCH_SCHEMA_MAJOR,
				schema_minor: BUGWATCH_SCHEMA_MINOR,
				log_schema_version: metadata.logSchemaVersion,
				fixture_manifest_hash: metadata.fixtureManifestHash,
				schema_catalog_hash: BUGWATCH_SCHEMA_CATALOG_HASH,
			});
		} finally {
			validDatabase.close();
		}

		const { db: malformedDatabase } = await createDatabase();
		try {
			createMinorOneDatabase(malformedDatabase);
			malformedDatabase.exec("DROP TABLE upstream_cache");
			expectSchemaIntegrity(() => migrateBugwatchSchema(malformedDatabase, metadata), "SCHEMA_DRIFT");
			expect(
				malformedDatabase
					.prepare<CountRow, []>(
						"SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'root_mutation_steps'",
					)
					.get()?.count,
			).toBe(0);
			expect(
				malformedDatabase
					.prepare<VersionMetaRow, []>(
						"SELECT schema_major, schema_minor, log_schema_version, fixture_manifest_hash, schema_catalog_hash FROM schema_meta WHERE id = 1",
					)
					.get(),
			).toEqual({
				schema_major: BUGWATCH_SCHEMA_MAJOR,
				schema_minor: 1,
				log_schema_version: metadata.logSchemaVersion,
				fixture_manifest_hash: metadata.fixtureManifestHash,
				schema_catalog_hash: BUGWATCH_SCHEMA_CATALOG_HASH,
			});
		} finally {
			malformedDatabase.close();
		}
	});

	it("rejects same-version metadata and catalog drift without repairing the store", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			db.prepare("UPDATE schema_meta SET log_schema_version = ? WHERE id = 1").run(metadata.logSchemaVersion + 1);
			expectSchemaIntegrity(() => migrateBugwatchSchema(db, metadata), "SCHEMA_DRIFT");
			expect(db.prepare<CountRow, []>("SELECT COUNT(*) AS count FROM schema_meta").get()?.count).toBe(1);

			db.prepare("UPDATE schema_meta SET log_schema_version = ? WHERE id = 1").run(metadata.logSchemaVersion);
			db.exec("DROP INDEX idx_upstream_cache_expiry_lru");
			expectSchemaIntegrity(() => migrateBugwatchSchema(db, metadata), "SCHEMA_DRIFT");
			expect(
				db
					.prepare<CountRow, []>(
						"SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'index' AND name = 'idx_upstream_cache_expiry_lru'",
					)
					.get()?.count,
			).toBe(0);
		} finally {
			db.close();
		}
	});
	it("rejects missing tables without recreating them", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			db.exec("DROP TABLE upstream_cache");
			expectSchemaIntegrity(() => migrateBugwatchSchema(db, metadata), "SCHEMA_DRIFT");
			expect(
				db
					.prepare<CountRow, []>(
						"SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'upstream_cache'",
					)
					.get()?.count,
			).toBe(0);
		} finally {
			db.close();
		}
	});

	it("rejects altered tables without partially modifying the store", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			db.exec("ALTER TABLE roots ADD COLUMN drift_marker TEXT");
			expectSchemaIntegrity(() => migrateBugwatchSchema(db, metadata), "SCHEMA_DRIFT");
			expect(
				db
					.prepare<CountRow, []>(
						"SELECT COUNT(*) AS count FROM pragma_table_info('roots') WHERE name = 'drift_marker'",
					)
					.get()?.count,
			).toBe(1);
		} finally {
			db.close();
		}
	});

	it("fails closed on CHECK literals, defaults, index expressions, and extra catalog objects", async () => {
		const alteredSchemas = [
			BUGWATCH_SCHEMA_SQL.replace(
				"kind TEXT NOT NULL CHECK(kind IN('project','unattributed','service'))",
				"kind TEXT NOT NULL CHECK(kind IN('PROJECT','unattributed','service'))",
			),
			BUGWATCH_SCHEMA_SQL.replace(
				"contiguous_through INTEGER NOT NULL DEFAULT 0 CHECK(contiguous_through>=0)",
				"contiguous_through INTEGER NOT NULL DEFAULT 1 CHECK(contiguous_through>=0)",
			),
			BUGWATCH_SCHEMA_SQL.replace(
				"CREATE INDEX IF NOT EXISTS idx_upstream_cache_expiry_lru ON upstream_cache(expires_at_ms, last_accessed_at_ms);",
				"CREATE INDEX IF NOT EXISTS idx_upstream_cache_expiry_lru ON upstream_cache(expires_at_ms, created_at_ms);",
			),
		];
		for (const alteredSchema of alteredSchemas) {
			expect(alteredSchema).not.toBe(BUGWATCH_SCHEMA_SQL);
			const { db } = await createDatabase();
			try {
				installRawSchema(db, alteredSchema);
				expectSchemaIntegrity(() => migrateBugwatchSchema(db, metadata), "SCHEMA_DRIFT");
			} finally {
				db.close();
			}
		}

		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			db.exec("CREATE TABLE unexpected_catalog_object(id INTEGER PRIMARY KEY)");
			expectSchemaIntegrity(() => migrateBugwatchSchema(db, metadata), "SCHEMA_DRIFT");
		} finally {
			db.close();
		}
	});

	it("enforces positive parser generation authority", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			expect(() =>
				db
					.prepare(
						"INSERT INTO roots(root_id, kind, canonical_path, enabled, revision, project_policy_hash, registered_at_ms) VALUES('root', 'project', '/tmp/root', 1, 0, 'policy', 1)",
					)
					.run(),
			).toThrow();
			expect(() =>
				db
					.prepare(
						"INSERT INTO scope_policies(scope_id, generation, revision_hash, semantic_json, content_hash, cas_token_hash, created_at_ms, writer_id, key_id, mac) VALUES('scope', 0, 'revision', '{}', 'content', 'token', 1, 'writer', 'key', 'mac')",
					)
					.run(),
			).toThrow();
			db.prepare(
				"INSERT INTO roots(root_id, kind, canonical_path, enabled, revision, project_policy_hash, registered_at_ms, root_json) VALUES('root', 'project', '/tmp/root', 1, 1, 'policy', 1, ?)",
			).run(rootAuthorityJson("root", "policy"));
			db.prepare(
				"INSERT INTO coverage_epochs(epoch_id, root_id, kind, state, policy_revision, coverage_status, started_at_ms) VALUES('epoch', 'root', 'enable_baseline', 'open', 'policy', 'unknown', 1)",
			).run();
			db.prepare(
				"INSERT INTO producer_boots(boot_id, scope_id, boot_core_hash, pid, pid_start_token, producer, started_at_ms, initial_policy_generation, initial_policy_hash, fatal_key_id, gjc_version, boot_core_json) VALUES('valid-boot', 'scope', 'valid-core', 1, 'start', 'producer', 1, 1, 'policy', 'key', 'version', ?)",
			).run(bootCoreJson("valid-boot"));
			expect(() =>
				db
					.prepare(
						"INSERT INTO producer_boots(boot_id, scope_id, boot_core_hash, pid, pid_start_token, producer, started_at_ms, initial_policy_generation, initial_policy_hash, fatal_key_id, gjc_version) VALUES('boot', 'scope', 'core', 1, 'start', 'producer', 1, 0, 'policy', 'key', 'version')",
					)
					.run(),
			).toThrow();
			expect(() =>
				db
					.prepare(
						"INSERT INTO boot_transport_records(boot_id, transport_epoch, record_kind, record_hash, policy_generation, policy_hash, start_seq, file_enabled, record_json, created_at_ms) VALUES('valid-boot', 1, 'start', 'record', 0, 'policy', 1, 1, '{}', 1)",
					)
					.run(),
			).toThrow();
			expect(() =>
				db
					.prepare(
						"INSERT INTO session_attachments(attachment_id, scope_id, attachment_token_hash, boot_id, boot_core_hash, root_id, started_at_ms, state, root_generation, baseline_epoch_id, current_transition_hash) VALUES('attachment', 'scope', 'token', 'valid-boot', 'valid-core', 'root', 1, 'prepared', 0, 'epoch', 'transition')",
					)
					.run(),
			).toThrow();
			expect(() =>
				db
					.prepare(
						"INSERT INTO root_mutations(mutation_id, scope_id, action, core_hash, expected_policy_generation, expected_policy_hash, phase, step_index, current_step_hash, created_at_ms, updated_at_ms) VALUES('mutation', 'scope', 'enable', 'mutation-core', 0, 'policy', 'prepared', 0, 'step', 1, 1)",
					)
					.run(),
			).toThrow();
			expect(() =>
				db
					.prepare(
						"INSERT INTO roots(root_id, kind, canonical_path, enabled, revision, project_policy_hash, registered_at_ms) VALUES('fractional-root', 'project', '/tmp/fractional-root', 1, 1.5, 'policy', 1)",
					)
					.run(),
			).toThrow();
			expect(() =>
				db
					.prepare(
						"INSERT INTO scope_policies(scope_id, generation, revision_hash, semantic_json, content_hash, cas_token_hash, created_at_ms, writer_id, key_id, mac) VALUES('fractional-scope', 1.5, 'revision', '{}', 'content', 'token', 1, 'writer', 'key', 'mac')",
					)
					.run(),
			).toThrow();
			expect(() => insertSource(db, 0.5)).toThrow();
			expect(() =>
				db.prepare("INSERT INTO producer_ranges(boot_id, start_seq, end_seq) VALUES('valid-boot', 1.5, 2)").run(),
			).toThrow();
		} finally {
			db.close();
		}
	});

	it("enforces bounded read-only upstream cache authority", async () => {
		const { db } = await createDatabase();
		try {
			migrateBugwatchSchema(db, metadata);
			const insert = db.prepare(
				"INSERT INTO upstream_cache(cache_key, request_hash, host, method, request_path_query, response_hash, response_status, response_etag, response_headers_json, response_payload, payload_byte_count, created_at_ms, expires_at_ms, last_accessed_at_ms) VALUES(?, ?, 'api.github.com', 'GET', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			);
			const emptyPayload = new Uint8Array();
			let sequence = 0;
			const insertValues = (
				cacheKey: string,
				requestHash: string,
				requestPathQuery: string,
				responseHash: string,
				responseStatus: number,
				responseEtag: string,
				responseHeadersJson: string,
				responsePayload: Uint8Array | string,
				payloadByteCount: number,
				createdAtMs = 1,
				expiresAtMs = 2,
				lastAccessedAtMs = 1,
			): void => {
				insert.run(
					cacheKey,
					requestHash,
					requestPathQuery,
					responseHash,
					responseStatus,
					responseEtag,
					responseHeadersJson,
					responsePayload,
					payloadByteCount,
					createdAtMs,
					expiresAtMs,
					lastAccessedAtMs,
				);
			};
			const insertTextLimit = (
				field: "cacheKey" | "requestHash" | "requestPathQuery" | "responseHash" | "responseEtag",
				limit: number,
			): void => {
				const values = {
					cacheKey: `cache-${sequence}`,
					requestHash: "request",
					requestPathQuery: `/repos/gajae-code/gjc?limit=${sequence}`,
					responseHash: "response",
					responseEtag: "",
				};
				sequence += 1;
				values[field] = field === "requestPathQuery" ? `/${"p".repeat(limit - 1)}` : "x".repeat(limit);
				insertValues(
					values.cacheKey,
					values.requestHash,
					values.requestPathQuery,
					values.responseHash,
					200,
					values.responseEtag,
					"{}",
					emptyPayload,
					0,
				);
				values[field] = field === "requestPathQuery" ? `/${"p".repeat(limit)}` : "x".repeat(limit + 1);
				expect(() =>
					insertValues(
						values.cacheKey,
						values.requestHash,
						values.requestPathQuery,
						values.responseHash,
						200,
						values.responseEtag,
						"{}",
						emptyPayload,
						0,
					),
				).toThrow();
			};

			insertTextLimit("cacheKey", 256);
			insertTextLimit("requestHash", 64);
			insertTextLimit("requestPathQuery", 8_192);
			insertTextLimit("responseHash", 64);
			insertTextLimit("responseEtag", 8_192);

			const maximumHeaders = `{"x":"${"a".repeat(65_528)}"}`;
			expect(new TextEncoder().encode(maximumHeaders).byteLength).toBe(65_536);
			insertValues("headers-max", "request", "/headers-max", "response", 200, "", maximumHeaders, emptyPayload, 0);
			const oversizedHeaders = `{"x":"${"a".repeat(65_529)}"}`;
			expect(() =>
				insertValues(
					"headers-over",
					"request",
					"/headers-over",
					"response",
					200,
					"",
					oversizedHeaders,
					emptyPayload,
					0,
				),
			).toThrow();

			const maximumPayload = new Uint8Array(2 * 1024 * 1024);
			insertValues(
				"payload-max",
				"request",
				"/payload-max",
				"response",
				599,
				"",
				"{}",
				maximumPayload,
				maximumPayload.byteLength,
			);
			const oversizedPayload = new Uint8Array(maximumPayload.byteLength + 1);
			expect(() =>
				insertValues(
					"payload-over",
					"request",
					"/payload-over",
					"response",
					200,
					"",
					"{}",
					oversizedPayload,
					oversizedPayload.byteLength,
				),
			).toThrow();

			const aggregatePath = `/q${"p".repeat(8_190)}`;
			insertValues(
				"y".repeat(256),
				"r".repeat(64),
				aggregatePath,
				"s".repeat(64),
				599,
				"e".repeat(8_192),
				maximumHeaders,
				maximumPayload,
				maximumPayload.byteLength,
			);

			expect(() =>
				insertValues("payload-text", "request", "/payload-text", "response", 200, "", "{}", "not-a-blob", 10),
			).toThrow();
			expect(() =>
				insertValues(
					"fractional-status",
					"request",
					"/fractional-status",
					"response",
					200.5,
					"",
					"{}",
					emptyPayload,
					0,
				),
			).toThrow();
			expect(() =>
				insertValues(
					"fractional-created",
					"request",
					"/fractional-created",
					"response",
					200,
					"",
					"{}",
					emptyPayload,
					0,
					1.5,
				),
			).toThrow();
			expect(() =>
				insertValues(
					"fractional-expires",
					"request",
					"/fractional-expires",
					"response",
					200,
					"",
					"{}",
					emptyPayload,
					0,
					1,
					2.5,
				),
			).toThrow();
			expect(() =>
				insertValues(
					"fractional-accessed",
					"request",
					"/fractional-accessed",
					"response",
					200,
					"",
					"{}",
					emptyPayload,
					0,
					1,
					2,
					1.5,
				),
			).toThrow();
			for (const [cacheKey, createdAtMs, expiresAtMs, lastAccessedAtMs] of [
				["negative-created", -1, 2, 1],
				["negative-expires", 1, -1, 1],
				["negative-accessed", 1, 2, -1],
				["expires-before-created", 2, 1, 2],
				["accessed-before-created", 2, 3, 1],
			] as const) {
				expect(() =>
					insertValues(
						cacheKey,
						"request",
						`/${cacheKey}`,
						"response",
						200,
						"",
						"{}",
						emptyPayload,
						0,
						createdAtMs,
						expiresAtMs,
						lastAccessedAtMs,
					),
				).toThrow();
			}
			expect(() =>
				insertValues("host-path", "request", "not-a-path", "response", 200, "", "{}", emptyPayload, 0),
			).toThrow();
			expect(() =>
				insertValues("headers-json", "request", "/headers-json", "response", 200, "", "{ }", emptyPayload, 0),
			).toThrow();
			for (const [host, method, responseStatus] of [
				["example.com", "GET", 200],
				["api.github.com", "POST", 200],
				["api.github.com", "GET", 600],
			] as const) {
				expect(() =>
					db
						.prepare(
							"INSERT INTO upstream_cache(cache_key, request_hash, host, method, request_path_query, response_hash, response_status, response_etag, response_headers_json, response_payload, payload_byte_count, created_at_ms, expires_at_ms, last_accessed_at_ms) VALUES(?, 'request', ?, ?, ?, 'response', ?, '', '{}', X'', 0, 1, 2, 1)",
						)
						.run(
							`origin-${host}-${method}-${responseStatus}`,
							host,
							method,
							`/origin-${method}-${responseStatus}`,
							responseStatus,
						),
				).toThrow();
			}
		} finally {
			db.close();
		}
	});
	it("validates retained root authority across enable, context, disable, and move revisions", async () => {
		const { db } = await createDatabase();
		const key = new TextEncoder().encode("persisted-root-authority-key");
		const keyId = "root-key";
		const signedRoot = (
			rootId: string,
			canonicalPath: string,
			enabled: boolean,
			persistContext: boolean,
			generation: number,
			activeMutationId: string | null = null,
		): { [key: string]: JsonValue } => {
			const unsigned: { [key: string]: JsonValue } = {
				activeMutationId,
				baselineEpochId: enabled ? "baseline" : null,
				canonicalPath,
				enabled,
				generation,
				keyId,
				nonce: `nonce-${rootId}-${generation}`,
				persistContext,
				projectPolicyHash: hash("policy"),
				rootId,
				schema: "gjc-bugwatch-root/v1",
				scopeId: "scope",
				updatedAt: new Date(generation).toISOString(),
			};
			return { ...unsigned, mac: hmacSha256Hex(key, "gjc-bugwatch-root-v1", macPayload(unsigned)) };
		};
		try {
			migrateBugwatchSchema(db, metadata);
			let oldRoot = signedRoot("old-root", "/tmp/old-root", false, false, 1);
			db.prepare(
				"INSERT INTO roots(root_id, kind, canonical_path, enabled, revision, project_policy_hash, registered_at_ms, disabled_at_ms, persist_context, baseline_epoch_id, active_mutation_id, root_json) VALUES('old-root', 'project', '/tmp/old-root', 0, 1, ?, 1, 1, 0, NULL, NULL, ?)",
			).run(hash("policy"), canonicalizeJson(oldRoot));
			oldRoot = signedRoot("old-root", "/tmp/old-root", true, false, 2);
			db.prepare(
				"UPDATE roots SET enabled=1, revision=2, disabled_at_ms=NULL, baseline_epoch_id='baseline', root_json=? WHERE root_id='old-root'",
			).run(canonicalizeJson(oldRoot));
			oldRoot = signedRoot("old-root", "/tmp/old-root", true, true, 3);
			db.prepare("UPDATE roots SET persist_context=1, revision=3, root_json=? WHERE root_id='old-root'").run(
				canonicalizeJson(oldRoot),
			);
			oldRoot = signedRoot("old-root", "/tmp/old-root", false, false, 4, "move");
			db.prepare(
				"UPDATE roots SET enabled=0, persist_context=0, revision=4, disabled_at_ms=4, baseline_epoch_id=NULL, active_mutation_id='move', root_json=? WHERE root_id='old-root'",
			).run(canonicalizeJson(oldRoot));
			const newRoot = signedRoot("new-root", "/tmp/new-root", true, false, 1, "move");
			db.prepare(
				"INSERT INTO roots(root_id, kind, canonical_path, enabled, revision, project_policy_hash, registered_at_ms, disabled_at_ms, persist_context, baseline_epoch_id, active_mutation_id, root_json) VALUES('new-root', 'project', '/tmp/new-root', 1, 1, ?, 4, NULL, 0, 'baseline', 'move', ?)",
			).run(hash("policy"), canonicalizeJson(newRoot));
			expect(() => validateBugwatchPersistedAuthorities(db, id => (id === keyId ? key : undefined))).not.toThrow();

			db.exec("DROP TRIGGER root_authority_revision_cas");
			const tampered = { ...oldRoot, mac: "0".repeat(64) };
			db.prepare("UPDATE roots SET root_json=? WHERE root_id='old-root'").run(canonicalizeJson(tampered));
			expect(() => validateBugwatchPersistedAuthorities(db, id => (id === keyId ? key : undefined))).toThrow(
				BugwatchSchemaIntegrityError,
			);
		} finally {
			db.close();
		}
	});
	it("consumes monitor authorization only through one matching receipt and rejects orphan authority", async () => {
		const { db } = await createDatabase();
		const key = new TextEncoder().encode("persisted-monitor-authority-key");
		const keyId = "monitor-key";
		const sign = (unsigned: { [key: string]: JsonValue }, domain: string): { [key: string]: JsonValue } => ({
			...unsigned,
			mac: hmacSha256Hex(key, domain, macPayload(unsigned)),
		});
		try {
			migrateBugwatchSchema(db, metadata);
			const root = sign(
				{
					activeMutationId: null,
					baselineEpochId: "baseline",
					canonicalPath: "/tmp/root",
					enabled: true,
					generation: 1,
					keyId,
					nonce: "root-nonce",
					persistContext: false,
					projectPolicyHash: hash("policy"),
					rootId: "root",
					schema: "gjc-bugwatch-root/v1",
					scopeId: "scope",
					updatedAt: new Date(1).toISOString(),
				},
				"gjc-bugwatch-root-v1",
			);
			db.prepare(
				"INSERT INTO roots(root_id, kind, canonical_path, enabled, revision, project_policy_hash, registered_at_ms, persist_context, baseline_epoch_id, root_json) VALUES('root', 'project', '/tmp/root', 1, 1, ?, 1, 0, 'baseline', ?)",
			).run(hash("policy"), canonicalizeJson(root));
			db.prepare(
				"INSERT INTO old_monitor_inventory_epochs(inventory_epoch_id, scope_id, state, started_at_ms, completed_at_ms, receipt_hash) VALUES('inventory', 'scope', 'complete', 1, 1, NULL)",
			).run();
			const inventory = sign(
				{
					adapterEvidenceHash: hash("inventory-evidence"),
					configHash: hash("monitor-config"),
					coveredRootIds: ["root"],
					inventoryEpochId: "inventory",
					keyId,
					kind: "process",
					monitorId: "monitor",
					observedAt: new Date(1).toISOString(),
					schema: "gjc-bugwatch-monitor-inventory/v1",
					scopeId: "scope",
					stableIdentifier: "stable",
					status: "active",
				},
				"gjc-bugwatch-monitor-inventory-v1",
			);
			db.prepare(
				"INSERT INTO old_monitors(inventory_epoch_id, monitor_id, kind, stable_identifier, owner, config_hash, status, observed_at_ms, inventory_json) VALUES('inventory', 'monitor', 'process', 'stable', 'owner', ?, 'active', 1, ?)",
			).run(hash("monitor-config"), canonicalizeJson(inventory));
			db.prepare(
				"INSERT INTO old_monitor_root_coverage(inventory_epoch_id, monitor_id, root_id, coverage_kind) VALUES('inventory', 'monitor', 'root', 'explicit')",
			).run();
			const action: { [key: string]: JsonValue } = {
				argvHash: hash("argv"),
				executableHash: hash("executable"),
				kind: "process",
				pid: 42,
				pidStartToken: "pid-start",
				signal: "TERM",
				uid: "1000",
			};
			const authorization = sign(
				{
					adapterKind: "process",
					authorizationId: "authorization",
					allowedAction: action,
					authorizedAt: new Date(1).toISOString(),
					expectedConfigHash: hash("monitor-config"),
					expiresAt: new Date(2).toISOString(),
					inventoryEpochId: "inventory",
					keyId,
					monitorId: "monitor",
					nonce: "nonce",
					schema: "gjc-bugwatch-monitor-disable-auth/v1",
					scopeId: "scope",
					stableIdentifier: "stable",
				},
				"gjc-bugwatch-monitor-disable-auth-v1",
			);
			const actionJson = canonicalizeJson(action);
			const actionHash = authenticatedHash(action);
			db.prepare(
				"INSERT INTO monitor_disable_authorizations(authorization_id, scope_id, inventory_epoch_id, monitor_id, action_kind, action_hash, expected_config_hash, consume_nonce_hash, state, authorized_at_ms, expires_at_ms, consumed_at_ms, action_json, authorization_json, key_id, mac) VALUES('authorization', 'scope', 'inventory', 'monitor', 'process', ?, ?, ?, 'authorized', 1, 2, NULL, ?, ?, ?, ?)",
			).run(
				actionHash,
				hash("monitor-config"),
				hash("nonce"),
				actionJson,
				canonicalizeJson(authorization),
				keyId,
				String(authorization.mac),
			);
			db.prepare(
				"UPDATE monitor_disable_authorizations SET state='executing' WHERE authorization_id='authorization'",
			).run();
			expect(() =>
				db
					.prepare(
						"UPDATE monitor_disable_authorizations SET state='consumed', consumed_at_ms=4 WHERE authorization_id='authorization'",
					)
					.run(),
			).toThrow("monitor authorization consume CAS mismatch");
			const receipt = sign(
				{
					actionHash,
					adapterKind: "process",
					afterHash: hash("after"),
					authorizationId: "authorization",
					beforeHash: hash("before"),
					coveredRootIds: ["root"],
					finishedAt: new Date(4).toISOString(),
					inventoryEpochId: "inventory",
					keyId,
					monitorId: "monitor",
					result: "disabled",
					schema: "gjc-bugwatch-monitor-disable-receipt/v1",
					scopeId: "scope",
					startedAt: new Date(3).toISOString(),
					steps: [],
				},
				"gjc-bugwatch-monitor-disable-receipt-v1",
			);
			expect(() =>
				db
					.prepare(
						"INSERT INTO monitor_disable_receipts(receipt_id, authorization_id, scope_id, inventory_epoch_id, monitor_id, adapter_kind, action_hash, before_hash, after_hash, result, steps_json, covered_roots_json, receipt_json, started_at_ms, finished_at_ms, receipt_hash, key_id, mac) VALUES('scope-mismatch', 'authorization', 'mismatch', 'inventory', 'monitor', 'process', ?, ?, ?, 'disabled', '[]', '[\"root\"]', ?, 3, 4, ?, ?, ?)",
					)
					.run(
						actionHash,
						hash("before"),
						hash("after"),
						canonicalizeJson(receipt),
						authenticatedHash(receipt),
						keyId,
						String(receipt.mac),
					),
			).toThrow("monitor receipt projection mismatch");
			db.prepare(
				"INSERT INTO monitor_disable_receipts(receipt_id, authorization_id, scope_id, inventory_epoch_id, monitor_id, adapter_kind, action_hash, before_hash, after_hash, result, steps_json, covered_roots_json, receipt_json, started_at_ms, finished_at_ms, receipt_hash, key_id, mac) VALUES('receipt', 'authorization', 'scope', 'inventory', 'monitor', 'process', ?, ?, ?, 'disabled', '[]', '[\"root\"]', ?, 3, 4, ?, ?, ?)",
			).run(
				actionHash,
				hash("before"),
				hash("after"),
				canonicalizeJson(receipt),
				authenticatedHash(receipt),
				keyId,
				String(receipt.mac),
			);
			expect(
				db
					.prepare<{ state: string; consumed_at_ms: number | null }, []>(
						"SELECT state, consumed_at_ms FROM monitor_disable_authorizations WHERE authorization_id='authorization'",
					)
					.get(),
			).toEqual({ state: "consumed", consumed_at_ms: 4 });
			expect(() => validateBugwatchPersistedAuthorities(db, id => (id === keyId ? key : undefined))).not.toThrow();
			expect(() =>
				db.prepare("UPDATE monitor_disable_receipts SET result='failed' WHERE receipt_id='receipt'").run(),
			).toThrow("monitor receipts are immutable");
			expect(() => db.prepare("DELETE FROM monitor_disable_receipts WHERE receipt_id='receipt'").run()).toThrow(
				"monitor receipts are immutable",
			);
			expect(() =>
				db
					.prepare(
						"INSERT INTO monitor_disable_receipts(receipt_id, authorization_id, scope_id, inventory_epoch_id, monitor_id, adapter_kind, action_hash, before_hash, after_hash, result, steps_json, covered_roots_json, receipt_json, started_at_ms, finished_at_ms, receipt_hash, key_id, mac) VALUES('replay', 'authorization', 'scope', 'inventory', 'monitor', 'process', ?, ?, ?, 'disabled', '[]', '[\"root\"]', ?, 3, 4, ?, ?, ?)",
					)
					.run(
						actionHash,
						hash("before"),
						hash("after"),
						canonicalizeJson(receipt),
						authenticatedHash(receipt),
						keyId,
						String(receipt.mac),
					),
			).toThrow();

			const orphanAction = { ...action, pid: 43 };
			const orphan = {
				...authorization,
				allowedAction: orphanAction,
				monitorId: "missing-monitor",
				nonce: "orphan-nonce",
				authorizationId: "orphan",
			} as { [key: string]: JsonValue };
			orphan.mac = hmacSha256Hex(key, "gjc-bugwatch-monitor-disable-auth-v1", macPayload(orphan));
			db.prepare(
				"INSERT INTO monitor_disable_authorizations(authorization_id, scope_id, inventory_epoch_id, monitor_id, action_kind, action_hash, expected_config_hash, consume_nonce_hash, state, authorized_at_ms, expires_at_ms, consumed_at_ms, action_json, authorization_json, key_id, mac) VALUES('orphan', 'scope', 'inventory', 'missing-monitor', 'process', ?, ?, ?, 'authorized', 1, 2, NULL, ?, ?, ?, ?)",
			).run(
				authenticatedHash(orphanAction),
				hash("monitor-config"),
				hash("orphan-nonce"),
				canonicalizeJson(orphanAction),
				canonicalizeJson(orphan),
				keyId,
				String(orphan.mac),
			);
			expect(() => validateBugwatchPersistedAuthorities(db, id => (id === keyId ? key : undefined))).toThrow(
				BugwatchSchemaIntegrityError,
			);
		} finally {
			db.close();
		}
	});
	it("migrates an empty schema 1.8 catalog through schema 1.10 and rejects legacy authority rows", async () => {
		const valid = await createDatabase();
		try {
			installRawSchema(valid.db, BUGWATCH_SCHEMA_SQL);
			valid.db.prepare("UPDATE schema_meta SET schema_minor=8").run();
			migrateBugwatchSchema(valid.db, metadata);
			expect(
				valid.db.prepare<{ schema_minor: number }, []>("SELECT schema_minor FROM schema_meta").get()?.schema_minor,
			).toBe(BUGWATCH_SCHEMA_MINOR);
		} finally {
			valid.db.close();
		}
		const blocked = await createDatabase();
		try {
			installRawSchema(blocked.db, BUGWATCH_SCHEMA_SQL);
			blocked.db.prepare("UPDATE schema_meta SET schema_minor=8").run();
			blocked.db
				.prepare(
					"INSERT INTO roots(root_id, kind, canonical_path, enabled, revision, project_policy_hash, registered_at_ms, disabled_at_ms, persist_context, baseline_epoch_id, active_mutation_id, root_json) VALUES('root', 'project', '/tmp/root', 1, 1, ?, 1, NULL, 0, NULL, NULL, ?)",
				)
				.run(hash("policy"), rootAuthorityJson("root", hash("policy")));
			expectSchemaIntegrity(() => migrateBugwatchSchema(blocked.db, metadata), "SCHEMA_DRIFT");
		} finally {
			blocked.db.close();
		}
	});
	it("persists schema identity and durable members across a real WAL close and reopen", async () => {
		const { db, directory } = await createDatabase();
		const databasePath = path.join(directory, "authority.sqlite");
		let closed = false;
		try {
			migrateBugwatchSchema(db, metadata);
			db.prepare(
				"INSERT INTO roots(root_id, kind, canonical_path, enabled, revision, project_policy_hash, registered_at_ms, disabled_at_ms, persist_context, baseline_epoch_id, active_mutation_id, root_json) VALUES(?, ?, NULL, 1, 1, '', 0, NULL, 0, NULL, NULL, NULL)",
			).run("service", "service");
			db.prepare(
				"INSERT INTO roots(root_id, kind, canonical_path, enabled, revision, project_policy_hash, registered_at_ms, disabled_at_ms, persist_context, baseline_epoch_id, active_mutation_id, root_json) VALUES(?, ?, NULL, 1, 1, '', 0, NULL, 0, NULL, NULL, NULL)",
			).run("unattributed", "unattributed");
			const claimTokenHash = hash("claim");
			db.prepare(
				"INSERT INTO store_operations(operation_id, owner_id, claim_token_hash, kind, from_version, to_version, phase, core_hash, current_step, current_step_hash, backup_path, quarantine_path, watermark_hash, core_json, started_at_ms, updated_at_ms) VALUES('operation', 'owner', ?, 'quarantine', 1, NULL, 'prepared', ?, 0, NULL, NULL, NULL, NULL, ?, 1, 1)",
			).run(claimTokenHash, hash("store-core"), storeOperationCoreJson("operation", claimTokenHash));
			const insertMember = db.prepare(
				"INSERT INTO store_operation_members(operation_id, member, source_path_hash, expected_presence, expected_size, expected_hash, quarantine_path_hash, state, observed_source_hash, observed_quarantine_hash, step_json, updated_at_ms) VALUES('operation', ?, ?, 1, 1, ?, ?, 'intent_recorded', NULL, NULL, '{}', 1)",
			);
			for (const member of ["db", "wal", "shm"] as const)
				insertMember.run(
					member,
					hash(`source-${member}`),
					hash(`expected-${member}`),
					hash(`quarantine-${member}`),
				);
			expect(db.prepare<{ journal_mode: string }, []>("PRAGMA journal_mode").get()?.journal_mode).toBe("wal");
			db.close();
			closed = true;

			const reopened = new Database(databasePath);
			try {
				migrateBugwatchSchema(reopened, metadata);
				expect(
					reopened
						.prepare<VersionMetaRow, []>(
							"SELECT schema_major, schema_minor, log_schema_version, fixture_manifest_hash, schema_catalog_hash FROM schema_meta WHERE id=1",
						)
						.get(),
				).toEqual({
					schema_major: BUGWATCH_SCHEMA_MAJOR,
					schema_minor: BUGWATCH_SCHEMA_MINOR,
					log_schema_version: BUGWATCH_LOG_SCHEMA_VERSION,
					fixture_manifest_hash: BUGWATCH_FIXTURE_MANIFEST_HASH,
					schema_catalog_hash: BUGWATCH_SCHEMA_CATALOG_HASH,
				});
				expect(getCatalogTableNames(reopened)).toEqual([...BUGWATCH_PERSISTED_TABLE_NAMES].sort());
				expect(
					reopened
						.prepare<{ member: string; state: string }, []>(
							"SELECT member, state FROM store_operation_members WHERE operation_id='operation' ORDER BY member",
						)
						.all(),
				).toEqual([
					{ member: "db", state: "intent_recorded" },
					{ member: "shm", state: "intent_recorded" },
					{ member: "wal", state: "intent_recorded" },
				]);
				expect(() => validateBugwatchPersistedAuthorities(reopened, () => undefined)).not.toThrow();
			} finally {
				reopened.close();
			}
		} finally {
			if (!closed) db.close();
		}
	});
});
