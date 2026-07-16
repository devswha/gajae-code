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
} from "@gajae-code/utils/bugwatch-contract";

export {
	BUGWATCH_FINGERPRINT_VERSION,
	BUGWATCH_FIXTURE_MANIFEST_HASH,
	BUGWATCH_LOG_SCHEMA_VERSION,
	BUGWATCH_NOISE_VERSION,
	BUGWATCH_REDACTION_VERSION,
	BUGWATCH_SCHEMA_CATALOG_HASH,
	BUGWATCH_SCHEMA_MAJOR,
	BUGWATCH_SCHEMA_MINOR,
	BUGWATCH_SEVERITY_VERSION,
};

/**
 * Frozen SQLite catalog for the Phase-0 authority store. Keep this in lockstep
 * with BUGWATCH_SCHEMA_SQL and the shared snapshot-class authority inventory.
 */
export const BUGWATCH_PERSISTED_TABLE_NAMES = [
	"schema_meta",
	"fingerprint_version_mappings",
	"scope_policies",
	"scope_policy_heads",
	"roots",
	"root_aliases",
	"producer_boots",
	"coverage_epochs",
	"boot_transport_records",
	"session_attachments",
	"attachment_transitions",
	"root_mutations",
	"root_mutation_steps",
	"root_mutation_outputs",
	"sources",
	"source_checkpoints",
	"archive_aliases",
	"producer_coverage",
	"producer_ranges",
	"physical_rows",
	"identity_quarantines",
	"observations",
	"candidates",
	"overflow_buckets",
	"capacity_blocks",
	"coverage_source_watermarks",
	"coverage_boot_watermarks",
	"coverage_boot_ranges",
	"rollback_epochs",
	"rollback_items",
	"daemon_runs",
	"store_operations",
	"store_operation_members",
	"authority_snapshot_packs",
	"authority_snapshot_items",
	"authority_snapshot_classes",
	"rebuild_authority_gaps",
	"old_monitor_inventory_epochs",
	"old_monitors",
	"old_monitor_root_coverage",
	"legacy_disable_receipts",
	"monitor_disable_authorizations",
	"monitor_disable_receipts",
	"root_mutation_rename_steps",
	"boot_final_records",
	"daemon_health",
	"authority_snapshot_cutoffs",
	"job_inputs",
	"triage_jobs",
	"triage_results",
	"upstream_cache",
	"artifact_outbox",
	"projection_heads",
	"job_projection_requirements",
	"manual_artifacts",
	"fingerprint_prefix_aliases",
	"context_records",
	"import_epochs",
] as const;

/**
 * SQLite tables that record snapshot metadata, reconstruction outcomes, or
 * derived relationships. They are persisted with their owning authority class
 * rather than represented as independent top-level snapshot classes.
 */
export const BUGWATCH_SCHEMA_HELPER_TABLE_MAPPING = {
	authority_snapshot_classes: "authority_snapshot_packs",
	scope_policy_heads: "scope_policies",
	rebuild_authority_gaps: "authority_snapshot_packs",
	daemon_health: "daemon_runs",
	authority_snapshot_cutoffs: "authority_snapshot_packs",
} as const satisfies Partial<Record<(typeof BUGWATCH_PERSISTED_TABLE_NAMES)[number], string>>;

/** Literal Phase-0 authority tables. Values are deliberately not normalized into app types. */
export const BUGWATCH_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS schema_meta (
 id INTEGER PRIMARY KEY CHECK(id=1), schema_major INTEGER NOT NULL, schema_minor INTEGER NOT NULL,
 log_schema_version INTEGER NOT NULL, redaction_version INTEGER NOT NULL, noise_version INTEGER NOT NULL,
 severity_version INTEGER NOT NULL, fingerprint_version INTEGER NOT NULL,
 fixture_manifest_hash TEXT NOT NULL, schema_catalog_hash TEXT NOT NULL, created_at_ms INTEGER NOT NULL, migrated_at_ms INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS fingerprint_version_mappings (
 from_version INTEGER NOT NULL, from_hash TEXT NOT NULL, to_version INTEGER NOT NULL, to_hash TEXT NOT NULL,
 fixture_manifest_hash TEXT NOT NULL, approved_at_ms INTEGER NOT NULL,
 PRIMARY KEY(from_version,from_hash,to_version), UNIQUE(to_version,to_hash,from_version,from_hash)
) STRICT;
CREATE TABLE IF NOT EXISTS scope_policies (
 scope_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>=1), revision_hash TEXT NOT NULL,
 semantic_json TEXT NOT NULL, content_hash TEXT NOT NULL,
 previous_generation INTEGER, previous_revision_hash TEXT, previous_content_hash TEXT,
 cas_token_hash TEXT NOT NULL, created_at_ms INTEGER NOT NULL, writer_id TEXT NOT NULL, key_id TEXT NOT NULL, mac TEXT NOT NULL,
 PRIMARY KEY(scope_id,generation), UNIQUE(scope_id,revision_hash),
 UNIQUE(scope_id,generation,revision_hash,content_hash,cas_token_hash),
 CHECK(
  (generation=1 AND previous_generation IS NULL AND previous_revision_hash IS NULL AND previous_content_hash IS NULL) OR
  (generation>1 AND previous_generation=generation-1 AND previous_revision_hash IS NOT NULL AND previous_content_hash IS NOT NULL)
 )
) STRICT;
CREATE TABLE IF NOT EXISTS scope_policy_heads (
 scope_id TEXT PRIMARY KEY, generation INTEGER NOT NULL CHECK(generation>=1), revision_hash TEXT NOT NULL,
 content_hash TEXT NOT NULL, cas_token_hash TEXT NOT NULL, updated_at_ms INTEGER NOT NULL, key_id TEXT NOT NULL, mac TEXT NOT NULL,
 head_json TEXT NOT NULL,
 FOREIGN KEY(scope_id,generation,revision_hash,content_hash,cas_token_hash)
  REFERENCES scope_policies(scope_id,generation,revision_hash,content_hash,cas_token_hash)
) STRICT;
CREATE TRIGGER IF NOT EXISTS scope_policy_revision_predecessor
BEFORE INSERT ON scope_policies
WHEN NEW.generation>1 AND NOT EXISTS(
 SELECT 1 FROM scope_policies AS predecessor
 WHERE predecessor.scope_id=NEW.scope_id
   AND predecessor.generation=NEW.previous_generation
   AND predecessor.revision_hash=NEW.previous_revision_hash
   AND predecessor.content_hash=NEW.previous_content_hash
)
BEGIN
 SELECT RAISE(ABORT, 'scope policy predecessor mismatch');
END;
CREATE TRIGGER IF NOT EXISTS scope_policy_revision_immutable_insert
BEFORE INSERT ON scope_policies
WHEN EXISTS(
 SELECT 1 FROM scope_policies AS existing
 WHERE existing.scope_id=NEW.scope_id AND existing.generation=NEW.generation
)
BEGIN
 SELECT RAISE(ABORT, 'scope policy revisions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS scope_policy_revision_immutable_update
BEFORE UPDATE ON scope_policies
BEGIN
 SELECT RAISE(ABORT, 'scope policy revisions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS scope_policy_revision_immutable_delete
BEFORE DELETE ON scope_policies
BEGIN
 SELECT RAISE(ABORT, 'scope policy revisions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS scope_policy_head_insert
BEFORE INSERT ON scope_policy_heads
WHEN NOT EXISTS(
 SELECT 1 FROM scope_policies AS revision
 WHERE revision.scope_id=NEW.scope_id
   AND revision.generation=NEW.generation
   AND revision.revision_hash=NEW.revision_hash
   AND revision.content_hash=NEW.content_hash
   AND revision.cas_token_hash=NEW.cas_token_hash
)
BEGIN
 SELECT RAISE(ABORT, 'scope policy head mismatch');
END;
CREATE TRIGGER IF NOT EXISTS scope_policy_head_envelope_insert
BEFORE INSERT ON scope_policy_heads
WHEN NEW.head_json!=
 '{"casToken":'||json_quote(json_extract(NEW.head_json,'$.casToken'))||
 ',"contentHash":'||json_quote(NEW.content_hash)||
 ',"generation":'||NEW.generation||
 ',"keyId":'||json_quote(NEW.key_id)||
 ',"mac":'||json_quote(NEW.mac)||
 ',"revisionHash":'||json_quote(NEW.revision_hash)||
 ',"schema":"gjc-bugwatch-policy-head/v2","scopeId":'||json_quote(NEW.scope_id)||
 ',"updatedAt":'||json_quote(strftime('%Y-%m-%dT%H:%M:%fZ',NEW.updated_at_ms/1000.0,'unixepoch'))||'}'
 OR strftime('%Y-%m-%dT%H:%M:%fZ',NEW.updated_at_ms/1000.0,'unixepoch') IS NULL
 OR json_extract(NEW.head_json,'$.casToken')=NEW.cas_token_hash
BEGIN
 SELECT RAISE(ABORT, 'scope policy head envelope mismatch');
END;
CREATE TRIGGER IF NOT EXISTS scope_policy_head_immutable_insert
BEFORE INSERT ON scope_policy_heads
WHEN EXISTS(SELECT 1 FROM scope_policy_heads AS existing WHERE existing.scope_id=NEW.scope_id)
BEGIN
 SELECT RAISE(ABORT, 'scope policy head must be updated by CAS');
END;
CREATE TRIGGER IF NOT EXISTS scope_policy_head_cas
BEFORE UPDATE ON scope_policy_heads
WHEN NEW.scope_id!=OLD.scope_id OR NEW.generation!=OLD.generation+1
 OR NOT EXISTS(
   SELECT 1 FROM scope_policies AS revision
   WHERE revision.scope_id=NEW.scope_id
     AND revision.generation=NEW.generation
     AND revision.revision_hash=NEW.revision_hash
     AND revision.content_hash=NEW.content_hash
     AND revision.cas_token_hash=NEW.cas_token_hash
     AND revision.previous_generation=OLD.generation
     AND revision.previous_revision_hash=OLD.revision_hash
     AND revision.previous_content_hash=OLD.content_hash
 )
BEGIN
 SELECT RAISE(ABORT, 'scope policy head CAS mismatch');
END;
CREATE TRIGGER IF NOT EXISTS scope_policy_head_envelope_update
BEFORE UPDATE ON scope_policy_heads
WHEN NEW.head_json!=
 '{"casToken":'||json_quote(json_extract(NEW.head_json,'$.casToken'))||
 ',"contentHash":'||json_quote(NEW.content_hash)||
 ',"generation":'||NEW.generation||
 ',"keyId":'||json_quote(NEW.key_id)||
 ',"mac":'||json_quote(NEW.mac)||
 ',"revisionHash":'||json_quote(NEW.revision_hash)||
 ',"schema":"gjc-bugwatch-policy-head/v2","scopeId":'||json_quote(NEW.scope_id)||
 ',"updatedAt":'||json_quote(strftime('%Y-%m-%dT%H:%M:%fZ',NEW.updated_at_ms/1000.0,'unixepoch'))||'}'
 OR strftime('%Y-%m-%dT%H:%M:%fZ',NEW.updated_at_ms/1000.0,'unixepoch') IS NULL
 OR json_extract(NEW.head_json,'$.casToken')=NEW.cas_token_hash
BEGIN
 SELECT RAISE(ABORT, 'scope policy head envelope mismatch');
END;
CREATE TRIGGER IF NOT EXISTS scope_policy_head_immutable_delete
BEFORE DELETE ON scope_policy_heads
BEGIN
 SELECT RAISE(ABORT, 'scope policy head cannot be deleted');
END;
CREATE TABLE IF NOT EXISTS roots (
 root_id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN('project','unattributed','service')),
 canonical_path TEXT UNIQUE, enabled INTEGER NOT NULL CHECK(enabled IN(0,1)), revision INTEGER NOT NULL CHECK(revision>=1),
 project_policy_hash TEXT NOT NULL, registered_at_ms INTEGER NOT NULL, disabled_at_ms INTEGER,
 persist_context INTEGER NOT NULL DEFAULT 0 CHECK(persist_context IN(0,1)), baseline_epoch_id TEXT,
 active_mutation_id TEXT,
 root_json TEXT CHECK(root_json IS NULL OR (json_valid(root_json) AND root_json=json(root_json))),
 CHECK(
  (kind='project' AND canonical_path IS NOT NULL AND root_json IS NOT NULL) OR
  (kind IN('unattributed','service') AND canonical_path IS NULL AND root_json IS NULL
   AND root_id=kind AND enabled=1 AND revision=1 AND project_policy_hash=''
   AND registered_at_ms=0 AND disabled_at_ms IS NULL AND persist_context=0
   AND baseline_epoch_id IS NULL AND active_mutation_id IS NULL)
 )
) STRICT;
CREATE TABLE IF NOT EXISTS root_aliases (
 old_root_id TEXT PRIMARY KEY REFERENCES roots(root_id), new_root_id TEXT NOT NULL REFERENCES roots(root_id),
 move_epoch_id TEXT NOT NULL UNIQUE, old_path_hash TEXT NOT NULL, new_path_hash TEXT NOT NULL, created_at_ms INTEGER NOT NULL,
 CHECK(old_root_id<>new_root_id)
) STRICT;
CREATE TABLE IF NOT EXISTS producer_boots (
 boot_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, boot_core_hash TEXT NOT NULL UNIQUE,
 pid INTEGER NOT NULL CHECK(pid>0), pid_start_token TEXT NOT NULL, producer TEXT NOT NULL,
 started_at_ms INTEGER NOT NULL, initial_policy_generation INTEGER NOT NULL CHECK(initial_policy_generation>=1), initial_policy_hash TEXT NOT NULL,
 fatal_key_id TEXT NOT NULL, gjc_version TEXT NOT NULL, build_sha TEXT, final_seq INTEGER,
 final_state TEXT CHECK(final_state IN('clean','crashed','unknown_disable','unknown_hard_kill')),
 final_record_hash TEXT, boot_core_json TEXT NOT NULL CHECK(json_valid(boot_core_json) AND boot_core_json=json(boot_core_json)),
 CHECK(final_seq IS NULL OR final_seq>=1)
) STRICT;
CREATE TABLE IF NOT EXISTS coverage_epochs (
 epoch_id TEXT PRIMARY KEY, root_id TEXT NOT NULL REFERENCES roots(root_id),
 kind TEXT NOT NULL CHECK(kind IN('enable_baseline','shadow','cutover','rollback','reconcile','disable')),
 state TEXT NOT NULL CHECK(state IN('open','complete','failed')), policy_revision TEXT NOT NULL,
 coverage_status TEXT NOT NULL CHECK(coverage_status IN('covered','gap','unknown')),
 started_at_ms INTEGER NOT NULL, completed_at_ms INTEGER, receipt_hash TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS boot_transport_records (
 boot_id TEXT NOT NULL REFERENCES producer_boots(boot_id), transport_epoch INTEGER NOT NULL CHECK(transport_epoch>=1),
 record_kind TEXT NOT NULL CHECK(record_kind IN('start','close')), record_hash TEXT NOT NULL UNIQUE,
 start_record_hash TEXT, policy_generation INTEGER NOT NULL CHECK(policy_generation>=1), policy_hash TEXT NOT NULL,
 start_seq INTEGER, end_seq INTEGER, file_enabled INTEGER, outcome TEXT, previous_record_hash TEXT,
 record_json TEXT NOT NULL, created_at_ms INTEGER NOT NULL,
 PRIMARY KEY(boot_id,transport_epoch,record_kind),
 CHECK((record_kind='start' AND start_seq IS NOT NULL AND file_enabled IN(0,1)) OR
       (record_kind='close' AND start_record_hash IS NOT NULL AND end_seq IS NOT NULL))
) STRICT;
CREATE TABLE IF NOT EXISTS session_attachments (
 attachment_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, attachment_token_hash TEXT NOT NULL,
 boot_id TEXT NOT NULL REFERENCES producer_boots(boot_id), boot_core_hash TEXT NOT NULL,
 root_id TEXT NOT NULL REFERENCES roots(root_id), session_id TEXT, started_at_ms INTEGER NOT NULL,
 ended_at_ms INTEGER, state TEXT NOT NULL CHECK(state IN('prepared','active','ended','unknown','aborted')),
 managed_session_root TEXT, session_file TEXT, root_generation INTEGER NOT NULL CHECK(root_generation>=1),
 baseline_epoch_id TEXT NOT NULL REFERENCES coverage_epochs(epoch_id), publish_seq INTEGER, retire_seq INTEGER,
 current_transition_hash TEXT NOT NULL, attachment_json TEXT NOT NULL CHECK(json_valid(attachment_json) AND attachment_json=json(attachment_json)),
 CHECK(ended_at_ms IS NULL OR ended_at_ms>=started_at_ms)
) STRICT;
CREATE TABLE IF NOT EXISTS attachment_transitions (
 attachment_id TEXT NOT NULL REFERENCES session_attachments(attachment_id), step_index INTEGER NOT NULL CHECK(step_index>=0),
 transition_hash TEXT NOT NULL UNIQUE CHECK(length(transition_hash)=64 AND transition_hash NOT GLOB '*[^0-9a-f]*'), state TEXT NOT NULL CHECK(state IN('prepared','active','ended','unknown','aborted')),
 previous_transition_hash TEXT, occurred_at_ms INTEGER NOT NULL,
 record_json TEXT NOT NULL CHECK(json_valid(record_json) AND record_json=json(record_json)), record_byte_count INTEGER NOT NULL CHECK(record_byte_count=length(CAST(record_json AS BLOB))),
 key_id TEXT NOT NULL CHECK(length(key_id)>0), mac TEXT NOT NULL CHECK(length(mac)=64 AND mac NOT GLOB '*[^0-9a-f]*'),
 PRIMARY KEY(attachment_id,step_index)
) STRICT;
CREATE TRIGGER IF NOT EXISTS attachment_transition_insert
BEFORE INSERT ON attachment_transitions
WHEN
 (NEW.step_index=0 AND NEW.previous_transition_hash IS NOT NULL) OR
 (NEW.step_index>0 AND NOT EXISTS(
  SELECT 1 FROM attachment_transitions AS predecessor
  WHERE predecessor.attachment_id=NEW.attachment_id
    AND predecessor.step_index=NEW.step_index-1
    AND predecessor.transition_hash=NEW.previous_transition_hash
 )) OR
 NEW.record_json!=(
  SELECT
   '{"attachmentId":'||json_quote(attachment.attachment_id)||
   ',"attachmentTokenHash":'||json_quote(attachment.attachment_token_hash)||
   ',"baselineEpochId":'||json_quote(attachment.baseline_epoch_id)||
   ',"bootCoreHash":'||json_quote(attachment.boot_core_hash)||
   ',"bootId":'||json_quote(attachment.boot_id)||
   ',"endedAt":'||json_quote(CASE WHEN attachment.ended_at_ms IS NULL THEN NULL ELSE strftime('%Y-%m-%dT%H:%M:%fZ',attachment.ended_at_ms/1000.0,'unixepoch') END)||
   ',"keyId":'||json_quote(NEW.key_id)||
   ',"mac":'||json_quote(NEW.mac)||
   ',"managedSessionRoot":'||json_quote(attachment.managed_session_root)||
   ',"publishSequence":'||json_quote(CASE WHEN attachment.publish_seq IS NULL THEN NULL ELSE CAST(attachment.publish_seq AS TEXT) END)||
   ',"retireSequence":'||json_quote(CASE WHEN attachment.retire_seq IS NULL THEN NULL ELSE CAST(attachment.retire_seq AS TEXT) END)||
   ',"rootGeneration":'||attachment.root_generation||
   ',"rootId":'||json_quote(attachment.root_id)||
   ',"schema":"gjc-bugwatch-attachment/v1"'||
   ',"scopeId":'||json_quote(attachment.scope_id)||
   ',"sessionFile":'||json_quote(attachment.session_file)||
   ',"sessionId":'||json_quote(attachment.session_id)||
   ',"startedAt":'||json_quote(strftime('%Y-%m-%dT%H:%M:%fZ',attachment.started_at_ms/1000.0,'unixepoch'))||
   ',"state":'||json_quote(NEW.state)||'}'
  FROM session_attachments AS attachment
  WHERE attachment.attachment_id=NEW.attachment_id
 ) OR
 strftime('%Y-%m-%dT%H:%M:%fZ',(SELECT started_at_ms FROM session_attachments WHERE attachment_id=NEW.attachment_id)/1000.0,'unixepoch') IS NULL
BEGIN
 SELECT RAISE(ABORT, 'attachment transition envelope or chain mismatch');
END;
CREATE TRIGGER IF NOT EXISTS attachment_transition_immutable_update
BEFORE UPDATE ON attachment_transitions
BEGIN
 SELECT RAISE(ABORT, 'attachment transitions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS attachment_transition_immutable_delete
BEFORE DELETE ON attachment_transitions
BEGIN
 SELECT RAISE(ABORT, 'attachment transitions are immutable');
END;
CREATE TABLE IF NOT EXISTS root_mutation_steps (
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
CREATE TRIGGER IF NOT EXISTS root_mutation_step_chain_insert
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
CREATE TRIGGER IF NOT EXISTS root_mutation_step_immutable_insert
BEFORE INSERT ON root_mutation_steps
WHEN EXISTS(
 SELECT 1 FROM root_mutation_steps AS existing
 WHERE existing.scope_id=NEW.scope_id AND existing.mutation_id=NEW.mutation_id AND existing.step_index=NEW.step_index
)
BEGIN
 SELECT RAISE(ABORT, 'root mutation steps are immutable');
END;
CREATE TRIGGER IF NOT EXISTS root_mutation_step_immutable_update
BEFORE UPDATE ON root_mutation_steps
BEGIN
 SELECT RAISE(ABORT, 'root mutation steps are immutable');
END;
CREATE TRIGGER IF NOT EXISTS root_mutation_step_immutable_delete
BEFORE DELETE ON root_mutation_steps
BEGIN
 SELECT RAISE(ABORT, 'root mutation steps are immutable');
END;
CREATE TABLE IF NOT EXISTS root_mutations (
 mutation_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN('enable','disable','set_context','move')),
 core_hash TEXT NOT NULL UNIQUE CHECK(length(core_hash)=64 AND core_hash NOT GLOB '*[^0-9a-f]*'), core_json TEXT NOT NULL CHECK(json_valid(core_json)),
 expected_policy_generation INTEGER NOT NULL CHECK(expected_policy_generation>=1), expected_policy_hash TEXT NOT NULL CHECK(length(expected_policy_hash)=64 AND expected_policy_hash NOT GLOB '*[^0-9a-f]*'),
 old_root_id TEXT REFERENCES roots(root_id), new_root_id TEXT REFERENCES roots(root_id),
 phase TEXT NOT NULL CHECK(phase IN('prepared','publishing','files_published','db_applied','baseline_complete','files_finalized','committed','aborted','conflict')),
 step_index INTEGER NOT NULL, current_step_hash TEXT NOT NULL, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
) STRICT;
CREATE TRIGGER IF NOT EXISTS root_mutation_core_projection_insert
BEFORE INSERT ON root_mutations
WHEN json_extract(NEW.core_json,'$.schema')!='gjc-bugwatch-root-mutation-core/v1'
 OR json_extract(NEW.core_json,'$.scopeId')!=NEW.scope_id
 OR json_extract(NEW.core_json,'$.mutationId')!=NEW.mutation_id
 OR json_extract(NEW.core_json,'$.action')!=NEW.action
 OR json_extract(NEW.core_json,'$.expectedPolicyGeneration')!=NEW.expected_policy_generation
 OR json_extract(NEW.core_json,'$.expectedPolicyHash')!=NEW.expected_policy_hash
 OR json_extract(NEW.core_json,'$.oldRootId') IS NOT NEW.old_root_id
 OR json_extract(NEW.core_json,'$.newRootId') IS NOT NEW.new_root_id
 OR json_extract(NEW.core_json,'$.createdAt') IS NULL
 OR json_extract(NEW.core_json,'$.keyId') IS NULL
 OR json_extract(NEW.core_json,'$.mac') IS NULL
BEGIN
 SELECT RAISE(ABORT, 'root mutation core projection mismatch');
END;
CREATE TRIGGER IF NOT EXISTS root_mutation_core_immutable_update
BEFORE UPDATE ON root_mutations
WHEN NEW.mutation_id!=OLD.mutation_id
 OR NEW.scope_id!=OLD.scope_id
 OR NEW.action!=OLD.action
 OR NEW.core_hash!=OLD.core_hash
 OR NEW.core_json!=OLD.core_json
 OR NEW.expected_policy_generation!=OLD.expected_policy_generation
 OR NEW.expected_policy_hash!=OLD.expected_policy_hash
 OR NEW.old_root_id IS NOT OLD.old_root_id
 OR NEW.new_root_id IS NOT OLD.new_root_id
 OR NEW.created_at_ms!=OLD.created_at_ms
BEGIN
 SELECT RAISE(ABORT, 'root mutation core identity is immutable');
END;
CREATE TRIGGER IF NOT EXISTS root_mutation_summary_insert
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
CREATE TRIGGER IF NOT EXISTS root_mutation_summary_update
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
CREATE TABLE IF NOT EXISTS root_mutation_outputs (
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
CREATE TRIGGER IF NOT EXISTS root_mutation_output_core_projection_insert
BEFORE INSERT ON root_mutation_outputs
WHEN NOT EXISTS(
 SELECT 1
 FROM root_mutations AS mutation, json_each(json_extract(mutation.core_json,'$.outputs')) AS output
 WHERE mutation.mutation_id=NEW.mutation_id
   AND json_extract(output.value,'$.target')=NEW.target
   AND json_extract(output.value,'$.pathHash')=NEW.path_hash
   AND json_extract(output.value,'$.precondition')=NEW.precondition
   AND json_extract(output.value,'$.expectedOldContentHash') IS NEW.expected_old_content_hash
   AND json_extract(output.value,'$.pendingContentHash')=NEW.pending_content_hash
   AND json_extract(output.value,'$.finalContentHash')=NEW.final_content_hash
   AND json_extract(output.value,'$.desiredRootGeneration')=NEW.desired_root_generation
   AND json_extract(output.value,'$.publicationOrder')=NEW.publication_order
)
BEGIN
 SELECT RAISE(ABORT, 'root mutation output core projection mismatch');
END;
CREATE TRIGGER IF NOT EXISTS root_mutation_output_immutable_update
BEFORE UPDATE ON root_mutation_outputs
BEGIN
 SELECT RAISE(ABORT, 'root mutation outputs are immutable');
END;
CREATE TRIGGER IF NOT EXISTS root_mutation_output_immutable_delete
BEFORE DELETE ON root_mutation_outputs
BEGIN
 SELECT RAISE(ABORT, 'root mutation outputs are immutable');
END;
CREATE TABLE IF NOT EXISTS sources (
 segment_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>=0),
 source_kind TEXT NOT NULL CHECK(source_kind IN('log','inbox','rollback')), path TEXT NOT NULL, file_identity_hint TEXT NOT NULL,
 prefix_anchor_length INTEGER NOT NULL CHECK(prefix_anchor_length BETWEEN 0 AND 4096), prefix_hash TEXT NOT NULL,
 committed_offset INTEGER NOT NULL CHECK(committed_offset>=0), boundary_hash TEXT, checkpoint_digest TEXT NOT NULL,
 validation_state TEXT NOT NULL CHECK(validation_state IN('unvalidated','revalidating','valid','mismatch','ambiguous')),
 state TEXT NOT NULL CHECK(state IN('active','draining','exhausted','generation_changed','orphaned','quarantined','archive_ambiguous','capacity_blocked')),
 block_id TEXT, updated_at_ms INTEGER NOT NULL, PRIMARY KEY(segment_id,generation)
) STRICT;
CREATE TABLE IF NOT EXISTS source_checkpoints (
 segment_id TEXT NOT NULL, generation INTEGER NOT NULL, kind TEXT NOT NULL CHECK(kind IN('chunk','tail')),
 chunk_index INTEGER NOT NULL CHECK(chunk_index>=0), start_offset INTEGER NOT NULL CHECK(start_offset>=0),
 end_offset INTEGER NOT NULL CHECK(end_offset>start_offset), hash TEXT NOT NULL, validated_at_ms INTEGER,
 PRIMARY KEY(segment_id,generation,kind,chunk_index),
 FOREIGN KEY(segment_id,generation) REFERENCES sources(segment_id,generation) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS archive_aliases (
 archive_digest TEXT NOT NULL, uncompressed_length INTEGER NOT NULL CHECK(uncompressed_length>=0),
 segment_id TEXT NOT NULL, generation INTEGER NOT NULL, lineage_kind TEXT NOT NULL CHECK(lineage_kind IN('full','prefix')),
 verified_checkpoint_digest TEXT NOT NULL, created_at_ms INTEGER NOT NULL,
 PRIMARY KEY(archive_digest,uncompressed_length,segment_id,generation),
 FOREIGN KEY(segment_id,generation) REFERENCES sources(segment_id,generation)
) STRICT;
CREATE TABLE IF NOT EXISTS producer_coverage (
 boot_id TEXT PRIMARY KEY REFERENCES producer_boots(boot_id), contiguous_through INTEGER NOT NULL DEFAULT 0 CHECK(contiguous_through>=0),
 max_seen INTEGER NOT NULL DEFAULT 0 CHECK(max_seen>=contiguous_through), final_seq INTEGER,
 state TEXT NOT NULL CHECK(state IN('open','complete','gap','unknown_hard_kill','reconciled_with_gap')), updated_at_ms INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS producer_ranges (
 boot_id TEXT NOT NULL REFERENCES producer_boots(boot_id), start_seq INTEGER NOT NULL CHECK(start_seq>=1),
 end_seq INTEGER NOT NULL CHECK(end_seq>=start_seq), PRIMARY KEY(boot_id,start_seq)
) STRICT;
CREATE TABLE IF NOT EXISTS physical_rows (
 segment_id TEXT NOT NULL, generation INTEGER NOT NULL, end_offset INTEGER NOT NULL CHECK(end_offset>0), raw_hash TEXT NOT NULL,
 boot_id TEXT REFERENCES producer_boots(boot_id), record_seq INTEGER, event_id TEXT,
 disposition TEXT NOT NULL CHECK(disposition IN('candidate','filtered','self','service','disabled_root','diagnostic','overflow')),
 PRIMARY KEY(segment_id,generation,end_offset), UNIQUE(boot_id,record_seq,segment_id,generation,end_offset),
 FOREIGN KEY(segment_id,generation) REFERENCES sources(segment_id,generation) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS identity_quarantines (
 quarantine_id TEXT PRIMARY KEY, segment_id TEXT NOT NULL, generation INTEGER NOT NULL, expected_offset INTEGER NOT NULL,
 raw_hash TEXT NOT NULL, claimed_boot_id TEXT, claimed_attachment_id TEXT, claimed_root_id TEXT, claimed_event_id TEXT,
 reason TEXT NOT NULL CHECK(reason IN('missing_boot','event_mismatch','attachment_mismatch','root_mismatch','interval_mismatch','manifest_conflict')),
 state TEXT NOT NULL CHECK(state IN('active','reconciled','dismissed')), created_at_ms INTEGER NOT NULL, resolved_at_ms INTEGER,
 UNIQUE(segment_id,generation,expected_offset), FOREIGN KEY(segment_id,generation) REFERENCES sources(segment_id,generation)
) STRICT;
CREATE TABLE IF NOT EXISTS observations (
 event_id TEXT PRIMARY KEY, root_id TEXT NOT NULL REFERENCES roots(root_id), boot_id TEXT REFERENCES producer_boots(boot_id),
 attachment_id TEXT REFERENCES session_attachments(attachment_id), correlation_id TEXT, record_seq INTEGER,
 fingerprint_version INTEGER NOT NULL, fingerprint_hash TEXT NOT NULL, fingerprint_text TEXT NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN('fatal','high','medium','low','diagnostic')),
 category TEXT NOT NULL CHECK(category IN('gjc-internal','error','warn','diagnostic')),
 message TEXT NOT NULL, stack_top TEXT, occurred_at_ms INTEGER, created_at_ms INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS candidates (
 root_id TEXT NOT NULL REFERENCES roots(root_id), fingerprint_version INTEGER NOT NULL, fingerprint_hash TEXT NOT NULL,
 count INTEGER NOT NULL CHECK(count>0), severity TEXT NOT NULL, category TEXT NOT NULL,
 sample_event_id TEXT REFERENCES observations(event_id) ON DELETE SET NULL,
 policy_state TEXT NOT NULL CHECK(policy_state IN('open','drafted','resolved','dismissed','suppressed','capacity_blocked','candidate_authority_unknown','triage_authority_unknown')),
 latest_revision INTEGER NOT NULL DEFAULT 0 CHECK(latest_revision>=0), next_eligible_at_ms INTEGER,
 PRIMARY KEY(root_id,fingerprint_version,fingerprint_hash)
) STRICT;
CREATE TABLE IF NOT EXISTS overflow_buckets (
 root_id TEXT NOT NULL REFERENCES roots(root_id), severity TEXT NOT NULL CHECK(severity IN('low','medium')),
 window_start_ms INTEGER NOT NULL, count INTEGER NOT NULL CHECK(count>0), first_at_ms INTEGER NOT NULL, last_at_ms INTEGER NOT NULL,
 first_raw_hash TEXT NOT NULL, last_raw_hash TEXT NOT NULL, PRIMARY KEY(root_id,severity,window_start_ms)
) STRICT;
CREATE TABLE IF NOT EXISTS capacity_blocks (
 block_id TEXT PRIMARY KEY, segment_id TEXT NOT NULL, generation INTEGER NOT NULL, expected_offset INTEGER NOT NULL,
 raw_hash TEXT NOT NULL, root_id TEXT NOT NULL REFERENCES roots(root_id), severity TEXT NOT NULL,
 reason TEXT NOT NULL CHECK(reason IN('candidate','db','wal','outbox','coverage_fragmentation','inbox')),
 state TEXT NOT NULL CHECK(state IN('active','cleared')), emergency_slot INTEGER CHECK(emergency_slot BETWEEN 0 AND 127),
 created_at_ms INTEGER NOT NULL, cleared_at_ms INTEGER, UNIQUE(segment_id,generation,expected_offset),
 FOREIGN KEY(segment_id,generation) REFERENCES sources(segment_id,generation)
) STRICT;
CREATE TABLE IF NOT EXISTS coverage_source_watermarks (
 epoch_id TEXT NOT NULL REFERENCES coverage_epochs(epoch_id), segment_id TEXT NOT NULL, generation INTEGER NOT NULL,
 offset INTEGER NOT NULL CHECK(offset>=0), boundary_hash TEXT, checkpoint_digest TEXT, source_state TEXT NOT NULL,
 PRIMARY KEY(epoch_id,segment_id,generation), FOREIGN KEY(segment_id,generation) REFERENCES sources(segment_id,generation)
) STRICT;
CREATE TABLE IF NOT EXISTS coverage_boot_watermarks (
 epoch_id TEXT NOT NULL REFERENCES coverage_epochs(epoch_id), boot_id TEXT NOT NULL REFERENCES producer_boots(boot_id),
 root_relation TEXT NOT NULL CHECK(root_relation IN('attached','unattributed','service')), frontier INTEGER NOT NULL, max_seen INTEGER NOT NULL,
 final_seq INTEGER, coverage_state TEXT NOT NULL, range_digest TEXT NOT NULL, PRIMARY KEY(epoch_id,boot_id)
) STRICT;
CREATE TABLE IF NOT EXISTS coverage_boot_ranges (
 epoch_id TEXT NOT NULL, boot_id TEXT NOT NULL, start_seq INTEGER NOT NULL, end_seq INTEGER NOT NULL CHECK(end_seq>=start_seq),
 PRIMARY KEY(epoch_id,boot_id,start_seq), FOREIGN KEY(epoch_id,boot_id) REFERENCES coverage_boot_watermarks(epoch_id,boot_id) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS rollback_epochs (
 epoch_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, role_transition_token TEXT NOT NULL UNIQUE, bundle_version INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN('quiescing','exporting','exported','released','fallback_active','importing','complete','failed')),
 manifest_hash TEXT, limits_json TEXT NOT NULL CHECK(json_valid(limits_json) AND limits_json=json(limits_json)),
 bundle_json TEXT NOT NULL CHECK(json_valid(bundle_json) AND bundle_json=json(bundle_json)),
 spool_manifest_json TEXT NOT NULL CHECK(json_valid(spool_manifest_json) AND spool_manifest_json=json(spool_manifest_json)),
 inbox_ack_json TEXT NOT NULL CHECK(json_valid(inbox_ack_json) AND inbox_ack_json=json(inbox_ack_json)),
 created_at_ms INTEGER NOT NULL, exported_at_ms INTEGER, released_at_ms INTEGER, completed_at_ms INTEGER
) STRICT;
CREATE TABLE IF NOT EXISTS rollback_items (
 epoch_id TEXT NOT NULL REFERENCES rollback_epochs(epoch_id), item_index INTEGER NOT NULL CHECK(item_index>=0), item_type TEXT NOT NULL,
 item_hash TEXT NOT NULL CHECK(length(item_hash)=64 AND item_hash NOT GLOB '*[^0-9a-f]*'), payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64 AND payload_hash NOT GLOB '*[^0-9a-f]*'),
 payload_byte_count INTEGER NOT NULL CHECK(payload_byte_count>=0), state TEXT NOT NULL CHECK(state IN('pending','applied','duplicate','failed')),
 payload BLOB NOT NULL CHECK(payload_byte_count=length(payload)), item_schema TEXT NOT NULL CHECK(item_schema='gjc-bugwatch-rollback-bundle-item/v1'),
 key_id TEXT NOT NULL, mac TEXT NOT NULL, item_json TEXT NOT NULL CHECK(json_valid(item_json) AND item_json=json(item_json)),
 PRIMARY KEY(epoch_id,item_index)
) STRICT;
CREATE TRIGGER IF NOT EXISTS rollback_item_authority_projection_insert
BEFORE INSERT ON rollback_items
WHEN json_extract(NEW.item_json,'$.schema')!=NEW.item_schema
 OR json_extract(NEW.item_json,'$.epochId')!=NEW.epoch_id
 OR json_extract(NEW.item_json,'$.itemIndex')!=NEW.item_index
 OR json_extract(NEW.item_json,'$.itemType')!=NEW.item_type
 OR json_extract(NEW.item_json,'$.payloadHash')!=NEW.payload_hash
 OR json_extract(NEW.item_json,'$.itemHash')!=NEW.item_hash
 OR json_extract(NEW.item_json,'$.keyId')!=NEW.key_id
 OR json_extract(NEW.item_json,'$.mac')!=NEW.mac
BEGIN
 SELECT RAISE(ABORT, 'rollback item authority projection mismatch');
END;
CREATE TRIGGER IF NOT EXISTS rollback_item_immutable_update
BEFORE UPDATE ON rollback_items
BEGIN
 SELECT RAISE(ABORT, 'rollback items are immutable');
END;
CREATE TRIGGER IF NOT EXISTS rollback_item_immutable_delete
BEFORE DELETE ON rollback_items
BEGIN
 SELECT RAISE(ABORT, 'rollback items are immutable');
END;
CREATE TABLE IF NOT EXISTS daemon_runs (
 owner_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, claim_token_hash TEXT NOT NULL UNIQUE,
 role TEXT NOT NULL CHECK(role IN('daemon','fallback')), pid INTEGER NOT NULL, pid_start_token TEXT NOT NULL,
 executable_fingerprint TEXT NOT NULL, protocol_major INTEGER NOT NULL, store_min INTEGER NOT NULL, store_max INTEGER NOT NULL,
 started_at_ms INTEGER NOT NULL, ended_at_ms INTEGER, outcome TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS store_operations (
 operation_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, claim_token_hash TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('migrate','restore','quarantine','rebuild')), from_version INTEGER NOT NULL, to_version INTEGER,
 phase TEXT NOT NULL, core_hash TEXT NOT NULL UNIQUE, current_step INTEGER NOT NULL, current_step_hash TEXT,
 backup_path TEXT, quarantine_path TEXT, watermark_hash TEXT,
 core_json TEXT NOT NULL CHECK(json_valid(core_json) AND core_json=json(core_json)),
 started_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS store_operation_members (
 operation_id TEXT NOT NULL REFERENCES store_operations(operation_id) ON DELETE CASCADE,
 member TEXT NOT NULL CHECK(member IN('db','wal','shm')), source_path_hash TEXT NOT NULL,
 expected_presence INTEGER NOT NULL CHECK(expected_presence IN(0,1)), expected_size INTEGER, expected_hash TEXT,
 quarantine_path_hash TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN('pending','intent_recorded','moved','verified_absent','mismatch','conflict')),
 observed_source_hash TEXT, observed_quarantine_hash TEXT, step_json TEXT NOT NULL CHECK(json_valid(step_json) AND step_json=json(step_json)),
 updated_at_ms INTEGER NOT NULL,
 PRIMARY KEY(operation_id,member), CHECK(source_path_hash<>quarantine_path_hash)
) STRICT;
CREATE TRIGGER IF NOT EXISTS store_operation_member_paths_insert
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
CREATE TRIGGER IF NOT EXISTS store_operation_member_identity_immutable_update
BEFORE UPDATE OF operation_id, member, source_path_hash, quarantine_path_hash ON store_operation_members
WHEN NEW.operation_id!=OLD.operation_id OR NEW.member!=OLD.member
  OR NEW.source_path_hash!=OLD.source_path_hash OR NEW.quarantine_path_hash!=OLD.quarantine_path_hash
BEGIN
 SELECT RAISE(ABORT, 'store operation member identities are immutable');
END;
CREATE TABLE IF NOT EXISTS authority_snapshot_packs (
 snapshot_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('migration','rebuild','cutover','rollback','manual_authority')),
 manifest_hash TEXT NOT NULL UNIQUE, merkle_root TEXT NOT NULL, item_count INTEGER NOT NULL CHECK(item_count>=0),
 byte_count INTEGER NOT NULL CHECK(byte_count>=0), created_at_ms INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN('writing','verified','superseded','quarantined'))
) STRICT;
CREATE TABLE IF NOT EXISTS authority_snapshot_items (
 snapshot_id TEXT NOT NULL REFERENCES authority_snapshot_packs(snapshot_id) ON DELETE CASCADE,
 item_index INTEGER NOT NULL CHECK(item_index>=0), item_type TEXT NOT NULL, authority_id TEXT NOT NULL,
 item_hash TEXT NOT NULL, payload_hash TEXT NOT NULL, previous_item_hash TEXT, payload BLOB NOT NULL,
 PRIMARY KEY(snapshot_id,item_index), UNIQUE(snapshot_id,item_type,authority_id,payload_hash), UNIQUE(snapshot_id,item_hash),
 FOREIGN KEY(snapshot_id,previous_item_hash) REFERENCES authority_snapshot_items(snapshot_id,item_hash)
) STRICT;
CREATE TRIGGER IF NOT EXISTS authority_snapshot_item_chain_insert
BEFORE INSERT ON authority_snapshot_items
WHEN (NEW.item_index=0 AND NEW.previous_item_hash IS NOT NULL)
  OR (NEW.item_index>0 AND NOT EXISTS(
   SELECT 1 FROM authority_snapshot_items AS predecessor
   WHERE predecessor.snapshot_id=NEW.snapshot_id
     AND predecessor.item_index=NEW.item_index-1
     AND predecessor.item_hash=NEW.previous_item_hash
  ))
BEGIN
 SELECT RAISE(ABORT, 'snapshot item predecessor must be the preceding item');
END;
CREATE TABLE IF NOT EXISTS authority_snapshot_classes (
 snapshot_id TEXT NOT NULL REFERENCES authority_snapshot_packs(snapshot_id) ON DELETE CASCADE,
 class_name TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN('payload','external_replay','excluded_safe')),
 item_count INTEGER NOT NULL CHECK(item_count>=0), class_digest TEXT NOT NULL, reconstructive_source TEXT NOT NULL,
 PRIMARY KEY(snapshot_id,class_name)
) STRICT;
CREATE TABLE IF NOT EXISTS rebuild_authority_gaps (
 rebuild_id TEXT NOT NULL, class_name TEXT NOT NULL, authority_id TEXT NOT NULL,
 reason TEXT NOT NULL CHECK(reason IN('missing_snapshot_item','missing_replay_source','post_cutoff_gap','digest_mismatch','cutoff_conflict')),
 disposition TEXT NOT NULL, detected_at_ms INTEGER NOT NULL, PRIMARY KEY(rebuild_id,class_name,authority_id)
) STRICT;
CREATE TABLE IF NOT EXISTS old_monitor_inventory_epochs (
 inventory_epoch_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN('collecting','complete','failed')),
 started_at_ms INTEGER NOT NULL, completed_at_ms INTEGER, receipt_hash TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS old_monitors (
 inventory_epoch_id TEXT NOT NULL REFERENCES old_monitor_inventory_epochs(inventory_epoch_id), monitor_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('gjc_cron','user_cron','systemd_user','process','tmux','plugin')),
 stable_identifier TEXT NOT NULL, owner TEXT NOT NULL, config_hash TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN('active','inactive','unknown')), observed_at_ms INTEGER NOT NULL,
 inventory_json TEXT NOT NULL CHECK(json_valid(inventory_json) AND inventory_json=json(inventory_json)),
 PRIMARY KEY(inventory_epoch_id,monitor_id), UNIQUE(inventory_epoch_id,kind,stable_identifier)
) STRICT;
CREATE TABLE IF NOT EXISTS old_monitor_root_coverage (
 inventory_epoch_id TEXT NOT NULL, monitor_id TEXT NOT NULL, root_id TEXT NOT NULL REFERENCES roots(root_id),
 coverage_kind TEXT NOT NULL CHECK(coverage_kind IN('global','explicit','inferred','unknown')),
 PRIMARY KEY(inventory_epoch_id,monitor_id,root_id),
 FOREIGN KEY(inventory_epoch_id,monitor_id) REFERENCES old_monitors(inventory_epoch_id,monitor_id) ON DELETE CASCADE
) STRICT;
CREATE TABLE IF NOT EXISTS monitor_disable_authorizations (
 authorization_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, inventory_epoch_id TEXT NOT NULL, monitor_id TEXT NOT NULL,
 action_kind TEXT NOT NULL, action_hash TEXT NOT NULL UNIQUE CHECK(length(action_hash)=64 AND action_hash NOT GLOB '*[^0-9a-f]*'), expected_config_hash TEXT NOT NULL,
 consume_nonce_hash TEXT NOT NULL UNIQUE, state TEXT NOT NULL CHECK(state IN('authorized','executing','consumed','expired','refused')),
 authorized_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, consumed_at_ms INTEGER,
 action_json TEXT NOT NULL CHECK(json_valid(action_json) AND action_json=json(action_json)),
 authorization_json TEXT NOT NULL CHECK(json_valid(authorization_json) AND authorization_json=json(authorization_json)),
 key_id TEXT NOT NULL, mac TEXT NOT NULL CHECK(length(mac)=64 AND mac NOT GLOB '*[^0-9a-f]*'),
 FOREIGN KEY(inventory_epoch_id,monitor_id) REFERENCES old_monitors(inventory_epoch_id,monitor_id)
) STRICT;
CREATE TRIGGER IF NOT EXISTS monitor_authorization_authority_projection_insert
BEFORE INSERT ON monitor_disable_authorizations
WHEN NEW.state!='authorized'
 OR NEW.consumed_at_ms IS NOT NULL
 OR json_extract(NEW.authorization_json,'$.schema')!='gjc-bugwatch-monitor-disable-auth/v1'
 OR json_extract(NEW.authorization_json,'$.scopeId')!=NEW.scope_id
 OR json_extract(NEW.authorization_json,'$.inventoryEpochId')!=NEW.inventory_epoch_id
 OR json_extract(NEW.authorization_json,'$.monitorId')!=NEW.monitor_id
 OR json_extract(NEW.authorization_json,'$.authorizationId')!=NEW.authorization_id
 OR json_extract(NEW.authorization_json,'$.adapterKind')!=NEW.action_kind
 OR json_extract(NEW.authorization_json,'$.expectedConfigHash')!=NEW.expected_config_hash
 OR json_type(NEW.authorization_json,'$.allowedAction')!='object'
 OR json_extract(NEW.authorization_json,'$.keyId')!=NEW.key_id
 OR json_extract(NEW.authorization_json,'$.mac')!=NEW.mac
 OR NEW.action_json!=json_extract(NEW.authorization_json,'$.allowedAction')
 OR json_type(NEW.authorization_json,'$.authorizedAt')!='text'
 OR json_type(NEW.authorization_json,'$.expiresAt')!='text'
 OR json_type(NEW.authorization_json,'$.nonce')!='text'
 OR json_extract(NEW.action_json,'$.kind')!=NEW.action_kind
 OR NOT EXISTS(
  SELECT 1 FROM old_monitor_inventory_epochs AS epoch
  JOIN old_monitors AS monitor
    ON monitor.inventory_epoch_id=epoch.inventory_epoch_id
   AND monitor.monitor_id=NEW.monitor_id
  WHERE epoch.inventory_epoch_id=NEW.inventory_epoch_id
    AND epoch.scope_id=NEW.scope_id
    AND monitor.kind=NEW.action_kind
    AND monitor.stable_identifier=json_extract(NEW.authorization_json,'$.stableIdentifier')
    AND monitor.config_hash=NEW.expected_config_hash
 )
BEGIN
 SELECT RAISE(ABORT, 'monitor authorization authority projection mismatch');
END;
CREATE TRIGGER IF NOT EXISTS monitor_authorization_consume_cas
BEFORE UPDATE ON monitor_disable_authorizations
WHEN NOT (
 (OLD.state='authorized' AND NEW.state='executing' AND NEW.consumed_at_ms IS NULL) OR
 (OLD.state IN('authorized','executing') AND NEW.state IN('expired','refused') AND NEW.consumed_at_ms IS NULL) OR
 (OLD.state='executing' AND NEW.state='consumed' AND NEW.consumed_at_ms IS NOT NULL AND EXISTS(
   SELECT 1 FROM monitor_disable_receipts AS receipt
   WHERE receipt.authorization_id=OLD.authorization_id
     AND receipt.inventory_epoch_id=OLD.inventory_epoch_id
     AND receipt.monitor_id=OLD.monitor_id
     AND receipt.adapter_kind=OLD.action_kind
     AND receipt.action_hash=OLD.action_hash
     AND receipt.finished_at_ms=NEW.consumed_at_ms
 ))
)
 OR NEW.authorization_id!=OLD.authorization_id
 OR NEW.scope_id!=OLD.scope_id
 OR NEW.inventory_epoch_id!=OLD.inventory_epoch_id
 OR NEW.monitor_id!=OLD.monitor_id
 OR NEW.action_kind!=OLD.action_kind
 OR NEW.action_hash!=OLD.action_hash
 OR NEW.expected_config_hash!=OLD.expected_config_hash
 OR NEW.consume_nonce_hash!=OLD.consume_nonce_hash
 OR NEW.authorized_at_ms!=OLD.authorized_at_ms
 OR NEW.expires_at_ms!=OLD.expires_at_ms
 OR NEW.action_json!=OLD.action_json
 OR NEW.authorization_json!=OLD.authorization_json
 OR NEW.key_id!=OLD.key_id
 OR NEW.mac!=OLD.mac
BEGIN
 SELECT RAISE(ABORT, 'monitor authorization consume CAS mismatch');
END;
CREATE TRIGGER IF NOT EXISTS monitor_authorization_immutable_delete
BEFORE DELETE ON monitor_disable_authorizations
BEGIN
 SELECT RAISE(ABORT, 'monitor authorizations are immutable');
END;
CREATE TABLE IF NOT EXISTS monitor_disable_receipts (
 receipt_id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL UNIQUE REFERENCES monitor_disable_authorizations(authorization_id),
 scope_id TEXT NOT NULL, inventory_epoch_id TEXT NOT NULL, monitor_id TEXT NOT NULL, adapter_kind TEXT NOT NULL, action_hash TEXT NOT NULL,
 before_hash TEXT NOT NULL, after_hash TEXT,
 result TEXT NOT NULL CHECK(result IN('disabled','already_inactive','unavailable','refused','partial_failure','failed')),
 steps_json TEXT NOT NULL CHECK(json_valid(steps_json) AND steps_json=json(steps_json)),
 covered_roots_json TEXT NOT NULL CHECK(json_valid(covered_roots_json) AND covered_roots_json=json(covered_roots_json)),
 receipt_json TEXT NOT NULL CHECK(json_valid(receipt_json) AND receipt_json=json(receipt_json)),
 started_at_ms INTEGER NOT NULL, finished_at_ms INTEGER NOT NULL,
 receipt_hash TEXT NOT NULL UNIQUE CHECK(length(receipt_hash)=64 AND receipt_hash NOT GLOB '*[^0-9a-f]*'),
 key_id TEXT NOT NULL, mac TEXT NOT NULL
) STRICT;
CREATE TRIGGER IF NOT EXISTS monitor_receipt_consume_authorization
BEFORE INSERT ON monitor_disable_receipts
WHEN NOT EXISTS(
 SELECT 1 FROM monitor_disable_authorizations AS authorization
 JOIN old_monitors AS monitor
   ON monitor.inventory_epoch_id=authorization.inventory_epoch_id
  AND monitor.monitor_id=authorization.monitor_id
 WHERE authorization.authorization_id=NEW.authorization_id
   AND authorization.scope_id=NEW.scope_id
   AND authorization.state='executing'
   AND authorization.inventory_epoch_id=NEW.inventory_epoch_id
   AND authorization.monitor_id=NEW.monitor_id
   AND authorization.action_kind=NEW.adapter_kind
   AND authorization.action_hash=NEW.action_hash
   AND authorization.expected_config_hash=monitor.config_hash
   AND NOT EXISTS(
    SELECT 1 FROM old_monitor_root_coverage AS coverage
    WHERE coverage.inventory_epoch_id=authorization.inventory_epoch_id
      AND coverage.monitor_id=authorization.monitor_id
      AND coverage.root_id NOT IN (SELECT value FROM json_each(NEW.covered_roots_json))
   )
   AND NOT EXISTS(
    SELECT 1 FROM json_each(NEW.covered_roots_json) AS covered
    WHERE covered.value NOT IN (
     SELECT coverage.root_id FROM old_monitor_root_coverage AS coverage
     WHERE coverage.inventory_epoch_id=authorization.inventory_epoch_id
       AND coverage.monitor_id=authorization.monitor_id
    )
   )
   AND (SELECT count(*) FROM json_each(NEW.covered_roots_json))=(
    SELECT count(*) FROM old_monitor_root_coverage AS coverage
    WHERE coverage.inventory_epoch_id=authorization.inventory_epoch_id
      AND coverage.monitor_id=authorization.monitor_id
   )
   AND NEW.receipt_json=json_object(
    'actionHash',NEW.action_hash,
    'adapterKind',NEW.adapter_kind,
    'afterHash',NEW.after_hash,
    'authorizationId',NEW.authorization_id,
    'beforeHash',NEW.before_hash,
    'coveredRootIds',json(NEW.covered_roots_json),
    'finishedAt',strftime('%Y-%m-%dT%H:%M:%fZ',NEW.finished_at_ms/1000.0,'unixepoch'),
    'inventoryEpochId',NEW.inventory_epoch_id,
    'keyId',NEW.key_id,
    'mac',NEW.mac,
    'monitorId',NEW.monitor_id,
    'result',NEW.result,
    'schema','gjc-bugwatch-monitor-disable-receipt/v1',
    'scopeId',NEW.scope_id,
    'startedAt',strftime('%Y-%m-%dT%H:%M:%fZ',NEW.started_at_ms/1000.0,'unixepoch'),
    'steps',json(NEW.steps_json)
   )
)
BEGIN
 SELECT RAISE(ABORT, 'monitor receipt authorization/action/inventory mismatch');
END;
CREATE TRIGGER IF NOT EXISTS monitor_receipt_consume_authorization_after
AFTER INSERT ON monitor_disable_receipts
BEGIN
 UPDATE monitor_disable_authorizations
 SET state='consumed', consumed_at_ms=NEW.finished_at_ms
 WHERE authorization_id=NEW.authorization_id AND state='executing';
END;
CREATE TRIGGER IF NOT EXISTS monitor_receipt_immutable_update
BEFORE UPDATE ON monitor_disable_receipts
BEGIN
 SELECT RAISE(ABORT, 'monitor receipts are immutable');
END;
CREATE TRIGGER IF NOT EXISTS monitor_receipt_immutable_delete
BEFORE DELETE ON monitor_disable_receipts
BEGIN
 SELECT RAISE(ABORT, 'monitor receipts are immutable');
END;
CREATE TABLE IF NOT EXISTS legacy_disable_receipts (
 receipt_id TEXT PRIMARY KEY, root_id TEXT NOT NULL REFERENCES roots(root_id), receipt_hash TEXT NOT NULL UNIQUE,
 payload BLOB NOT NULL, payload_json TEXT NOT NULL CHECK(json_valid(payload_json) AND payload_json=json(payload_json)),
 created_at_ms INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS root_mutation_rename_steps (
 scope_id TEXT NOT NULL, mutation_id TEXT NOT NULL REFERENCES root_mutations(mutation_id) ON DELETE CASCADE,
 core_hash TEXT NOT NULL, step_index INTEGER NOT NULL CHECK(step_index>=0),
 target TEXT NOT NULL CHECK(target IN('old_root','new_root')),
 lifecycle TEXT NOT NULL CHECK(lifecycle IN('pending','final')),
 action TEXT NOT NULL CHECK(action IN('rename_intent','rename_complete')),
 expected_destination_hash TEXT CHECK(expected_destination_hash IS NULL OR (length(expected_destination_hash)=64 AND expected_destination_hash NOT GLOB '*[^0-9a-f]*')),
 source_temp_hash TEXT NOT NULL CHECK(length(source_temp_hash)=64 AND source_temp_hash NOT GLOB '*[^0-9a-f]*'),
 desired_destination_hash TEXT NOT NULL CHECK(length(desired_destination_hash)=64 AND desired_destination_hash NOT GLOB '*[^0-9a-f]*'),
 observed_destination_hash TEXT CHECK(observed_destination_hash IS NULL OR (length(observed_destination_hash)=64 AND observed_destination_hash NOT GLOB '*[^0-9a-f]*')),
 previous_step_hash TEXT CHECK(previous_step_hash IS NULL OR (length(previous_step_hash)=64 AND previous_step_hash NOT GLOB '*[^0-9a-f]*')),
 step_hash TEXT NOT NULL UNIQUE CHECK(length(step_hash)=64 AND step_hash NOT GLOB '*[^0-9a-f]*'),
 occurred_at_ms INTEGER NOT NULL, record_json TEXT NOT NULL CHECK(json_valid(record_json) AND record_json=json(record_json)),
 record_byte_count INTEGER NOT NULL CHECK(record_byte_count=length(CAST(record_json AS BLOB))),
 key_id TEXT NOT NULL, mac TEXT NOT NULL CHECK(length(mac)=64 AND mac NOT GLOB '*[^0-9a-f]*'),
 PRIMARY KEY(mutation_id,step_index), UNIQUE(mutation_id,target,lifecycle,action)
) STRICT;
CREATE TRIGGER IF NOT EXISTS root_mutation_rename_step_projection_insert
BEFORE INSERT ON root_mutation_rename_steps
WHEN NOT EXISTS(
 SELECT 1 FROM root_mutations AS mutation
 WHERE mutation.mutation_id=NEW.mutation_id AND mutation.scope_id=NEW.scope_id AND mutation.core_hash=NEW.core_hash
)
 OR json_extract(NEW.record_json,'$.schema')!='gjc-bugwatch-root-rename-step/v2'
 OR json_extract(NEW.record_json,'$.scopeId')!=NEW.scope_id
 OR json_extract(NEW.record_json,'$.mutationId')!=NEW.mutation_id
 OR json_extract(NEW.record_json,'$.coreHash')!=NEW.core_hash
 OR json_extract(NEW.record_json,'$.stepIndex')!=NEW.step_index
 OR json_extract(NEW.record_json,'$.target')!=NEW.target
 OR json_extract(NEW.record_json,'$.lifecycle')!=NEW.lifecycle
 OR json_extract(NEW.record_json,'$.action')!=NEW.action
 OR json_extract(NEW.record_json,'$.expectedDestinationHash') IS NOT NEW.expected_destination_hash
 OR json_extract(NEW.record_json,'$.sourceTempHash')!=NEW.source_temp_hash
 OR json_extract(NEW.record_json,'$.desiredDestinationHash')!=NEW.desired_destination_hash
 OR json_extract(NEW.record_json,'$.observedDestinationHash') IS NOT NEW.observed_destination_hash
 OR json_extract(NEW.record_json,'$.previousStepHash') IS NOT NEW.previous_step_hash
 OR json_extract(NEW.record_json,'$.keyId')!=NEW.key_id
 OR json_extract(NEW.record_json,'$.mac')!=NEW.mac
 OR json_extract(NEW.record_json,'$.occurredAt')!=strftime('%Y-%m-%dT%H:%M:%fZ',NEW.occurred_at_ms/1000.0,'unixepoch')
 OR strftime('%Y-%m-%dT%H:%M:%fZ',NEW.occurred_at_ms/1000.0,'unixepoch') IS NULL
BEGIN
 SELECT RAISE(ABORT, 'root mutation rename step projection mismatch');
END;
CREATE TRIGGER IF NOT EXISTS root_mutation_rename_step_chain_insert
BEFORE INSERT ON root_mutation_rename_steps
WHEN (NEW.step_index=0 AND NEW.previous_step_hash IS NOT NULL)
 OR (NEW.step_index>0 AND NOT EXISTS(
  SELECT 1 FROM root_mutation_rename_steps AS predecessor
  WHERE predecessor.mutation_id=NEW.mutation_id
   AND predecessor.step_index=NEW.step_index-1
   AND predecessor.step_hash=NEW.previous_step_hash
 ))
BEGIN
 SELECT RAISE(ABORT, 'root mutation rename step chain mismatch');
END;
CREATE TRIGGER IF NOT EXISTS root_mutation_rename_step_immutable_update
BEFORE UPDATE ON root_mutation_rename_steps
BEGIN
 SELECT RAISE(ABORT, 'root mutation rename steps are immutable');
END;
CREATE TRIGGER IF NOT EXISTS root_mutation_rename_step_immutable_delete
BEFORE DELETE ON root_mutation_rename_steps
BEGIN
 SELECT RAISE(ABORT, 'root mutation rename steps are immutable');
END;
CREATE TABLE IF NOT EXISTS boot_final_records (
 boot_id TEXT PRIMARY KEY REFERENCES producer_boots(boot_id), record_hash TEXT NOT NULL UNIQUE,
 final_seq INTEGER NOT NULL CHECK(final_seq>=1), state TEXT NOT NULL CHECK(state IN('clean','crashed','unknown_disable')),
 last_transport_record_hash TEXT NOT NULL, attachment_snapshot_hash TEXT NOT NULL,
 previous_record_hash TEXT NOT NULL, record_json TEXT NOT NULL, created_at_ms INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS daemon_health (
 health_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES daemon_runs(owner_id), scope_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN('healthy','degraded','blocked','stopped')),
 reason TEXT, affected_roots_json TEXT NOT NULL, observed_at_ms INTEGER NOT NULL,
 UNIQUE(owner_id, observed_at_ms)
) STRICT;
CREATE TABLE IF NOT EXISTS authority_snapshot_cutoffs (
 snapshot_id TEXT PRIMARY KEY REFERENCES authority_snapshot_packs(snapshot_id) ON DELETE CASCADE,
 operation_id TEXT NOT NULL, quiesce_token_hash TEXT NOT NULL, cutoff_at_ms INTEGER NOT NULL,
 sqlite_backup_hash TEXT NOT NULL, schema_meta_hash TEXT NOT NULL, source_watermarks_hash TEXT NOT NULL,
 registry_frontiers_hash TEXT NOT NULL, inbox_frontier_hash TEXT NOT NULL, emergency_frontier_hash TEXT NOT NULL,
 rollback_spool_frontier_hash TEXT NOT NULL, artifact_frontier_hash TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_mutation_rename_step ON root_mutation_rename_steps(mutation_id, target, lifecycle, step_index);
CREATE INDEX IF NOT EXISTS idx_boot_final_record ON boot_final_records(record_hash);
CREATE INDEX IF NOT EXISTS idx_daemon_health_state ON daemon_health(scope_id, state, observed_at_ms);
CREATE TABLE IF NOT EXISTS job_inputs (
 job_id TEXT PRIMARY KEY, root_id TEXT NOT NULL, fingerprint_version INTEGER NOT NULL, fingerprint_hash TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>=1), policy_version TEXT NOT NULL,
 input_json TEXT NOT NULL CHECK(json_valid(input_json) AND input_json=json(input_json)), input_hash TEXT NOT NULL CHECK(length(input_hash)=64 AND input_hash NOT GLOB '*[^0-9a-f]*'),
 input_byte_count INTEGER NOT NULL CHECK(input_byte_count=length(CAST(input_json AS BLOB))),
 created_at_ms INTEGER NOT NULL, UNIQUE(root_id,fingerprint_version,fingerprint_hash,revision),
 FOREIGN KEY(root_id,fingerprint_version,fingerprint_hash) REFERENCES candidates(root_id,fingerprint_version,fingerprint_hash)
) STRICT;
CREATE TRIGGER IF NOT EXISTS job_input_immutable_update
BEFORE UPDATE ON job_inputs
BEGIN
 SELECT RAISE(ABORT, 'job inputs are immutable');
END;
CREATE TRIGGER IF NOT EXISTS job_input_immutable_delete
BEFORE DELETE ON job_inputs
BEGIN
 SELECT RAISE(ABORT, 'job inputs are immutable');
END;
CREATE TABLE IF NOT EXISTS triage_jobs (
 job_id TEXT PRIMARY KEY REFERENCES job_inputs(job_id),
 state TEXT NOT NULL CHECK(state IN('queued','running','retryable','awaiting_artifacts','completed','deferred','matched','dismissed','quarantined','conflict','disabled')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0), max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 10),
 lease_token TEXT, lease_expires_at_ms INTEGER, next_attempt_at_ms INTEGER, worker_protocol_major INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
 CHECK((state='running' AND lease_token IS NOT NULL AND lease_expires_at_ms IS NOT NULL) OR
       (state!='running' AND lease_token IS NULL AND lease_expires_at_ms IS NULL))
) STRICT;
CREATE TABLE IF NOT EXISTS triage_results (
 result_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES triage_jobs(job_id), attempt INTEGER NOT NULL CHECK(attempt>=1),
 lease_token TEXT NOT NULL, result_kind TEXT NOT NULL CHECK(result_kind IN('draft','matched','dismissed','deferred','retryable','quarantined')),
 result_json TEXT NOT NULL CHECK(json_valid(result_json) AND result_json=json(result_json)), input_hash TEXT NOT NULL, context_hash TEXT, evidence_hash TEXT NOT NULL, output_hash TEXT NOT NULL CHECK(length(output_hash)=64 AND output_hash NOT GLOB '*[^0-9a-f]*'),
 output_byte_count INTEGER NOT NULL CHECK(output_byte_count=length(CAST(result_json AS BLOB))),
 upstream_sha TEXT, created_at_ms INTEGER NOT NULL, UNIQUE(job_id,attempt)
) STRICT;
CREATE TRIGGER IF NOT EXISTS triage_result_immutable_update
BEFORE UPDATE ON triage_results
BEGIN
 SELECT RAISE(ABORT, 'triage results are immutable');
END;
CREATE TRIGGER IF NOT EXISTS triage_result_immutable_delete
BEFORE DELETE ON triage_results
BEGIN
 SELECT RAISE(ABORT, 'triage results are immutable');
END;
CREATE TABLE IF NOT EXISTS upstream_cache (
 cache_key TEXT PRIMARY KEY CHECK(length(CAST(cache_key AS BLOB)) BETWEEN 1 AND 256),
 request_hash TEXT NOT NULL CHECK(length(CAST(request_hash AS BLOB)) BETWEEN 1 AND 64),
 host TEXT NOT NULL CHECK(host='api.github.com'),
 method TEXT NOT NULL CHECK(method='GET'),
 request_path_query TEXT NOT NULL CHECK(length(CAST(request_path_query AS BLOB)) BETWEEN 1 AND 8192 AND substr(request_path_query,1,1)='/' AND instr(request_path_query,'#')=0),
 response_hash TEXT NOT NULL CHECK(length(CAST(response_hash AS BLOB)) BETWEEN 1 AND 64),
 response_status INTEGER NOT NULL CHECK(response_status BETWEEN 100 AND 599),
 response_etag TEXT NOT NULL CHECK(length(CAST(response_etag AS BLOB))<=8192),
 response_headers_json TEXT NOT NULL CHECK(length(CAST(response_headers_json AS BLOB))<=65536 AND json_valid(response_headers_json) AND response_headers_json=json(response_headers_json)),
 response_payload BLOB NOT NULL,
 payload_byte_count INTEGER NOT NULL CHECK(payload_byte_count BETWEEN 0 AND 2097152 AND payload_byte_count=length(response_payload)),
 created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0), expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>=0), last_accessed_at_ms INTEGER NOT NULL CHECK(last_accessed_at_ms>=0),
 CHECK(expires_at_ms>=created_at_ms), CHECK(last_accessed_at_ms>=created_at_ms),
 CHECK(
	length(CAST(cache_key AS BLOB)) +
	length(CAST(request_hash AS BLOB)) +
	length(CAST(request_path_query AS BLOB)) +
	length(CAST(response_hash AS BLOB)) +
	length(CAST(response_etag AS BLOB)) +
	length(CAST(response_headers_json AS BLOB)) +
	payload_byte_count <= 2179456
 ),
 UNIQUE(host,method,request_path_query)
) STRICT;
CREATE TABLE IF NOT EXISTS artifact_outbox (
 outbox_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES triage_jobs(job_id), result_id TEXT NOT NULL REFERENCES triage_results(result_id),
 artifact_kind TEXT NOT NULL CHECK(artifact_kind IN('draft','receipt','projection')), target_relpath TEXT NOT NULL,
 immutable INTEGER NOT NULL CHECK(immutable IN(0,1)), required INTEGER NOT NULL CHECK(required IN(0,1)),
 projection_kind TEXT, required_projection_generation INTEGER, expected_prior_hash TEXT, content_hash TEXT NOT NULL CHECK(length(content_hash)=64 AND content_hash NOT GLOB '*[^0-9a-f]*'), content BLOB NOT NULL,
 content_byte_count INTEGER NOT NULL CHECK(content_byte_count>=0 AND content_byte_count=length(content)),
 state TEXT NOT NULL CHECK(state IN('pending','materialized','adopted','conflict','failed','cancelled')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0), updated_at_ms INTEGER NOT NULL,
 UNIQUE(job_id,artifact_kind,target_relpath)
) STRICT;
CREATE TRIGGER IF NOT EXISTS artifact_outbox_authority_immutable_update
BEFORE UPDATE OF outbox_id, job_id, result_id, artifact_kind, target_relpath, immutable, required, projection_kind, required_projection_generation, expected_prior_hash, content_hash, content, content_byte_count ON artifact_outbox
BEGIN
 SELECT RAISE(ABORT, 'artifact outbox authority is immutable');
END;
CREATE TABLE IF NOT EXISTS projection_heads (
 root_id TEXT NOT NULL REFERENCES roots(root_id), projection_kind TEXT NOT NULL CHECK(projection_kind IN('index','resolved_markdown','resolved_jsonl')),
 target_relpath TEXT NOT NULL, next_generation INTEGER NOT NULL DEFAULT 0 CHECK(next_generation>=0),
 dirty_through_generation INTEGER NOT NULL DEFAULT 0, applied_generation INTEGER NOT NULL DEFAULT 0,
 state TEXT NOT NULL CHECK(state IN('clean','dirty','materializing')), claim_token TEXT, claim_generation INTEGER,
 current_hash TEXT, version INTEGER NOT NULL DEFAULT 0, updated_at_ms INTEGER NOT NULL,
 PRIMARY KEY(root_id,projection_kind), UNIQUE(root_id,target_relpath),
 CHECK(applied_generation<=dirty_through_generation AND dirty_through_generation<=next_generation),
 CHECK((state='materializing' AND claim_token IS NOT NULL AND claim_generation IS NOT NULL) OR
       (state!='materializing' AND claim_token IS NULL AND claim_generation IS NULL))
) STRICT;
CREATE TABLE IF NOT EXISTS job_projection_requirements (
 job_id TEXT NOT NULL REFERENCES triage_jobs(job_id), root_id TEXT NOT NULL, projection_kind TEXT NOT NULL,
 required_generation INTEGER NOT NULL CHECK(required_generation>=1), PRIMARY KEY(job_id,projection_kind),
 FOREIGN KEY(root_id,projection_kind) REFERENCES projection_heads(root_id,projection_kind)
) STRICT;
CREATE TABLE IF NOT EXISTS manual_artifacts (
 artifact_id TEXT PRIMARY KEY, root_id TEXT NOT NULL REFERENCES roots(root_id), path TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('draft','index','resolved_markdown','resolved_jsonl')),
 fingerprint_version INTEGER, full_fingerprint_hash TEXT, revision INTEGER, content_hash TEXT NOT NULL CHECK(length(content_hash)=64 AND content_hash NOT GLOB '*[^0-9a-f]*'),
 content BLOB NOT NULL, content_byte_count INTEGER NOT NULL CHECK(content_byte_count>=0 AND content_byte_count=length(content)),
 ownership TEXT NOT NULL CHECK(ownership IN('manual','legacy_generated')), import_epoch_id TEXT REFERENCES import_epochs(epoch_id), created_at_ms INTEGER NOT NULL,
 UNIQUE(root_id,path)
) STRICT;
CREATE TRIGGER IF NOT EXISTS manual_artifact_immutable_update
BEFORE UPDATE ON manual_artifacts
BEGIN
 SELECT RAISE(ABORT, 'manual artifacts are immutable');
END;
CREATE TRIGGER IF NOT EXISTS manual_artifact_immutable_delete
BEFORE DELETE ON manual_artifacts
BEGIN
 SELECT RAISE(ABORT, 'manual artifacts are immutable');
END;
CREATE TABLE IF NOT EXISTS fingerprint_prefix_aliases (
 root_id TEXT NOT NULL REFERENCES roots(root_id), fingerprint_version INTEGER NOT NULL, full_hash TEXT NOT NULL,
 prefix_len INTEGER NOT NULL CHECK(prefix_len IN(8,12,16,64)), prefix TEXT NOT NULL,
 source TEXT NOT NULL CHECK(source IN('generated','imported')), artifact_id TEXT REFERENCES manual_artifacts(artifact_id),
 PRIMARY KEY(root_id,fingerprint_version,full_hash), UNIQUE(root_id,fingerprint_version,prefix)
) STRICT;
CREATE TABLE IF NOT EXISTS context_records (
 context_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES triage_jobs(job_id), path TEXT NOT NULL UNIQUE,
 content_hash TEXT NOT NULL, byte_count INTEGER NOT NULL CHECK(byte_count BETWEEN 1 AND 16384), expires_at_ms INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN('present','deleting','deleted')), deleted_at_ms INTEGER, delete_proof_hash TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS import_epochs (
 epoch_id TEXT PRIMARY KEY, root_id TEXT NOT NULL REFERENCES roots(root_id),
 kind TEXT NOT NULL CHECK(kind IN('legacy_resolved','legacy_drafts','manual_refresh','rollback_import')),
 source_path_hash TEXT NOT NULL, source_content_hash TEXT NOT NULL, byte_count INTEGER NOT NULL CHECK(byte_count>=0),
 item_count INTEGER NOT NULL CHECK(item_count>=0), state TEXT NOT NULL CHECK(state IN('importing','complete','failed')),
 started_at_ms INTEGER NOT NULL, completed_at_ms INTEGER, UNIQUE(root_id,kind,source_path_hash,source_content_hash)
) STRICT;
CREATE TRIGGER IF NOT EXISTS root_authority_projection_insert
BEFORE INSERT ON roots
WHEN
 (NEW.kind='project' AND (
  json_extract(NEW.root_json,'$.schema')!='gjc-bugwatch-root/v1'
  OR json_extract(NEW.root_json,'$.rootId')!=NEW.root_id
  OR json_extract(NEW.root_json,'$.canonicalPath') IS NOT NEW.canonical_path
  OR json_type(NEW.root_json,'$.keyId') IS NULL
  OR json_type(NEW.root_json,'$.mac') IS NULL
  OR json_type(NEW.root_json,'$.updatedAt')!='text'
  OR json_type(NEW.root_json,'$.nonce')!='text'
  OR length(json_extract(NEW.root_json,'$.mac'))!=64
  OR json_extract(NEW.root_json,'$.mac') GLOB '*[^0-9a-f]*'
  OR json_extract(NEW.root_json,'$.enabled')!=NEW.enabled
  OR json_extract(NEW.root_json,'$.persistContext')!=NEW.persist_context
  OR json_extract(NEW.root_json,'$.generation')!=NEW.revision
  OR json_extract(NEW.root_json,'$.projectPolicyHash')!=NEW.project_policy_hash
  OR json_extract(NEW.root_json,'$.baselineEpochId') IS NOT NEW.baseline_epoch_id
  OR json_extract(NEW.root_json,'$.activeMutationId') IS NOT NEW.active_mutation_id
 )) OR
 (NEW.kind IN('unattributed','service') AND (
  NEW.root_id!=NEW.kind OR NEW.canonical_path IS NOT NULL OR NEW.root_json IS NOT NULL
  OR NEW.enabled!=1 OR NEW.revision!=1 OR NEW.persist_context!=0
  OR NEW.baseline_epoch_id IS NOT NULL OR NEW.active_mutation_id IS NOT NULL OR NEW.disabled_at_ms IS NOT NULL
 ))
BEGIN
 SELECT RAISE(ABORT, 'root authority projection mismatch');
END;
CREATE TRIGGER IF NOT EXISTS root_authority_revision_cas
BEFORE UPDATE ON roots
WHEN NEW.root_id!=OLD.root_id
 OR NEW.kind!=OLD.kind
 OR NEW.registered_at_ms!=OLD.registered_at_ms
 OR NEW.revision!=OLD.revision+1
 OR json_extract(NEW.root_json,'$.schema')!='gjc-bugwatch-root/v1'
 OR json_extract(NEW.root_json,'$.rootId')!=NEW.root_id
 OR json_extract(NEW.root_json,'$.canonicalPath') IS NOT NEW.canonical_path
 OR json_type(NEW.root_json,'$.keyId') IS NULL
 OR json_type(NEW.root_json,'$.mac') IS NULL
 OR json_type(NEW.root_json,'$.updatedAt')!='text'
 OR json_type(NEW.root_json,'$.nonce')!='text'
 OR length(json_extract(NEW.root_json,'$.mac'))!=64
 OR json_extract(NEW.root_json,'$.mac') GLOB '*[^0-9a-f]*'
 OR json_extract(NEW.root_json,'$.enabled')!=NEW.enabled
 OR json_extract(NEW.root_json,'$.persistContext')!=NEW.persist_context
 OR json_extract(NEW.root_json,'$.generation')!=NEW.revision
 OR json_extract(NEW.root_json,'$.projectPolicyHash')!=NEW.project_policy_hash
 OR json_extract(NEW.root_json,'$.baselineEpochId') IS NOT NEW.baseline_epoch_id
 OR json_extract(NEW.root_json,'$.activeMutationId') IS NOT NEW.active_mutation_id
 OR (NEW.enabled=1 AND NEW.disabled_at_ms IS NOT NULL)
 OR (NEW.enabled=0 AND NEW.disabled_at_ms IS NULL)
BEGIN
 SELECT RAISE(ABORT, 'root authority revision CAS mismatch');
END;
CREATE TRIGGER IF NOT EXISTS boot_core_projection_insert
BEFORE INSERT ON producer_boots
WHEN json_extract(NEW.boot_core_json,'$.schema')!='gjc-bugwatch-boot-core/v1'
 OR json_extract(NEW.boot_core_json,'$.scopeId')!=NEW.scope_id
 OR json_extract(NEW.boot_core_json,'$.bootId')!=NEW.boot_id
 OR json_extract(NEW.boot_core_json,'$.pid')!=NEW.pid
 OR json_extract(NEW.boot_core_json,'$.pidStartToken')!=NEW.pid_start_token
 OR json_extract(NEW.boot_core_json,'$.producer')!=NEW.producer
 OR json_extract(NEW.boot_core_json,'$.initialPolicyGeneration')!=NEW.initial_policy_generation
 OR json_extract(NEW.boot_core_json,'$.initialPolicyHash')!=NEW.initial_policy_hash
 OR json_extract(NEW.boot_core_json,'$.fatalKeyId')!=NEW.fatal_key_id
 OR json_extract(NEW.boot_core_json,'$.gjcVersion')!=NEW.gjc_version
 OR json_extract(NEW.boot_core_json,'$.buildSha') IS NOT NEW.build_sha
BEGIN
 SELECT RAISE(ABORT, 'boot core projection mismatch');
END;
CREATE TRIGGER IF NOT EXISTS boot_core_immutable_update
BEFORE UPDATE OF boot_id, scope_id, boot_core_hash, boot_core_json ON producer_boots
BEGIN
 SELECT RAISE(ABORT, 'boot core is immutable');
END;
CREATE TRIGGER IF NOT EXISTS attachment_authority_projection_insert
BEFORE INSERT ON session_attachments
WHEN json_extract(NEW.attachment_json,'$.schema')!='gjc-bugwatch-attachment/v1'
 OR json_extract(NEW.attachment_json,'$.scopeId')!=NEW.scope_id
 OR json_extract(NEW.attachment_json,'$.attachmentId')!=NEW.attachment_id
 OR json_extract(NEW.attachment_json,'$.bootId')!=NEW.boot_id
 OR json_extract(NEW.attachment_json,'$.bootCoreHash')!=NEW.boot_core_hash
 OR json_extract(NEW.attachment_json,'$.rootId')!=NEW.root_id
 OR json_extract(NEW.attachment_json,'$.state')!=NEW.state
 OR json_extract(NEW.attachment_json,'$.rootGeneration')!=NEW.root_generation
 OR json_extract(NEW.attachment_json,'$.baselineEpochId')!=NEW.baseline_epoch_id
BEGIN
 SELECT RAISE(ABORT, 'attachment authority projection mismatch');
END;
CREATE TRIGGER IF NOT EXISTS attachment_authority_immutable_update
BEFORE UPDATE OF attachment_id, scope_id, boot_id, boot_core_hash, root_id, attachment_json ON session_attachments
BEGIN
 SELECT RAISE(ABORT, 'attachment authority is immutable');
END;
CREATE TRIGGER IF NOT EXISTS monitor_inventory_projection_insert
BEFORE INSERT ON old_monitors
WHEN json_extract(NEW.inventory_json,'$.schema')!='gjc-bugwatch-monitor-inventory/v1'
 OR json_extract(NEW.inventory_json,'$.inventoryEpochId')!=NEW.inventory_epoch_id
 OR json_extract(NEW.inventory_json,'$.monitorId')!=NEW.monitor_id
 OR json_extract(NEW.inventory_json,'$.kind')!=NEW.kind
 OR json_extract(NEW.inventory_json,'$.stableIdentifier')!=NEW.stable_identifier
 OR json_extract(NEW.inventory_json,'$.configHash')!=NEW.config_hash
 OR json_extract(NEW.inventory_json,'$.status')!=NEW.status
BEGIN
 SELECT RAISE(ABORT, 'monitor inventory projection mismatch');
END;
CREATE TRIGGER IF NOT EXISTS monitor_authorization_projection_insert
BEFORE INSERT ON monitor_disable_authorizations
WHEN json_extract(NEW.action_json,'$.kind')!=NEW.action_kind
BEGIN
 SELECT RAISE(ABORT, 'monitor authorization projection mismatch');
END;
CREATE TRIGGER IF NOT EXISTS monitor_receipt_projection_insert
BEFORE INSERT ON monitor_disable_receipts
WHEN json_extract(NEW.receipt_json,'$.schema')!='gjc-bugwatch-monitor-disable-receipt/v1'
 OR json_extract(NEW.receipt_json,'$.authorizationId')!=NEW.authorization_id
 OR json_extract(NEW.receipt_json,'$.scopeId')!=NEW.scope_id
 OR json_extract(NEW.receipt_json,'$.actionHash')!=NEW.action_hash
 OR json_extract(NEW.receipt_json,'$.inventoryEpochId')!=NEW.inventory_epoch_id
 OR json_extract(NEW.receipt_json,'$.monitorId')!=NEW.monitor_id
 OR json_extract(NEW.receipt_json,'$.adapterKind')!=NEW.adapter_kind
 OR json_extract(NEW.receipt_json,'$.beforeHash')!=NEW.before_hash
 OR json_extract(NEW.receipt_json,'$.afterHash') IS NOT NEW.after_hash
 OR json_extract(NEW.receipt_json,'$.result')!=NEW.result
 OR json_extract(NEW.receipt_json,'$.steps')!=json(NEW.steps_json)
 OR json_extract(NEW.receipt_json,'$.coveredRootIds')!=json(NEW.covered_roots_json)
 OR json_extract(NEW.receipt_json,'$.startedAt')!=strftime('%Y-%m-%dT%H:%M:%fZ',NEW.started_at_ms/1000.0,'unixepoch')
 OR json_extract(NEW.receipt_json,'$.finishedAt')!=strftime('%Y-%m-%dT%H:%M:%fZ',NEW.finished_at_ms/1000.0,'unixepoch')
 OR json_extract(NEW.receipt_json,'$.keyId')!=NEW.key_id
 OR json_extract(NEW.receipt_json,'$.mac')!=NEW.mac
BEGIN
 SELECT RAISE(ABORT, 'monitor receipt projection mismatch');
END;
CREATE TRIGGER IF NOT EXISTS store_operation_core_projection_insert
BEFORE INSERT ON store_operations
WHEN json_extract(NEW.core_json,'$.schema')!='gjc-bugwatch-store-operation-core/v1'
 OR json_extract(NEW.core_json,'$.operationId')!=NEW.operation_id
 OR json_extract(NEW.core_json,'$.ownerId')!=NEW.owner_id
 OR json_extract(NEW.core_json,'$.claimTokenHash')!=NEW.claim_token_hash
 OR json_extract(NEW.core_json,'$.kind')!=NEW.kind
 OR json_extract(NEW.core_json,'$.fromVersion')!=NEW.from_version
 OR json_extract(NEW.core_json,'$.toVersion') IS NOT NEW.to_version
BEGIN
 SELECT RAISE(ABORT, 'store operation core projection mismatch');
END;
CREATE TRIGGER IF NOT EXISTS store_operation_core_immutable_update
BEFORE UPDATE OF operation_id, owner_id, claim_token_hash, kind, from_version, to_version, core_hash, core_json ON store_operations
BEGIN
 SELECT RAISE(ABORT, 'store operation core is immutable');
END;
CREATE INDEX IF NOT EXISTS idx_jobs_state_next_lease ON triage_jobs(state, next_attempt_at_ms, lease_expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_outbox_state ON artifact_outbox(state, updated_at_ms);
CREATE INDEX IF NOT EXISTS idx_projection_state ON projection_heads(state, updated_at_ms);
CREATE INDEX IF NOT EXISTS idx_context_expiry ON context_records(expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_artifact_fingerprint ON manual_artifacts(root_id, fingerprint_version, full_fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_prefix_alias ON fingerprint_prefix_aliases(root_id, fingerprint_version, prefix);
CREATE INDEX IF NOT EXISTS idx_epoch_state ON coverage_epochs(state, started_at_ms);
CREATE INDEX IF NOT EXISTS idx_attachments_root_time ON session_attachments(root_id, started_at_ms);
CREATE INDEX IF NOT EXISTS idx_sources_state_block ON sources(state, block_id);
CREATE INDEX IF NOT EXISTS idx_coverage_state ON producer_coverage(state, updated_at_ms);
CREATE INDEX IF NOT EXISTS idx_ranges_boot_end ON producer_ranges(boot_id, end_seq);
CREATE INDEX IF NOT EXISTS idx_candidates_eligible ON candidates(policy_state, next_eligible_at_ms);
CREATE INDEX IF NOT EXISTS idx_snapshot_state ON authority_snapshot_packs(kind, state);
CREATE INDEX IF NOT EXISTS idx_store_operation_phase ON store_operations(phase, updated_at_ms);
CREATE INDEX IF NOT EXISTS idx_store_member_state ON store_operation_members(state, updated_at_ms);
CREATE INDEX IF NOT EXISTS idx_monitor_status ON old_monitors(status, observed_at_ms);
CREATE INDEX IF NOT EXISTS idx_monitor_root ON old_monitor_root_coverage(root_id);
CREATE INDEX IF NOT EXISTS idx_monitor_authorization_state ON monitor_disable_authorizations(state, expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_transport_boot_epoch ON boot_transport_records(boot_id, transport_epoch);
CREATE INDEX IF NOT EXISTS idx_policy_predecessor ON scope_policies(scope_id, previous_generation, previous_revision_hash);
CREATE INDEX IF NOT EXISTS idx_policy_generation ON scope_policies(scope_id, generation);
CREATE INDEX IF NOT EXISTS idx_physical_boot_seq ON physical_rows(boot_id, record_seq);
CREATE INDEX IF NOT EXISTS idx_upstream_cache_expiry_lru ON upstream_cache(expires_at_ms, last_accessed_at_ms);
`;
