import * as crypto from "node:crypto";
import { canonicalizeJson, type JsonValue } from "./canonical";

export const BUGWATCH_CONTRACT_VERSION = "1" as const;
export const BUGWATCH_LOG_SCHEMA_VERSION = 2 as const;
export const BUGWATCH_REDACTION_VERSION = 1 as const;
export const BUGWATCH_NOISE_VERSION = 1 as const;
export const BUGWATCH_SEVERITY_VERSION = 1 as const;
export const BUGWATCH_FINGERPRINT_VERSION = 1 as const;
/** Exact persisted-store compatibility tuple compiled into snapshot validation. */
export const BUGWATCH_SCHEMA_MAJOR = 1 as const;
export const BUGWATCH_SCHEMA_MINOR = 12 as const;
export const BUGWATCH_SCHEMA_CATALOG_HASH = "f02867a9aeff319b5264684ac3d8e47db3ed5e658d2ae3a6c9ebf5567e2bdef8" as const;

/** Replaces fixture self-references before deriving its deterministic manifest identity. */
export const BUGWATCH_FIXTURE_MANIFEST_HASH_SENTINEL =
	"0000000000000000000000000000000000000000000000000000000000000000" as const;

/**
 * Canonical fixture-manifest identity projection.
 *
 * Generated snapshot artifacts carry cryptographic values derived from the
 * fixture identity itself. Keep their semantic structure in the projection,
 * replacing only those circular derived leaves with a fixed sentinel.
 */
export function canonicalizeBugwatchFixtureManifestIdentity(value: JsonValue): string {
	canonicalizeJson(value);
	return canonicalizeJson(projectBugwatchFixtureManifestIdentity(value));
}

function projectBugwatchFixtureManifestIdentity(value: JsonValue): JsonValue {
	if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
	const root = value as { [key: string]: JsonValue };
	const projected: { [key: string]: JsonValue } = {};
	for (const [key, nested] of Object.entries(root)) {
		if (key !== "envelopes" || nested === null || typeof nested !== "object" || Array.isArray(nested)) {
			projected[key] = nested;
			continue;
		}
		const envelopes = nested as { [key: string]: JsonValue };
		projected[key] = Object.fromEntries(
			Object.entries(envelopes).map(([envelopeKey, envelope]) => [
				envelopeKey,
				envelopeKey === "snapshot"
					? projectSnapshotManifest(envelope)
					: envelopeKey === "snapshotItems"
						? projectSnapshotItems(envelope)
						: envelopeKey === "snapshotFrontierEvidence"
							? projectSnapshotFrontierEvidence(envelope)
							: envelope,
			]),
		) as JsonValue;
	}
	return projected;
}

function projectSnapshotManifest(value: JsonValue): JsonValue {
	return projectGeneratedArtifact(
		value,
		new Set([
			"fixtureManifestHash",
			"snapshotKeyDigest",
			"policyKeyringDigest",
			"fatalKeyringDigest",
			"registryKeyringDigest",
			"itemsSha256",
			"byteCount",
			"merkleRoot",
			"previousManifestHash",
			"quiesceTokenHash",
			"sqliteBackupHash",
			"schemaMetaHash",
			"sourceWatermarksHash",
			"registryFrontiersHash",
			"inboxFrontierHash",
			"emergencyFrontierHash",
			"rollbackSpoolFrontierHash",
			"artifactFrontierHash",
			"classDigest",
			"mac",
		]),
	);
}

function projectSnapshotItems(value: JsonValue): JsonValue {
	if (!Array.isArray(value)) return value;
	return value.map(item => {
		if (item === null || typeof item !== "object" || Array.isArray(item)) return item;
		const projected: { [key: string]: JsonValue } = {};
		for (const [key, nested] of Object.entries(item as { [key: string]: JsonValue })) {
			if (key === "payloadHash" || key === "previousItemHash" || key === "mac")
				projected[key] = BUGWATCH_FIXTURE_MANIFEST_HASH_SENTINEL;
			else if (key === "payload") projected[key] = projectFixtureManifestReferences(nested);
			else projected[key] = nested;
		}
		return projected;
	});
}

function projectFixtureManifestReferences(value: JsonValue): JsonValue {
	if (Array.isArray(value)) return value.map(projectFixtureManifestReferences);
	if (value === null || typeof value !== "object") return value;
	const projected: { [key: string]: JsonValue } = {};
	for (const [key, nested] of Object.entries(value))
		projected[key] =
			key === "fixtureManifestHash" || key === "fixture_manifest_hash"
				? BUGWATCH_FIXTURE_MANIFEST_HASH_SENTINEL
				: projectFixtureManifestReferences(nested);
	return projected;
}

function projectSnapshotFrontierEvidence(value: JsonValue): JsonValue {
	return projectGeneratedArtifact(
		value,
		new Set([
			"fixtureManifestHash",
			"fixture_manifest_hash",
			"backupHash",
			"databaseHash",
			"recordHash",
			"previousRecordHash",
		]),
	);
}

function projectGeneratedArtifact(value: JsonValue, derivedLeaves: ReadonlySet<string>): JsonValue {
	if (Array.isArray(value)) return value.map(item => projectGeneratedArtifact(item, derivedLeaves));
	if (value === null || typeof value !== "object") return value;
	const projected: { [key: string]: JsonValue } = {};
	for (const [key, nested] of Object.entries(value))
		projected[key] = derivedLeaves.has(key)
			? BUGWATCH_FIXTURE_MANIFEST_HASH_SENTINEL
			: projectGeneratedArtifact(nested, derivedLeaves);
	return projected;
}
/** SHA-256 of the canonical bugwatch contract fixture manifest. */
export const BUGWATCH_FIXTURE_MANIFEST_HASH =
	"b0da4f37328d7237b938744de85e21fe8d876b16892e78aa9e0d6838637b0a27" as const;

export const MAX_RANGES_PER_BOOT = 4096 as const;
export const MAX_GAP_SPAN = 1_000_000 as const;
export const INBOX_SLOTS = 8192 as const;
export const INBOX_ENVELOPE_BYTES = 8192 as const;
export const INBOX_PROBES = 64 as const;
export const CONTEXT_CUMULATIVE_BYTES_PER_JOB = 16_384 as const;
export const EMERGENCY_FILE_BYTES = 1_048_576 as const;
export const EMERGENCY_PAGE_BYTES = 4096 as const;
export const EMERGENCY_LOGICAL_SLOTS = 128 as const;
export const EMERGENCY_PAGES_PER_LOGICAL_SLOT = 2 as const;

const REDACTED = "[REDACTED]";
const PATH = "<path>";
const URL = /\b[a-z][a-z0-9+.-]*:\/\/[^\s)"']+/gi;
const URL_CREDENTIALS = /\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+(?::[^\s/@]*)?@/gi;
const POSIX_PATH = /(?:^|[\s("'=])\/(?:[^\s)"']+)/g;
const HOME_PATH = /(?:^|[\s("'=:])(?:~\/|\$HOME\/)[^\s)"']+/g;
const WINDOWS_PATH = /\b[A-Z]:\\(?:[^\s)"']+)/gi;
const FILE_URI = /\bfile:\/\/\/?[^\s)"']+/gi;
const PATH_VALUE =
	/(\b(?:path|cwd|directory|dir|file|session(?:[_-]?(?:file|root|path))?|project(?:[_-]?root)?|artifact(?:[_-]?(?:path|file|root)|Path|File|Root)|managed(?:[_-]?session(?:[_-]?(?:root|path|file))?|Session(?:Root|Path|File)))\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)/gi;
const RELATIVE_PATH = /(?:^|[\s("'=])\.\.?\/[^\s)"']+/g;
const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi;
const ACCOUNT_ID = /\b(?:account|acct|user)[_-]?(?:id)?\s*[=:]\s*[A-Za-z0-9_-]{4,}\b/gi;
const AUTHORIZATION = /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*/gi;
const JWT = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;
const AWS = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;
const GITHUB = /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g;
const SLACK = /\bxox(?:[abprs]|p)-[A-Za-z0-9-]{10,}\b/g;
const SENSITIVE_VALUE =
	/((?:"(?:api[_-]?key|apiKey|secret(?:[_-]?(?:access[_-]?key|accessKey))?|auth(?:[_-]?token|Token)|token|access[_-]?token|accessToken|refresh[_-]?token|refreshToken|client[_-]?secret|clientSecret|password|passwd|private[_-]?key|privateKey)"|'(?:api[_-]?key|apiKey|secret(?:[_-]?(?:access[_-]?key|accessKey))?|auth(?:[_-]?token|Token)|token|access[_-]?token|accessToken|refresh[_-]?token|refreshToken|client[_-]?secret|clientSecret|password|passwd|private[_-]?key|privateKey)'|(?:api[_-]?key|apiKey|secret(?:[_-]?(?:access[_-]?key|accessKey))?|auth(?:[_-]?token|Token)|token|access[_-]?token|accessToken|refresh[_-]?token|refreshToken|client[_-]?secret|clientSecret|password|passwd|private[_-]?key|privateKey))\s*)([=:])\s*(?:"[^"]*"|'[^']*'|[^\s,;}]+)/gi;
const OPAQUE_TOKEN = /\b(?:tok_[A-Za-z0-9_-]{16,}|[0-9a-f]{32,})\b/gi;
const NOISE_POSITIVE_PHRASE =
	/\b(?:model discovery complete|local server listening|credential refresh completed|token expired|usage fetch queued|reusing parent session)\b/;
const NOISE_FAILURE_OR_NEGATION =
	/\b(?:fail(?:ed|ing|ure)?|error|exception|not|never|no|unable|cannot|can't|denied|refused|unavailable|timed?\s*out)\b/;
const TIMESTAMP = /\b\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-][0-2]\d:?[0-5]\d)?\b/g;
const PID = /\b(?:pid|process(?:\s+id)?)\s*[=:]?\s*\d+\b/gi;
const LARGE_NUMBER = /\b\d{4,}\b/g;
const LINE_COLUMN = /:\d+(?::\d+)?\b/g;
const INTERNAL_RUNTIME_FRAME =
	/\b(?:node:internal|internal\/(?:process|modules)|packages\/(?:agent|coding-agent|utils)\/src\/)/i;

/** Deterministically removes credentials and local payload paths before persistence. */
export function redactBugwatchText(input: string): string {
	return input
		.replace(URL_CREDENTIALS, "$1")
		.replace(AUTHORIZATION, REDACTED)
		.replace(JWT, REDACTED)
		.replace(AWS, REDACTED)
		.replace(GITHUB, REDACTED)
		.replace(SLACK, REDACTED)
		.replace(SENSITIVE_VALUE, (_match, key: string, separator: string) => `${key}${separator}${REDACTED}`)
		.replace(OPAQUE_TOKEN, REDACTED)
		.replace(EMAIL, REDACTED)
		.replace(UUID, REDACTED)
		.replace(ACCOUNT_ID, REDACTED)
		.replace(PATH_VALUE, `$1${PATH}`)
		.replace(FILE_URI, PATH)
		.replace(POSIX_PATH, match => `${match[0] === "/" ? "" : match[0][0]}${PATH}`)
		.replace(RELATIVE_PATH, match => `${match[0] === "." ? "" : match[0][0]}${PATH}`)
		.replace(HOME_PATH, match => `${match[0][0].match(/[\s("'=:]/) ? match[0][0] : ""}${PATH}`)
		.replace(WINDOWS_PATH, PATH);
}

/** True only when text already contains no v1-recognized sensitive material. */
export function isBugwatchTextRedacted(input: string): boolean {
	return input === redactBugwatchText(input);
}

/** Keeps a stack's stable symbol shape without retaining source locations or payload paths. */
export function normalizeBugwatchStack(input: string): string {
	return normalizeBugwatchFingerprintText(input)
		.replace(/\bat\s+([^\s(]+)\s*\([^)]*\)/g, "at $1")
		.replace(/\bat\s+([^\s(]+)\s+\[[^\]]*\]/g, "at $1")
		.replace(/\s+/g, " ")
		.trim();
}

/** Normalizes volatile values after redaction for stable fingerprinting. */
export function normalizeBugwatchFingerprintText(input: string): string {
	return redactBugwatchText(input)
		.replace(URL, "<url>")
		.replace(TIMESTAMP, "<timestamp>")
		.replace(PID, "pid=<pid>")
		.replace(LINE_COLUMN, ":<line>:<column>")
		.replace(LARGE_NUMBER, "<number>")
		.toLowerCase()
		.replace(/\s+/g, " ")
		.trim();
}

/** Normalizes signal text before classification decisions. */
export function normalizeBugwatchSignal(input: string): string {
	return redactBugwatchText(input).replace(/\s+/g, " ").trim();
}

export type BugwatchSignalCategoryV1 = "gjc-internal" | "error" | "warn" | "diagnostic";
export type BugwatchLogLevelV1 = "debug" | "info" | "warn" | "error";
export type BugwatchSignalHookV1 = "fatal" | null;

export interface BugwatchSignalAuthorityV1 {
	category: BugwatchSignalCategoryV1;
	hook: BugwatchSignalHookV1;
	level: BugwatchLogLevelV1;
	message: string;
	stackTop: string | null;
}

/** Applies the exact v1 noise patterns; unmatched messages are always signals. */
export function classifyBugwatchNoise(input: string): "signal" | "noise" {
	const normalized = normalizeBugwatchSignal(input).toLowerCase();
	return NOISE_POSITIVE_PHRASE.test(normalized) && !NOISE_FAILURE_OR_NEGATION.test(normalized) ? "noise" : "signal";
}

/** Maps v1 severity exclusively from fatal-hook, category, level, and trusted stack authority. */
export function classifyBugwatchSeverity(
	authority: BugwatchSignalAuthorityV1,
): "fatal" | "high" | "medium" | "low" | "diagnostic" {
	if (authority.hook === "fatal") return "fatal";
	if (authority.category === "diagnostic") return "diagnostic";
	if (authority.level === "error")
		return authority.stackTop !== null && INTERNAL_RUNTIME_FRAME.test(authority.stackTop) ? "high" : "medium";
	if (authority.level === "warn") return classifyBugwatchNoise(authority.message) === "noise" ? "diagnostic" : "low";
	return "diagnostic";
}

/** SHA-256 of `v1\n<category>\n<message>\n<first-stack-frame>` after v1 redaction and normalization. */
export function fingerprintBugwatchSignal(category: string, input: string, stackTop: string | null = null): string {
	const normalizedCategory = normalizeBugwatchFingerprintText(category);
	const normalizedMessage = normalizeBugwatchFingerprintText(input);
	const normalizedStack = stackTop === null ? "" : normalizeBugwatchStack(stackTop);
	return crypto
		.createHash("sha256")
		.update(`v${BUGWATCH_FINGERPRINT_VERSION}\n${normalizedCategory}\n${normalizedMessage}\n${normalizedStack}`)
		.digest("hex");
}
