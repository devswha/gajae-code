import { describe, expect, it } from "bun:test";
import {
	AUTHORITY_CLASS_NAMES,
	type AuthoritySnapshotManifestV2,
	adoptPolicyHead,
	BUGWATCH_FIXTURE_MANIFEST_HASH,
	BugwatchContractError,
	canonicalizeBugwatchFixtureManifestIdentity,
	canonicalizeJson,
	computeEventId,
	EMERGENCY_FILE_BYTES,
	fatalCoreHash,
	hmacSha256Hex,
	INBOX_ENVELOPE_BYTES,
	isBugwatchTextRedacted,
	type JsonValue,
	MAX_GAP_SPAN,
	MAX_RANGES_PER_BOOT,
	type PolicySemanticV1,
	parseAuthoritySnapshotManifestV2,
	parseCanonicalJson,
	parseFatalEnvelopeSlotBytesV1,
	parseFatalEnvelopeV1,
	parseMonitorDisableActionV1,
	parseMonitorDisableAuthorizationV1,
	parsePolicySemanticV1,
	policyContentHash,
	redactBugwatchText,
	type ScopePolicyHeadV2,
	type ScopePolicyRevisionV2,
	sha256Hex,
	validatePolicyChain,
	verifyMac,
} from "../src/bugwatch-contract";
import fixture from "./fixtures/bugwatch-contract-v1.json" with { type: "json" };

const fixtureMacKey = new TextEncoder().encode("bugwatch-fixture-mac-key");
function withoutMac(value: { [key: string]: JsonValue }): JsonValue {
	const payload: { [key: string]: JsonValue } = {};
	for (const [key, entry] of Object.entries(value)) if (key !== "mac") payload[key] = entry;
	return payload;
}

function signedRevision(
	generation: number,
	semantic: PolicySemanticV1,
	previous: ScopePolicyRevisionV2 | null,
): ScopePolicyRevisionV2 {
	const revision: ScopePolicyRevisionV2 = {
		schema: "gjc-bugwatch-policy-revision/v2",
		scopeId: semantic.scopeId,
		generation,
		semantic,
		contentHash: policyContentHash(semantic),
		previousGeneration: previous?.generation ?? null,
		previousRevisionHash: previous === null ? null : sha256Hex(canonicalizeJson(previous as unknown as JsonValue)),
		previousContentHash: previous?.contentHash ?? null,
		casTokenHash: sha256Hex(`cas-token-${generation}`),
		createdAt: `2026-01-02T03:04:0${generation}.000Z`,
		writerId: "fixture-writer",
		keyId: "fixture-key",
		mac: "",
	};
	revision.mac = hmacSha256Hex(
		fixtureMacKey,
		"gjc-bugwatch-policy-revision-v2",
		withoutMac(revision as unknown as { [key: string]: JsonValue }),
	);
	return revision;
}

function signedHead(revision: ScopePolicyRevisionV2): ScopePolicyHeadV2 {
	const head: ScopePolicyHeadV2 = {
		schema: "gjc-bugwatch-policy-head/v2",
		scopeId: revision.scopeId,
		generation: revision.generation,
		revisionHash: sha256Hex(canonicalizeJson(revision as unknown as JsonValue)),
		contentHash: revision.contentHash,
		casToken: `cas-token-${revision.generation}`,
		updatedAt: `2026-01-02T03:04:1${revision.generation}.000Z`,
		keyId: "fixture-key",
		mac: "",
	};
	head.mac = hmacSha256Hex(
		fixtureMacKey,
		"gjc-bugwatch-policy-head-v2",
		withoutMac(head as unknown as { [key: string]: JsonValue }),
	);
	return head;
}

function expectContractError(operation: () => void, code: string): void {
	try {
		operation();
	} catch (error) {
		expect(error).toBeInstanceOf(BugwatchContractError);
		expect((error as BugwatchContractError).code).toBe(code);
		return;
	}
	throw new Error(`Expected BugwatchContractError(${code})`);
}

function fixtureManifestHash(): string {
	return sha256Hex(canonicalizeBugwatchFixtureManifestIdentity(fixture as unknown as JsonValue));
}

function fixtureSnapshot(): AuthoritySnapshotManifestV2 {
	const snapshot = structuredClone(fixture.envelopes.snapshot) as unknown as AuthoritySnapshotManifestV2;
	if (
		snapshot.fixtureManifestHash !== BUGWATCH_FIXTURE_MANIFEST_HASH ||
		fixtureManifestHash() !== BUGWATCH_FIXTURE_MANIFEST_HASH
	)
		throw new Error("Fixture snapshot manifest hash does not match its identity projection");
	return snapshot;
}

function withRecomputedFatalCore<T extends { fatalCoreHash: string }>(fatal: T): T {
	fatal.fatalCoreHash = fatalCoreHash(fatal as unknown as JsonValue);
	return fatal;
}

describe("bugwatch contract fault boundaries", () => {
	it("rejects malformed, duplicate-key, noncanonical-number, unknown-field, and unknown-schema policy bytes", () => {
		expectContractError(() => parseCanonicalJson(fixture.faultInputs.malformed), "INVALID_JSON");
		expectContractError(() => parseCanonicalJson(fixture.faultInputs.duplicateKey), "INVALID_JSON");
		expectContractError(() => parseCanonicalJson(fixture.faultInputs.noncanonicalNumber), "NONCANONICAL_JSON");
		expectContractError(
			() => parsePolicySemanticV1({ ...fixture.semanticPolicies.a, unexpected: true }),
			"UNKNOWN_FIELD",
		);
		const unsupportedSchema = structuredClone(fixture.semanticPolicies.a);
		unsupportedSchema.schema = "gjc-bugwatch-policy-semantics/v2";
		expectContractError(() => parsePolicySemanticV1(unsupportedSchema), "UNSUPPORTED_SCHEMA");
	});

	it("enforces compiled policy and non-policy hard limits", () => {
		const oversize = structuredClone(fixture.semanticPolicies.a);
		oversize.ingest.maxRowsPerTick = fixture.faultInputs.oversizePolicy.maxRowsPerTick;
		expectContractError(() => parsePolicySemanticV1(oversize), "OUT_OF_RANGE");
		expect(MAX_RANGES_PER_BOOT).toBe(4096);
		expect(MAX_GAP_SPAN).toBe(1_000_000);
		expect(INBOX_ENVELOPE_BYTES).toBe(8192);
		expect(EMERGENCY_FILE_BYTES).toBe(1_048_576);
	});

	it("rejects signed fatal envelopes with false core identities", () => {
		const falseIdentity = { ...fixture.envelopes.fatal, fatalCoreHash: "0".repeat(64), mac: "" };
		falseIdentity.mac = hmacSha256Hex(
			fixtureMacKey,
			"gjc-bugwatch-fatal-mac-v1",
			Object.fromEntries(Object.entries(falseIdentity).filter(([key]) => key !== "mac")) as JsonValue,
		);
		expectContractError(() => parseFatalEnvelopeV1(falseIdentity), "INVALID_HASH");
		expect(() =>
			verifyMac(falseIdentity as unknown as JsonValue, "gjc-bugwatch-fatal-mac-v1", fixtureMacKey),
		).not.toThrow();
	});
	it("requires a cryptographically bound gjc-internal fatal category", () => {
		const { category: _category, ...missingCategory } = fixture.envelopes.fatal;
		expectContractError(() => parseFatalEnvelopeV1(missingCategory), "UNKNOWN_FIELD");

		const otherCategory = withRecomputedFatalCore({ ...fixture.envelopes.fatal, category: "error" });
		expectContractError(() => parseFatalEnvelopeV1(otherCategory), "INVALID_SCHEMA");

		const categoryTampered = { ...fixture.envelopes.fatal, category: "error" };
		expect(fatalCoreHash(categoryTampered as unknown as JsonValue)).not.toBe(fixture.envelopes.fatal.fatalCoreHash);
		expectContractError(
			() => verifyMac(categoryTampered as unknown as JsonValue, "gjc-bugwatch-fatal-mac-v1", fixtureMacKey),
			"INVALID_MAC",
		);

		const categoryRehashed = withRecomputedFatalCore({ ...categoryTampered, mac: "" });
		categoryRehashed.mac = hmacSha256Hex(
			fixtureMacKey,
			"gjc-bugwatch-fatal-mac-v1",
			Object.fromEntries(Object.entries(categoryRehashed).filter(([key]) => key !== "mac")) as JsonValue,
		);
		expectContractError(() => parseFatalEnvelopeV1(categoryRehashed), "INVALID_SCHEMA");
		expectContractError(
			() => parseFatalEnvelopeSlotBytesV1(new TextEncoder().encode(`${canonicalizeJson(categoryRehashed)}\n`)),
			"INVALID_SCHEMA",
		);
	});
	it("rejects rehashed and re-MACed unredacted fatal text", () => {
		const unredacted = withRecomputedFatalCore({
			...fixture.envelopes.fatal,
			message:
				"accessToken=access-canary refreshToken=refresh-canary clientSecret=secret-canary privateKey=private-canary sessionFile=.gjc/session.json projectRoot=../private-project",
			mac: "",
		});
		unredacted.mac = hmacSha256Hex(
			fixtureMacKey,
			"gjc-bugwatch-fatal-mac-v1",
			Object.fromEntries(Object.entries(unredacted).filter(([key]) => key !== "mac")) as JsonValue,
		);
		expectContractError(() => parseFatalEnvelopeV1(unredacted), "INVALID_SCHEMA");
	});
	it("detects fatal-envelope tampering after schema parsing", () => {
		const tampered = structuredClone(fixture.envelopes.fatal);
		tampered.message = "tampered after reservation";
		expectContractError(() => parseFatalEnvelopeV1(tampered), "INVALID_HASH");
	});

	it("rejects unknown fatal fields and invalid record sequence text", () => {
		const extraField = { ...fixture.envelopes.fatal, unexpected: true };
		expectContractError(() => parseFatalEnvelopeV1(extraField), "UNKNOWN_FIELD");
		expectContractError(() => computeEventId(fixture.envelopes.fatal.bootId, "0042"), "INVALID_SEQUENCE");
		expectContractError(
			() => computeEventId(fixture.envelopes.fatal.bootId, "9223372036854775808"),
			"INVALID_SEQUENCE",
		);
	});
	it("fails closed for malformed fatal scalars, enums, nullable fields, hashes, identities, and sizes", () => {
		const wrongSequence = withRecomputedFatalCore({ ...fixture.envelopes.fatal, recordSeq: 42 });
		expectContractError(() => parseFatalEnvelopeV1(wrongSequence), "INVALID_SEQUENCE");

		const wrongKind = withRecomputedFatalCore({ ...fixture.envelopes.fatal, kind: "fatal" });
		expectContractError(() => parseFatalEnvelopeV1(wrongKind), "INVALID_SCHEMA");

		const wrongNullable = withRecomputedFatalCore({ ...fixture.envelopes.fatal, stackTop: false });
		expectContractError(() => parseFatalEnvelopeV1(wrongNullable), "INVALID_SCHEMA");

		const malformedDigest = { ...fixture.envelopes.fatal, fatalCoreHash: "ABC" };
		expectContractError(() => parseFatalEnvelopeV1(malformedDigest), "INVALID_SCHEMA");

		const mismatchedEvent = { ...fixture.envelopes.fatal, eventId: "0".repeat(64) };
		expectContractError(() => parseFatalEnvelopeV1(mismatchedEvent), "INVALID_SCHEMA");

		const oversizedMessage = withRecomputedFatalCore({
			...fixture.envelopes.fatal,
			message: "x".repeat(INBOX_ENVELOPE_BYTES),
		});
		expectContractError(() => parseFatalEnvelopeV1(oversizedMessage), "OUT_OF_RANGE");

		const oversizedEnvelope = withRecomputedFatalCore({
			...fixture.envelopes.fatal,
			message: "x".repeat(4_000),
			stackTop: "x".repeat(4_000),
		});
		expectContractError(() => parseFatalEnvelopeV1(oversizedEnvelope), "OUT_OF_RANGE");
	});

	it("accepts only one canonical LF-framed fatal slot representation", () => {
		const encoder = new TextEncoder();
		const slotBytes = (fatal: JsonValue): Uint8Array => encoder.encode(`${canonicalizeJson(fatal)}\n`);
		const framed = slotBytes(fixture.envelopes.fatal as unknown as JsonValue);
		expect(parseFatalEnvelopeSlotBytesV1(framed).eventId).toBe(fixture.expected.eventId);
		expectContractError(() => parseFatalEnvelopeSlotBytesV1(framed.subarray(0, -1)), "INVALID_JSON");
		expectContractError(
			() => parseFatalEnvelopeSlotBytesV1(encoder.encode(`${canonicalizeJson(fixture.envelopes.fatal)}\n\n`)),
			"INVALID_JSON",
		);
		expectContractError(
			() => parseFatalEnvelopeSlotBytesV1(encoder.encode(`${JSON.stringify(fixture.envelopes.fatal)}\n`)),
			"NONCANONICAL_JSON",
		);

		const exact = withRecomputedFatalCore({
			...fixture.envelopes.fatal,
			message: "x".repeat(4096),
			stackTop: "",
		});
		const padding = INBOX_ENVELOPE_BYTES - slotBytes(exact as unknown as JsonValue).byteLength;
		exact.stackTop = "x".repeat(padding);
		withRecomputedFatalCore(exact);
		const exactBytes = slotBytes(exact as unknown as JsonValue);
		expect(exactBytes.byteLength).toBe(INBOX_ENVELOPE_BYTES);
		expect(parseFatalEnvelopeSlotBytesV1(exactBytes).recordSeq).toBe(exact.recordSeq);
		expectContractError(
			() => parseFatalEnvelopeSlotBytesV1(new Uint8Array(INBOX_ENVELOPE_BYTES + 1)),
			"OUT_OF_RANGE",
		);
	});
	it("redacts normalized credential and relative-path canaries without overmatching field names", () => {
		const raw =
			"secretAccessKey=secret-access-canary authToken=auth-token-canary artifactPath=./private-artifact managedSessionRoot=../private-session relative ./scratch/log ../parent/log authTokenized=retained artifactPathology=retained";
		const redacted = redactBugwatchText(raw);
		expect(isBugwatchTextRedacted(raw)).toBe(false);
		expect(isBugwatchTextRedacted(redacted)).toBe(true);
		for (const canary of [
			"secret-access-canary",
			"auth-token-canary",
			"./private-artifact",
			"../private-session",
			"./scratch/log",
			"../parent/log",
		])
			expect(redacted).not.toContain(canary);
		expect(redacted).toContain("authTokenized=retained");
		expect(redacted).toContain("artifactPathology=retained");
	});
	it("rejects incomplete or duplicate authority snapshot inventories", () => {
		expect(AUTHORITY_CLASS_NAMES).toHaveLength(62);
		const incomplete = fixtureSnapshot();
		incomplete.classes.pop();
		expectContractError(() => parseAuthoritySnapshotManifestV2(incomplete as unknown as JsonValue), "INVALID_SCHEMA");

		const duplicate = fixtureSnapshot();
		duplicate.classes[duplicate.classes.length - 1] = { ...duplicate.classes[0] };
		expectContractError(() => parseAuthoritySnapshotManifestV2(duplicate as unknown as JsonValue), "INVALID_SCHEMA");
		expect(duplicate.classes).toHaveLength(AUTHORITY_CLASS_NAMES.length);
	});
	it("rejects manifests missing the retained policy key reference", () => {
		const { policyKeyringId: _policyKeyringId, ...missingPolicyKey } = fixtureSnapshot();
		expectContractError(
			() => parseAuthoritySnapshotManifestV2(missingPolicyKey as unknown as JsonValue),
			"UNKNOWN_FIELD",
		);
	});

	it("fails closed on a skipped or tampered policy revision chain", () => {
		const unsignedHead = {
			schema: "gjc-bugwatch-policy-head/v2",
			scopeId: "scope-fixture",
			generation: 3,
			revisionHash: "a".repeat(64),
			contentHash: "b".repeat(64),
			casToken: "fixture-cas-token",
			updatedAt: "2026-01-02T03:04:08.000Z",
			keyId: "fixture-key",
		} as const;
		const head = {
			...unsignedHead,
			mac: hmacSha256Hex(fixtureMacKey, "gjc-bugwatch-policy-head-v2", unsignedHead),
		};
		expectContractError(
			() => validatePolicyChain(head as unknown as ScopePolicyHeadV2, [], () => fixtureMacKey),
			"POLICY_CHAIN_GAP",
		);
		const signedUnknown = { ...head, unexpected: true, mac: "" };
		signedUnknown.mac = hmacSha256Hex(
			fixtureMacKey,
			"gjc-bugwatch-policy-head-v2",
			Object.fromEntries(Object.entries(signedUnknown).filter(([key]) => key !== "mac")) as JsonValue,
		);
		expectContractError(
			() => validatePolicyChain(signedUnknown as unknown as ScopePolicyHeadV2, [], () => fixtureMacKey),
			"UNKNOWN_FIELD",
		);

		const signedUnsupported = { ...head, schema: "gjc-bugwatch-policy-head/v3", mac: "" };
		signedUnsupported.mac = hmacSha256Hex(
			fixtureMacKey,
			"gjc-bugwatch-policy-head-v2",
			Object.fromEntries(Object.entries(signedUnsupported).filter(([key]) => key !== "mac")) as JsonValue,
		);
		expectContractError(
			() => validatePolicyChain(signedUnsupported as unknown as ScopePolicyHeadV2, [], () => fixtureMacKey),
			"UNSUPPORTED_SCHEMA",
		);
	});
	it("rejects correctly MACed policy heads with an unbound raw CAS token", () => {
		const policy = parsePolicySemanticV1(fixture.semanticPolicies.a);
		const revision = signedRevision(1, policy, null);
		const head = { ...signedHead(revision), casToken: "wrong-cas-token", mac: "" };
		head.mac = hmacSha256Hex(
			fixtureMacKey,
			"gjc-bugwatch-policy-head-v2",
			withoutMac(head as unknown as { [key: string]: JsonValue }),
		);
		const keyForId = (keyId: string): Uint8Array | undefined => (keyId === "fixture-key" ? fixtureMacKey : undefined);

		expectContractError(() => validatePolicyChain(head, [revision], keyForId), "POLICY_CHAIN_GAP");
		expectContractError(
			() => adoptPolicyHead({ head: null, revisions: [] }, head, [revision], keyForId),
			"POLICY_CHAIN_GAP",
		);
	});
	it("anchors policy adoption to an authenticated retained terminal revision", () => {
		const policyA = parsePolicySemanticV1(fixture.semanticPolicies.a);
		const policyB = parsePolicySemanticV1(fixture.semanticPolicies.b);
		const first = signedRevision(1, policyA, null);
		const second = signedRevision(2, policyB, first);
		const third = signedRevision(3, policyA, second);
		const firstHead = signedHead(first);
		const thirdHead = signedHead(third);
		const keyForId = (keyId: string): Uint8Array | undefined => (keyId === "fixture-key" ? fixtureMacKey : undefined);

		expectContractError(
			() => adoptPolicyHead({ head: firstHead, revisions: [] }, thirdHead, [second, third], keyForId),
			"POLICY_CHAIN_GAP",
		);

		const conflictingFirst = signedRevision(1, policyB, null);
		expectContractError(
			() =>
				adoptPolicyHead({ head: firstHead, revisions: [conflictingFirst] }, thirdHead, [second, third], keyForId),
			"POLICY_CHAIN_GAP",
		);

		const forkedStart = signedRevision(2, policyB, conflictingFirst);
		expectContractError(
			() =>
				adoptPolicyHead({ head: firstHead, revisions: [first] }, signedHead(forkedStart), [forkedStart], keyForId),
			"POLICY_CHAIN_GAP",
		);

		const missingKeyHead = { ...firstHead, keyId: "missing-key" } as ScopePolicyHeadV2;
		expectContractError(
			() => adoptPolicyHead({ head: missingKeyHead, revisions: [first] }, thirdHead, [second, third], keyForId),
			"UNKNOWN_KEY",
		);

		const adopted = adoptPolicyHead({ head: firstHead, revisions: [first] }, thirdHead, [second, third], keyForId);
		if ("outcome" in adopted) throw new Error("valid contiguous policy catch-up was classified stale");
		expect(adopted.revisions.map(revision => revision.generation)).toEqual([1, 2, 3]);
	});
	it("rejects malformed, unbound, duplicate, and empty destructive monitor targets", () => {
		const markerLineBytesBase64 = Buffer.from("# gjc-bugwatch fixture-owner\n").toString("base64");
		const jobLineBytesBase64 = Buffer.from("* * * * * gjc bugwatch --owner fixture-owner\n").toString("base64");
		const cron = {
			kind: "user_cron" as const,
			expectedCrontabHash: "0".repeat(64),
			markerLineHash: sha256Hex(Buffer.from(markerLineBytesBase64, "base64")),
			jobLineHash: sha256Hex(Buffer.from(jobLineBytesBase64, "base64")),
			markerLineBytesBase64,
			jobLineBytesBase64,
		};
		expect(parseMonitorDisableActionV1(cron)).toEqual(cron);
		expectContractError(
			() => parseMonitorDisableActionV1({ ...cron, markerLineBytesBase64: "YQ" }),
			"INVALID_SCHEMA",
		);
		expectContractError(() => parseMonitorDisableActionV1({ ...cron, markerLineBytesBase64: "" }), "INVALID_SCHEMA");
		for (const invalidLine of [
			"# gjc-bugwatch marker",
			"# gjc-bugwatch marker\r\n",
			"# other marker\n",
			"# gjc-bugwatch marker\0\n",
		]) {
			expectContractError(
				() =>
					parseMonitorDisableActionV1({
						...cron,
						markerLineBytesBase64: Buffer.from(invalidLine).toString("base64"),
					}),
				"INVALID_SCHEMA",
			);
		}
		expectContractError(
			() => parseMonitorDisableActionV1({ ...cron, jobLineBytesBase64: markerLineBytesBase64 }),
			"INVALID_SCHEMA",
		);
		const systemdUnit = {
			name: "gjc-bugwatch.service",
			expectedPropertiesHash: "0".repeat(64),
			expectedFragmentPathHash: "0".repeat(64),
		};
		expectContractError(
			() =>
				parseMonitorDisableActionV1({
					kind: "systemd_user",
					operation: "disable_now",
					units: [systemdUnit, systemdUnit],
				}),
			"INVALID_SCHEMA",
		);
		expectContractError(
			() =>
				parseMonitorDisableActionV1({
					kind: "tmux_session",
					serverIdentityHash: "0".repeat(64),
					sessionId: "session",
					paneIds: [],
					allPaneTagsHash: "0".repeat(64),
				}),
			"INVALID_SCHEMA",
		);
	});
	it("accepts only immutable monitor disable authorizations", () => {
		const action = {
			kind: "process" as const,
			pid: 1,
			pidStartToken: "start",
			uid: "1000",
			executableHash: "0".repeat(64),
			argvHash: "0".repeat(64),
			signal: "TERM" as const,
		};
		const authorization = {
			schema: "gjc-bugwatch-monitor-disable-auth/v1",
			scopeId: "scope",
			authorizationId: "authorization",
			inventoryEpochId: "epoch",
			monitorId: "monitor",
			adapterKind: "process",
			stableIdentifier: "pid:1",
			expectedConfigHash: "0".repeat(64),
			allowedAction: action,
			authorizedAt: "2026-01-02T03:04:05.000Z",
			expiresAt: "2026-01-02T03:04:06.000Z",
			nonce: "nonce",
			keyId: "key",
			mac: "0".repeat(64),
		};
		expect(() => parseMonitorDisableAuthorizationV1(authorization)).not.toThrow();
		expectContractError(
			() => parseMonitorDisableAuthorizationV1({ ...authorization, state: "consumed" }),
			"UNKNOWN_FIELD",
		);
		expectContractError(
			() =>
				parseMonitorDisableAuthorizationV1({
					...authorization,
					schema: "gjc-bugwatch-monitor-disable-authorization/v1",
				}),
			"UNSUPPORTED_SCHEMA",
		);
	});
});
