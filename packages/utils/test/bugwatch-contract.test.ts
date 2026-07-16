import { describe, expect, it } from "bun:test";
import {
	AUTHORITY_CLASS_NAMES,
	type AuthoritySnapshotFrontierEvidenceV1,
	type AuthoritySnapshotManifestV2,
	adoptPolicyHead,
	BUGWATCH_FIXTURE_MANIFEST_HASH,
	BugwatchContractError,
	canonicalizeBugwatchFixtureManifestIdentity,
	canonicalizeJson,
	captureSemanticsHash,
	computeEventId,
	fatalCoreHash,
	hmacSha256Hex,
	type JsonValue,
	type PolicySemanticV1,
	parseAttachmentV1,
	parseAuthoritySnapshotManifestV2,
	parseBootCoreV1,
	parseBootFinalV1,
	parseBootTransportCloseV1,
	parseFatalEnvelopeV1,
	parseLeaseV1,
	parseMonitorDisableActionV1,
	parsePolicySemanticV1,
	parseRootControlV1,
	parseSourceAuthorityV1,
	policyContentHash,
	type ScopePolicyHeadV2,
	type ScopePolicyRevisionV2,
	sha256Hex,
	validatePolicyChain,
	verifyAuthoritySnapshotPackV2,
	verifyMac,
} from "@gajae-code/utils/bugwatch-contract";
import fixture from "./fixtures/bugwatch-contract-v1.json" with { type: "json" };

const fixtureMacKey = new TextEncoder().encode("bugwatch-fixture-mac-key");

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
		previousRevisionHash: previous === null ? null : canonicalHash(previous as unknown as JsonValue),
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

function withoutMac(value: { [key: string]: JsonValue }): JsonValue {
	const payload: { [key: string]: JsonValue } = {};
	for (const [key, entry] of Object.entries(value)) if (key !== "mac") payload[key] = entry;
	return payload;
}

function canonicalHash(value: JsonValue): string {
	return sha256Hex(canonicalizeJson(value));
}
function signedHead(revision: ScopePolicyRevisionV2): ScopePolicyHeadV2 {
	const head: ScopePolicyHeadV2 = {
		schema: "gjc-bugwatch-policy-head/v2",
		scopeId: revision.scopeId,
		generation: revision.generation,
		revisionHash: canonicalHash(revision as unknown as JsonValue),
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
function fixtureSnapshotFrontierEvidence(): AuthoritySnapshotFrontierEvidenceV1 {
	return structuredClone(fixture.envelopes.snapshotFrontierEvidence) as AuthoritySnapshotFrontierEvidenceV1;
}

describe("bugwatch contract fixture v1", () => {
	it("parses deterministic authority examples and canonical semantic policy", () => {
		expect(canonicalizeJson({ z: 1, a: [true, 2] })).toBe(fixture.expected.canonical);
		expect(policyContentHash(parsePolicySemanticV1(fixture.semanticPolicies.a))).toBe(
			fixture.expected.policyContentHashes.a,
		);
		expect(policyContentHash(parsePolicySemanticV1(fixture.semanticPolicies.b))).toBe(
			fixture.expected.policyContentHashes.b,
		);
		expect(captureSemanticsHash(parsePolicySemanticV1(fixture.semanticPolicies.a))).not.toBe(
			captureSemanticsHash(parsePolicySemanticV1(fixture.semanticPolicies.b)),
		);

		expect(parseLeaseV1(fixture.envelopes.lease).scopeId).toBe("scope-fixture");
		expect(parseRootControlV1(fixture.envelopes.root).rootId).toBe("root-fixture");
		expect(parseBootCoreV1(fixture.envelopes.boot).sequenceOrigin).toBe("1");
		expect(parseAttachmentV1(fixture.envelopes.attachment).state).toBe("active");
		expect(parseSourceAuthorityV1(fixture.envelopes.source).segmentId).toBe("segment-fixture");
		expect(parseFatalEnvelopeV1(fixture.envelopes.fatal).eventId).toBe(fixture.expected.eventId);
		expect(fixture.envelopes.monitorAction.kind).toBe("process");

		const snapshot = fixtureSnapshot();
		const parsedSnapshot = parseAuthoritySnapshotManifestV2(snapshot as unknown as JsonValue);
		expect(parsedSnapshot.classes).toHaveLength(AUTHORITY_CLASS_NAMES.length);
		const verifiedSnapshot = verifyAuthoritySnapshotPackV2(
			snapshot as unknown as JsonValue,
			fixture.envelopes.snapshotItems as unknown as JsonValue[],
			{
				snapshot: { keyId: snapshot.snapshotKeyId, keyBytes: fixtureMacKey },
				policy: { keyId: snapshot.policyKeyringId, keyBytes: fixtureMacKey },
				fatal: { keyId: snapshot.fatalKeyringId, keyBytes: fixtureMacKey },
				registry: { keyId: snapshot.registryKeyringId, keyBytes: fixtureMacKey },
				rollback: { keyId: snapshot.rollbackKeyringId, keyBytes: fixtureMacKey },
			},
			null,
			fixtureSnapshotFrontierEvidence(),
		);
		expect(verifiedSnapshot.manifest).toEqual(parsedSnapshot);
		expect(verifiedSnapshot.items).toHaveLength(fixture.envelopes.snapshotItems.length);
	});

	it("retains semantic A to B to A identity while validating every transition", () => {
		const policyA = parsePolicySemanticV1(fixture.semanticPolicies.a);
		const policyB = parsePolicySemanticV1(fixture.semanticPolicies.b);
		const first = signedRevision(1, policyA, null);
		const second = signedRevision(2, policyB, first);
		const third = signedRevision(3, policyA, second);
		const head: ScopePolicyHeadV2 = {
			schema: "gjc-bugwatch-policy-head/v2",
			scopeId: policyA.scopeId,
			generation: 3,
			revisionHash: canonicalHash(third as unknown as JsonValue),
			contentHash: third.contentHash,
			casToken: "cas-token-3",
			updatedAt: "2026-01-02T03:04:08.000Z",
			keyId: "fixture-key",
			mac: "",
		};
		head.mac = hmacSha256Hex(
			fixtureMacKey,
			"gjc-bugwatch-policy-head-v2",
			withoutMac(head as unknown as { [key: string]: JsonValue }),
		);

		const verified = validatePolicyChain(head, [first, second, third], keyId =>
			keyId === "fixture-key" ? fixtureMacKey : undefined,
		);
		expect(verified.revisions.map(revision => revision.generation)).toEqual([1, 2, 3]);
		expect(first.contentHash).toBe(third.contentHash);
		expect(first.contentHash).not.toBe(second.contentHash);
		expect(first.previousRevisionHash).toBeNull();
		expect(third.previousRevisionHash).toBe(canonicalHash(second as unknown as JsonValue));
	});

	it("recomputes stable fatal identity and authenticates the redacted envelope", () => {
		const fatal = parseFatalEnvelopeV1(fixture.envelopes.fatal);
		expect(computeEventId(fatal.bootId, fatal.recordSeq)).toBe(fixture.expected.eventId);
		expect(fatal.mac).toBe(fixture.expected.fatalMac);
		expect(() => verifyMac(fatal as unknown as JsonValue, "gjc-bugwatch-fatal-mac-v1", fixtureMacKey)).not.toThrow();
	});
	it("rejects null required boot and attachment fields", () => {
		const attachment = fixture.envelopes.attachment;
		for (const key of ["attachmentId", "rootId", "baselineEpochId"] as const)
			expect(() => parseAttachmentV1({ ...attachment, [key]: null })).toThrow();
		expect(() => parseAttachmentV1({ ...attachment, publishSequence: "0" })).toThrow();
		expect(() => parseAttachmentV1({ ...attachment, endedAt: "not-a-timestamp" })).toThrow();

		const close = {
			schema: "gjc-bugwatch-transport-close/v1",
			scopeId: "scope-fixture",
			bootId: "boot-fixture",
			bootCoreHash: "0".repeat(64),
			transportEpoch: 0,
			startRecordHash: "0".repeat(64),
			endSequenceInclusive: "1",
			endedAt: "2026-01-02T03:04:05.000Z",
			outcome: "closed",
			keyId: "fixture-key",
			previousRecordHash: "0".repeat(64),
			mac: "0".repeat(64),
		};
		expect(() => parseBootTransportCloseV1({ ...close, endedAt: null })).toThrow();

		const final = {
			schema: "gjc-bugwatch-boot-final/v1",
			scopeId: "scope-fixture",
			bootId: "boot-fixture",
			bootCoreHash: "0".repeat(64),
			finalSequence: "1",
			endedAt: "2026-01-02T03:04:05.000Z",
			state: "clean",
			lastTransportRecordHash: "0".repeat(64),
			attachmentSnapshotHash: "0".repeat(64),
			keyId: "fixture-key",
			previousRecordHash: "0".repeat(64),
			mac: "0".repeat(64),
		};
		expect(() => parseBootFinalV1({ ...final, previousRecordHash: null })).toThrow();
	});
	it("adopts 3,1,2 notifications incrementally and rejects stale heads without retained authority", () => {
		const policyA = parsePolicySemanticV1(fixture.semanticPolicies.a);
		const policyB = parsePolicySemanticV1(fixture.semanticPolicies.b);
		const first = signedRevision(1, policyA, null);
		const second = signedRevision(2, policyB, first);
		const third = signedRevision(3, policyA, second);
		const fourth = signedRevision(4, policyB, third);
		const firstHead = signedHead(first);
		const secondHead = signedHead(second);
		const thirdHead = signedHead(third);
		const fourthHead = signedHead(fourth);
		const keyForId = (keyId: string): Uint8Array | undefined => (keyId === "fixture-key" ? fixtureMacKey : undefined);

		const afterFirst = adoptPolicyHead({ head: null, revisions: [] }, firstHead, [first], keyForId);
		if ("outcome" in afterFirst) throw new Error("initial policy was classified stale");
		const afterThree = adoptPolicyHead(afterFirst, thirdHead, [second, third], keyForId);
		if ("outcome" in afterThree) throw new Error("notification 3 did not catch up through revision 3");
		expect(afterThree.revisions.map(revision => revision.generation)).toEqual([1, 2, 3]);
		expect(adoptPolicyHead(afterThree, firstHead, [], keyForId)).toEqual({ outcome: "stale", state: afterThree });
		expect(adoptPolicyHead(afterThree, secondHead, [], keyForId)).toEqual({ outcome: "stale", state: afterThree });
		expect(adoptPolicyHead(afterThree, thirdHead, [], keyForId)).toEqual({ outcome: "stale", state: afterThree });

		const pruned = { head: afterThree.head, revisions: [] };
		expectContractError(() => adoptPolicyHead(pruned, firstHead, [], keyForId), "POLICY_CHAIN_GAP");

		const catchUpFromFour = adoptPolicyHead(afterFirst, fourthHead, [second, third, fourth], keyForId);
		if ("outcome" in catchUpFromFour) throw new Error("head 4 did not catch up from generation 1");
		expect(catchUpFromFour.revisions.map(revision => revision.generation)).toEqual([1, 2, 3, 4]);
	});

	it("rejects active-chain forks and gaps while strict-parsing signed policy envelopes", () => {
		const policyA = parsePolicySemanticV1(fixture.semanticPolicies.a);
		const policyB = parsePolicySemanticV1(fixture.semanticPolicies.b);
		const first = signedRevision(1, policyA, null);
		const second = signedRevision(2, policyB, first);
		const third = signedRevision(3, policyA, second);
		const firstHead = signedHead(first);
		const thirdHead = signedHead(third);
		const keyForId = (keyId: string): Uint8Array | undefined => (keyId === "fixture-key" ? fixtureMacKey : undefined);
		const state = { head: firstHead, revisions: [first] };
		const conflictingSecond = signedRevision(2, policyA, first);

		expectContractError(
			() => adoptPolicyHead(state, thirdHead, [second, conflictingSecond, third], keyForId),
			"POLICY_EQUIVOCATION",
		);
		expectContractError(() => adoptPolicyHead(state, thirdHead, [third], keyForId), "POLICY_CHAIN_GAP");

		const unknownHead = { ...firstHead, unexpected: true, mac: "" };
		unknownHead.mac = hmacSha256Hex(
			fixtureMacKey,
			"gjc-bugwatch-policy-head-v2",
			withoutMac(unknownHead as unknown as { [key: string]: JsonValue }),
		);
		expectContractError(
			() => validatePolicyChain(unknownHead as unknown as ScopePolicyHeadV2, [first], keyForId),
			"UNKNOWN_FIELD",
		);

		const unsupportedHead = { ...firstHead, schema: "gjc-bugwatch-policy-head/v3", mac: "" };
		unsupportedHead.mac = hmacSha256Hex(
			fixtureMacKey,
			"gjc-bugwatch-policy-head-v2",
			withoutMac(unsupportedHead as unknown as { [key: string]: JsonValue }),
		);
		expectContractError(
			() => validatePolicyChain(unsupportedHead as unknown as ScopePolicyHeadV2, [first], keyForId),
			"UNSUPPORTED_SCHEMA",
		);

		const unknownRevision = { ...first, unexpected: true, mac: "" };
		unknownRevision.mac = hmacSha256Hex(
			fixtureMacKey,
			"gjc-bugwatch-policy-revision-v2",
			withoutMac(unknownRevision as unknown as { [key: string]: JsonValue }),
		);
		expectContractError(
			() => validatePolicyChain(firstHead, [unknownRevision as unknown as ScopePolicyRevisionV2], keyForId),
			"UNKNOWN_FIELD",
		);
		expectContractError(
			() => adoptPolicyHead(state, thirdHead, [unknownRevision as unknown as ScopePolicyRevisionV2], keyForId),
			"UNKNOWN_FIELD",
		);

		const unsupportedRevision = { ...first, schema: "gjc-bugwatch-policy-revision/v3", mac: "" };
		unsupportedRevision.mac = hmacSha256Hex(
			fixtureMacKey,
			"gjc-bugwatch-policy-revision-v2",
			withoutMac(unsupportedRevision as unknown as { [key: string]: JsonValue }),
		);
		expectContractError(
			() => validatePolicyChain(firstHead, [unsupportedRevision as unknown as ScopePolicyRevisionV2], keyForId),
			"UNSUPPORTED_SCHEMA",
		);
	});
	it("binds parsed user-cron bytes to their declared line hashes", () => {
		const markerLineBytesBase64 = Buffer.from("# gjc-bugwatch fixture-owner\n").toString("base64");
		const jobLineBytesBase64 = Buffer.from("* * * * * gjc bugwatch --owner fixture-owner\n").toString("base64");
		const action = {
			kind: "user_cron" as const,
			expectedCrontabHash: "0".repeat(64),
			markerLineHash: sha256Hex(Buffer.from(markerLineBytesBase64, "base64")),
			jobLineHash: sha256Hex(Buffer.from(jobLineBytesBase64, "base64")),
			markerLineBytesBase64,
			jobLineBytesBase64,
		};
		expect(parseMonitorDisableActionV1(action)).toEqual(action);
	});
	it("recomputes the fatal core hash before MAC validation", () => {
		const fatal = parseFatalEnvelopeV1(fixture.envelopes.fatal);
		expect(fatal.fatalCoreHash).toBe(fatalCoreHash(fatal as unknown as JsonValue));
	});
});
