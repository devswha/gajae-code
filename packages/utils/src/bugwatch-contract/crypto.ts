import * as crypto from "node:crypto";
import { BugwatchContractError, canonicalizeJson, type JsonValue, jsonObject } from "./canonical";
import {
	type PolicySemanticV1,
	parsePolicySemanticV1,
	parseScopePolicyHeadV2,
	parseScopePolicyRevisionV2,
	type ScopePolicyHeadV2,
	type ScopePolicyRevisionV2,
} from "./schemas";

function bytes(value: string): Uint8Array {
	return new TextEncoder().encode(value);
}
function objectWithoutMac(value: { [key: string]: JsonValue }): { [key: string]: JsonValue } {
	const copy: { [key: string]: JsonValue } = {};
	for (const [key, entry] of Object.entries(value)) if (key !== "mac") copy[key] = entry;
	return copy;
}

export function sha256Hex(value: string | Uint8Array): string {
	return crypto.createHash("sha256").update(value).digest("hex");
}
export function hmacSha256Hex(key: Uint8Array, domain: string, value: JsonValue): string {
	return crypto
		.createHmac("sha256", key)
		.update(bytes(`${domain}\0${canonicalizeJson(value)}`))
		.digest("hex");
}
export function macPayload(value: JsonValue): JsonValue {
	return objectWithoutMac(jsonObject(value, "MAC envelope"));
}
export function verifyMac(value: JsonValue, domain: string, key: Uint8Array): void {
	const object = jsonObject(value, "MAC envelope");
	const mac = object.mac;
	if (typeof mac !== "string" || !/^[0-9a-f]{64}$/.test(mac))
		throw new BugwatchContractError("INVALID_MAC", "Envelope MAC must be lowercase HMAC-SHA-256 hex");
	const expected = hmacSha256Hex(key, domain, macPayload(object));
	if (!crypto.timingSafeEqual(Buffer.from(mac, "hex"), Buffer.from(expected, "hex")))
		throw new BugwatchContractError("INVALID_MAC", `Envelope MAC does not verify for ${domain}`);
}
export function authenticatedHash(value: JsonValue): string {
	return sha256Hex(canonicalizeJson(value));
}
export function fatalCoreHash(value: JsonValue): string {
	const core = jsonObject(value, "fatal envelope");
	const copy: { [key: string]: JsonValue } = {};
	for (const [key, entry] of Object.entries(core)) if (key !== "mac" && key !== "fatalCoreHash") copy[key] = entry;
	return sha256Hex(canonicalizeJson(copy));
}
export function policyContentHash(policy: PolicySemanticV1): string {
	const semantic = parsePolicySemanticV1(policy as unknown as JsonValue);
	return sha256Hex(canonicalizeJson(semantic as unknown as JsonValue));
}
export function captureSemanticsHash(policy: PolicySemanticV1): string {
	const semantic = parsePolicySemanticV1(policy as unknown as JsonValue);
	return sha256Hex(
		canonicalizeJson({
			daemon: semantic.daemon,
			ingest: semantic.ingest,
			inbox: semantic.inbox,
			archive: semantic.archive,
			coverage: semantic.coverage,
		} as unknown as JsonValue),
	);
}
export function revisionHash(revision: ScopePolicyRevisionV2): string {
	return authenticatedHash(revision as unknown as JsonValue);
}
export function computeEventId(bootId: string, recordSeq: string): string {
	if (!/^[1-9][0-9]*$/.test(recordSeq))
		throw new BugwatchContractError(
			"INVALID_SEQUENCE",
			"record sequence must be unsigned decimal text without leading zeroes",
		);
	const sequence = BigInt(recordSeq);
	if (sequence > 9_223_372_036_854_775_807n)
		throw new BugwatchContractError("INVALID_SEQUENCE", "record sequence exceeds int64 range");
	const encoded = Buffer.alloc(8);
	encoded.writeBigUInt64BE(sequence);
	return crypto
		.createHash("sha256")
		.update("gjc-event-v1\0")
		.update(bootId)
		.update("\0")
		.update(encoded)
		.digest("hex");
}
export interface PolicyChainAnchor {
	generation: number;
	revisionHash: string;
	contentHash: string;
}
export interface VerifiedPolicyChain {
	head: ScopePolicyHeadV2;
	revisions: ScopePolicyRevisionV2[];
}
export function validatePolicyChain(
	head: ScopePolicyHeadV2,
	revisions: readonly ScopePolicyRevisionV2[],
	keyForId: (keyId: string) => Uint8Array | undefined,
	anchor: PolicyChainAnchor | null = null,
): VerifiedPolicyChain {
	const parsedHead = parseScopePolicyHeadV2(head as unknown as JsonValue);
	const parsedRevisions = revisions.map(revision => parseScopePolicyRevisionV2(revision as unknown as JsonValue));
	if (parsedRevisions.length === 0) throw new BugwatchContractError("POLICY_CHAIN_GAP", "Policy chain is empty");
	const terminal = parsedRevisions[parsedRevisions.length - 1];
	let previous = anchor;
	for (const revision of parsedRevisions) {
		const key = keyForId(revision.keyId);
		if (key === undefined)
			throw new BugwatchContractError("UNKNOWN_KEY", `No key for policy revision ${revision.keyId}`);
		verifyMac(revision as unknown as JsonValue, "gjc-bugwatch-policy-revision-v2", key);
		if (revision.scopeId !== parsedHead.scopeId || revision.generation < 1)
			throw new BugwatchContractError("POLICY_CHAIN_GAP", "Invalid revision scope or generation");
		if (policyContentHash(revision.semantic) !== revision.contentHash)
			throw new BugwatchContractError("INVALID_HASH", "Policy revision content hash does not match semantic policy");
		if (previous === null) {
			if (
				revision.generation !== 1 ||
				revision.previousGeneration !== null ||
				revision.previousRevisionHash !== null ||
				revision.previousContentHash !== null
			)
				throw new BugwatchContractError("POLICY_CHAIN_GAP", "Invalid first policy revision");
		} else if (
			revision.generation !== previous.generation + 1 ||
			revision.previousGeneration !== previous.generation ||
			revision.previousRevisionHash !== previous.revisionHash ||
			revision.previousContentHash !== previous.contentHash
		) {
			throw new BugwatchContractError("POLICY_CHAIN_GAP", "Policy revision predecessor does not match");
		}
		previous = {
			generation: revision.generation,
			revisionHash: revisionHash(revision),
			contentHash: revision.contentHash,
		};
	}
	if (
		previous === null ||
		parsedHead.generation !== previous.generation ||
		parsedHead.revisionHash !== previous.revisionHash ||
		parsedHead.contentHash !== previous.contentHash
	)
		throw new BugwatchContractError("POLICY_CHAIN_GAP", "Policy head does not name terminal revision");
	const headKey = keyForId(parsedHead.keyId);
	if (headKey === undefined)
		throw new BugwatchContractError("UNKNOWN_KEY", `No key for policy head ${parsedHead.keyId}`);
	verifyMac(parsedHead as unknown as JsonValue, "gjc-bugwatch-policy-head-v2", headKey);
	if (sha256Hex(parsedHead.casToken) !== terminal.casTokenHash)
		throw new BugwatchContractError("POLICY_CHAIN_GAP", "Policy head CAS token does not match terminal revision");
	return { head: parsedHead, revisions: parsedRevisions };
}
export interface PolicyAdoptionState {
	head: ScopePolicyHeadV2 | null;
	revisions: ScopePolicyRevisionV2[];
}
export interface PolicyAdoptionStale {
	outcome: "stale";
	state: PolicyAdoptionState;
}

export type PolicyAdoptionResult = PolicyAdoptionState | PolicyAdoptionStale;

export function adoptPolicyHead(
	state: PolicyAdoptionState,
	head: ScopePolicyHeadV2,
	revisions: readonly ScopePolicyRevisionV2[],
	keyForId: (keyId: string) => Uint8Array | undefined,
): PolicyAdoptionResult {
	const parsedHead = parseScopePolicyHeadV2(head as unknown as JsonValue);
	const headKey = keyForId(parsedHead.keyId);
	if (headKey === undefined)
		throw new BugwatchContractError("UNKNOWN_KEY", `No key for policy head ${parsedHead.keyId}`);
	verifyMac(parsedHead as unknown as JsonValue, "gjc-bugwatch-policy-head-v2", headKey);

	const currentHead = state.head === null ? null : parseScopePolicyHeadV2(state.head as unknown as JsonValue);
	if (currentHead !== null) {
		const currentHeadKey = keyForId(currentHead.keyId);
		if (currentHeadKey === undefined)
			throw new BugwatchContractError("UNKNOWN_KEY", `No key for adopted policy head ${currentHead.keyId}`);
		verifyMac(currentHead as unknown as JsonValue, "gjc-bugwatch-policy-head-v2", currentHeadKey);
		if (parsedHead.scopeId !== currentHead.scopeId)
			throw new BugwatchContractError("POLICY_SCOPE_MISMATCH", "Policy head scope does not match adopted scope");
	}
	const parsedCandidates = revisions.map(revision => parseScopePolicyRevisionV2(revision as unknown as JsonValue));
	const candidateByGeneration = new Map<number, ScopePolicyRevisionV2>();
	for (const revision of parsedCandidates) {
		const key = keyForId(revision.keyId);
		if (key === undefined)
			throw new BugwatchContractError("UNKNOWN_KEY", `No key for policy revision ${revision.keyId}`);
		verifyMac(revision as unknown as JsonValue, "gjc-bugwatch-policy-revision-v2", key);
		if (revision.scopeId !== parsedHead.scopeId)
			throw new BugwatchContractError("POLICY_SCOPE_MISMATCH", "Policy revision scope does not match policy head");
		const existing = candidateByGeneration.get(revision.generation);
		if (existing !== undefined && revisionHash(existing) !== revisionHash(revision))
			throw new BugwatchContractError("POLICY_EQUIVOCATION", "Conflicting candidate policy revision");
		candidateByGeneration.set(revision.generation, revision);
	}
	const retained = new Map<number, ScopePolicyRevisionV2>();
	for (const sourceRevision of state.revisions) {
		const revision = parseScopePolicyRevisionV2(sourceRevision as unknown as JsonValue);
		const key = keyForId(revision.keyId);
		if (key === undefined)
			throw new BugwatchContractError("UNKNOWN_KEY", `No key for retained policy revision ${revision.keyId}`);
		verifyMac(revision as unknown as JsonValue, "gjc-bugwatch-policy-revision-v2", key);
		if (revision.scopeId !== parsedHead.scopeId)
			throw new BugwatchContractError(
				"POLICY_SCOPE_MISMATCH",
				"Retained policy revision scope does not match policy head",
			);
		const existing = retained.get(revision.generation);
		if (existing !== undefined && revisionHash(existing) !== revisionHash(revision))
			throw new BugwatchContractError("POLICY_EQUIVOCATION", "Conflicting retained policy revision");
		retained.set(revision.generation, revision);
	}
	if (currentHead === null) {
		if (retained.size !== 0)
			throw new BugwatchContractError(
				"POLICY_CHAIN_GAP",
				"Retained policy revisions require an adopted policy head",
			);
	} else {
		const retainedTerminal = retained.get(currentHead.generation);
		if (
			retainedTerminal === undefined ||
			revisionHash(retainedTerminal) !== currentHead.revisionHash ||
			retainedTerminal.contentHash !== currentHead.contentHash
		)
			throw new BugwatchContractError(
				"POLICY_CHAIN_GAP",
				"Adopted policy head does not match retained terminal revision",
			);
		if (sha256Hex(currentHead.casToken) !== retainedTerminal.casTokenHash)
			throw new BugwatchContractError(
				"POLICY_CHAIN_GAP",
				"Adopted policy head CAS token does not match retained terminal revision",
			);
		for (const revision of retained.values()) {
			if (revision.generation > currentHead.generation)
				throw new BugwatchContractError(
					"POLICY_CHAIN_GAP",
					"Retained policy revision is newer than adopted policy head",
				);
		}
	}

	if (currentHead !== null && parsedHead.generation <= currentHead.generation) {
		const retainedRevision = retained.get(parsedHead.generation);
		if (
			retainedRevision === undefined ||
			revisionHash(retainedRevision) !== parsedHead.revisionHash ||
			retainedRevision.contentHash !== parsedHead.contentHash
		)
			throw new BugwatchContractError(
				"POLICY_CHAIN_GAP",
				"Stale policy head does not match a retained policy revision",
			);
		if (sha256Hex(parsedHead.casToken) !== retainedRevision.casTokenHash)
			throw new BugwatchContractError(
				"POLICY_CHAIN_GAP",
				"Stale policy head CAS token does not match a retained policy revision",
			);
		return { outcome: "stale", state };
	}

	for (const revision of candidateByGeneration.values()) {
		const existing = retained.get(revision.generation);
		if (existing !== undefined && revisionHash(existing) !== revisionHash(revision))
			throw new BugwatchContractError("POLICY_EQUIVOCATION", "Conflicting retained policy revision");
	}

	const candidate = [...candidateByGeneration.values()].sort((left, right) => left.generation - right.generation);
	if (candidate.length === 0) throw new BugwatchContractError("POLICY_CHAIN_GAP", "Policy chain is empty");
	const first = candidate[0];
	const expectedFirstGeneration = currentHead === null ? 1 : currentHead.generation + 1;
	if (first.generation !== expectedFirstGeneration)
		throw new BugwatchContractError(
			"POLICY_CHAIN_GAP",
			"Candidate policy chain does not start at the next generation",
		);
	const verified = validatePolicyChain(
		parsedHead,
		candidate,
		keyForId,
		currentHead === null
			? null
			: {
					generation: currentHead.generation,
					revisionHash: currentHead.revisionHash,
					contentHash: currentHead.contentHash,
				},
	);

	for (const revision of verified.revisions) retained.set(revision.generation, revision);
	return {
		head: verified.head,
		revisions: [...retained.values()].sort((left, right) => left.generation - right.generation),
	};
}
