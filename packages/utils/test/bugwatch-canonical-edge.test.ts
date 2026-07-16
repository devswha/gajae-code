import { describe, expect, it } from "bun:test";
import {
	BugwatchContractError,
	canonicalizeJson,
	type JsonValue,
	MAX_CANONICAL_JSON_DEPTH,
	parseCanonicalJson,
} from "../src/bugwatch-contract";

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
class CustomPrototype {}
function nestedArrays(depth: number): JsonValue {
	let value: JsonValue = "leaf";
	for (let index = 0; index < depth; index++) value = [value];
	return value;
}

function nestedMixedContainers(depth: number): JsonValue {
	let value: JsonValue = "leaf";
	for (let index = 0; index < depth; index++) {
		value = index % 2 === 0 ? [value] : { value };
	}
	return value;
}

describe("bugwatch canonical JSON edge cases", () => {
	it("canonicalizes BMP and non-BMP Unicode with canonical JSON escapes", () => {
		const value: JsonValue = {
			bmp: "café",
			emoji: "😀",
			"\u0000": "\b\t\n\f\r",
		};
		const canonical = '{"\\u0000":"\\b\\t\\n\\f\\r","bmp":"café","emoji":"😀"}';

		expect(canonicalizeJson(value)).toBe(canonical);
		expect(canonicalizeJson(parseCanonicalJson(canonical))).toBe(canonical);
	});

	it("retains escaped and special keys as ordinary own properties", () => {
		const parsed = parseCanonicalJson(
			'{"\\u0000":"control","__proto__":{"constructor":"ordinary"},"constructor":"ordinary","path":"a/b"}',
		) as { [key: string]: JsonValue };

		expect(Object.getPrototypeOf(parsed)).toBeNull();
		expect(Object.hasOwn(parsed, "__proto__")).toBe(true);
		expect(Object.hasOwn(parsed, "constructor")).toBe(true);
		expect(Object.hasOwn(parsed, "\u0000")).toBe(true);
		const protoEntry = Reflect.get(parsed, "__proto__") as unknown as JsonValue;
		expect(canonicalizeJson(protoEntry)).toBe('{"constructor":"ordinary"}');
		expect(canonicalizeJson(parsed)).toBe(
			'{"\\u0000":"control","__proto__":{"constructor":"ordinary"},"constructor":"ordinary","path":"a/b"}',
		);
	});
	it("rejects non-plain runtime objects and retains ordinary object prototypes", () => {
		for (const value of [
			new Date(),
			new Map(),
			new Boolean(true),
			new Number(1),
			/value/,
			new Set(),
			new String("value"),
			new CustomPrototype(),
		] as unknown[]) {
			expectContractError(() => canonicalizeJson(value as JsonValue), "INVALID_JSON_VALUE");
		}

		const ordinary: JsonValue = { beta: 2, alpha: 1 };
		const nullPrototype = parseCanonicalJson('{"alpha":1,"beta":2}');
		expect(canonicalizeJson(ordinary)).toBe('{"alpha":1,"beta":2}');
		expect(Object.getPrototypeOf(nullPrototype)).toBeNull();
		expect(canonicalizeJson(nullPrototype)).toBe('{"alpha":1,"beta":2}');
	});
	it("rejects sparse arrays before recursively canonicalizing them", () => {
		const leading = new Array<JsonValue>(2);
		leading[1] = "value";
		const trailing: JsonValue[] = ["value"];
		trailing.length = 2;
		const allHoles = new Array<JsonValue>(2);
		const nested: JsonValue[] = [["value"]];
		(nested[0] as JsonValue[]).length = 2;

		for (const value of [leading, trailing, allHoles, nested]) {
			expectContractError(() => canonicalizeJson(value), "INVALID_JSON_VALUE");
		}
	});

	it("accepts safe canonical numbers and rejects alternate JSON encodings", () => {
		const parsed = parseCanonicalJson('{"fraction":1.5,"integer":9007199254740991}') as {
			[key: string]: JsonValue;
		};
		expect(parsed.fraction).toBe(1.5);
		expect(parsed.integer).toBe(9_007_199_254_740_991);

		for (const text of [' {"value":1}', '{"value":1.0}', '{"value":0.0}', '{"value":-0}']) {
			expect(() => parseCanonicalJson(text)).toThrow(BugwatchContractError);
		}
	});

	it("rejects lone UTF-16 surrogates in values and keys", () => {
		expectContractError(() => canonicalizeJson("\ud800"), "INVALID_JSON_VALUE");
		expectContractError(() => canonicalizeJson({ "\udc00": "value" }), "INVALID_JSON_VALUE");
		expectContractError(() => parseCanonicalJson('{"value":"\\ud800"}'), "INVALID_JSON");
		expectContractError(() => parseCanonicalJson('{"\\udc00":"value"}'), "INVALID_JSON");
	});
	it("bounds nested authority envelopes during canonicalization and parsing", () => {
		const arrayAtLimit = nestedArrays(MAX_CANONICAL_JSON_DEPTH);
		const arrayCanonical = canonicalizeJson(arrayAtLimit);
		const mixedAtLimit = nestedMixedContainers(MAX_CANONICAL_JSON_DEPTH);
		const mixedCanonical = canonicalizeJson(mixedAtLimit);

		expect(canonicalizeJson(parseCanonicalJson(arrayCanonical))).toBe(arrayCanonical);
		expect(canonicalizeJson(parseCanonicalJson(mixedCanonical))).toBe(mixedCanonical);

		expectContractError(() => canonicalizeJson(nestedArrays(MAX_CANONICAL_JSON_DEPTH + 1)), "INVALID_JSON_VALUE");
		expectContractError(
			() =>
				parseCanonicalJson(
					`${"[".repeat(MAX_CANONICAL_JSON_DEPTH + 1)}0${"]".repeat(MAX_CANONICAL_JSON_DEPTH + 1)}`,
				),
			"INVALID_JSON",
		);
		expectContractError(
			() => canonicalizeJson(nestedMixedContainers(MAX_CANONICAL_JSON_DEPTH + 1)),
			"INVALID_JSON_VALUE",
		);
		expectContractError(() => parseCanonicalJson('{"value":'.repeat(MAX_CANONICAL_JSON_DEPTH + 1)), "INVALID_JSON");
	});

	it("rejects malformed strings, noncanonical escapes, and duplicate special keys", () => {
		for (const text of [
			'{"value":"\\x"}',
			'{"value":"unterminated}',
			'{"path":"a\\/b"}',
			'{"\\u0061":1}',
			'{"__proto__":1,"__proto__":2}',
			'{"constructor":1,"constructor":2}',
		]) {
			expect(() => parseCanonicalJson(text)).toThrow(BugwatchContractError);
		}
	});
});
