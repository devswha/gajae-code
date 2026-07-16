export type JsonPrimitive = boolean | null | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
/** Maximum nested object/array containers accepted in authority envelopes. */
export const MAX_CANONICAL_JSON_DEPTH = 32;

export class BugwatchContractError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.name = "BugwatchContractError";
		this.code = code;
	}
}

function isPlainObject(value: JsonValue): value is { [key: string]: JsonValue } {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
}

function hasLoneSurrogate(value: string): boolean {
	for (let index = 0; index < value.length; index++) {
		const codeUnit = value.charCodeAt(index);
		if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
			if (index + 1 >= value.length) return true;
			const next = value.charCodeAt(index + 1);
			if (next < 0xdc00 || next > 0xdfff) return true;
			index++;
		} else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
			return true;
		}
	}
	return false;
}

function canonicalString(value: string): string {
	if (hasLoneSurrogate(value)) {
		throw new BugwatchContractError("INVALID_JSON_VALUE", "JSON strings must not contain lone UTF-16 surrogates");
	}
	return JSON.stringify(value);
}

function canonicalKey(value: string): string {
	if (hasLoneSurrogate(value)) {
		throw new BugwatchContractError("INVALID_JSON_VALUE", "JSON object keys must not contain lone UTF-16 surrogates");
	}
	return JSON.stringify(value);
}

function canonicalNumber(value: number): string {
	if (!Number.isFinite(value) || Object.is(value, -0)) {
		throw new BugwatchContractError(
			"NONCANONICAL_NUMBER",
			"JSON numbers must be finite and must not be negative zero",
		);
	}
	return JSON.stringify(value);
}

/** RFC 8785-compatible serialization for the contract's JSON value subset. */
export function canonicalizeJson(value: JsonValue): string {
	return canonicalizeValue(value, 0);
}

function canonicalizeValue(value: JsonValue, depth: number): string {
	if (value === null || typeof value === "boolean") return JSON.stringify(value);
	if (typeof value === "string") return canonicalString(value);
	if (typeof value === "number") return canonicalNumber(value);
	if (Array.isArray(value)) {
		if (depth >= MAX_CANONICAL_JSON_DEPTH) {
			throw new BugwatchContractError(
				"INVALID_JSON_VALUE",
				`JSON nesting exceeds the maximum depth of ${MAX_CANONICAL_JSON_DEPTH}`,
			);
		}
		for (let index = 0; index < value.length; index++) {
			if (!(index in value))
				throw new BugwatchContractError("INVALID_JSON_VALUE", "JSON arrays must not contain holes");
		}
		return `[${value.map(entry => canonicalizeValue(entry, depth + 1)).join(",")}]`;
	}
	if (!isPlainObject(value)) {
		throw new BugwatchContractError("INVALID_JSON_VALUE", "Only plain JSON objects are canonicalizable");
	}
	if (depth >= MAX_CANONICAL_JSON_DEPTH) {
		throw new BugwatchContractError(
			"INVALID_JSON_VALUE",
			`JSON nesting exceeds the maximum depth of ${MAX_CANONICAL_JSON_DEPTH}`,
		);
	}
	const keys = Object.keys(value).sort();
	return `{${keys.map(key => `${canonicalKey(key)}:${canonicalizeValue(value[key], depth + 1)}`).join(",")}}`;
}

class StrictJsonParser {
	#text: string;
	#index = 0;

	constructor(text: string) {
		this.#text = text;
	}

	parse(): JsonValue {
		const value = this.#value();
		if (this.#index !== this.#text.length) this.#fail("Unexpected trailing JSON content");
		return value;
	}

	#value(depth = 0): JsonValue {
		const character = this.#text[this.#index];
		if (character === "{") return this.#object(depth);
		if (character === "[") return this.#array(depth);
		if (character === '"') return this.#string();
		if (character === "t" && this.#take("true")) return true;
		if (character === "f" && this.#take("false")) return false;
		if (character === "n" && this.#take("null")) return null;
		if (character === "-" || (character !== undefined && character >= "0" && character <= "9")) return this.#number();
		this.#fail("Expected a JSON value");
	}

	#object(depth: number): { [key: string]: JsonValue } {
		if (depth >= MAX_CANONICAL_JSON_DEPTH) {
			this.#fail(`JSON nesting exceeds the maximum depth of ${MAX_CANONICAL_JSON_DEPTH}`);
		}
		this.#index++;
		const result = Object.create(null) as { [key: string]: JsonValue };
		const keys = new Set<string>();
		if (this.#text[this.#index] === "}") {
			this.#index++;
			return result;
		}
		while (true) {
			if (this.#text[this.#index] !== '"') this.#fail("Expected an object key");
			const key = this.#string();
			if (keys.has(key)) this.#fail(`Duplicate key: ${key}`);
			keys.add(key);
			if (this.#text[this.#index++] !== ":") this.#fail("Expected a colon");
			result[key] = this.#value(depth + 1);
			const next = this.#text[this.#index++];
			if (next === "}") return result;
			if (next !== ",") this.#fail("Expected a comma or closing brace");
		}
	}

	#array(depth: number): JsonValue[] {
		if (depth >= MAX_CANONICAL_JSON_DEPTH) {
			this.#fail(`JSON nesting exceeds the maximum depth of ${MAX_CANONICAL_JSON_DEPTH}`);
		}
		this.#index++;
		const result: JsonValue[] = [];
		if (this.#text[this.#index] === "]") {
			this.#index++;
			return result;
		}
		while (true) {
			result.push(this.#value(depth + 1));
			const next = this.#text[this.#index++];
			if (next === "]") return result;
			if (next !== ",") this.#fail("Expected a comma or closing bracket");
		}
	}

	#string(): string {
		const start = this.#index++;
		let escaped = false;
		while (this.#index < this.#text.length) {
			const character = this.#text[this.#index++];
			if (character < " ") this.#fail("Control character in JSON string");
			if (character === '"' && !escaped) {
				try {
					const value = JSON.parse(this.#text.slice(start, this.#index)) as string;
					if (hasLoneSurrogate(value)) this.#fail("Lone UTF-16 surrogate in JSON string");
					return value;
				} catch (error) {
					if (error instanceof BugwatchContractError) throw error;
					this.#fail("Invalid JSON string");
				}
			}
			escaped = character === "\\" ? !escaped : false;
		}
		this.#fail("Unterminated JSON string");
	}

	#number(): number {
		const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(this.#text.slice(this.#index));
		if (match === null) this.#fail("Invalid JSON number");
		this.#index += match[0].length;
		const value = Number(match[0]);
		if (!Number.isFinite(value) || Object.is(value, -0)) this.#fail("Noncanonical JSON number");
		return value;
	}

	#take(word: string): boolean {
		if (!this.#text.startsWith(word, this.#index)) return false;
		this.#index += word.length;
		return true;
	}

	#fail(message: string): never {
		throw new BugwatchContractError("INVALID_JSON", `${message} at byte ${this.#index}`);
	}
}

/** Parses duplicate-key-free canonical JSON. Whitespace and alternate number spellings fail closed. */
export function parseCanonicalJson(text: string): JsonValue {
	const value = new StrictJsonParser(text).parse();
	if (canonicalizeJson(value) !== text) {
		throw new BugwatchContractError("NONCANONICAL_JSON", "JSON bytes are not canonical JCS");
	}
	return value;
}

export function jsonObject(value: JsonValue, context: string): { [key: string]: JsonValue } {
	if (!isPlainObject(value)) throw new BugwatchContractError("INVALID_SCHEMA", `${context} must be an object`);
	return value;
}
