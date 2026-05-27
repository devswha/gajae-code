import { readFile } from "fs/promises";

export function safeJsonParse<T>(raw: string, fallback: T): T {
	try {
		return JSON.parse(raw) as T;
	} catch {
		return fallback;
	}
}

export async function safeReadJsonFile<T>(filePath: string, fallback: T): Promise<T> {
	try {
		const raw = await readFile(filePath, "utf-8");
		return JSON.parse(raw) as T;
	} catch {
		return fallback;
	}
}
