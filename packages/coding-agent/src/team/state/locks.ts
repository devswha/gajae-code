import { existsSync } from "fs";
import { mkdir, readFile, rm, stat, writeFile } from "fs/promises";
import { dirname, join } from "path";

interface TeamPathDeps {
	teamDir: (teamName: string, cwd: string) => string;
	taskClaimLockDir: (teamName: string, taskId: string, cwd: string) => string;
	mailboxLockDir: (teamName: string, workerName: string, cwd: string) => string;
}

const LOCK_OWNER_RETRY_MS = 25;

function lockOwnerToken(): string {
	return `${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}`;
}

async function maybeRecoverStaleLock(lockDir: string, lockStaleMs: number): Promise<boolean> {
	try {
		const info = await stat(lockDir);
		const ageMs = Date.now() - info.mtimeMs;
		if (ageMs > lockStaleMs) {
			await rm(lockDir, { recursive: true, force: true });
			return true;
		}
	} catch {}
	return false;
}

async function sleep(ms: number): Promise<void> {
	await new Promise(resolve => setTimeout(resolve, ms));
}

export async function withScalingLock<T>(
	teamName: string,
	cwd: string,
	lockStaleMs: number,
	deps: TeamPathDeps,
	fn: () => Promise<T>,
): Promise<T> {
	const lockDir = join(deps.teamDir(teamName, cwd), ".lock.scaling");
	const ownerPath = join(lockDir, "owner");
	const ownerToken = lockOwnerToken();
	const deadline = Date.now() + 10_000;
	await mkdir(dirname(lockDir), { recursive: true });
	while (true) {
		try {
			await mkdir(lockDir);
			try {
				await writeFile(ownerPath, ownerToken, "utf8");
			} catch (error) {
				await rm(lockDir, { recursive: true, force: true });
				throw error;
			}
			break;
		} catch (error) {
			const err = error as NodeJS.ErrnoException;
			if (err.code !== "EEXIST") throw error;
			if (await maybeRecoverStaleLock(lockDir, lockStaleMs)) continue;
			if (Date.now() > deadline) {
				throw new Error(`Timed out acquiring scaling lock for team ${teamName}`);
			}
			await sleep(50);
		}
	}

	try {
		return await fn();
	} finally {
		try {
			const currentOwner = await readFile(ownerPath, "utf8");
			if (currentOwner.trim() === ownerToken) {
				await rm(lockDir, { recursive: true, force: true });
			}
		} catch {}
	}
}

export async function withTeamLock<T>(
	teamName: string,
	cwd: string,
	lockStaleMs: number,
	deps: TeamPathDeps,
	fn: () => Promise<T>,
): Promise<T> {
	const lockDir = join(deps.teamDir(teamName, cwd), ".lock.create-task");
	const ownerPath = join(lockDir, "owner");
	const ownerToken = lockOwnerToken();
	const deadline = Date.now() + 5000;
	while (true) {
		try {
			await mkdir(lockDir);
			try {
				await writeFile(ownerPath, ownerToken, "utf8");
			} catch (error) {
				await rm(lockDir, { recursive: true, force: true });
				throw error;
			}
			break;
		} catch (error) {
			const err = error as NodeJS.ErrnoException;
			if (err.code !== "EEXIST") throw error;
			if (await maybeRecoverStaleLock(lockDir, lockStaleMs)) continue;
			if (Date.now() > deadline) {
				throw new Error(`Timed out acquiring team task lock for ${teamName}`);
			}
			await sleep(LOCK_OWNER_RETRY_MS);
		}
	}

	try {
		return await fn();
	} finally {
		try {
			const currentOwner = await readFile(ownerPath, "utf8");
			if (currentOwner.trim() === ownerToken) {
				await rm(lockDir, { recursive: true, force: true });
			}
		} catch {}
	}
}

export async function withTaskClaimLock<T>(
	teamName: string,
	taskId: string,
	cwd: string,
	lockStaleMs: number,
	deps: TeamPathDeps,
	fn: () => Promise<T>,
): Promise<{ ok: true; value: T } | { ok: false }> {
	const lockDir = deps.taskClaimLockDir(teamName, taskId, cwd);
	const ownerPath = join(lockDir, "owner");
	const ownerToken = lockOwnerToken();
	const deadline = Date.now() + 5000;
	while (true) {
		try {
			await mkdir(lockDir);
			break;
		} catch (error) {
			const err = error as NodeJS.ErrnoException;
			if (err.code !== "EEXIST") throw error;
			if (await maybeRecoverStaleLock(lockDir, lockStaleMs)) continue;
			if (Date.now() > deadline) return { ok: false };
			await sleep(LOCK_OWNER_RETRY_MS);
		}
	}

	try {
		try {
			await writeFile(ownerPath, ownerToken, "utf8");
		} catch (error) {
			await rm(lockDir, { recursive: true, force: true });
			throw error;
		}
		return { ok: true, value: await fn() };
	} finally {
		try {
			const currentOwner = await readFile(ownerPath, "utf8");
			if (currentOwner.trim() === ownerToken) {
				await rm(lockDir, { recursive: true, force: true });
			}
		} catch {}
	}
}

export async function withMailboxLock<T>(
	teamName: string,
	workerName: string,
	cwd: string,
	lockStaleMs: number,
	deps: TeamPathDeps,
	fn: () => Promise<T>,
): Promise<T> {
	const root = deps.teamDir(teamName, cwd);
	if (!existsSync(root)) {
		throw new Error(`Team ${teamName} not found`);
	}
	const lockDir = deps.mailboxLockDir(teamName, workerName, cwd);
	const ownerPath = join(lockDir, "owner");
	const ownerToken = lockOwnerToken();
	const deadline = Date.now() + 5000;
	await mkdir(dirname(lockDir), { recursive: true });
	while (true) {
		try {
			await mkdir(lockDir, { recursive: false });
			try {
				await writeFile(ownerPath, ownerToken, "utf8");
			} catch (error) {
				await rm(lockDir, { recursive: true, force: true });
				throw error;
			}
			break;
		} catch (error) {
			const err = error as NodeJS.ErrnoException;
			if (err.code !== "EEXIST") throw error;
			if (await maybeRecoverStaleLock(lockDir, lockStaleMs)) continue;
			if (Date.now() > deadline) {
				throw new Error(`Timed out acquiring mailbox lock for ${teamName}/${workerName}`);
			}
			await sleep(LOCK_OWNER_RETRY_MS);
		}
	}

	try {
		return await fn();
	} finally {
		try {
			const currentOwner = await readFile(ownerPath, "utf8");
			if (currentOwner.trim() === ownerToken) {
				await rm(lockDir, { recursive: true, force: true });
			}
		} catch {}
	}
}
