#!/usr/bin/env bun

import { chmodSync } from "node:fs";
import * as path from "node:path";

const packageDir = path.join(import.meta.dir, "..");
const outputPath = path.join(packageDir, "dist", "cli.js");
const shebang = "#!/usr/bin/env bun";

// Keep platform/native and lazy-loaded heavy modules out of the JS bundle:
// `@gajae-code/natives` resolves its platform `.node` relative to its own
// installed location (only correct when loaded from node_modules at runtime),
// and `mupdf` is a large WASM PDF engine loaded on demand.
// Also externalize the relative `../../natives/native/index.js` imports (used
// by cli/hashline/edit warmup probes) and any `.node` addon so the native
// loader runs from its installed location instead of being inlined here.
const externals = ["mupdf", "@gajae-code/natives", "*natives/native/index.js", "*.node"];

// Worker entrypoints. Unlike the compiled binary (which lists these as
// `--compile` additional entries), the JS bundle spawns them via
// `new Worker(new URL("./<name>.ts", import.meta.url))`. Bundled into
// `dist/cli.js`, every spawn site's `import.meta.url` is the bundle, so each
// URL resolves to `dist/<name>.ts`. We must emit a bundle at exactly that path.
const workers: { entry: string; outfile: string }[] = [
	{ entry: "../stats/src/sync-worker.ts", outfile: "dist/sync-worker.ts" },
	{ entry: "./src/tools/browser/tab-worker-entry.ts", outfile: "dist/tab-worker-entry.ts" },
	{ entry: "./src/eval/js/worker-entry.ts", outfile: "dist/worker-entry.ts" },
];

async function runCommand(command: string[], env: NodeJS.ProcessEnv = Bun.env): Promise<void> {
	const proc = Bun.spawn(command, {
		cwd: packageDir,
		env,
		stdout: "inherit",
		stderr: "inherit",
	});
	const exitCode = await proc.exited;
	if (exitCode !== 0) {
		throw new Error(`Command failed with exit code ${exitCode}: ${command.join(" ")}`);
	}
}

function buildArgs(entry: string, outfile: string): string[] {
	const args = ["bun", "build", entry, "--minify", "--keep-names", "--target=bun"];
	for (const external of externals) args.push("--external", external);
	args.push("--outfile", outfile);
	return args;
}

async function ensureShebang(): Promise<void> {
	const output = await Bun.file(outputPath).text();
	if (!output.startsWith(`${shebang}\n`)) {
		const withoutExistingShebang = output.startsWith("#!") ? output.replace(/^#!.*(?:\r?\n|$)/u, "") : output;
		await Bun.write(outputPath, `${shebang}\n${withoutExistingShebang}`);
	}
	// Mark the bin executable so it runs directly (matches how npm/bun set +x on
	// install) for the bundle install-smoke and any direct invocation.
	chmodSync(outputPath, 0o755);
}

async function main(): Promise<void> {
	await runCommand(["bun", "--cwd=../stats", "scripts/generate-client-bundle.ts", "--generate"]);
	try {
		await runCommand(buildArgs("./src/cli.ts", "dist/cli.js"));
		await ensureShebang();
		for (const worker of workers) {
			await runCommand(buildArgs(worker.entry, worker.outfile));
		}
	} finally {
		await runCommand(["bun", "--cwd=../stats", "scripts/generate-client-bundle.ts", "--reset"]);
	}
}

await main();
