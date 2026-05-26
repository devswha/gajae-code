import { Command } from "@gajae-code/utils/cli";

export default class PendingGjcRuntimeCommand extends Command {
	static description = "Gajae Code runtime endpoint (implementation pending)";
	static examples: string[] = [];

	async run(): Promise<void> {
		process.stderr.write("This gjc runtime endpoint is not implemented in this migration slice yet.\n");
		process.exitCode = 1;
	}
}
