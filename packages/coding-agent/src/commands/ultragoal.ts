import { Command } from "@gajae-code/utils/cli";

import { ultragoalCommand } from "../cli/ultragoal";

export default class Ultragoal extends Command {
	static description = "Run GJC Ultragoal workflow commands";
	static strict = false;
	static examples = ["$ gjc ultragoal status --json"];

	async run(): Promise<void> {
		await ultragoalCommand(this.argv);
	}
}
