import { Command } from "@gajae-code/utils/cli";

import { teamCommand } from "../cli/team";

export default class Team extends Command {
	static description = "Run native GJC tmux team orchestration commands";
	static strict = false;

	async run(): Promise<void> {
		await teamCommand(this.argv);
	}
}
