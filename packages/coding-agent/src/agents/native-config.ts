export function composeRoleInstructionsForRole(
	roleName: string,
	promptContent: string,
	_resolvedModel?: string,
): string {
	const trimmed = promptContent.trim();
	return trimmed.length > 0 ? trimmed : `You are the ${roleName} worker.`;
}
