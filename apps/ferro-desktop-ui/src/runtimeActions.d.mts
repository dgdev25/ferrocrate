export function runtimeActionAvailability(state: {
  actionBusy: boolean;
  logsFollowing: boolean;
  terminalActive: boolean;
}): { allowed: boolean; reason: string | null };
