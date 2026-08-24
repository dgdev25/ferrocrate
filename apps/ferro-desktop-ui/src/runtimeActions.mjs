export function runtimeActionAvailability({ actionBusy }) {
  return actionBusy
    ? { allowed: false, reason: "Another runtime action is still in progress." }
    : { allowed: true, reason: null };
}
