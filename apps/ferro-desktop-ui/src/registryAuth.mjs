export function registryStatusText(status) {
  return status.logged_in
    ? `Signed in to ${status.registry} as ${status.username || "stored user"}`
    : `Not signed in to ${status.registry}`;
}
