export function composeStatusClass(status) {
  if (status === "running") return "status-running";
  if (status === "paused") return "status-paused";
  return "status-stopped";
}

export function composeLogTarget(service) {
  return service.container_id || service.name;
}
