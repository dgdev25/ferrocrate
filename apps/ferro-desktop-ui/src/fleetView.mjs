export const FLEET_SECTIONS = ["hosts", "containers", "deploys", "health"];

export function canOperateFleet(role) {
  return role === "operate";
}

export function chooseRunHost(currentHost, hosts) {
  return currentHost || hosts.find((host) => host?.connected)?.node_id || "";
}

export function shouldShowFleetRefreshError(role) {
  return role === "view" || role === "operate";
}

export function normalizeFleetSnapshot(value) {
  if (!value || typeof value !== "object") {
    return { cluster_epoch: 0, hosts: [], deploys: [] };
  }
  return {
    cluster_epoch: Number.isFinite(value.cluster_epoch) ? value.cluster_epoch : 0,
    hosts: Array.isArray(value.hosts) ? value.hosts : [],
    deploys: Array.isArray(value.deploys) ? value.deploys : [],
  };
}

export function fleetHostState(host) {
  if (host?.enrollment_state === "revoked") return "revoked";
  if (host?.connected) return host.health === "healthy" ? "online" : "degraded";
  return "offline";
}

export function fleetContainerRows(hosts) {
  return hosts.flatMap((host) => {
    const containers = Array.isArray(host?.containers) ? host.containers : [];
    return containers.map((container) => {
      const rawName = container.name ?? container.Name ?? container.Names?.[0] ?? "unnamed";
      return {
        hostId: String(host.node_id ?? "unknown"),
        id: String(container.id ?? container.Id ?? container.ID ?? "unknown"),
        name: String(rawName).replace(/^\//, ""),
        image: String(container.image ?? container.Image ?? "unknown"),
        status: String(container.status ?? container.Status ?? container.state ?? container.State ?? "unknown"),
      };
    });
  });
}
