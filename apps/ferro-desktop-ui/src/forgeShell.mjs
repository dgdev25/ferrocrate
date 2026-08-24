export function formatContainerPorts(ports) {
  if (!Array.isArray(ports) || ports.length === 0) return "—";
  return ports
    .map((port) => `${port.host_port}→${port.container_port}/${port.protocol || "tcp"}`)
    .join(", ");
}

export function parseContainerRows(output) {
  try {
    const records = JSON.parse(output || "[]");
    if (!Array.isArray(records)) return [];
    return records.map((record) => {
      const state = String(record.status || "unknown").toLowerCase();
      const exitCode = record.last_exit_code;
      const status = state === "running"
        ? "Running"
        : state === "exited" && exitCode != null
          ? `Exited (${exitCode})`
          : state.charAt(0).toUpperCase() + state.slice(1);
      return {
        id: String(record.id || ""),
        name: String(record.name || record.id || "unnamed"),
        image: String(record.image || "—"),
        state,
        status,
        health: String(record.health_status || "none").toLowerCase(),
        ports: formatContainerPorts(record.ports),
      };
    });
  } catch {
    return [];
  }
}

export function filterContainers(rows, query) {
  const needle = query.trim().toLowerCase();
  if (!needle) return rows;
  return rows.filter((row) => (
    `${row.name} ${row.image} ${row.status} ${row.ports}`.toLowerCase().includes(needle)
  ));
}

export function statusTone(row) {
  if (row.health === "unhealthy") return "unhealthy";
  return row.state === "running" ? "running" : "stopped";
}

export function shellKeyboardCommand(event) {
  if (event.key === "Escape") return "close-dialog";
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") return "focus-search";
  return null;
}

export function daemonIsAvailable(snapshot) {
  return snapshot?.containers?.ok === true && snapshot?.images?.ok === true;
}
