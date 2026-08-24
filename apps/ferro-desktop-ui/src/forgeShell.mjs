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
        composeProject: record.labels?.["com.docker.compose.project"] || null,
        composeService: record.labels?.["com.docker.compose.service"] || null,
        startedAt: Number(record.started_at_unix || record.created_at_unix || 0),
        cpu: Number.isFinite(Number(record.cpu_percent))
          ? `${Number(record.cpu_percent).toFixed(1)}%`
          : "—",
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
  if (row.state === "running" && row.health !== "none" && row.health !== "healthy") return "degraded";
  return row.state === "running" ? "running" : "exited";
}

export function statusLabel(row) {
  const tone = statusTone(row);
  if (tone === "unhealthy") return "Unhealthy";
  if (tone === "degraded") return "Degraded";
  return row.status;
}

export function filterContainersByStatus(rows, filter) {
  if (filter === "all") return rows;
  return rows.filter((row) => statusTone(row) === filter);
}

export function groupContainers(rows) {
  const projects = new Map();
  const standalone = [];
  for (const row of rows) {
    if (!row.composeProject) {
      standalone.push(row);
      continue;
    }
    const project = projects.get(row.composeProject) || [];
    project.push(row);
    projects.set(row.composeProject, project);
  }
  const groups = [...projects.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, projectRows]) => ({
      name,
      compose: true,
      rows: projectRows,
      running: projectRows.filter((row) => row.state === "running").length,
    }));
  if (standalone.length) {
    groups.push({
      name: "Standalone",
      compose: false,
      rows: standalone,
      running: standalone.filter((row) => row.state === "running").length,
    });
  }
  return groups;
}

export function shellKeyboardCommand(event) {
  if (event.key === "Escape") return "close-dialog";
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") return "focus-search";
  return null;
}

export function daemonIsAvailable(snapshot) {
  return snapshot?.containers?.ok === true && snapshot?.images?.ok === true;
}
