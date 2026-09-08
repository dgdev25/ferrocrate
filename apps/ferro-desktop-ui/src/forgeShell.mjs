export function formatContainerPorts(ports) {
  if (!Array.isArray(ports) || ports.length === 0) return "—";
  return ports
    .map((port) => {
      const host = port.PublicPort ?? port.host_port;
      const container = port.PrivatePort ?? port.container_port;
      const protocol = port.Type ?? port.protocol ?? "tcp";
      return host == null ? `${container}/${protocol}` : `${host}→${container}/${protocol}`;
    })
    .join(", ");
}

function dockerStatus(record, state) {
  const detail = String(record.Status ?? record.status ?? "");
  const exitCode = record.last_exit_code ?? detail.match(/Exited \((-?\d+)\)/i)?.[1];
  if (state === "running") return "Running";
  if (state === "exited" && exitCode != null) return `Exited (${exitCode})`;
  return state.charAt(0).toUpperCase() + state.slice(1);
}

function dockerHealth(record) {
  const explicit = record.health_status;
  if (explicit) return String(explicit).toLowerCase();
  const detail = String(record.Status ?? "");
  return detail.match(/\((healthy|unhealthy|starting)\)/i)?.[1]?.toLowerCase() || "none";
}

export function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let scaled = bytes;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${scaled.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function parseContainerRows(output) {
  try {
    const records = JSON.parse(output || "[]");
    if (!Array.isArray(records)) return [];
    return records.map((record) => {
      const state = String(record.State ?? record.status ?? "unknown").toLowerCase();
      const status = dockerStatus(record, state);
      const cpuPercent = Number.isFinite(Number(record.cpu_percent))
        ? Number(record.cpu_percent)
        : null;
      const memoryUsage = record.memory_usage == null || !Number.isFinite(Number(record.memory_usage))
        ? null
        : Number(record.memory_usage);
      return {
        id: String(record.Id ?? record.id ?? ""),
        name: String(record.Names?.[0]?.replace(/^\//, "") || record.name || record.Id || record.id || "unnamed"),
        image: String(record.Image ?? record.image ?? "—"),
        state,
        status,
        health: dockerHealth(record),
        ports: formatContainerPorts(record.Ports ?? record.ports),
        composeProject: (record.Labels ?? record.labels)?.["com.docker.compose.project"] || null,
        composeService: (record.Labels ?? record.labels)?.["com.docker.compose.service"] || null,
        startedAt: Number(record.Created ?? record.started_at_unix ?? record.created_at_unix ?? 0),
        cpu: cpuPercent == null ? (state === "running" ? "" : "—") : `${cpuPercent.toFixed(1)}%`,
        cpuPercent,
        memory: memoryUsage == null ? (state === "running" ? "" : "—") : formatBytes(memoryUsage),
        memoryUsage,
        memoryLimit: null,
        statsAvailable: null,
      };
    });
  } catch {
    return [];
  }
}

export function parseContainerStats(response) {
  if (!response || !Array.isArray(response.samples)) return [];
  return response.samples.map((sample) => {
    const cpuPercent = sample.cpu_percent != null && Number.isFinite(Number(sample.cpu_percent)) ? Number(sample.cpu_percent) : null;
    const memoryUsage = sample.memory_usage != null && Number.isFinite(Number(sample.memory_usage)) ? Number(sample.memory_usage) : null;
    return {
      id: String(sample.id || ""),
      available: sample.available === true && cpuPercent != null && memoryUsage != null,
      cpuPercent,
      memoryUsage,
      memoryLimit: sample.memory_limit != null && Number.isFinite(Number(sample.memory_limit)) ? Number(sample.memory_limit) : null,
    };
  });
}

export function mergeContainerStats(rows, samples) {
  const byId = new Map(samples.map((sample) => [sample.id, sample]));
  return rows.map((row) => {
    const sample = byId.get(row.id);
    if (!sample) return row;
    if (!sample.available) {
      return { ...row, statsAvailable: false, cpu: "", cpuPercent: null, memory: "", memoryUsage: null, memoryLimit: null };
    }
    const memory = sample.memoryUsage == null
      ? ""
      : `${formatBytes(sample.memoryUsage)} / ${sample.memoryLimit == null ? "Unlimited" : formatBytes(sample.memoryLimit)}`;
    return {
      ...row,
      statsAvailable: true,
      cpu: sample.cpuPercent == null ? "" : `${sample.cpuPercent.toFixed(1)}%`,
      cpuPercent: sample.cpuPercent,
      memory,
      memoryUsage: sample.memoryUsage,
      memoryLimit: sample.memoryLimit,
    };
  });
}

export function shouldPollContainerStats(activeSection, visibilityState) {
  return activeSection === "containers" && visibilityState === "visible";
}

export function beginContainerStatsPoll(owner, activeSection, visibilityState) {
  if (owner.inFlight || !shouldPollContainerStats(activeSection, visibilityState)) return false;
  owner.inFlight = true;
  return true;
}

export function containerStatsUnavailableMessage() {
  return "Live resource stats unavailable for one or more running containers.";
}

export function resourceTotals(rows) {
  const cpuValues = rows.map((row) => row.cpuPercent).filter(Number.isFinite);
  const memoryRows = rows.filter((row) => Number.isFinite(row.memoryUsage));
  const memoryValues = memoryRows.map((row) => row.memoryUsage);
  const allMemoryLimitsFinite = memoryRows.length > 0 && memoryRows.every((row) => Number.isFinite(row.memoryLimit));
  const memoryLimits = memoryRows.map((row) => row.memoryLimit).filter(Number.isFinite);
  return {
    cpu: cpuValues.length
      ? `${cpuValues.reduce((total, value) => total + value, 0).toFixed(1)}%`
      : null,
    memory: memoryValues.length
      ? `${formatBytes(memoryValues.reduce((total, value) => total + value, 0))}${allMemoryLimitsFinite ? ` / ${formatBytes(memoryLimits.reduce((total, value) => total + value, 0))}` : " / Unlimited"}`
      : null,
  };
}

export function resourceTotalsForSurface(rows, activeSection, visibilityState) {
  return shouldPollContainerStats(activeSection, visibilityState)
    ? resourceTotals(rows)
    : { cpu: null, memory: null };
}

export function filterContainers(rows, query) {
  const needle = query.trim().toLowerCase();
  if (!needle) return rows;
  return rows.filter((row) => (
    `${row.composeProject || ""} ${row.composeService || ""} ${row.name} ${row.image} ${row.status} ${row.ports}`.toLowerCase().includes(needle)
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

export function tabKeyboardTarget(tabs, current, key) {
  const index = tabs.indexOf(current);
  if (index < 0 || !tabs.length) return null;
  if (key === "Home") return tabs[0];
  if (key === "End") return tabs[tabs.length - 1];
  if (key === "ArrowRight") return tabs[(index + 1) % tabs.length];
  if (key === "ArrowLeft") return tabs[(index - 1 + tabs.length) % tabs.length];
  return null;
}

export function daemonIsAvailable(snapshot) {
  if (snapshot?.daemon) return snapshot.daemon.state === "running";
  return snapshot?.containers?.ok === true && snapshot?.images?.ok === true;
}

export function daemonStatusPresentation(status) {
  const state = status?.state || "stopped";
  const labels = {
    starting: "daemon starting",
    running: "daemon running",
    stopped: "daemon stopped",
    failed: "daemon failed",
  };
  const titles = {
    starting: "Ferrocrate API daemon is starting",
    running: status?.socket_path ? `Ferrocrate API daemon at ${status.socket_path}` : "Ferrocrate API daemon is running",
    stopped: status?.reason || "Ferrocrate API daemon is stopped",
    failed: status?.reason || "Ferrocrate API daemon failed",
  };
  return { label: labels[state] || labels.stopped, tone: state, title: titles[state] || titles.stopped };
}

export function containerRemoveAvailability(row) {
  return row?.state === "running"
    ? { allowed: false, reason: "Stop this container before removing it." }
    : { allowed: true, reason: null };
}
