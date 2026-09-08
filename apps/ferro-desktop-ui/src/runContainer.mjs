export function parseCommandWords(command) {
  const words = [];
  let current = "";
  let quote = null;
  let escaped = false;
  let escapeQuote = null;
  let started = false;
  for (const character of command) {
    if (escaped) {
      if (escapeQuote === '"' && !['"', "\\", "$", "`", "\n"].includes(character)) {
        current += "\\";
      }
      if (character !== "\n") current += character;
      escaped = false;
      escapeQuote = null;
      started = true;
    } else if (character === "\\" && quote !== "'") {
      escaped = true;
      escapeQuote = quote;
      started = true;
    } else if (quote) {
      if (character === quote) quote = null;
      else current += character;
    } else if (character === "'" || character === '"') {
      quote = character;
      started = true;
    } else if (/\s/.test(character)) {
      if (started) {
        words.push(current);
        current = "";
        started = false;
      }
    } else {
      current += character;
      started = true;
    }
  }
  if (escaped) throw new Error("Command cannot end with an escape character");
  if (quote) throw new Error("Unterminated quote in command");
  if (started) words.push(current);
  return words;
}

export function buildRunContainerOptions({ command, ports, volumes, memoryMb, cpus }) {
  for (const row of ports) {
    if (!row.host.trim() && !row.container.trim()) continue;
    requestedHostPorts({ ports: [`${row.host.trim()}:${row.container.trim()}`] });
  }
  const memoryNumber = memoryMb.trim() ? Number(memoryMb) : null;
  const cpuNumber = cpus.trim() ? Number(cpus) : null;
  if (memoryNumber != null && (!Number.isFinite(memoryNumber) || memoryNumber <= 0)) throw new Error("Memory must be a positive number of MB");
  if (cpuNumber != null && (!Number.isFinite(cpuNumber) || cpuNumber <= 0)) throw new Error("CPUs must be a positive number");
  const cpuPeriod = cpuNumber == null ? null : 100000;
  return {
    command: parseCommandWords(command),
    ports: ports.filter((row) => row.host.trim() && row.container.trim()).map((row) => `${row.host.trim()}:${row.container.trim()}`),
    volumes: volumes.filter((row) => row.source.trim() && row.target.trim()).map((row) => `${row.source.trim()}:${row.target.trim()}`),
    memory: memoryNumber == null ? null : Math.round(memoryNumber * 1024 * 1024),
    cpuQuota: cpuNumber == null ? null : Math.round(cpuNumber * cpuPeriod),
    cpuPeriod,
  };
}

export function buildRunContainerInvokeArgs({ image, name, environment, pullIfMissing, ...fields }) {
  const options = buildRunContainerOptions(fields);
  return {
    image,
    name: name.trim() || null,
    command: options.command,
    ports: options.ports,
    volumes: options.volumes,
    pullIfMissing,
    environment: environment.split("\n").map((value) => value.trim()).filter(Boolean),
    memory: options.memory,
    cpuQuota: options.cpuQuota,
    cpuPeriod: options.cpuPeriod,
  };
}

export async function submitRunContainer({ invoke, payload, begin, onBegin, onResult, onError, onSuccess, finish }) {
  if (!begin()) return null;
  onBegin();
  try {
    const result = await invoke("run_new_container", payload);
    onResult(result);
    if (!result.ok) {
      onError(result.message || result.stderr || `Container run failed with status ${result.code}`);
      return result;
    }
    await onSuccess(result);
    return result;
  } catch (error) {
    onError(String(error));
    return null;
  } finally {
    finish();
  }
}

export const LAUNCHER_PRESETS = [
  { id: 'postgres', label: 'PostgreSQL', image: 'postgres:17-alpine', port: 5432, target: '/var/lib/postgresql/data' },
  { id: 'redis', label: 'Redis', image: 'redis:7-alpine', port: 6379, target: '/data' },
  { id: 'nginx', label: 'Nginx', image: 'nginx:alpine', port: 8080, containerPort: 80, target: '/usr/share/nginx/html' },
];

export async function applyLauncherPreset(id, invoke, suffix = crypto.randomUUID().slice(0, 8)) {
  const preset = LAUNCHER_PRESETS.find(preset => preset.id === id);
  if (!preset || !/^[a-zA-Z0-9-]+$/.test(suffix)) throw new Error('Invalid launcher preset');
  const probes = await invoke('preflight_container_ports', { ports: [preset.port] });
  const port = probes[0];
  if (!port || port.port !== preset.port || !Number.isInteger(port.suggested) || port.suggested < 1 || port.suggested > 65535) throw new Error('Runtime host did not return a valid port suggestion');
  const name = `ferro-${id}-${suffix}`;
  const password = crypto.randomUUID().replaceAll('-', '');
  return {
    image: preset.image, name, pullIfMissing: true,
    command: id === 'redis' ? `redis-server --appendonly yes --requirepass ${password}` : '',
    environment: id === 'postgres' ? `POSTGRES_PASSWORD=${password}` : '',
    ports: [{ host: String(port.suggested), container: String(preset.containerPort ?? preset.port) }],
    volumes: [{ source: `${name}-data`, target: preset.target }],
    memoryMb: '', cpus: '',
  };
}

export function requestedHostPorts(payload) {
  return payload.ports.map(mapping => {
    const parts = mapping.split(':');
    if (parts.length !== 2 || parts.some(part => !/^\d+$/.test(part) || Number(part) < 1 || Number(part) > 65535)) throw new Error('Port mappings require numeric host and container ports from 1 to 65535');
    return Number(parts[0]);
  });
}

// A probe is advisory; a competing process can bind before the runtime starts.
// Recover the current conflict for review without retrying or removing anything.
export async function recoverPortConflict(message, payload, invoke) {
  if (!/address already in use|eaddrinuse|port\b.{0,80}(?:in use|allocated)|bind\b.{0,60}(?:in use|allocated)/i.test(message)) return null;
  try {
    const ports = requestedHostPorts(payload);
    const probes = await invoke('preflight_container_ports', { ports });
    if (probes.length !== ports.length || probes.some((probe, index) => probe.port !== ports[index])) return null;
    return probes.find(probe => !probe.available) ?? null;
  } catch {
    return null;
  }
}
