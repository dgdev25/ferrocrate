export function buildRunContainerOptions({ command, ports, volumes, memoryMb, cpus }) {
  const memoryNumber = memoryMb.trim() ? Number(memoryMb) : null;
  const cpuNumber = cpus.trim() ? Number(cpus) : null;
  if (memoryNumber != null && (!Number.isFinite(memoryNumber) || memoryNumber <= 0)) throw new Error("Memory must be a positive number of MB");
  if (cpuNumber != null && (!Number.isFinite(cpuNumber) || cpuNumber <= 0)) throw new Error("CPUs must be a positive number");
  const cpuPeriod = cpuNumber == null ? null : 100000;
  return {
    command: command.trim() ? command.trim().split(/\s+/) : [],
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
