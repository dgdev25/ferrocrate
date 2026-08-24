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
