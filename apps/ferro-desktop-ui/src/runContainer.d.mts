export type MappingRow = { source: string; target: string };
export type PortRow = { host: string; container: string };
export function buildRunContainerOptions(input: {
  command: string;
  ports: PortRow[];
  volumes: MappingRow[];
  memoryMb: string;
  cpus: string;
}): { command: string[]; ports: string[]; volumes: string[]; memory: number | null; cpuQuota: number | null; cpuPeriod: number | null };
