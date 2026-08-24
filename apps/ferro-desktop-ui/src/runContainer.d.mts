export type MappingRow = { source: string; target: string };
export type PortRow = { host: string; container: string };
export function buildRunContainerOptions(input: {
  command: string;
  ports: PortRow[];
  volumes: MappingRow[];
  memoryMb: string;
  cpus: string;
}): { command: string[]; ports: string[]; volumes: string[]; memory: number | null; cpuQuota: number | null; cpuPeriod: number | null };
export function buildRunContainerInvokeArgs(input: {
  image: string;
  name: string;
  command: string;
  ports: PortRow[];
  volumes: MappingRow[];
  environment: string;
  pullIfMissing: boolean;
  memoryMb: string;
  cpus: string;
}): {
  image: string;
  name: string | null;
  command: string[];
  ports: string[];
  volumes: string[];
  pullIfMissing: boolean;
  environment: string[];
  memory: number | null;
  cpuQuota: number | null;
  cpuPeriod: number | null;
};
