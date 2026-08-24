export type ContainerRow = {
  id: string;
  name: string;
  image: string;
  state: string;
  status: string;
  health: string;
  ports: string;
  composeProject: string | null;
  composeService: string | null;
  startedAt: number;
  cpu: string;
  cpuPercent: number | null;
  memory: string;
  memoryUsage: number | null;
};

export type ContainerStatusFilter = "all" | "running" | "degraded" | "unhealthy" | "exited";
export type ContainerTone = Exclude<ContainerStatusFilter, "all">;
export type ContainerGroup = {
  name: string;
  compose: boolean;
  rows: ContainerRow[];
  running: number;
};

export function formatContainerPorts(ports: Array<{ host_port: number; container_port: number; protocol: string }>): string;
export function formatBytes(value: number): string;
export function parseContainerRows(output: string): ContainerRow[];
export function filterContainers(rows: ContainerRow[], query: string): ContainerRow[];
export function filterContainersByStatus(rows: ContainerRow[], filter: ContainerStatusFilter): ContainerRow[];
export function groupContainers(rows: ContainerRow[]): ContainerGroup[];
export function statusTone(row: Pick<ContainerRow, "state" | "health">): ContainerTone;
export function statusLabel(row: Pick<ContainerRow, "state" | "health" | "status">): string;
export function shellKeyboardCommand(event: Pick<KeyboardEvent, "key" | "metaKey" | "ctrlKey">): "close-dialog" | "focus-search" | null;
export function daemonIsAvailable(snapshot: { containers?: { ok?: boolean }; images?: { ok?: boolean } } | null): boolean;
export function resourceTotals(rows: Array<Pick<ContainerRow, "cpuPercent" | "memoryUsage">>): { cpu: string | null; memory: string | null };
