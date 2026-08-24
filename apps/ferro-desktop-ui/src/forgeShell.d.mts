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
  memoryLimit: number | null;
  statsAvailable: boolean | null;
};

export type ContainerStatsSample = {
  id: string;
  available: boolean;
  cpuPercent: number | null;
  memoryUsage: number | null;
  memoryLimit: number | null;
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
export function parseContainerStats(response: unknown): ContainerStatsSample[];
export function mergeContainerStats(rows: ContainerRow[], samples: ContainerStatsSample[]): ContainerRow[];
export function shouldPollContainerStats(activeSection: string, visibilityState: DocumentVisibilityState): boolean;
export function beginContainerStatsPoll(owner: { inFlight: boolean }, activeSection: string, visibilityState: DocumentVisibilityState): boolean;
export function containerStatsUnavailableMessage(): string;
export function filterContainers(rows: ContainerRow[], query: string): ContainerRow[];
export function filterContainersByStatus(rows: ContainerRow[], filter: ContainerStatusFilter): ContainerRow[];
export function groupContainers(rows: ContainerRow[]): ContainerGroup[];
export function statusTone(row: Pick<ContainerRow, "state" | "health">): ContainerTone;
export function statusLabel(row: Pick<ContainerRow, "state" | "health" | "status">): string;
export function shellKeyboardCommand(event: Pick<KeyboardEvent, "key" | "metaKey" | "ctrlKey">): "close-dialog" | "focus-search" | null;
export function daemonIsAvailable(snapshot: { daemon?: { state: string }; containers?: { ok?: boolean }; images?: { ok?: boolean } } | null): boolean;
export function daemonStatusPresentation(status?: { state: string; reason?: string | null; socket_path?: string }): { label: string; tone: string; title: string };
export function containerRemoveAvailability(row: { state: string }): { allowed: boolean; reason: string | null };
export function resourceTotals(rows: Array<Pick<ContainerRow, "cpuPercent" | "memoryUsage" | "memoryLimit">>): { cpu: string | null; memory: string | null };
export function resourceTotalsForSurface(rows: Array<Pick<ContainerRow, "cpuPercent" | "memoryUsage" | "memoryLimit">>, activeSection: string, visibilityState: DocumentVisibilityState): { cpu: string | null; memory: string | null };
