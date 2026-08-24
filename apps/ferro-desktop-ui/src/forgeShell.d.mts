export type ContainerRow = {
  id: string;
  name: string;
  image: string;
  state: string;
  status: string;
  health: string;
  ports: string;
};

export function formatContainerPorts(ports: Array<{ host_port: number; container_port: number; protocol: string }>): string;
export function parseContainerRows(output: string): ContainerRow[];
export function filterContainers(rows: ContainerRow[], query: string): ContainerRow[];
export function statusTone(row: Pick<ContainerRow, "state" | "health">): "running" | "unhealthy" | "stopped";
export function shellKeyboardCommand(event: Pick<KeyboardEvent, "key" | "metaKey" | "ctrlKey">): "close-dialog" | "focus-search" | null;
export function daemonIsAvailable(snapshot: { containers?: { ok?: boolean }; images?: { ok?: boolean } } | null): boolean;
