export type MappingRow = { source: string; target: string };
export type PortRow = { host: string; container: string };
export function parseCommandWords(command: string): string[];
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
export function submitRunContainer<Result extends { ok: boolean; code: number; message?: string; stderr: string }>(options: {
  invoke: (command: "run_new_container", payload: ReturnType<typeof buildRunContainerInvokeArgs>) => Promise<Result>;
  payload: ReturnType<typeof buildRunContainerInvokeArgs>;
  begin: () => boolean;
  onBegin: () => void;
  onResult: (result: Result) => void;
  onError: (message: string) => void;
  onSuccess: (result: Result) => void | Promise<void>;
  finish: () => void;
}): Promise<Result | null>;

export const LAUNCHER_PRESETS: Array<{ id: string; label: string; image: string; port: number; containerPort?: number; target: string }>;
export function applyLauncherPreset(id: string, invoke: (command: string, args: { ports: number[] }) => Promise<import('./types').LaunchPort[]>, suffix?: string): Promise<import('./dialogForms.mjs').RunContainerDraft>;
export function requestedHostPorts(payload: { ports: string[] }): number[];
export function recoverPortConflict(message: string, payload: { ports: string[] }, invoke: (command: string, args: { ports: number[] }) => Promise<import('./types').LaunchPort[]>): Promise<import('./types').LaunchPort | null>;
