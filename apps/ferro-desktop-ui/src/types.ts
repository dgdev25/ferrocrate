export type CommandResult = {
  ok: boolean;
  code: number;
  stdout: string;
  stderr: string;
  message: string;
};

export type DesktopSnapshot = {
  daemon: {
    state: "starting" | "running" | "stopping" | "stopped" | "failed" | "unavailable";
    healthy: boolean;
    socket_path: string;
    reason: string | null;
    platform: "linux-native" | "desktop-vm";
    custom_networks: boolean;
  };
  runtime: CommandResult;
  containers: CommandResult;
  images: CommandResult;
};

export type ContainerStatsSample = {
  id: string;
  available: boolean;
  cpu_percent: number | null;
  memory_usage: number | null;
  memory_limit: number | null;
};

export type ContainerStatsResponse = {
  samples: ContainerStatsSample[];
};

export type DesktopAction =
  | "vm_start"
  | "vm_stop"
  | "pull_image"
  | "remove_image"
  | "start_container"
  | "stop_container"
  | "remove_container"
  | "container_prune"
  | "image_prune";

export type VolumeAction = "create" | "remove" | "prune";

export type VolumeMountUsage = {
  container_id: string;
  container_name: string;
  destination: string;
  read_write: boolean;
};

export type VolumeSummary = {
  name: string;
  driver: string;
  mountpoint: string;
  created_at: string;
  mounts: VolumeMountUsage[];
};

export type NetworkAction = "create" | "remove";

export type NetworkContainerAttachment = {
  container_id: string;
  name: string;
  ipv4_address: string;
  ipv6_address: string;
  ports: string[];
};

export type NetworkSummary = {
  name: string;
  driver: string;
  subnets: string[];
  containers: NetworkContainerAttachment[];
};

export type ContainerMountSummary = {
  kind: string;
  source: string;
  destination: string;
  access: "ro" | "rw";
};

export type ContainerHealthLogSummary = {
  start: string;
  end: string;
  exit_code: number;
  output: string;
};

export type ContainerHealthSummary = {
  status: string;
  failing_streak: number;
  log: ContainerHealthLogSummary[];
};

export type ContainerDetailSummary = {
  id: string;
  name: string;
  image: string;
  status: string;
  command: string[];
  environment: string[];
  working_dir: string;
  user: string;
  mounts: ContainerMountSummary[];
  health: ContainerHealthSummary | null;
  resources: {
    memory: number;
    cpu_quota: number;
    cpu_period: number;
  };
  restart_policy: {
    name: string;
    maximum_retry_count: number;
  };
};

export type RegistryAuthStatus = {
  registry: string;
  logged_in: boolean;
  username: string | null;
};

export type ComposeAction = "up" | "down" | "stop" | "start";

export type ComposeServiceSummary = {
  name: string;
  status: string;
  container_id: string | null;
};

export type ComposeSnapshot = {
  config: string;
  services: ComposeServiceSummary[];
};

export type BuildProgressFrame = {
  build_id: string;
  stream: "stdout" | "stderr";
  text: string;
};

export type PaidBackendConfig = {
  release_base_url: string;
  token_endpoint: string;
  issuance_endpoint?: string | null;
};

export type SessionSummary = {
  token_present: boolean;
  subject: string | null;
  plan: string | null;
  expires_at: number | null;
  expired: boolean | null;
};

export type EntitlementSummary = {
  status: string;
  plan: string | null;
  subject: string | null;
  expires_at: number | null;
  features: string[];
  message: string | null;
};

export type PaidAuthState = {
  config: PaidBackendConfig | null;
  session: SessionSummary;
  entitlement: EntitlementSummary | null;
};

export type InstallerRunSummary = {
  dry_run: boolean;
  ok: boolean;
  command: string;
  result: CommandResult | null;
};

export type DoctorAction = {
  id: string;
  description: string;
  command: string | null;
  requires_confirmation: boolean;
};

export type DoctorCheck = {
  id: string;
  ok: boolean;
  message: string;
  hint: string | null;
  remediated: boolean;
};

export type DesktopBackendCapabilities = {
  terminal: boolean;
  registry: boolean;
  containers: boolean;
  networks: boolean;
  volumes: boolean;
  custom_networks: boolean;
  streaming_exec: boolean;
};

export type DesktopBackendStatus = {
  backend: string;
  platform: string;
  state: "stopped" | "starting" | "running" | "stopping" | "failed" | "unavailable";
  healthy: boolean;
  endpoint: string;
  reason: string | null;
  capabilities: DesktopBackendCapabilities;
};

export type DoctorPayload = {
  healthy: boolean;
  fix: boolean;
  bootstrap: boolean;
  dry_run: boolean;
  confirmed: boolean;
  actions: DoctorAction[];
  checks: DoctorCheck[];
  desktop_backend?: DesktopBackendStatus;
};

export type DoctorSummary = {
  ok: boolean;
  raw: DoctorPayload;
};
