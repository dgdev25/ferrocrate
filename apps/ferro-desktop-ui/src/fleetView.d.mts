export type FleetRole = "view" | "operate";
export type FleetSection = "hosts" | "containers" | "deploys" | "health";
export const FLEET_SECTIONS: FleetSection[];
export function canOperateFleet(role: string | null): boolean;
export function chooseRunHost(currentHost: string, hosts: Array<{ node_id?: string; connected?: boolean; enrollment_state?: string }>): string;
export function shouldShowFleetRefreshError(role: FleetRole | null): boolean;
export function isFleetSessionExpired(error: unknown): boolean;
export function normalizeFleetSnapshot(value: unknown): {
  cluster_epoch: number;
  hosts: unknown[];
  deploys: unknown[];
};
export function fleetHostState(host: Record<string, unknown>): "online" | "degraded" | "offline" | "revoked";
export function fleetContainerRows(hosts: Record<string, unknown>[]): Array<{
  hostId: string;
  id: string;
  name: string;
  image: string;
  status: string;
}>;
