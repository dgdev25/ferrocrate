import type { ContainerRow, ContainerGroup } from './forgeShell.mjs';
import type { VolumeSummary, NetworkSummary, DesktopAction } from './types';
export type WorkspaceGroup = ContainerGroup & { volumes: VolumeSummary[]; networks: NetworkSummary[] };
export function workspaceGroups(rows: ContainerRow[], volumes: VolumeSummary[], networks: NetworkSummary[], allRows?: ContainerRow[], filters?: { search?: string; status?: string }): WorkspaceGroup[];
type Actions = { busy: boolean; onAction(action: DesktopAction, label: string, target: string): void; onInspect(target: string, tab: 'logs' | 'terminal' | 'inspect'): void };
export function ServiceActions(props: Actions & { row: ContainerRow }): import('react').ReactElement;
export function WorkspaceCard(props: Actions & { group: WorkspaceGroup; selectedId?: string }): import('react').ReactElement;
