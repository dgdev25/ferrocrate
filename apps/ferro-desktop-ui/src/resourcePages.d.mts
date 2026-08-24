import type { ChangeEventHandler, MouseEventHandler, ReactElement } from "react";

export type ResourceSection = "containers" | "images" | "volumes" | "networks" | "compose";
export type ResourceDialog = "volume" | "network" | null;
export type ResourceDialogCommand = "open-volume" | "open-network" | "close-dialog" | "focus-search" | null;

export function resourcePageState(section: ResourceSection, itemCount: number, options?: { loaded?: boolean }): {
  content: "empty" | "table";
  primaryAction: string | null;
};
export function containerContentState(totalCount: number, visibleCount: number, query: string): "empty" | "filtered-empty" | "table";
export function filterNamedResources<T>(rows: T[], query: string, getName?: (row: T) => string): T[];
export function runtimeSurfaceState(snapshot: { containers?: { ok?: boolean; stderr?: string }; images?: { ok?: boolean; stderr?: string } } | null, activeSection: string): "loading" | "first-run" | "resource";
export function snapshotFailureDetail(snapshot: { containers?: { ok?: boolean; code?: number; stderr?: string }; images?: { ok?: boolean; code?: number; stderr?: string } } | null): string | null;
export function applyRuntimeSurfaceTransition(surface: string, callbacks: Record<string, (() => void) | undefined>): boolean;
export function runFirstRunRecovery(options: {
  start: () => Promise<{ ok: boolean; code: number; stdout: string; stderr: string }>;
  refreshSnapshot?: () => Promise<void>;
  refreshVolumes?: () => Promise<void>;
  refreshNetworks?: () => Promise<void>;
  refreshCompose?: () => Promise<void>;
}): Promise<{ ok: boolean; code: number; stdout: string; stderr: string }>;
export function nextResourceDialog(current: ResourceDialog, command: ResourceDialogCommand): ResourceDialog;
export function shouldShowFirstRun(
  snapshot: { containers?: { ok?: boolean }; images?: { ok?: boolean } } | null,
  activeSection: string,
): boolean;
export function ResourceEmptyState(props: {
  section: ResourceSection;
  disabled?: boolean;
  onAction?: MouseEventHandler<HTMLButtonElement>;
}): ReactElement | null;
export function failurePresentation(error: unknown, messages?: Partial<Record<"daemon" | "license" | "generic", string>>): {
  kind: "daemon" | "license" | "binary" | "generic";
  message: string;
  detail: string;
};
export function ActionErrorNotice(props: {
  error?: unknown;
  humanMessage?: string;
  technicalDetail?: string;
  onDismiss?: () => void;
  onStart?: () => void;
  onReviewLicensing?: (detail: string) => void;
  onDoctor?: () => void;
}): ReactElement | null;
export function FirstRunState(props: {
  busy?: boolean;
  error?: unknown;
  onStart?: MouseEventHandler<HTMLButtonElement>;
  onDoctor?: MouseEventHandler<HTMLButtonElement>;
}): ReactElement;
export function ResourceCreateDialog(props: {
  kind: ResourceDialog;
  name: string;
  subnet?: string;
  busy?: boolean;
  error?: unknown;
  onNameChange?: ChangeEventHandler<HTMLInputElement>;
  onSubnetChange?: ChangeEventHandler<HTMLInputElement>;
  onCancel?: MouseEventHandler<HTMLButtonElement>;
  onCreate?: MouseEventHandler<HTMLButtonElement>;
  onStart?: () => void;
  onReviewLicensing?: (detail: string) => void;
}): ReactElement | null;
export function RuntimeLoadingState(): ReactElement;
export function LicensingDialog(props: {
  open: boolean;
  detail: string;
  onClose: () => void;
  onOpenSettings: () => void;
}): ReactElement | null;
