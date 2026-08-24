import type { ChangeEventHandler, MouseEventHandler, ReactElement } from "react";

export type ResourceSection = "containers" | "images" | "volumes" | "networks" | "compose";
export type ResourceDialog = "volume" | "network" | null;
export type ResourceDialogCommand = "open-volume" | "open-network" | "close-dialog" | "focus-search" | null;

export function resourcePageState(section: ResourceSection, itemCount: number): {
  content: "empty" | "table";
  primaryAction: string | null;
};
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
export function failurePresentation(error: unknown): {
  kind: "daemon" | "license" | "generic";
  message: string;
  detail: string;
};
export function ActionErrorNotice(props: {
  error?: unknown;
  onDismiss?: MouseEventHandler<HTMLButtonElement>;
  onStart?: MouseEventHandler<HTMLButtonElement>;
  onReviewLicensing?: MouseEventHandler<HTMLButtonElement>;
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
}): ReactElement | null;
