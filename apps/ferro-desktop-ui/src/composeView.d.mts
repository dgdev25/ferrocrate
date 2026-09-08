import type { ComposeServiceSummary } from "./types";
import type { ChangeEventHandler, MouseEventHandler, ReactElement } from "react";

export function composeChooserMode(dialogAvailable: boolean): "native-dialog" | "host-path";
export function ComposeFileDialog(props: {
  open: boolean;
  value: string;
  busy: boolean;
  error?: string | null;
  onChange: ChangeEventHandler<HTMLInputElement>;
  onSubmit: MouseEventHandler<HTMLButtonElement>;
  onCancel: MouseEventHandler<HTMLButtonElement>;
}): ReactElement | null;

export function ComposeServiceLogsButton(props: {
  service: ComposeServiceSummary;
  busy?: boolean;
  onLogs: (service: ComposeServiceSummary) => void;
}): ReactElement;

export function composeStatusClass(status: string): string;
export function composeLogTarget(service: ComposeServiceSummary): string;
