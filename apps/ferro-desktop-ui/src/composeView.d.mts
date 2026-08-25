import type { ComposeServiceSummary } from "./types";
import type { ChangeEventHandler, MouseEventHandler, ReactElement } from "react";

export function composeChooserMode(dialogAvailable: boolean): "native-dialog" | "host-path";
export function ComposeFileDialog(props: {
  open: boolean;
  value: string;
  busy: boolean;
  onChange: ChangeEventHandler<HTMLInputElement>;
  onSubmit: MouseEventHandler<HTMLButtonElement>;
  onCancel: MouseEventHandler<HTMLButtonElement>;
}): ReactElement | null;

export function composeStatusClass(status: string): string;
export function composeLogTarget(service: ComposeServiceSummary): string;
