import type { ReactElement, Ref } from "react";
import type { DoctorSummary, InstallerRunSummary, PaidAuthState } from "./types";

export function completeDoctorRun(options: {
  execute: () => Promise<DoctorSummary>;
  refresh: () => Promise<void>;
  setResult: (result: DoctorSummary) => void;
  setError: (error: string) => void;
  close: () => void;
  scheduleResultsFocus: () => void;
  finish: () => void;
}): Promise<void>;

export function DoctorPage(props: {
  result: DoctorSummary | null;
  busy?: boolean;
  resultsTableRef?: Ref<HTMLTableElement>;
  onRun: () => void;
  onStart?: () => void;
  onStop?: () => void;
}): ReactElement;

export function SettingsPage(props: {
  authState: PaidAuthState | null;
  installerResult: InstallerRunSummary | null;
  nativeLinux?: boolean;
  daemonStatus?: { state: string };
  onOpenAccount?: () => void;
  onOpenInstall?: () => void;
}): ReactElement;
