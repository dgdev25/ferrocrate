import type { ReactElement } from "react";
import type { DoctorSummary, InstallerRunSummary, PaidAuthState } from "./types";

export function DoctorPage(props: {
  result: DoctorSummary | null;
  busy?: boolean;
  onRun: () => void;
  onStart?: () => void;
  onStop?: () => void;
}): ReactElement;

export function SettingsPage(props: {
  authState: PaidAuthState | null;
  installerResult: InstallerRunSummary | null;
  onOpenAccount: () => void;
  onOpenInstall: () => void;
}): ReactElement;
