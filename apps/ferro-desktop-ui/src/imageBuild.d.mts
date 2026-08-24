export function buildStepText(text: string): string;
export function formatBuildDuration(durationMs: number | null): string;
export function buildFailurePresentation(error: unknown): {
  kind: "daemon" | "license" | "binary" | "generic";
  message: string;
  detail: string;
};

export type BuildHistoryEntry = {
  id: string;
  image: string;
  status: "building" | "succeeded" | "failed";
  durationMs: number | null;
  progress: Array<{ build_id: string; stream: "stdout" | "stderr"; text: string }>;
  error?: string;
};

export type BuildProgressFrame = BuildHistoryEntry["progress"][number];

export function appendBuildProgress(
  history: BuildHistoryEntry[],
  frame: BuildProgressFrame,
): BuildHistoryEntry[];

export function buildInvokeArgs(context: string, tag: string, buildId: string): {
  context: string;
  tag: string;
  buildId: string;
};

export function BuildHistoryList(props: {
  builds: BuildHistoryEntry[];
  disabled?: boolean;
  onNewBuild?: () => void;
  onStart?: () => void;
  onReviewLicensing?: (detail: string) => void;
  onDoctor?: () => void;
}): import("react").ReactElement;

export function BuildLicensingDialog(props: {
  open: boolean;
  detail?: string;
  onClose?: () => void;
  onOpenSettings?: () => void;
}): import("react").ReactElement | null;
