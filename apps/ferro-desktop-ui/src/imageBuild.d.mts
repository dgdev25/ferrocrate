export function buildStepText(text: string): string;
export function formatBuildDuration(durationMs: number | null): string;
export function buildFailurePresentation(error: unknown): {
  kind: "daemon" | "license" | "generic";
  message: string;
  detail: string;
};

export type BuildHistoryEntry = {
  id: string;
  image: string;
  status: "building" | "succeeded" | "failed";
  durationMs: number | null;
  progress: Array<{ stream: "stdout" | "stderr"; text: string }>;
  error?: string;
};

export function BuildHistoryList(props: {
  builds: BuildHistoryEntry[];
  disabled?: boolean;
  onNewBuild?: () => void;
  onStart?: () => void;
  onReviewLicensing?: () => void;
}): import("react").ReactElement;
