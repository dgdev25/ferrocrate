import type { ChangeEvent, ReactElement } from "react";

export type ImageRow = {
  id: string;
  reference: string;
  size: string;
  created: string;
};

export function formatImageSize(bytes: number | string | null | undefined): string;
export function formatImageCreated(value: number | string | null | undefined): string;
export function pullFailurePresentation(error: unknown): { kind: "daemon" | "license" | "generic"; message: string; detail: string };
export function ImagePagePullAction(props: { hasImages: boolean; disabled?: boolean; onOpen?: () => void }): ReactElement | null;
export function ImageEmptyState(props: { hasImages: boolean; disabled?: boolean; onOpen?: () => void }): ReactElement | null;
export function PullImageDialog(props: {
  open: boolean;
  imageTarget: string;
  progress?: string;
  failure?: { kind: "daemon" | "license" | "generic"; message: string; detail: string } | null;
  busy?: boolean;
  onCancel?: () => void;
  onImageTargetChange?: (event: ChangeEvent<HTMLInputElement>) => void;
  onPull?: () => void;
  onStart?: () => void;
  onReviewLicensing?: () => void;
}): ReactElement | null;
export function parseImageRows(output: string): ImageRow[];
