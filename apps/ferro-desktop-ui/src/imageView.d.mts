export type ImageRow = {
  id: string;
  reference: string;
  size: string;
  created: string;
};

export function formatImageSize(bytes: number | string | null | undefined): string;
export function formatImageCreated(value: number | string | null | undefined): string;
export function pullFailurePresentation(error: unknown): { kind: "daemon" | "license" | "generic"; message: string; detail: string };
export function parseImageRows(output: string): ImageRow[];
