export type ImageRow = {
  id: string;
  reference: string;
  size: string;
  created: string;
};

export function formatImageSize(bytes: number | string | null | undefined): string;
export function parseImageRows(output: string): ImageRow[];
