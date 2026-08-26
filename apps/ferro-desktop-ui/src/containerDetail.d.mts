export function maskEnvironment(environment: string[]): string[];
export function parseOptionalLimit(value: string): number | null;
export function loadContainerSelection<T>(
  target: string,
  loadDetail: (target: string) => Promise<T>,
): Promise<{ target: string; detail: T | null; error: string | null }>;
