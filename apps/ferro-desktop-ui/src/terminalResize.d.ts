type ResizeCallback = (columns: number, rows: number) => void;

export const DEFAULT_TERMINAL_ENV: string;

export function applyRemoteTerminalResize(
  columns: number,
  rows: number,
  active: boolean,
  resizeRemote: ResizeCallback,
): void;

export function applyTerminalResize(
  width: number,
  height: number,
  active: boolean,
  resizeLocal: ResizeCallback,
  resizeRemote: ResizeCallback,
): void;
