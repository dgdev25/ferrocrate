export const DEFAULT_TERMINAL_ENV = "";

export function applyRemoteTerminalResize(columns, rows, active, resizeRemote) {
  if (active) resizeRemote(columns, rows);
}

export function applyTerminalResize(width, height, active, resizeLocal, resizeRemote) {
  if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) return;
  const columns = Math.max(20, Math.floor(width / 8.4));
  const rows = Math.max(6, Math.floor(height / 17));
  resizeLocal(columns, rows);
  applyRemoteTerminalResize(columns, rows, active, resizeRemote);
}
