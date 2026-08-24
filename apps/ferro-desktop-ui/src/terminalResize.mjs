export const DEFAULT_TERMINAL_ENV = "";

export function applyTerminalResize(width, height, active, resizeLocal, resizeRemote) {
  const columns = Math.max(20, Math.floor(width / 8.4));
  const rows = Math.max(6, Math.floor(height / 17));
  resizeLocal(columns, rows);
  if (active) resizeRemote(columns, rows);
}
