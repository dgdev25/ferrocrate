export type TerminalOutputPayload = { data: number[]; stderr: boolean };

export type TerminalWriter = {
  write(data: Uint8Array): void;
};

export type MutableTerminalRef<T> = { current: T | null };

export function writeTerminalOutput<T extends TerminalWriter>(
  terminalRef: MutableTerminalRef<T>,
  payload: TerminalOutputPayload,
): boolean;

export function mountTerminalHost<Host, Terminal>(
  host: Host | null,
  terminalRef: MutableTerminalRef<Terminal>,
  createMountedTerminal: (host: Host) => { terminal: Terminal; dispose(): void },
): (() => void) | undefined;
