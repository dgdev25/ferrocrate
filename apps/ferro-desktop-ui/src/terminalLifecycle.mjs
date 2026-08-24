export function writeTerminalOutput(terminalRef, payload) {
  const terminal = terminalRef.current;
  if (!terminal) return false;
  terminal.write(new Uint8Array(payload.data));
  return true;
}

export function mountTerminalHost(host, terminalRef, createMountedTerminal) {
  if (!host || terminalRef.current) return undefined;
  const mounted = createMountedTerminal(host);
  terminalRef.current = mounted.terminal;
  let disposed = false;
  return () => {
    if (disposed) return;
    disposed = true;
    mounted.dispose();
    if (terminalRef.current === mounted.terminal) {
      terminalRef.current = null;
    }
  };
}
