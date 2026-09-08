export function createTerminalCommandQueue(): {
  invoke<T>(command: string, operation: () => Promise<T>): Promise<T>;
};
