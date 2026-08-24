export type WebBridgeEvent<T> = { event: string; payload: T };
export type WebBridgeUnlisten = () => void;

export type WebBridgeRuntime = {
  capabilities: { dialog: boolean };
  invoke<T>(command: string, args?: Record<string, unknown>, options?: { timeoutMs?: number }): Promise<T>;
  listen<T>(event: string, handler: (event: WebBridgeEvent<T>) => void): Promise<WebBridgeUnlisten>;
  open(options?: { directory?: boolean; multiple?: boolean }): Promise<string | string[] | null>;
};

export function extractWebBridgeToken(target?: typeof globalThis): string | null;
export function createWebBridgeRuntime(options?: Record<string, unknown>): WebBridgeRuntime;
export function installWebBridgeRuntime(target: Window & typeof globalThis, runtime?: WebBridgeRuntime): WebBridgeRuntime;
