export type WebBridgeEvent<T> = { event: string; payload: T };
export type WebBridgeUnlisten = () => void;

export type WebBridgeRuntime = {
  invoke<T>(command: string, args?: Record<string, unknown>): Promise<T>;
  listen<T>(event: string, handler: (event: WebBridgeEvent<T>) => void): Promise<WebBridgeUnlisten>;
  open(options?: { directory?: boolean; multiple?: boolean }): Promise<string | string[] | null>;
};

export function createWebBridgeRuntime(options?: Record<string, unknown>): WebBridgeRuntime;
export function installWebBridgeRuntime(target: Window & typeof globalThis, runtime?: WebBridgeRuntime): WebBridgeRuntime;
