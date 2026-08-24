import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";
import { open as tauriOpen } from "@tauri-apps/plugin-dialog";

import { createWebBridgeRuntime, installWebBridgeRuntime } from "./webBridgeRuntime.mjs";

const nativeTauriAvailable = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
const webRuntime = nativeTauriAvailable ? null : installWebBridgeRuntime(window, createWebBridgeRuntime());

export function invoke<T>(
  command: string,
  args?: Record<string, unknown>,
  options?: { timeoutMs?: number },
): Promise<T> {
  return nativeTauriAvailable
    ? tauriInvoke<T>(command, args)
    : webRuntime!.invoke<T>(command, args, options);
}

export function listen<T>(event: string, handler: (event: { event: string; payload: T }) => void) {
  return nativeTauriAvailable ? tauriListen<T>(event, handler) : webRuntime!.listen<T>(event, handler);
}

export function open(options?: { directory?: boolean; multiple?: boolean }) {
  return nativeTauriAvailable ? tauriOpen(options) : webRuntime!.open(options);
}
