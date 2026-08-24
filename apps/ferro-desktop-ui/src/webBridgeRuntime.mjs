export function createWebBridgeRuntime(options = {}) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  const eventSourceFactory = options.eventSourceFactory ?? ((url) => new globalThis.EventSource(url));
  const promptImpl = options.promptImpl ?? globalThis.prompt?.bind(globalThis);

  return {
    async invoke(command, args = {}) {
      if (!fetchImpl) throw new Error("web bridge fetch is unavailable");
      const response = await fetchImpl(`/__tauri/${encodeURIComponent(command)}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(args ?? {}),
      });
      const payload = await response.json();
      if (!response.ok || (payload && typeof payload === "object" && "error" in payload)) {
        throw new Error(String(payload?.error ?? `command ${command} failed`));
      }
      return payload;
    },

    async listen(event, handler) {
      const source = eventSourceFactory(`/__tauri/stream/${encodeURIComponent(event)}`);
      source.onmessage = (message) => {
        handler({ event, payload: JSON.parse(message.data) });
      };
      return () => source.close();
    },

    async open(options = {}) {
      if (!promptImpl) throw new Error("browser path selection is unavailable");
      const kind = options.directory ? "directory" : "file";
      return promptImpl(`Enter the ${kind} path visible to Ferrocrate:`, "") || null;
    },
  };
}

export function installWebBridgeRuntime(target, runtime = createWebBridgeRuntime()) {
  if (!target.__TAURI__) {
    target.__TAURI__ = {
      core: { invoke: runtime.invoke },
      event: { listen: runtime.listen },
      dialog: { open: runtime.open },
    };
  }
  return runtime;
}
