const TOKEN_STORAGE_KEY = "ferrocrate.webBridgeToken";

export function extractWebBridgeToken(target = globalThis) {
  const hash = target.location?.hash ?? "";
  const hashParams = new URLSearchParams(hash.startsWith("#") ? hash.slice(1) : hash);
  const hashToken = hashParams.get("token");
  if (hashToken) {
    target.sessionStorage?.setItem(TOKEN_STORAGE_KEY, hashToken);
    hashParams.delete("token");
    const remainingHash = hashParams.toString();
    const cleanUrl = `${target.location.pathname}${target.location.search}${remainingHash ? `#${remainingHash}` : ""}`;
    target.history?.replaceState(null, "", cleanUrl);
    return hashToken;
  }
  return target.sessionStorage?.getItem(TOKEN_STORAGE_KEY) ?? null;
}

export function createWebBridgeRuntime(options = {}) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  const eventSourceFactory = options.eventSourceFactory ?? ((url) => new globalThis.EventSource(url));
  const promptImpl = options.promptImpl ?? globalThis.prompt?.bind(globalThis);
  const token = options.token ?? extractWebBridgeToken(options.target ?? globalThis);

  return {
    async invoke(command, args = {}) {
      if (!fetchImpl) throw new Error("web bridge fetch is unavailable");
      const response = await fetchImpl(`/__tauri/${encodeURIComponent(command)}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(args ?? {}),
      });
      const payload = await response.json();
      if (!response.ok || (payload && typeof payload === "object" && "error" in payload)) {
        throw new Error(String(payload?.error ?? `command ${command} failed`));
      }
      return payload;
    },

    async listen(event, handler) {
      const streamCommand = event.startsWith("terminal-")
        ? "start_terminal"
        : event.startsWith("container-log-")
          ? "start_log_follow"
          : event === "image-build-progress"
            ? "build_image"
            : event;
      const streamUrl = `/__tauri/stream/${encodeURIComponent(streamCommand)}`;
      const source = eventSourceFactory(token ? `${streamUrl}?token=${encodeURIComponent(token)}` : streamUrl);
      source.onmessage = (message) => {
        const envelope = JSON.parse(message.data);
        if (envelope.event === event) handler({ event, payload: envelope.payload });
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
