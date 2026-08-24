const TOKEN_STORAGE_KEY = "ferrocrate.webBridgeToken";
export const DEFAULT_INVOKE_TIMEOUT_MS = 60_000;

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
  const target = options.target ?? globalThis;
  const dialogOpenImpl = options.dialogOpenImpl ?? target.__TAURI__?.dialog?.open;
  const dialogAvailable = typeof dialogOpenImpl === "function";
  const token = options.token ?? extractWebBridgeToken(target);
  const defaultTimeoutMs = options.defaultTimeoutMs ?? DEFAULT_INVOKE_TIMEOUT_MS;
  let eventSource;
  let eventSourceReady;

  function sharedEventSource() {
    if (eventSource) return eventSource;
    const streamUrl = token
      ? `/__tauri/stream?token=${encodeURIComponent(token)}`
      : "/__tauri/stream";
    eventSource = eventSourceFactory(streamUrl);
    target.addEventListener?.("beforeunload", () => eventSource.close(), { once: true });
    return eventSource;
  }

  function waitForEventSource(signal) {
    const source = sharedEventSource();
    if (source.readyState === 1) return Promise.resolve();
    if (source.readyState === 2) {
      return Promise.reject(new Error("terminal event stream is closed"));
    }
    if (eventSourceReady) return eventSourceReady;
    if (signal.aborted) return Promise.reject(new Error("terminal event stream wait was aborted"));

    let resolveReady;
    let rejectReady;
    const ready = new Promise((resolve, reject) => {
      resolveReady = resolve;
      rejectReady = reject;
    });
    eventSourceReady = ready;

    const cleanup = () => {
      source.removeEventListener("open", onOpen);
      source.removeEventListener("error", onError);
      signal.removeEventListener("abort", onAbort);
      if (eventSourceReady === ready) eventSourceReady = undefined;
    };
    const settle = (callback, value) => {
      cleanup();
      callback(value);
    };
    const onOpen = () => settle(resolveReady);
    const onError = () => settle(rejectReady, new Error("terminal event stream failed to connect"));
    const onAbort = () => settle(rejectReady, new Error("terminal event stream wait was aborted"));
    source.addEventListener("open", onOpen);
    source.addEventListener("error", onError);
    signal.addEventListener("abort", onAbort, { once: true });

    if (source.readyState === 1) onOpen();
    else if (source.readyState === 2) settle(rejectReady, new Error("terminal event stream is closed"));
    return ready;
  }

  return {
    capabilities: { dialog: dialogAvailable },

    async invoke(command, args = {}, invokeOptions = {}) {
      if (!fetchImpl) throw new Error("web bridge fetch is unavailable");
      const timeoutMs = invokeOptions.timeoutMs ?? defaultTimeoutMs;
      const controller = new AbortController();
      const timeoutError = new Error(
        `${command} timed out after ${timeoutMs} ${timeoutMs === 1 ? "millisecond" : "milliseconds"}. Please try again.`,
      );
      let timedOut = false;
      let timeoutId;
      const timeout = new Promise((_, reject) => {
        timeoutId = setTimeout(() => {
          timedOut = true;
          reject(timeoutError);
          controller.abort();
        }, timeoutMs);
      });
      const request = (async () => {
        try {
          if (command === "start_terminal") {
            await waitForEventSource(controller.signal);
          }
          const response = await fetchImpl(`/__tauri/${encodeURIComponent(command)}`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              ...(token ? { authorization: `Bearer ${token}` } : {}),
            },
            body: JSON.stringify(args ?? {}),
            signal: controller.signal,
          });
          const payload = await response.json();
          if (!response.ok || (payload && typeof payload === "object" && "error" in payload)) {
            throw new Error(String(payload?.error ?? `command ${command} failed`));
          }
          return payload;
        } catch (error) {
          if (timedOut) throw timeoutError;
          throw error;
        }
      })();
      try {
        return await Promise.race([request, timeout]);
      } finally {
        clearTimeout(timeoutId);
      }
    },

    async listen(event, handler) {
      const source = sharedEventSource();
      const listener = (message) => {
        handler({ event, payload: JSON.parse(message.data) });
      };
      source.addEventListener(event, listener);
      let listening = true;
      return () => {
        if (!listening) return;
        listening = false;
        source.removeEventListener(event, listener);
      };
    },

    async open(options = {}) {
      if (!dialogAvailable) {
        throw new Error("Native file and directory dialogs are unavailable in web mode.");
      }
      return dialogOpenImpl(options);
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
