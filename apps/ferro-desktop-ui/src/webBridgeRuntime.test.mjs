import assert from "node:assert/strict";
import test from "node:test";

import {
  createWebBridgeRuntime,
  DEFAULT_INVOKE_TIMEOUT_MS,
  extractWebBridgeToken,
} from "./webBridgeRuntime.mjs";
import { writeTerminalOutput } from "./terminalLifecycle.mjs";

test("web bridge token is extracted from the hash, persisted, and stripped", () => {
  const stored = new Map();
  const replaced = [];
  const target = {
    location: { hash: "#token=secret-token", pathname: "/dashboard", search: "?tab=logs" },
    history: { replaceState: (...args) => replaced.push(args) },
    sessionStorage: {
      getItem: (key) => stored.get(key) ?? null,
      setItem: (key, value) => stored.set(key, value),
    },
  };

  assert.equal(extractWebBridgeToken(target), "secret-token");
  assert.equal(stored.get("ferrocrate.webBridgeToken"), "secret-token");
  assert.deepEqual(replaced, [[null, "", "/dashboard?tab=logs"]]);
});

test("web bridge invoke posts JSON args and surfaces command errors", async () => {
  const requests = [];
  const runtime = createWebBridgeRuntime({
    token: "secret-token",
    fetchImpl: async (url, init) => {
      requests.push({ url, init });
      if (url.endsWith("/broken")) {
        return { ok: false, json: async () => ({ error: "daemon unavailable" }) };
      }
      return { ok: true, json: async () => ({ ok: true }) };
    },
    eventSourceFactory: () => { throw new Error("not used"); },
  });

  assert.deepEqual(await runtime.invoke("get_desktop_snapshot", { refresh: true }), { ok: true });
  assert.equal(requests[0].url, "/__tauri/get_desktop_snapshot");
  assert.equal(requests[0].init.method, "POST");
  assert.equal(requests[0].init.headers.authorization, "Bearer secret-token");
  assert.equal(requests[0].init.body, JSON.stringify({ refresh: true }));
  await assert.rejects(runtime.invoke("broken"), /daemon unavailable/);
});

test("N web bridge listeners share one named-event SSE connection", async () => {
  const sources = [];
  let unload;
  const runtime = createWebBridgeRuntime({
    token: "secret-token",
    target: { addEventListener: (name, handler) => { if (name === "beforeunload") unload = handler; } },
    fetchImpl: async () => { throw new Error("not used"); },
    eventSourceFactory: (url) => {
      const listeners = new Map();
      const source = {
        url,
        listeners,
        closed: false,
        addEventListener(name, handler) {
          const handlers = listeners.get(name) ?? new Set();
          handlers.add(handler);
          listeners.set(name, handlers);
        },
        removeEventListener(name, handler) {
          listeners.get(name)?.delete(handler);
        },
        close() { this.closed = true; },
        emit(name, payload) {
          for (const handler of listeners.get(name) ?? []) {
            handler({ data: JSON.stringify(payload) });
          }
        },
      };
      sources.push(source);
      return source;
    },
  });
  const received = [];

  const unlistenOutput = await runtime.listen("terminal-output", (event) => received.push(event));
  const unlistenError = await runtime.listen("terminal-error", (event) => received.push(event));
  const unlistenLogs = await runtime.listen("container-log-batch", (event) => received.push(event));
  assert.equal(sources.length, 1);
  assert.equal(sources[0].url, "/__tauri/stream?token=secret-token");
  sources[0].emit("terminal-output", { data: [65], stderr: false });
  assert.deepEqual(received, [{ event: "terminal-output", payload: { data: [65], stderr: false } }]);

  unlistenOutput();
  unlistenError();
  unlistenLogs();
  assert.equal(sources[0].closed, false);
  unload();
  assert.equal(sources[0].closed, true);
});

test("terminal startup waits for the event stream so the first prompt is visible", async () => {
  const listeners = new Map();
  let streamOpen = false;
  const mountedTerminal = {
    visibleText: "",
    rows: [""],
    write(bytes) {
      this.visibleText += new TextDecoder().decode(bytes);
      this.rows = this.visibleText.split(/\r?\n/);
    },
  };
  const terminalRef = { current: mountedTerminal };
  const source = {
    readyState: 0,
    addEventListener(name, handler) {
      const handlers = listeners.get(name) ?? new Set();
      handlers.add(handler);
      listeners.set(name, handlers);
    },
    removeEventListener(name, handler) { listeners.get(name)?.delete(handler); },
    close() {},
    open() {
      streamOpen = true;
      this.readyState = 1;
      for (const handler of listeners.get("open") ?? []) handler({});
    },
    emit(name, payload) {
      if (!streamOpen) return;
      for (const handler of listeners.get(name) ?? []) {
        handler({ data: JSON.stringify(payload) });
      }
    },
  };
  const runtime = createWebBridgeRuntime({
    token: "secret-token",
    eventSourceFactory: () => source,
    fetchImpl: async () => {
      source.emit("terminal-output", {
        data: Array.from(new TextEncoder().encode("/ # ")),
        stderr: false,
      });
      return { ok: true, json: async () => ({ ok: true }) };
    },
  });
  await runtime.listen("terminal-output", (event) => {
    writeTerminalOutput(terminalRef, event.payload);
  });

  const started = runtime.invoke("start_terminal", { target: "demo", shell: "sh", env: [] });
  await Promise.resolve();
  assert.equal(mountedTerminal.visibleText, "");
  source.open();
  await started;

  assert.equal(mountedTerminal.rows[0], "/ # ");

  terminalRef.current = null;
  source.emit("terminal-output", { data: [88], stderr: false });
  assert.equal(mountedTerminal.visibleText, "/ # ");

  const remountedTerminal = {
    visibleText: "",
    write(bytes) { this.visibleText += new TextDecoder().decode(bytes); },
  };
  terminalRef.current = remountedTerminal;
  source.emit("terminal-output", { data: [36, 32], stderr: false });
  assert.equal(remountedTerminal.visibleText, "$ ");
});

test("terminal startup rejects a closed event stream without posting", async () => {
  let fetches = 0;
  const source = {
    readyState: 2,
    addEventListener() {},
    removeEventListener() {},
    close() {},
  };
  const runtime = createWebBridgeRuntime({
    token: "secret-token",
    eventSourceFactory: () => source,
    fetchImpl: async () => {
      fetches += 1;
      return { ok: true, json: async () => ({ ok: true }) };
    },
  });

  await assert.rejects(
    runtime.invoke("start_terminal", {}, { timeoutMs: 25 }),
    /event stream is closed/i,
  );
  assert.equal(fetches, 0);
});

test("a reconnecting event stream keeps waiting through error and starts after open", async () => {
  const listeners = new Map();
  const source = {
    readyState: 0,
    addEventListener(name, handler) {
      const handlers = listeners.get(name) ?? new Set();
      handlers.add(handler);
      listeners.set(name, handlers);
    },
    removeEventListener(name, handler) { listeners.get(name)?.delete(handler); },
    close() {},
    emit(name) {
      for (const handler of [...(listeners.get(name) ?? [])]) handler({});
    },
  };
  let fetches = 0;
  const runtime = createWebBridgeRuntime({
    token: "secret-token",
    eventSourceFactory: () => source,
    fetchImpl: async () => {
      fetches += 1;
      return { ok: true, json: async () => ({ ok: true }) };
    },
  });

  let settled = false;
  const started = runtime.invoke("start_terminal", {}, { timeoutMs: 50 });
  void started.then(
    () => { settled = true; },
    () => { settled = true; },
  );
  source.emit("error");
  await Promise.resolve();
  assert.equal(settled, false);
  assert.equal(listeners.get("open")?.size, 1);
  assert.equal(listeners.get("error")?.size, 1);

  source.readyState = 1;
  source.emit("open");
  await started;
  assert.equal(fetches, 1);
  assert.equal(listeners.get("open")?.size, 0);
  assert.equal(listeners.get("error")?.size, 0);
});

test("terminal startup timeout aborts and removes readiness listeners", async () => {
  const listeners = new Map();
  const source = {
    readyState: 0,
    addEventListener(name, handler) {
      const handlers = listeners.get(name) ?? new Set();
      handlers.add(handler);
      listeners.set(name, handlers);
    },
    removeEventListener(name, handler) { listeners.get(name)?.delete(handler); },
    close() {},
  };
  const runtime = createWebBridgeRuntime({
    token: "secret-token",
    eventSourceFactory: () => source,
    fetchImpl: async () => ({ ok: true, json: async () => ({ ok: true }) }),
  });

  await assert.rejects(
    runtime.invoke("start_terminal", {}, { timeoutMs: 10 }),
    /start_terminal timed out after 10 milliseconds/i,
  );
  assert.equal(listeners.get("open")?.size, 0);
  assert.equal(listeners.get("error")?.size, 0);
});

test("a mount/unmount/remount cycle leaves exactly one listener", async () => {
  const registered = new Map();
  const source = {
    addEventListener(name, handler) {
      const handlers = registered.get(name) ?? new Set();
      handlers.add(handler);
      registered.set(name, handlers);
    },
    removeEventListener(name, handler) { registered.get(name)?.delete(handler); },
    close() {},
  };
  const runtime = createWebBridgeRuntime({
    token: "secret-token",
    eventSourceFactory: () => source,
  });

  const firstUnmount = await runtime.listen("terminal-output", () => {});
  firstUnmount();
  await runtime.listen("terminal-output", () => {});

  assert.equal(registered.get("terminal-output")?.size, 1);
});

test("web bridge invoke rejects with a human timeout message", async () => {
  assert.equal(DEFAULT_INVOKE_TIMEOUT_MS, 60_000);
  const runtime = createWebBridgeRuntime({
    token: "secret-token",
    fetchImpl: () => new Promise(() => {}),
  });

  await assert.rejects(
    runtime.invoke("get_desktop_snapshot", {}, { timeoutMs: 10 }),
    /get_desktop_snapshot timed out after 10 milliseconds\. Please try again\./,
  );
});

test("web bridge invoke accepts a longer per-command timeout", async () => {
  const runtime = createWebBridgeRuntime({
    token: "secret-token",
    defaultTimeoutMs: 5,
    fetchImpl: async () => {
      await new Promise((resolve) => setTimeout(resolve, 15));
      return { ok: true, json: async () => ({ ok: true }) };
    },
  });

  assert.deepEqual(
    await runtime.invoke("build_image", {}, { timeoutMs: 50 }),
    { ok: true },
  );
});

test("web bridge reports that native host path dialogs are unavailable", async () => {
  const runtime = createWebBridgeRuntime({ token: "secret-token", target: {} });

  assert.equal(typeof runtime.capabilities, "object");
  assert.equal(runtime.capabilities.dialog, false);
  await assert.rejects(
    runtime.open({ directory: true }),
    /native file and directory dialogs are unavailable in web mode/i,
  );
});
