import assert from "node:assert/strict";
import test from "node:test";

import { createWebBridgeRuntime, extractWebBridgeToken } from "./webBridgeRuntime.mjs";

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

test("web bridge listen delivers SSE payloads and closes on unlisten", async () => {
  const sources = [];
  const runtime = createWebBridgeRuntime({
    token: "secret-token",
    fetchImpl: async () => { throw new Error("not used"); },
    eventSourceFactory: (url) => {
      const source = { url, onmessage: null, closed: false, close() { this.closed = true; } };
      sources.push(source);
      return source;
    },
  });
  const received = [];

  const unlisten = await runtime.listen("terminal-output", (event) => received.push(event));
  assert.equal(sources[0].url, "/__tauri/stream/start_terminal?token=secret-token");
  sources[0].onmessage({
    data: JSON.stringify({ event: "terminal-output", payload: { data: [65], stderr: false } }),
  });
  assert.deepEqual(received, [{ event: "terminal-output", payload: { data: [65], stderr: false } }]);

  unlisten();
  assert.equal(sources[0].closed, true);
});
