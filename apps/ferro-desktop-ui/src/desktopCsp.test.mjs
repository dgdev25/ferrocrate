import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const config = JSON.parse(
  readFileSync(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"),
);
const csp = config.app.security.csp;

test("desktop CSP permits only bundled assets and Tauri IPC", () => {
  assert.equal(csp.includes("'unsafe-eval'"), false);
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /connect-src 'self' ipc: http:\/\/ipc\.localhost https:\/\/ipc\.localhost/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /frame-src 'none'/);
  assert.match(csp, /base-uri 'self'/);
  assert.match(csp, /form-action 'none'/);
});

test("desktop CSP keeps native dialog and terminal command paths available", () => {
  const runtime = readFileSync(new URL("./desktopRuntime.ts", import.meta.url), "utf8");
  const backend = readFileSync(new URL("../src-tauri/src/main.rs", import.meta.url), "utf8");
  assert.match(runtime, /@tauri-apps\/plugin-dialog/);
  for (const command of ["start_terminal", "write_terminal", "resize_terminal", "close_terminal"]) {
    assert.match(backend, new RegExp(`fn ${command}\\(`));
  }
});
