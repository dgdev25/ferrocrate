import assert from "node:assert/strict";
import test from "node:test";
import { applyTerminalResize, DEFAULT_TERMINAL_ENV } from "./terminalResize.mjs";

test("terminal resize always updates xterm and only resizes an active daemon exec", () => {
  const local = [];
  const remote = [];
  const resizeLocal = (columns, rows) => local.push([columns, rows]);
  const resizeRemote = (columns, rows) => remote.push([columns, rows]);

  applyTerminalResize(840, 340, false, resizeLocal, resizeRemote);
  applyTerminalResize(840, 340, true, resizeLocal, resizeRemote);

  assert.deepEqual(local, [[100, 20], [100, 20]]);
  assert.deepEqual(remote, [[100, 20]]);
});

test("terminal resize enforces readable minimum dimensions", () => {
  const local = [];
  applyTerminalResize(1, 1, false, (columns, rows) => local.push([columns, rows]), () => {});
  assert.deepEqual(local, [[20, 6]]);
});

test("terminal starts without an attached override by default", () => {
  assert.equal(DEFAULT_TERMINAL_ENV, "");
});
