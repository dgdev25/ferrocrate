import assert from "node:assert/strict";
import test from "node:test";
import {
  applyRemoteTerminalResize,
  applyTerminalResize,
  DEFAULT_TERMINAL_ENV,
} from "./terminalResize.mjs";

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

test("active terminal dimensions can be synchronized immediately after exec start", () => {
  const remote = [];
  applyRemoteTerminalResize(90, 18, false, (columns, rows) => remote.push([columns, rows]));
  applyRemoteTerminalResize(90, 18, true, (columns, rows) => remote.push([columns, rows]));
  assert.deepEqual(remote, [[90, 18]]);
});

test('hidden or invalid terminal measurements preserve local and remote dimensions', () => {
  for (const [width, height] of [[0, 300], [800, 0], [0, 0], [-1, 300], [NaN, 300], [800, Infinity]]) {
    const local = [];
    const remote = [];
    applyTerminalResize(width, height, true, (...args) => local.push(args), (...args) => remote.push(args));
    assert.deepEqual(local, [], `${width} by ${height}`);
    assert.deepEqual(remote, [], `${width} by ${height}`);
  }
});
