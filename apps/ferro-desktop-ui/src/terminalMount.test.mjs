import assert from "node:assert/strict";
import test from "node:test";

import { mountTerminalHost, writeTerminalOutput } from "./terminalLifecycle.mjs";

test("a terminal mounts when its conditional host appears and disposes once", () => {
  const terminalRef = { current: null };
  const createdFor = [];
  let disposals = 0;
  const terminal = { write() {} };
  const create = (host) => {
    createdFor.push(host);
    return { terminal, dispose: () => { disposals += 1; } };
  };

  assert.equal(mountTerminalHost(null, terminalRef, create), undefined);
  assert.equal(createdFor.length, 0);

  const cleanup = mountTerminalHost("terminal-host", terminalRef, create);
  assert.equal(terminalRef.current, terminal);
  assert.deepEqual(createdFor, ["terminal-host"]);
  assert.equal(mountTerminalHost("terminal-host", terminalRef, create), undefined);

  cleanup();
  cleanup();
  assert.equal(disposals, 1);
  assert.equal(terminalRef.current, null);
});

test("stale cleanup preserves a remounted terminal target", () => {
  const first = { write() {} };
  const second = { write() {} };
  const terminalRef = { current: null };
  const cleanup = mountTerminalHost("first-host", terminalRef, () => ({
    terminal: first,
    dispose() {},
  }));

  terminalRef.current = second;
  cleanup();

  assert.equal(terminalRef.current, second);
});

test("terminal output follows the current mounted target and ignores no target", () => {
  const first = { visibleText: "", write(bytes) { this.visibleText += new TextDecoder().decode(bytes); } };
  const second = { visibleText: "", write(bytes) { this.visibleText += new TextDecoder().decode(bytes); } };
  const terminalRef = { current: null };

  assert.equal(writeTerminalOutput(terminalRef, { data: [88], stderr: false }), false);
  terminalRef.current = first;
  assert.equal(writeTerminalOutput(terminalRef, { data: [65], stderr: false }), true);
  terminalRef.current = second;
  assert.equal(writeTerminalOutput(terminalRef, { data: [66], stderr: false }), true);
  assert.equal(first.visibleText, "A");
  assert.equal(second.visibleText, "B");
});
