import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("inspector fields have stable form names", () => {
  const source = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
  for (const name of [
    "global-search",
    "log-filter",
    "terminal-shell",
    "terminal-user",
    "terminal-workdir",
    "container-memory-bytes",
    "container-cpu-quota",
    "container-cpu-period",
  ]) {
    assert.match(source, new RegExp(`name="${name}"`));
  }
});
