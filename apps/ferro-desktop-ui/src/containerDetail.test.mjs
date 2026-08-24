import test from "node:test";
import assert from "node:assert/strict";

import { loadContainerSelection, maskEnvironment, parseOptionalLimit } from "./containerDetail.mjs";

test("environment masking preserves keys without exposing values", () => {
  assert.deepEqual(
    maskEnvironment(["TOKEN=secret", "EMPTY=", "PATH=/usr/bin"]),
    ["TOKEN=••••••", "EMPTY=••••••", "PATH=••••••"],
  );
});

test("row selection is retained when detail loading fails and returns an inspector error", async () => {
  const selected = await loadContainerSelection("container-7", async () => { throw new Error("inspect unavailable"); });
  assert.equal(selected.target, "container-7");
  assert.equal(selected.detail, null);
  assert.match(selected.error, /inspect unavailable/);
});

test("optional resource limits distinguish blank, zero, and invalid input", () => {
  assert.equal(parseOptionalLimit(""), null);
  assert.equal(parseOptionalLimit("0"), 0);
  assert.equal(parseOptionalLimit("134217728"), 134_217_728);
  assert.throws(() => parseOptionalLimit("1.5"), /whole number/);
  assert.throws(() => parseOptionalLimit("-1"), /whole number/);
});
