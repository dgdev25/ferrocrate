import test from "node:test";
import assert from "node:assert/strict";

import { maskEnvironment, parseOptionalLimit } from "./containerDetail.mjs";

test("environment masking preserves keys without exposing values", () => {
  assert.deepEqual(
    maskEnvironment(["TOKEN=secret", "EMPTY=", "PATH=/usr/bin"]),
    ["TOKEN=••••••", "EMPTY=••••••", "PATH=••••••"],
  );
});

test("optional resource limits distinguish blank, zero, and invalid input", () => {
  assert.equal(parseOptionalLimit(""), null);
  assert.equal(parseOptionalLimit("0"), 0);
  assert.equal(parseOptionalLimit("134217728"), 134_217_728);
  assert.throws(() => parseOptionalLimit("1.5"), /whole number/);
  assert.throws(() => parseOptionalLimit("-1"), /whole number/);
});
