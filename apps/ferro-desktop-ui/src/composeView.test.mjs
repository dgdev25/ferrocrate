import assert from "node:assert/strict";
import test from "node:test";

import { composeLogTarget, composeStatusClass } from "./composeView.mjs";

test("compose service status maps to stable visual states", () => {
  assert.equal(composeStatusClass("running"), "status-running");
  assert.equal(composeStatusClass("paused"), "status-paused");
  assert.equal(composeStatusClass("exited"), "status-stopped");
  assert.equal(composeStatusClass("not_created"), "status-stopped");
});

test("compose logs prefer the exact projected container id", () => {
  assert.equal(composeLogTarget({ name: "api", container_id: "abc123" }), "abc123");
  assert.equal(composeLogTarget({ name: "api", container_id: null }), "api");
});
