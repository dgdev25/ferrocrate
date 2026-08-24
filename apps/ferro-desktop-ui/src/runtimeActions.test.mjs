import test from "node:test";
import assert from "node:assert/strict";

import { runtimeActionAvailability } from "./runtimeActions.mjs";

test("log and terminal streams never block independent runtime actions", () => {
  assert.deepEqual(runtimeActionAvailability({ actionBusy: false, logsFollowing: true, terminalActive: true }), { allowed: true, reason: null });
  assert.deepEqual(runtimeActionAvailability({ actionBusy: true, logsFollowing: false, terminalActive: false }), { allowed: false, reason: "Another runtime action is still in progress." });
});
