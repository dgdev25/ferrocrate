import assert from "node:assert/strict";
import test from "node:test";

import { buildStepText } from "./imageBuild.mjs";

test("build progress unwraps daemon stream frames and preserves failures", () => {
  assert.equal(buildStepText('{"stream":"Step 1/2 : FROM alpine\\n"}'), "Step 1/2 : FROM alpine");
  assert.equal(buildStepText('{"error":"executor failed"}'), "executor failed");
  assert.equal(buildStepText("plain stderr output"), "plain stderr output");
});
