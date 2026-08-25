import assert from "node:assert/strict";
import test from "node:test";

import { productSurfaceLabel } from "./surfaceLabel.mjs";

test("embedded browser build identifies itself as Dashboard", () => {
  assert.equal(productSurfaceLabel({ __FERROCRATE_DASHBOARD__: true }), "Dashboard");
  assert.equal(productSurfaceLabel({}), "Desktop");
});
