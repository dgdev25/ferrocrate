import test from "node:test";
import assert from "node:assert/strict";

import { clearErrorsForNavigation, errorForSection, setSectionError } from "./errorScopes.mjs";

test("page errors stay on their producing surface and navigation clears them", () => {
  const errors = setSectionError({}, "doctor", "doctor failed");
  assert.equal(errorForSection(errors, "doctor"), "doctor failed");
  assert.equal(errorForSection(errors, "images"), null);
  assert.deepEqual(clearErrorsForNavigation(errors), {});
});
