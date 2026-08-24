import test from "node:test";
import assert from "node:assert/strict";

import * as errorScopes from "./errorScopes.mjs";

const { clearErrorsForNavigation, errorForSection, setSectionError } = errorScopes;

test("page errors stay on their producing surface and navigation clears them", () => {
  const errors = setSectionError({}, "doctor", "doctor failed");
  assert.equal(errorForSection(errors, "doctor"), "doctor failed");
  assert.equal(errorForSection(errors, "images"), null);
  assert.deepEqual(clearErrorsForNavigation(errors), {});
});

test("network-create failures stay in their dialog and navigation clears transient page state", () => {
  assert.equal(typeof errorScopes.resourceActionState, "function");
  assert.equal(typeof errorScopes.navigationTransientState, "function");

  const failedCreate = { ok: false, code: 1, stdout: "", stderr: "network failed", message: "Network Create did not complete" };
  const createState = errorScopes.resourceActionState("create", failedCreate, failedCreate.message);
  assert.deepEqual(createState, {
    actionResult: null,
    dialogError: "Network Create did not complete",
    pageError: null,
  });

  const navigated = errorScopes.navigationTransientState(
    setSectionError({}, "networks", "page failed"),
  );
  assert.deepEqual(navigated, {
    actionLabel: "",
    actionResult: null,
    sectionErrors: {},
  });
  assert.equal(errorForSection(navigated.sectionErrors, "doctor"), null);
  assert.equal(errorForSection(navigated.sectionErrors, "images"), null);

  const failedRemove = errorScopes.resourceActionState("remove", failedCreate, failedCreate.message);
  assert.deepEqual(failedRemove, {
    actionResult: failedCreate,
    dialogError: null,
    pageError: "Network Create did not complete",
  });
});
