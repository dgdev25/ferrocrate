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
    dismissDialogs: true,
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

test("a rejected resource create cannot relabel a previous action result", async () => {
  assert.equal(typeof errorScopes.resourceActionStartState, "function");

  const previous = { ok: true, code: 0, stdout: "removed", stderr: "", message: "" };
  let actionResult = previous;
  actionResult = errorScopes.resourceActionStartState("create", actionResult).actionResult;

  await assert.rejects(Promise.reject(new Error("invoke rejected")), /invoke rejected/);
  assert.equal(actionResult, null);
  assert.equal(errorScopes.resourceActionStartState("remove", previous).actionResult, previous);
});

test("a create completion is ignored after its dialog generation is dismissed", () => {
  const failedCreate = { ok: false, code: 1, stdout: "", stderr: "late failure", message: "Create failed" };
  assert.equal(errorScopes.resourceActionState("create", failedCreate, failedCreate.message, 4, 5), null);
  assert.deepEqual(errorScopes.resourceActionState("create", failedCreate, failedCreate.message, 5, 5), {
    actionResult: null,
    dialogError: "Create failed",
    pageError: null,
  });
});
