import assert from "node:assert/strict";
import test from "node:test";

import * as imageView from "./imageView.mjs";

test("image rows format byte sizes and Unix creation times for the table", () => {
  assert.deepEqual(imageView.parseImageRows(JSON.stringify([{
    Id: "sha256:abc",
    RepoTags: ["docker.io/library/alpine:latest"],
    Size: 1572864,
    Created: 1700000000,
  }])), [{
    id: "sha256:abc",
    reference: "docker.io/library/alpine:latest",
    size: "1.5 MB",
    created: "2023-11-14 22:13 UTC",
  }]);
});

test("pull failures give people a recovery path while retaining the technical detail", () => {
  assert.equal(typeof imageView.pullFailurePresentation, "function");
  assert.deepEqual(imageView.pullFailurePresentation("daemon connection refused"), {
    kind: "daemon",
    message: "Ferrocrate isn't running",
    detail: "daemon connection refused",
  });
  assert.deepEqual(imageView.pullFailurePresentation("missing entitlement for image pull"), {
    kind: "license",
    message: "Your current plan doesn't include image pulls.",
    detail: "missing entitlement for image pull",
  });
});
