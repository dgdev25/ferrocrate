import test from "node:test";
import assert from "node:assert/strict";

import { registryStatusText } from "./registryAuth.mjs";

test("registry status identifies the authenticated registry and user", () => {
  assert.equal(
    registryStatusText({
      registry: "registry.example.com",
      logged_in: true,
      username: "alice",
    }),
    "Signed in to registry.example.com as alice",
  );
  assert.equal(
    registryStatusText({
      registry: "registry.example.com",
      logged_in: false,
      username: null,
    }),
    "Not signed in to registry.example.com",
  );
});
