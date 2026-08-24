import test from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { registryStatusText } from "./registryAuth.mjs";
import * as registryAuth from "./registryAuth.mjs";

test("registry title-bar label exposes a compact account identity", () => {
  assert.equal(
    registryStatusText({
      registry: "registry.example.com",
      logged_in: true,
      username: "alice",
    }),
    "alice",
  );
  assert.equal(
    registryStatusText({
      registry: "registry.example.com",
      logged_in: false,
      username: null,
    }),
    "Sign in",
  );
});

test("rendered registry account control provides sign-in and signed-in states", () => {
  assert.equal(typeof registryAuth.RegistryAccountControl, "function");

  const signedOut = renderToStaticMarkup(createElement(registryAuth.RegistryAccountControl, {
    status: null,
    onOpen: () => {},
  }));
  assert.match(signedOut, /Sign in/);
  assert.match(signedOut, /aria-label="Sign in to a registry"/);

  const signedIn = renderToStaticMarkup(createElement(registryAuth.RegistryAccountControl, {
    status: { registry: "registry.example.com", logged_in: true, username: "alice" },
    onOpen: () => {},
  }));
  assert.match(signedIn, /class="registry-avatar"/);
  assert.match(signedIn, />A<\/span><span>alice<\/span>/);
  assert.match(signedIn, /aria-label="Registry account: alice"/);
});
