import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ComposeFileDialog, composeChooserMode, composeLogTarget, composeStatusClass } from "./composeView.mjs";

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

test("Compose chooses a validated host-path fallback when native dialogs are unavailable", () => {
  assert.equal(composeChooserMode(true), "native-dialog");
  assert.equal(composeChooserMode(false), "host-path");
  const markup = renderToStaticMarkup(createElement(ComposeFileDialog, {
    open: true,
    value: "/srv/app/compose.yml",
    onChange: () => {},
    onSubmit: () => {},
    onCancel: () => {},
  }));
  assert.match(markup, /role="dialog"/);
  assert.match(markup, /Enter an absolute file path on the daemon host\./);
  assert.match(markup, /\/srv\/app\/compose.yml/);
  assert.match(markup, /Load Compose file/);
});
