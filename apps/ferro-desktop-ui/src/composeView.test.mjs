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

test("failed Compose file loads keep an actionable error and editable path inside the dialog", () => {
  const markup = renderToStaticMarkup(createElement(ComposeFileDialog, {
    open: true, value: "/srv/app/broken.yml", busy: false,
    error: "Could not parse Compose file: services must be a mapping",
    onChange: () => {}, onSubmit: () => {}, onCancel: () => {},
  }));
  assert.match(markup, /role="dialog"[\s\S]*role="alert"[\s\S]*services must be a mapping[\s\S]*<\/section>/);
  assert.match(markup, /value="\/srv\/app\/broken.yml"/);
  assert.doesNotMatch(markup.match(/<input[^>]*>/)?.[0] || "", /disabled/);
  assert.match(markup, /Technical details/);
});

test("Compose logs remain a direct service-specific action with unavailable-service guards", async () => {
  const { ComposeServiceLogsButton } = await import("./composeView.mjs");
  assert.equal(typeof ComposeServiceLogsButton, "function");
  const service = { name: "api", container_id: "exact-container", status: "running" };
  let selected;
  const button = ComposeServiceLogsButton({ service, busy: false, onLogs: value => { selected = value; } });
  button.props.onClick();
  assert.equal(selected, service);
  const markup = renderToStaticMarkup(button);
  assert.match(markup, /aria-label="Logs for Compose service api"/);
  assert.doesNotMatch(markup, /<details|<summary|overflow-menu/);
  assert.match(markup, />Logs<\/button>/);
  assert.match(renderToStaticMarkup(createElement(ComposeServiceLogsButton, { service: { ...service, status: "not_created" }, onLogs: () => {} })), /disabled/);
  assert.match(renderToStaticMarkup(createElement(ComposeServiceLogsButton, { service, busy: true, onLogs: () => {} })), /disabled/);
});
