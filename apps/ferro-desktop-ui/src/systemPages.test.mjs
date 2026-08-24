import test from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import * as systemPages from "./systemPages.mjs";

function buttons(element, found = []) {
  if (!element || typeof element !== "object") return found;
  if (typeof element.type === "function") return buttons(element.type(element.props), found);
  if (element.type === "button") found.push(element);
  for (const child of [element.props?.children].flat(Infinity)) buttons(child, found);
  return found;
}

test("Doctor is one empty state before a run and one checks table afterward", () => {
  assert.equal(typeof systemPages.DoctorPage, "function");
  const empty = renderToStaticMarkup(createElement(systemPages.DoctorPage, {
    result: null,
    onRun: () => {},
  }));
  assert.match(empty, /Check this installation/);
  assert.equal((empty.match(/<button/g) || []).length, 1);
  assert.doesNotMatch(empty, /<input|<table/);

  const populated = renderToStaticMarkup(createElement(systemPages.DoctorPage, {
    result: {
      ok: false,
      raw: {
        checks: [{ id: "runtime", ok: false, message: "Runtime unavailable", hint: "Start Ferrocrate", remediated: false }],
      },
    },
    onRun: () => {},
    onStart: () => {},
    onStop: () => {},
  }));
  assert.equal((populated.match(/<table/g) || []).length, 1);
  assert.match(populated, /Runtime unavailable/);
  assert.match(populated, /Start Ferrocrate/);
  assert.doesNotMatch(populated, /<input/);
});

test("Settings is a single capability table whose forms stay behind row actions", () => {
  assert.equal(typeof systemPages.SettingsPage, "function");
  const opened = [];
  const page = systemPages.SettingsPage({
    authState: { session: { token_present: true, plan: "pro" }, entitlement: { status: "ok" } },
    installerResult: { ok: true },
    onOpenAccount: () => opened.push("account"),
    onOpenInstall: () => opened.push("install"),
  });
  const markup = renderToStaticMarkup(page);
  assert.equal((markup.match(/<table/g) || []).length, 1);
  assert.match(markup, /Account and plan/);
  assert.match(markup, /Install and bootstrap/);
  assert.doesNotMatch(markup, /<input|<textarea/);
  for (const button of buttons(page)) button.props.onClick?.();
  assert.deepEqual(opened, ["account", "install"]);
});
