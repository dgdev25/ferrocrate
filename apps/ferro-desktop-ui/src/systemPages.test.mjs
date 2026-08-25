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

function findElement(element, type) {
  if (!element || typeof element !== "object") return null;
  if (element.type === type) return element;
  if (typeof element.type === "function") return findElement(element.type(element.props), type);
  for (const child of [element.props?.children].flat(Infinity)) {
    const match = findElement(child, type);
    if (match) return match;
  }
  return null;
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

test("Doctor surfaces a failed desktop backend as a needs-attention row", () => {
  const markup = renderToStaticMarkup(createElement(systemPages.DoctorPage, {
    result: {
      ok: false,
      raw: {
        checks: [{
          id: "desktop_backend",
          ok: false,
          message: "WSL2 backend is failed: relay unavailable",
          hint: "Capabilities: terminal, registry, containers, networks, volumes, custom networks, streaming exec.",
          remediated: false,
        }],
      },
    },
    onRun: () => {},
    onStart: () => {},
    onStop: () => {},
  }));

  assert.match(markup, /1 need attention/);
  assert.match(markup, /WSL2 backend is failed: relay unavailable/);
  assert.match(markup, /Capabilities: terminal, registry, containers/);
});

test("Doctor results table accepts a focus ref and is programmatically focusable", () => {
  const resultsTableRef = { current: null };
  const page = systemPages.DoctorPage({
    result: { ok: true, raw: { checks: [] } },
    resultsTableRef,
    onRun: () => {},
    onStart: () => {},
    onStop: () => {},
  });

  const table = findElement(page, "table");
  assert.ok(table);
  assert.equal(table.ref, resultsTableRef);
  assert.equal(table.props.tabIndex, -1);
});

test("completed Doctor runs close before scheduling results focus", async () => {
  const events = [];
  const result = { ok: true, raw: { checks: [] } };

  await systemPages.completeDoctorRun({
    execute: async () => { events.push("execute"); return result; },
    refresh: async () => { events.push("refresh"); },
    setResult: (value) => { events.push(["result", value]); },
    setError: (error) => { events.push(["error", error]); },
    close: () => { events.push("close"); },
    scheduleResultsFocus: () => { events.push("focus"); },
    finish: () => { events.push("finish"); },
  });

  assert.deepEqual(events, ["execute", ["result", result], "refresh", "close", "focus", "finish"]);
});

test("failed Doctor runs close without scheduling results focus", async () => {
  const events = [];

  await systemPages.completeDoctorRun({
    execute: async () => { events.push("execute"); throw new Error("doctor failed"); },
    refresh: async () => { events.push("refresh"); },
    setResult: (value) => { events.push(["result", value]); },
    setError: (error) => { events.push(["error", error]); },
    close: () => { events.push("close"); },
    scheduleResultsFocus: () => { events.push("focus"); },
    finish: () => { events.push("finish"); },
  });

  assert.deepEqual(events, ["execute", ["error", "Error: doctor failed"], "close", "finish"]);
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

test("native Linux settings show installed runtime truth and omit VM bootstrap", () => {
  const markup = renderToStaticMarkup(createElement(systemPages.SettingsPage, {
    authState: { session: { token_present: false } },
    nativeLinux: true,
    daemonStatus: { state: "running" },
  }));
  assert.match(markup, /Local Ferrocrate runtime/);
  assert.match(markup, />Running</);
  assert.doesNotMatch(markup, /Install and bootstrap|virtual machine/i);
});
