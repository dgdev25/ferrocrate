import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import * as resourcePages from "./resourcePages.mjs";

test("each resource empty state renders an icon, one sentence, and one action", () => {
  assert.equal(typeof resourcePages.ResourceEmptyState, "function");
  for (const [section, action] of [
    ["containers", "Run a container"],
    ["images", "Pull an image"],
    ["volumes", "Create a volume"],
    ["networks", "Create a network"],
    ["compose", "Choose a Compose file"],
  ]) {
    const markup = renderToStaticMarkup(createElement(resourcePages.ResourceEmptyState, { section }));
    assert.match(markup, /empty-state-icon/);
    assert.match(markup, new RegExp(`>${action.replaceAll(" ", " ")}<\\/button>`));
    assert.equal((markup.match(/<button/g) || []).length, 1);
    assert.equal((markup.match(/<span class="empty-state-copy">/g) || []).length, 1);
    assert.doesNotMatch(markup, /No data yet|Runtime error|entitlement/i);
  }
});

test("resource page state keeps empty and populated controls mutually exclusive", () => {
  assert.equal(typeof resourcePages.resourcePageState, "function");
  assert.deepEqual(resourcePages.resourcePageState("volumes", 0), {
    content: "empty",
    primaryAction: null,
  });
  assert.deepEqual(resourcePages.resourcePageState("volumes", 2), {
    content: "table",
    primaryAction: "create-volume",
  });
  assert.deepEqual(resourcePages.resourcePageState("compose", 0), {
    content: "empty",
    primaryAction: null,
  });
  assert.deepEqual(resourcePages.resourcePageState("compose", 3), {
    content: "table",
    primaryAction: "choose-compose-file",
  });
});

test("Escape closes the active resource creation dialog", () => {
  assert.equal(typeof resourcePages.nextResourceDialog, "function");
  assert.equal(resourcePages.nextResourceDialog(null, "open-volume"), "volume");
  assert.equal(resourcePages.nextResourceDialog("volume", "close-dialog"), null);
  assert.equal(resourcePages.nextResourceDialog(null, "open-network"), "network");
  assert.equal(resourcePages.nextResourceDialog("network", "close-dialog"), null);
  assert.equal(resourcePages.nextResourceDialog("network", "focus-search"), "network");
});

test("first-run is a single recovery surface with existing start and Doctor paths", () => {
  assert.equal(typeof resourcePages.FirstRunState, "function");
  const markup = renderToStaticMarkup(createElement(resourcePages.FirstRunState));
  assert.match(markup, /Ferrocrate runs containers and images on your machine/);
  assert.match(markup, />Start Ferrocrate<\/button>/);
  assert.match(markup, />Open Doctor<\/button>/);
  assert.equal((markup.match(/btn btn-primary/g) || []).length, 1);
  assert.doesNotMatch(markup, /Runtime error|daemon unreachable|connection refused/i);
});

test("first-run replaces resource pages only when runtime data is unavailable", () => {
  assert.equal(typeof resourcePages.shouldShowFirstRun, "function");
  const unavailable = { containers: { ok: false }, images: { ok: false } };
  const available = { containers: { ok: true }, images: { ok: true } };
  assert.equal(resourcePages.shouldShowFirstRun(null, "containers"), false);
  assert.equal(resourcePages.shouldShowFirstRun(unavailable, "containers"), true);
  assert.equal(resourcePages.shouldShowFirstRun(unavailable, "volumes"), true);
  assert.equal(resourcePages.shouldShowFirstRun(unavailable, "doctor"), false);
  assert.equal(resourcePages.shouldShowFirstRun(unavailable, "settings"), false);
  assert.equal(resourcePages.shouldShowFirstRun(available, "containers"), false);
});

test("action failures keep technical output behind a disclosure", () => {
  assert.equal(typeof resourcePages.ActionErrorNotice, "function");
  const markup = renderToStaticMarkup(createElement(resourcePages.ActionErrorNotice, {
    error: "network proxy connection refused: exit code 1",
  }));
  assert.match(markup, /Ferrocrate isn&#x27;t running/);
  assert.match(markup, /<details>/);
  assert.match(markup, /Technical details/);
  assert.doesNotMatch(markup, /<strong>Runtime error<\/strong>/);
});
