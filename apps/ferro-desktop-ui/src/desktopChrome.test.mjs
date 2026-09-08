import test from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import * as desktopChrome from "./desktopChrome.mjs";

test("desktop tabs follow the binding order with counts and right-aligned system tabs", () => {
  assert.equal(typeof desktopChrome.DesktopTabBar, "function");
  const markup = renderToStaticMarkup(createElement(desktopChrome.DesktopTabBar, {
    activeSection: "containers",
    counts: { containers: 5, images: 12, builds: 2, compose: 1, volumes: 4, networks: 3, fleet: 2 },
    doctorIssues: 2,
    onSelect: () => {},
  }));
  const labels = ["Workspaces", "Images", "Build activity", "Resources", "Compose", "Volumes", "Networks", "Fleet"];
  let previous = -1;
  for (const label of labels) {
    const position = markup.indexOf(label);
    assert.ok(position > previous, `${label} must follow the mockup order`);
    previous = position;
  }
  assert.match(markup, /class="desktop-tabs"/);
  assert.match(markup, /class="tab-spacer"/);
  assert.match(markup, /aria-label="Settings"/);
  assert.match(markup, /<span>Settings<\/span>/);
  assert.match(markup, /folded-forge-mark.png/);
  assert.match(markup, /aria-current="page"/);
  assert.match(markup, /<details class="sidebar-resources"><summary/);
  assert.equal((markup.match(/class="tab-count"/g) || []).length, 7);
  assert.doesNotMatch(markup, /☀|☾|⚙|▶|🩺/u);
});

test("desktop tabs report every selection through one navigation callback", () => {
  const selected = [];
  const bar = desktopChrome.DesktopTabBar({
    activeSection: "images",
    counts: { containers: 0, images: 1, builds: 0, compose: 0, volumes: 0, networks: 0, fleet: 0 },
    doctorIssues: 0,
    onSelect: (section) => selected.push(section),
  });
  function visit(node) {
    if (node?.type === "button") node.props.onClick();
    for (const child of [node?.props?.children].flat(Infinity)) if (child && typeof child === "object") visit(child);
  }
  visit(bar);
  assert.deepEqual(selected, ["containers", "images", "builds", "compose", "volumes", "networks", "fleet", "doctor", "settings"]);
});

test("the title-bar Run action belongs only to the Containers page", () => {
  assert.equal(desktopChrome.showGlobalRunAction("containers"), true);
  for (const section of ["images", "builds", "compose", "volumes", "networks", "fleet", "doctor", "settings"]) {
    assert.equal(desktopChrome.showGlobalRunAction(section), false);
  }
});
