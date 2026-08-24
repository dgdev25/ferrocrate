import test from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import * as desktopChrome from "./desktopChrome.mjs";

test("desktop tabs follow the binding order with counts and right-aligned system tabs", () => {
  assert.equal(typeof desktopChrome.DesktopTabBar, "function");
  const markup = renderToStaticMarkup(createElement(desktopChrome.DesktopTabBar, {
    activeSection: "containers",
    counts: { containers: 5, images: 12, builds: 2, compose: 1, volumes: 4, networks: 3 },
    doctorIssues: 2,
    onSelect: () => {},
  }));
  const labels = ["Containers", "Images", "Builds", "Compose", "Volumes", "Networks"];
  let previous = -1;
  for (const label of labels) {
    const position = markup.indexOf(label);
    assert.ok(position > previous, `${label} must follow the mockup order`);
    previous = position;
  }
  assert.match(markup, /class="desktop-tabs"/);
  assert.match(markup, /class="tab-spacer"/);
  assert.match(markup, /aria-label="Settings"/);
  assert.doesNotMatch(markup, /<span>Settings<\/span>/);
  assert.match(markup, /<span class="visually-hidden">Settings<\/span>/);
  assert.match(markup, /aria-current="page"/);
  assert.equal((markup.match(/class="tab-count"/g) || []).length, 6);
  assert.doesNotMatch(markup, /sidebar|☀|☾|⚙|▶|🩺/u);
});

test("desktop tabs report every selection through one navigation callback", () => {
  const selected = [];
  const bar = desktopChrome.DesktopTabBar({
    activeSection: "images",
    counts: { containers: 0, images: 1, builds: 0, compose: 0, volumes: 0, networks: 0 },
    doctorIssues: 0,
    onSelect: (section) => selected.push(section),
  });
  for (const child of bar.props.children.flat(Infinity)) {
    if (child?.type === "button") child.props.onClick();
  }
  assert.deepEqual(selected, ["containers", "images", "builds", "compose", "volumes", "networks", "doctor", "settings"]);
});

test("the title-bar Run action belongs only to the Containers page", () => {
  assert.equal(desktopChrome.showGlobalRunAction("containers"), true);
  for (const section of ["images", "builds", "compose", "volumes", "networks", "doctor", "settings"]) {
    assert.equal(desktopChrome.showGlobalRunAction(section), false);
  }
});
