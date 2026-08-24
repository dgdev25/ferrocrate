import test from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import * as iconSystem from "./iconSystem.mjs";

test("the desktop icon vocabulary renders consistent accessible line SVGs", () => {
  assert.equal(typeof iconSystem.Icon, "function");
  for (const name of [
    "box",
    "images",
    "hammer",
    "compose",
    "disk",
    "globe",
    "pulse",
    "gear",
    "play",
    "stop",
    "trash",
    "terminal",
    "search",
    "sun",
    "moon",
    "refresh",
    "more",
    "close",
    "pause",
  ]) {
    const markup = renderToStaticMarkup(createElement(iconSystem.Icon, { name }));
    assert.match(markup, /^<svg/);
    assert.match(markup, /width="18" height="18"/);
    assert.match(markup, /fill="none"/);
    assert.match(markup, /stroke="currentColor"/);
    assert.match(markup, /stroke-width="1.75"/);
    assert.match(markup, /stroke-linecap="round"/);
    assert.match(markup, /stroke-linejoin="round"/);
    assert.match(markup, /aria-hidden="true"/);
  }
});

test("icons accept a consistent compact size without changing stroke styling", () => {
  const markup = renderToStaticMarkup(createElement(iconSystem.Icon, {
    name: "play",
    size: 16,
    className: "action-icon",
  }));
  assert.match(markup, /class="action-icon"/);
  assert.match(markup, /width="16" height="16"/);
  assert.match(markup, /stroke-width="1.75"/);
});
