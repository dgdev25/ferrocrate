import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import * as imageBuild from "./imageBuild.mjs";

const { buildStepText } = imageBuild;

test("build progress unwraps daemon stream frames and preserves failures", () => {
  assert.equal(buildStepText('{"stream":"Step 1/2 : FROM alpine\\n"}'), "Step 1/2 : FROM alpine");
  assert.equal(buildStepText('{"error":"executor failed"}'), "executor failed");
  assert.equal(buildStepText("plain stderr output"), "plain stderr output");
});

test("rendered builds history keeps one primary action and shows live progress in its row", () => {
  assert.equal(typeof imageBuild.BuildHistoryList, "function");
  const markup = renderToStaticMarkup(createElement(imageBuild.BuildHistoryList, {
    builds: [{
      id: "build-1",
      image: "local/demo:latest",
      status: "building",
      durationMs: null,
      progress: [{ stream: "stdout", text: "Step 2/3 : COPY . ." }],
    }],
    onNewBuild: () => {},
  }));

  assert.match(markup, /<table>/);
  assert.match(markup, /Image/);
  assert.match(markup, /Status/);
  assert.match(markup, /Duration/);
  assert.match(markup, /local\/demo:latest/);
  assert.match(markup, /Building/);
  assert.match(markup, /Building…/);
  assert.match(markup, /Step 2\/3 : COPY \. \./);
  assert.equal((markup.match(/btn btn-primary/g) || []).length, 1);
});

test("rendered empty builds state teaches how to start a build with one action", () => {
  assert.equal(typeof imageBuild.BuildHistoryList, "function");
  const markup = renderToStaticMarkup(createElement(imageBuild.BuildHistoryList, {
    builds: [],
    onNewBuild: () => {},
  }));

  assert.match(markup, /Ready to build an image\./);
  assert.match(markup, /Choose a directory and image tag to start a new build\./);
  assert.match(markup, />New build<\/button>/);
  assert.equal((markup.match(/btn btn-primary/g) || []).length, 1);
});

test("failed builds explain known daemon failures and keep the original detail disclosed", () => {
  assert.equal(typeof imageBuild.buildFailurePresentation, "function");
  const markup = renderToStaticMarkup(createElement(imageBuild.BuildHistoryList, {
    builds: [{
      id: "build-2",
      image: "local/demo:latest",
      status: "failed",
      durationMs: 1200,
      progress: [],
      error: "daemon connection refused",
    }],
    onNewBuild: () => {},
    onStart: () => {},
  }));

  assert.match(markup, /Ferrocrate isn&#x27;t running/);
  assert.match(markup, />Start<\/button>/);
  assert.match(markup, /Technical details/);
  assert.match(markup, /daemon connection refused/);
});
