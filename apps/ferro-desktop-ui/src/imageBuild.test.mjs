import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import * as imageBuild from "./imageBuild.mjs";

const { buildStepText } = imageBuild;

function findButton(element, label) {
  if (!element || typeof element !== "object") return null;
  if (element.type === "button" && element.props.children === label) return element;
  const children = element.props?.children;
  for (const child of Array.isArray(children) ? children : [children]) {
    const found = findButton(child, label);
    if (found) return found;
  }
  return null;
}

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
      progress: [{ build_id: "build-1", stream: "stdout", text: "Step 2/3 : COPY . ." }],
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

test("missing build binary routes to Doctor through the centralized failure vocabulary", () => {
  assert.deepEqual(imageBuild.buildFailurePresentation("spawn ferrocrate ENOENT"), {
    kind: "binary",
    message: "Ferrocrate isn't installed",
    detail: "spawn ferrocrate ENOENT",
  });
  const markup = renderToStaticMarkup(createElement(imageBuild.BuildHistoryList, {
    builds: [{ id: "build-missing", image: "local/demo", status: "failed", durationMs: 2, progress: [], error: "spawn ferrocrate ENOENT" }],
    onNewBuild: () => {},
    onDoctor: () => {},
  }));
  assert.match(markup, /Open Doctor/);
});

test("build progress frames update only the history row with the matching build ID", () => {
  assert.equal(typeof imageBuild.appendBuildProgress, "function");
  const history = [{
    id: "build-a",
    image: "local/a:latest",
    status: "building",
    durationMs: null,
    progress: [],
  }, {
    id: "build-b",
    image: "local/b:latest",
    status: "succeeded",
    durationMs: 900,
    progress: [{ build_id: "build-b", stream: "stdout", text: "done" }],
  }];

  assert.deepEqual(imageBuild.appendBuildProgress(history, {
    build_id: "build-a",
    stream: "stdout",
    text: "Step 1/2 : FROM alpine",
  }), [{
    ...history[0],
    progress: [{ build_id: "build-a", stream: "stdout", text: "Step 1/2 : FROM alpine" }],
  }, history[1]]);
});

test("licensing dialog explains image-build access without technical account jargon", () => {
  assert.equal(typeof imageBuild.BuildLicensingDialog, "function");
  const markup = renderToStaticMarkup(createElement(imageBuild.BuildLicensingDialog, {
    open: true,
    detail: "missing entitlement for image build",
    onClose: () => {},
    onOpenSettings: () => {},
  }));

  assert.match(markup, /role="dialog"/);
  assert.match(markup, /Image builds aren&#x27;t included in your current plan\./);
  assert.match(markup, /Use an account with image-build access, then try again\./);
  assert.match(markup, /Open technical settings/);
  assert.match(markup, /Technical details/);
  assert.match(markup, /missing entitlement for image build/);
  assert.doesNotMatch(markup, />entitlement</i);
});

test("missing build access exposes the friendly licensing route from its history row", () => {
  const markup = renderToStaticMarkup(createElement(imageBuild.BuildHistoryList, {
    builds: [{
      id: "build-3",
      image: "local/demo:latest",
      status: "failed",
      durationMs: 1300,
      progress: [],
      error: "missing entitlement for image build",
    }],
    onNewBuild: () => {},
    onReviewLicensing: () => {},
  }));

  assert.match(markup, /Your current plan doesn&#x27;t include image builds\./);
  assert.match(markup, />Review licensing<\/button>/);
  assert.match(markup, /<details><summary>Technical details<\/summary>/);
});

test("build invocation uses Tauri's camelCase argument contract", () => {
  assert.equal(typeof imageBuild.buildInvokeArgs, "function");
  assert.deepEqual(imageBuild.buildInvokeArgs("/work/demo", "local/demo:latest", "build-9"), {
    context: "/work/demo",
    tag: "local/demo:latest",
    buildId: "build-9",
  });
});

test("build recovery buttons call their supplied callbacks", () => {
  let starts = 0;
  let licensingDetail = "";
  const element = imageBuild.BuildHistoryList({
    builds: [{
      id: "build-daemon",
      image: "local/daemon:latest",
      status: "failed",
      durationMs: 900,
      progress: [],
      error: "daemon connection refused",
    }, {
      id: "build-license",
      image: "local/license:latest",
      status: "failed",
      durationMs: 900,
      progress: [],
      error: "missing entitlement for image build",
    }],
    onNewBuild: () => {},
    onStart: () => { starts += 1; },
    onReviewLicensing: (detail) => { licensingDetail = detail; },
  });

  const start = findButton(element, "Start");
  const review = findButton(element, "Review licensing");
  assert.ok(start);
  assert.ok(review);
  start.props.onClick();
  review.props.onClick();
  assert.equal(starts, 1);
  assert.equal(licensingDetail, "missing entitlement for image build");
});
