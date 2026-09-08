import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import * as imageView from "./imageView.mjs";

const imageRecords = await readFile(join(dirname(fileURLToPath(import.meta.url)), "fixtures/ferrocrate-images.json"), "utf8");

test("image rows format byte sizes and Unix creation times for the table", () => {
  assert.deepEqual(imageView.parseImageRows(imageRecords), [{
    id: "sha256:d529dd0c6e5597ac7e4a3e2dea65c3fcc6173f4cae713c409265c1dd9914a11b",
    reference: "alpine:latest",
    fullReference: "registry-1.docker.io/library/alpine:latest",
    size: "3.7 MB",
    created: "2026-08-24 23:39 UTC",
  }]);
});

test("image usage includes stopped container references and normalized registry names", () => {
  const row = imageView.parseImageRows('[{"RepoTags":["registry-1.docker.io/library/alpine:latest"]}]')[0];
  assert.equal(imageView.imageIsUsed(row, ["alpine:latest"]), true);
  assert.equal(imageView.imageIsUsed(row, ["other:latest"]), false);
});

test("pull failures give people a recovery path while retaining the technical detail", () => {
  assert.equal(typeof imageView.pullFailurePresentation, "function");
  assert.deepEqual(imageView.pullFailurePresentation("daemon connection refused"), {
    kind: "daemon",
    message: "Ferrocrate isn't running",
    detail: "daemon connection refused",
  });
  assert.deepEqual(imageView.pullFailurePresentation("missing entitlement for image pull"), {
    kind: "license",
    message: "Your current plan doesn't include image pulls.",
    detail: "missing entitlement for image pull",
  });
  assert.deepEqual(imageView.pullFailurePresentation("spawn ferrocrate ENOENT"), {
    kind: "binary",
    message: "Ferrocrate isn't installed",
    detail: "spawn ferrocrate ENOENT",
  });
});

test("a successful pull closes the blocking dialog while a failed pull stays actionable", () => {
  assert.deepEqual(imageView.pullCompletionState({ ok: true, stderr: "" }), {
    open: false,
    progress: "",
    failure: null,
  });
  assert.deepEqual(imageView.pullCompletionState({ ok: false, stderr: "registry timed out" }), {
    open: true,
    progress: "",
    failure: {
      kind: "generic",
      message: "Something went wrong",
      detail: "registry timed out",
    },
  });
});

test("rendered pull dialog exposes progress and accessible recovery actions", () => {
  assert.equal(typeof imageView.PullImageDialog, "function");
  const loading = renderToStaticMarkup(createElement(imageView.PullImageDialog, {
    open: true,
    imageTarget: "alpine:latest",
    progress: "Pull in progress. This may take a moment.",
    onImageTargetChange: () => {},
  }));
  assert.match(loading, /role="dialog"/);
  assert.match(loading, /Pull progress/);
  assert.match(loading, /Pull in progress\. This may take a moment\./);

  const daemon = renderToStaticMarkup(createElement(imageView.PullImageDialog, {
    open: true,
    imageTarget: "alpine:latest",
    failure: imageView.pullFailurePresentation("daemon connection refused"),
    onImageTargetChange: () => {},
  }));
  assert.match(daemon, /Ferrocrate isn&#x27;t running/);
  assert.match(daemon, />Start<\/button>/);
  assert.match(daemon, /<details>/);
  assert.match(daemon, /Technical details/);
  assert.match(daemon, /daemon connection refused/);

  const license = renderToStaticMarkup(createElement(imageView.PullImageDialog, {
    open: true,
    imageTarget: "alpine:latest",
    failure: imageView.pullFailurePresentation("missing entitlement for image pull"),
    onImageTargetChange: () => {},
  }));
  assert.match(license, /Your current plan doesn&#x27;t include image pulls\./);
  assert.match(license, /Review licensing/);

  const unknown = renderToStaticMarkup(createElement(imageView.PullImageDialog, {
    open: true,
    imageTarget: "alpine:latest",
    failure: imageView.pullFailurePresentation("registry timed out"),
    onImageTargetChange: () => {},
  }));
  assert.match(unknown, /Something went wrong/);
  assert.doesNotMatch(unknown, />Start<\/button>/);
  assert.doesNotMatch(unknown, /Review licensing/);

  const missing = renderToStaticMarkup(createElement(imageView.PullImageDialog, {
    open: true,
    imageTarget: "alpine:latest",
    failure: imageView.pullFailurePresentation("spawn ferrocrate ENOENT"),
    onImageTargetChange: () => {},
    onDoctor: () => {},
  }));
  assert.match(missing, /Open Doctor/);
});

test("rendered image page states have exactly one primary pull CTA", () => {
  assert.equal(typeof imageView.ImagePagePullAction, "function");
  assert.equal(typeof imageView.ImageEmptyState, "function");
  const populated = renderToStaticMarkup(createElement("div", null,
    createElement(imageView.ImagePagePullAction, { hasImages: true }),
    createElement(imageView.ImageEmptyState, { hasImages: true }),
  ));
  const empty = renderToStaticMarkup(createElement("div", null,
    createElement(imageView.ImagePagePullAction, { hasImages: false }),
    createElement(imageView.ImageEmptyState, { hasImages: false }),
  ));
  assert.equal((populated.match(/btn btn-primary/g) || []).length, 1);
  assert.equal((empty.match(/btn btn-primary/g) || []).length, 1);
  assert.match(empty, /There are no local images\./);
});

test('digest-pinned running containers mark their tagged image in use', () => {
  const digest = `sha256:${'a'.repeat(64)}`;
  const row = imageView.parseImageRows(JSON.stringify([{ Id: digest, RepoTags: ['registry-1.docker.io/library/alpine:latest'] }]))[0];
  assert.equal(imageView.imageIsUsed(row, [`registry-1.docker.io/library/alpine@${digest}`]), true);
  assert.equal(imageView.imageIsUsed(row, [digest]), true);
  assert.equal(imageView.imageIsUsed(row, [`registry-1.docker.io/library/alpine@sha256:${'b'.repeat(64)}`]), false);
});
