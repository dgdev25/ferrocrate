import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import * as imageView from "./imageView.mjs";

test("image rows format byte sizes and Unix creation times for the table", () => {
  assert.deepEqual(imageView.parseImageRows(JSON.stringify([{
    Id: "sha256:abc",
    RepoTags: ["docker.io/library/alpine:latest"],
    Size: 1572864,
    Created: 1700000000,
  }])), [{
    id: "sha256:abc",
    reference: "docker.io/library/alpine:latest",
    size: "1.5 MB",
    created: "2023-11-14 22:13 UTC",
  }]);
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
  assert.match(unknown, /We couldn&#x27;t pull this image\./);
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
