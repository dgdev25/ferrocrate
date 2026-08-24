import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { PullImageDialog } from "./imageView.mjs";
import { HostPathField, ResourceCreateDialog } from "./resourcePages.mjs";

const appSource = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");

function assertExplicitLabels(markup) {
  const controls = [...markup.matchAll(/<(input|textarea|select)\b([^>]*)>/g)];
  assert.ok(controls.length > 0, "expected at least one form control");
  for (const [, element, attributes] of controls) {
    const id = attributes.match(/\bid="([^"]+)"/)?.[1];
    const ariaLabel = attributes.match(/\baria-label="([^"]+)"/)?.[1];
    assert.ok(
      ariaLabel || (id && markup.includes(`for="${id}"`)),
      `${element} must have aria-label or a stable id with a matching label`,
    );
  }
}

test("every App dialog control has a stable explicit accessible name", () => {
  const dialogRegion = appSource.slice(appSource.indexOf("{doctorDialogOpen ?"));
  const controls = [...dialogRegion.matchAll(/<(input|textarea|select)\b([^>]*)>/g)];
  assert.equal(controls.length, 25, "update the dialog inventory when controls are added or removed");
  for (const [, element, attributes] of controls) {
    assert.match(attributes, /\b(?:id|aria-label)=/, `${element} must have a stable id or aria-label`);
  }

  const expectedAssociations = [
    ["doctor-fix", "Apply safe fixes"],
    ["doctor-bootstrap", "Prepare missing components"],
    ["doctor-dry-run", "Preview changes only"],
    ["doctor-confirm", "Allow changes that need confirmation"],
    ["account-release-service-url", "Release service URL"],
    ["account-token-service-url", "Token service URL"],
    ["account-session-service-url", "Session service URL"],
    ["account-customer-id", "Customer ID"],
    ["account-access-token", "Access token (optional)"],
    ["account-session-token", "Session token"],
    ["run-container-image", "Image"],
    ["run-container-name", "Name"],
    ["run-container-command", "Command (optional)"],
    ["run-container-pull-missing", "Pull image if it is not available locally"],
    ["run-container-environment", "Environment (one KEY=value per line)"],
    ["run-container-memory", "Memory (MB)"],
    ["run-container-cpus", "CPUs"],
    ["build-image-reference", "Image reference"],
    ["registry-server", "Registry server"],
    ["registry-username", "Username"],
    ["registry-password", "Password or token"],
  ];

  for (const [id, label] of expectedAssociations) {
    assert.match(appSource, new RegExp(`<label[^>]*htmlFor="${id}"[^>]*>`));
    assert.match(appSource, new RegExp(`<span>${label.replace(/[()]/g, "\\$&")}</span>`));
    assert.match(appSource, new RegExp(`<(?:input|textarea)[^>]*id="${id}"`));
  }
});

test("shared dialog components explicitly label every rendered control", () => {
  const noop = () => {};
  const surfaces = [
    createElement(PullImageDialog, { open: true, imageTarget: "alpine", progress: "", failure: null, busy: false, onCancel: noop, onImageTargetChange: noop, onPull: noop }),
    createElement(ResourceCreateDialog, { kind: "network", name: "app", subnet: "", onNameChange: noop, onSubnetChange: noop, onCancel: noop, onCreate: noop }),
    createElement(ResourceCreateDialog, { kind: "volume", name: "data", onNameChange: noop, onCancel: noop, onCreate: noop }),
    createElement(HostPathField, { label: "Build context directory", kind: "directory", value: "/tmp", onChange: noop }),
  ];

  for (const surface of surfaces) assertExplicitLabels(renderToStaticMarkup(surface));
});
