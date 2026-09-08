import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import * as resourcePages from "./resourcePages.mjs";

function findButton(element, label) {
  if (!element || typeof element !== "object") return null;
  if (typeof element.type === "function") return findButton(element.type(element.props), label);
  if (element.type === "button" && element.props.children === label) return element;
  const children = element.props?.children;
  for (const child of Array.isArray(children) ? children : [children]) {
    const found = findButton(child, label);
    if (found) return found;
  }
  return null;
}

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

test("web mode renders a validated daemon-host path fallback when dialogs are unavailable", () => {
  assert.equal(typeof resourcePages.HostPathField, "function");
  assert.equal(resourcePages.hostPathError("relative/compose.yml", "file"), "Enter an absolute file path on the daemon host.");
  assert.equal(resourcePages.hostPathError("/srv/app/compose.yml", "file"), null);
  assert.equal(resourcePages.hostPathError("C:\\work\\app", "directory"), null);

  const invalid = renderToStaticMarkup(createElement(resourcePages.HostPathField, {
    label: "Compose file",
    kind: "file",
    value: "relative/compose.yml",
    dialogAvailable: false,
    submitLabel: "Load Compose file",
    onChange: () => {},
  }));
  assert.match(invalid, /absolute file path on the daemon host/);
  assert.match(invalid, /aria-invalid="true"/);
  assert.match(invalid, /Load Compose file/);
  assert.match(invalid, /disabled=""/);
  assert.doesNotMatch(invalid, /Choose file/);

  const valid = renderToStaticMarkup(createElement(resourcePages.HostPathField, {
    label: "Build context directory",
    kind: "directory",
    value: "/srv/app",
    dialogAvailable: false,
    onChange: () => {},
  }));
  assert.match(valid, /value="\/srv\/app"/);
  assert.doesNotMatch(valid, /aria-invalid="true"/);
  assert.doesNotMatch(valid, /Choose directory/);
});

test("resource page state keeps empty and populated controls mutually exclusive while a loaded Compose project stays populated", () => {
  assert.equal(typeof resourcePages.resourcePageState, "function");
  assert.deepEqual(resourcePages.resourcePageState("volumes", 0), {
    content: "empty",
    primaryAction: null,
  });
  assert.deepEqual(resourcePages.resourcePageState("volumes", 2), {
    content: "table",
    primaryAction: "create-volume",
  });
  assert.deepEqual(resourcePages.resourcePageState("compose", 0, { loaded: false }), {
    content: "empty",
    primaryAction: null,
  });
  assert.deepEqual(resourcePages.resourcePageState("compose", 0, { loaded: true }), {
    content: "table",
    primaryAction: "choose-compose-file",
  });
  assert.deepEqual(resourcePages.resourcePageState("compose", 3), {
    content: "table",
    primaryAction: "choose-compose-file",
  });
});

test("rendered empty pages keep one primary CTA and invoke always-reachable overflow actions", () => {
  assert.equal(typeof resourcePages.EmptyResourcePage, "function");
  let refreshes = 0;
  let prunes = 0;
  const props = {
    section: "volumes",
    count: 0,
    overflowLabel: "More volume actions",
    actions: [
      { label: "Refresh volumes", onAction: () => { refreshes += 1; } },
      { label: "Prune unused volumes", danger: true, onAction: () => { prunes += 1; } },
    ],
    onPrimary: () => {},
  };
  const markup = renderToStaticMarkup(createElement(resourcePages.EmptyResourcePage, props));
  assert.match(markup, /More volume actions/);
  assert.match(markup, /Refresh volumes/);
  assert.match(markup, /Prune unused volumes/);
  assert.match(markup, />Create a volume<\/button>/);
  assert.equal((markup.match(/btn btn-primary/g) || []).length, 1);

  findButton(resourcePages.EmptyResourcePage(props), "Refresh volumes").props.onClick();
  findButton(resourcePages.EmptyResourcePage(props), "Prune unused volumes").props.onClick();
  assert.equal(refreshes, 1);
  assert.equal(prunes, 1);
});

test("filtered container state replaces the table instead of rendering beneath it", () => {
  assert.equal(typeof resourcePages.containerContentState, "function");
  assert.equal(resourcePages.containerContentState(0, 0, ""), "empty");
  assert.equal(resourcePages.containerContentState(2, 0, "web"), "filtered-empty");
  assert.equal(resourcePages.containerContentState(2, 1, "web"), "table");
});

test("global resource search filters every named desktop resource", () => {
  const rows = [{ name: "database" }, { name: "frontend" }];
  assert.deepEqual(resourcePages.filterNamedResources(rows, "DATA", (row) => row.name), [{ name: "database" }]);
  assert.deepEqual(resourcePages.filterNamedResources(rows, "", (row) => row.name), rows);
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

test("runtime surface distinguishes initial loading, known daemon absence, and ordinary command failures", () => {
  assert.equal(typeof resourcePages.runtimeSurfaceState, "function");
  assert.equal(typeof resourcePages.isDaemonUnavailable, "function");
  const unavailable = {
    containers: { ok: false, stderr: "Cannot connect to the Ferrocrate daemon: connection refused" },
    images: { ok: false, stderr: "dial unix /run/ferrocrate.sock: connection refused" },
  };
  const ordinaryFailure = {
    containers: { ok: false, stderr: "container output was invalid JSON" },
    images: { ok: true, stderr: "" },
  };
  const available = { containers: { ok: true }, images: { ok: true } };
  assert.equal(resourcePages.runtimeSurfaceState(null, "containers"), "loading");
  assert.equal(resourcePages.runtimeSurfaceState(unavailable, "containers"), "first-run");
  assert.equal(resourcePages.runtimeSurfaceState(unavailable, "doctor"), "resource");
  assert.equal(resourcePages.runtimeSurfaceState(ordinaryFailure, "containers"), "resource");
  assert.equal(resourcePages.runtimeSurfaceState(available, "containers"), "resource");
  assert.equal(resourcePages.isDaemonUnavailable("container output was invalid JSON"), false);
  assert.equal(resourcePages.isDaemonUnavailable("No such file: /tmp/compose.yml"), false);
});

test("first-run transition closes every runtime dialog and resets resource dialog state", () => {
  assert.equal(typeof resourcePages.applyRuntimeSurfaceTransition, "function");
  assert.equal(typeof resourcePages.resourceDialogTransition, "function");
  const calls = [];
  assert.equal(resourcePages.applyRuntimeSurfaceTransition("resource", { closeRun: () => calls.push("run") }), false);
  assert.equal(resourcePages.applyRuntimeSurfaceTransition("first-run", {
    closeRun: () => calls.push("run"),
    closePull: () => calls.push("pull"),
    closeBuild: () => calls.push("build"),
    closeRegistry: () => calls.push("registry"),
    closeResource: () => calls.push("resource"),
    closeLicensing: () => calls.push("licensing"),
  }), true);
  assert.deepEqual(calls, ["run", "pull", "build", "registry", "resource", "licensing"]);
  assert.deepEqual(resourcePages.resourceDialogTransition({ kind: "volume", name: "data", subnet: "", error: "failed" }, "close-dialog"), {
    kind: null,
    name: "",
    subnet: "",
    error: null,
  });
  assert.deepEqual(resourcePages.resourceDialogTransition({ kind: null, name: "stale", subnet: "stale", error: "stale" }, "open-network"), {
    kind: "network",
    name: "",
    subnet: "",
    error: null,
  });
});

test("successful first-run start refreshes all runtime-backed resources before returning", async () => {
  assert.equal(typeof resourcePages.runFirstRunRecovery, "function");
  const calls = [];
  const result = await resourcePages.runFirstRunRecovery({
    start: async () => { calls.push("start"); return { ok: true, code: 0, stdout: "started", stderr: "" }; },
    refreshSnapshot: async () => { calls.push("snapshot"); },
    refreshVolumes: async () => { calls.push("volumes"); },
    refreshNetworks: async () => { calls.push("networks"); },
    refreshCompose: async () => { calls.push("compose"); },
  });
  assert.equal(result.ok, true);
  assert.equal(calls[0], "start");
  assert.deepEqual(new Set(calls.slice(1)), new Set(["snapshot", "volumes", "networks", "compose"]));
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

test("action failures can show a clean message while retaining raw proxy details", () => {
  const markup = renderToStaticMarkup(createElement(resourcePages.ActionErrorNotice, {
    error: "restart: demo: io error: Permission denied",
    humanMessage: "restart: demo: io error: Permission denied",
    technicalDetail: "\u001b[2m2026-08-24T17:09:02Z WARN runtime noise\u001b[0m\nrestart: demo: io error: Permission denied\nStatus 1",
  }));
  assert.match(markup, /<strong>restart: demo: io error: Permission denied<\/strong>/);
  assert.match(markup, /2026-08-24T17:09:02Z WARN runtime noise/);
});

test("unknown and missing-binary failures use human titles and keep recovery reachable", () => {
  assert.deepEqual(resourcePages.failurePresentation("ferrocrate: command not found"), {
    kind: "binary",
    message: "Ferrocrate isn't installed",
    detail: "ferrocrate: command not found",
  });
  assert.equal(resourcePages.failurePresentation("unexpected parse failure").message, "Something went wrong");
  let doctor = 0;
  const markup = renderToStaticMarkup(createElement(resourcePages.ActionErrorNotice, {
    error: "spawn ferrocrate ENOENT",
    onDoctor: () => { doctor += 1; },
  }));
  assert.match(markup, /Open Doctor/);
  findButton(resourcePages.ActionErrorNotice({ error: "spawn ferrocrate ENOENT", onDoctor: () => { doctor += 1; } }), "Open Doctor").props.onClick();
  assert.equal(doctor, 1);
});

test("dialog error recovery buttons invoke daemon and licensing callbacks with detail", () => {
  let starts = 0;
  let licensingDetail = "";
  const daemon = resourcePages.ResourceCreateDialog({
    kind: "volume",
    name: "data",
    error: "daemon connection refused",
    onStart: () => { starts += 1; },
  });
  const license = resourcePages.ResourceCreateDialog({
    kind: "network",
    name: "app",
    error: "missing entitlement for networks",
    onReviewLicensing: (detail) => { licensingDetail = detail; },
  });
  findButton(daemon, "Start Ferrocrate").props.onClick();
  findButton(license, "Review licensing").props.onClick();
  assert.equal(starts, 1);
  assert.equal(licensingDetail, "missing entitlement for networks");
});

test("friendly licensing dialog avoids account jargon and invokes technical settings secondarily", () => {
  assert.equal(typeof resourcePages.LicensingDialog, "function");
  let settings = 0;
  const props = {
    open: true,
    detail: "missing entitlement for container run",
    onClose: () => {},
    onOpenSettings: () => { settings += 1; },
  };
  const markup = renderToStaticMarkup(createElement(resourcePages.LicensingDialog, props));
  assert.match(markup, /isn&#x27;t included in your current plan/);
  assert.match(markup, /Open technical settings/);
  assert.match(markup, /<details>/);
  assert.doesNotMatch(markup.split("<details>")[0], /entitlement/i);
  findButton(resourcePages.LicensingDialog(props), "Open technical settings").props.onClick();
  assert.equal(settings, 1);
});

test("initial bridge failure has an actionable unavailable state instead of loading forever", () => {
  assert.equal(resourcePages.runtimeSurfaceState(null, "containers", "Connection refused"), "unavailable");
  assert.equal(resourcePages.runtimeSurfaceState(null, "containers"), "loading");
  assert.equal(resourcePages.runtimeSurfaceState(null, "doctor", "Connection refused"), "resource");
});
