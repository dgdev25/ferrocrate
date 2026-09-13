import test from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { AccountDialog, BuildImageDialog, credentialErrorMessage, DoctorDialog, InstallDialog, RegistryDialog, RunContainerDialog } from "./dialogForms.mjs";
import { ComposeFileDialog } from "./composeView.mjs";
import { PullImageDialog } from "./imageView.mjs";
import { BuildLicensingDialog } from "./imageBuild.mjs";
import { LicensingDialog, ResourceCreateDialog } from "./resourcePages.mjs";
import { DialogFocusScope } from "./modalFocus.mjs";

test("standalone modal families connect shared keyboard isolation and close handling", () => {
  const close = () => {};
  for (const element of [
    ComposeFileDialog({ open: true, value: "", onChange: close, onCancel: close }),
    PullImageDialog({ open: true, imageTarget: "", onImageTargetChange: close, onCancel: close }),
    ResourceCreateDialog({ kind: "volume", name: "", onNameChange: close, onCancel: close }),
    ResourceCreateDialog({ kind: "network", name: "", onNameChange: close, onSubnetChange: close, onCancel: close }),
    LicensingDialog({ open: true, onClose: close }),
    BuildLicensingDialog({ open: true, onClose: close }),
  ]) {
    assert.equal(element.type, DialogFocusScope);
    assert.equal(element.props.onClose, close);
    assert.ok(element.props.dialogId);
    assert.doesNotMatch(renderToStaticMarkup(element), /autofocus/i);
  }
});
import { submitRunContainer } from "./runContainer.mjs";

const noop = () => {};

function assertRenderedControlsAreExplicitlyNamed(markup) {
  const controls = [...markup.matchAll(/<(input|textarea|select)\b([^>]*)>/g)];
  const ids = [...markup.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(ids).size, ids.length, "every rendered control id must be unique");
  for (const [, element, attributes] of controls) {
    const id = attributes.match(/\bid="([^"]+)"/)?.[1];
    const ariaLabel = attributes.match(/\baria-label="([^"]+)"/)?.[1];
    if (ariaLabel) continue;
    assert.ok(id, `${element} must have aria-label or an id`);
    const labels = [...markup.matchAll(new RegExp(`<label\\b[^>]*for="${id}"[^>]*>([\\s\\S]*?)<\\/label>`, "g"))];
    assert.equal(labels.length, 1, `${id} must resolve to exactly one label`);
    assert.ok(labels[0][1].replace(/<[^>]+>/g, "").trim(), `${id} label must contain text`);
  }
}

function appDialogProps() {
  return {
    doctor: { open: true, fix: true, bootstrap: false, dryRun: true, confirm: false, busy: false, onFixChange: noop, onBootstrapChange: noop, onDryRunChange: noop, onConfirmChange: noop, onCancel: noop, onRun: noop },
    account: { open: true, releaseBaseUrl: "", tokenEndpoint: "", issuanceEndpoint: "", customerId: "", accessToken: "", sessionToken: "", authLoading: false, accountConnected: false, plan: null, expiresAt: null, entitlement: {}, onReleaseBaseUrlChange: noop, onTokenEndpointChange: noop, onIssuanceEndpointChange: noop, onCustomerIdChange: noop, onAccessTokenChange: noop, onSessionTokenChange: noop, onClose: noop, onSaveBackend: noop, onConnect: noop, onDisconnect: noop, onRefresh: noop, onSaveSession: noop },
    run: { open: true, draft: { image: "alpine:latest", name: "", command: "", pullIfMissing: true, ports: [{ host: "", container: "" }], volumes: [{ source: "", target: "" }], environment: "", memoryMb: "", cpus: "" }, busy: false, error: null, onDraftChange: noop, onCancel: noop, onRun: noop },
    build: { open: true, context: "/tmp/build", tag: "local/build:latest", dialogAvailable: false, busy: false, onContextChange: noop, onChooseContext: noop, onTagChange: noop, onCancel: noop, onBuild: noop },
    registry: { open: true, target: "registry.example.com", username: "", password: "", status: null, accountName: "", busy: false, loading: false, onTargetChange: noop, onUsernameChange: noop, onPasswordChange: noop, onCancel: noop, onCheck: noop, onLogout: noop, onLogin: noop },
  };
}

test("account failures remain visible inside the editable modal", () => {
  const props = appDialogProps().account;
  for (const extra of [{ error: "Token service URL must be valid" },
    { entitlement: { status: "error", message: "token endpoint rejected session" } }]) {
    const markup = renderToStaticMarkup(createElement(AccountDialog, { ...props, ...extra }));
    assert.match(markup, /role="alert"/);
    assert.match(markup, /Token service URL must be valid|token endpoint rejected session/);
    assert.match(markup, /id="account-token-service-url"/);
  }
});

test("credential failures show safe actionable headlines without copying server responses", () => {
  assert.match(credentialErrorMessage("Error: Token service URL must be a valid HTTP or HTTPS URL"), /Token service URL.*HTTP or HTTPS/);
  assert.match(credentialErrorMessage("Error: Session token must be a signed JWT with a future expiry"), /valid.*unexpired/i);
  assert.match(credentialErrorMessage("Error: token endpoint request failed: secret-response"), /cannot be reached/);
  assert.match(credentialErrorMessage("Error: issuance_endpoint is not configured"), /Session service URL/);
  const rejection = credentialErrorMessage("error: login: registry rejected credentials: 401 secret-response");
  assert.match(rejection, /username.*password/i);
  assert.doesNotMatch(rejection, /secret-response/);
  assert.equal(credentialErrorMessage("unexpected secret-response"), undefined);
});

test("registry rejected credentials stay visible beside the retry form", () => {
  const markup = renderToStaticMarkup(createElement(RegistryDialog, {
    ...appDialogProps().registry, error: "login: registry rejected credentials: 401",
  }));
  assert.match(markup, /role="alert"/);
  assert.match(markup, /Check the username and password/);
  assert.match(markup, /id="registry-password"/);
});

test("every rendered dialog control has one stable explicit accessible name", () => {
  const props = appDialogProps();
  const markup = renderToStaticMarkup(createElement("div", null,
    createElement(DoctorDialog, props.doctor),
    createElement(AccountDialog, props.account),
    createElement(RunContainerDialog, props.run),
    createElement(BuildImageDialog, props.build),
    createElement(InstallDialog, { open: true, installerResult: null, busy: false, onClose: noop, onPreview: noop, onInstall: noop }),
    createElement(RegistryDialog, props.registry),
    createElement(PullImageDialog, { open: true, imageTarget: "alpine", progress: "", failure: null, busy: false, onCancel: noop, onImageTargetChange: noop, onPull: noop }),
    createElement(ResourceCreateDialog, { kind: "network", name: "app", subnet: "", onNameChange: noop, onSubnetChange: noop, onCancel: noop, onCreate: noop }),
    createElement(ResourceCreateDialog, { kind: "volume", name: "data", onNameChange: noop, onCancel: noop, onCreate: noop }),
    createElement(BuildLicensingDialog, { open: true, detail: "detail", onClose: noop, onOpenSettings: noop }),
    createElement(LicensingDialog, { open: true, detail: "detail", onClose: noop, onOpenSettings: noop }),
  ));
  assertRenderedControlsAreExplicitlyNamed(markup);
  assert.equal([...markup.matchAll(/<(?:input|textarea|select)\b/g)].length, 30);
});

function findElement(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (predicate(node)) return node;
  const children = Array.isArray(node.props?.children) ? node.props.children : [node.props?.children];
  for (const child of children) {
    const match = findElement(child, predicate);
    if (match) return match;
  }
  return null;
}

test("Run container edits invoke the native command with the entered name and parsed command", async () => {
  const props = appDialogProps().run;
  const calls = [];
  props.onDraftChange = (draft) => { props.draft = draft; };
  props.onRun = (payload) => submitRunContainer({
    invoke: async (command, invokePayload) => {
      calls.push({ command, payload: invokePayload });
      return { ok: true, code: 0, message: "", stdout: "", stderr: "" };
    },
    payload,
    begin: () => true,
    onBegin: noop,
    onResult: noop,
    onError: assert.fail,
    onSuccess: noop,
    finish: noop,
  });

  let tree = RunContainerDialog(props);
  findElement(tree, (node) => node.props?.id === "run-container-name").props.onChange({ target: { value: "sentinel-worker" } });
  tree = RunContainerDialog(props);
  findElement(tree, (node) => node.props?.id === "run-container-command").props.onChange({ target: { value: "printf sentinel-command" } });
  tree = RunContainerDialog(props);
  await findElement(tree, (node) => node.props?.id === "run-container-submit").props.onClick();

  assert.equal(calls[0].command, "run_new_container");
  assert.equal(calls[0].payload.name, "sentinel-worker");
  assert.deepEqual(calls[0].payload.command, ["printf", "sentinel-command"]);
});

test("launcher starts with an explicit preset or custom choice and preserves custom draft settings", () => {
  const props = { ...appDialogProps().run, onPreset: noop };
  props.onDraftChange = draft => { props.draft = draft; };
  let tree = RunContainerDialog(props);
  assert.equal(findElement(tree, node => node.props?.id === "run-container-submit").props.disabled, true);
  const custom = findElement(tree, node => node.type === "button" && node.props.children === "Custom image");
  custom.props.onClick();
  tree = RunContainerDialog(props);
  assert.equal(findElement(tree, node => node.props?.id === "run-container-submit").props.disabled, false);
  assert.equal(props.draft.image, "alpine:latest");
  assert.equal(props.draft.pullIfMissing, true);
  const markup = renderToStaticMarkup(tree);
  assert.match(markup, /PostgreSQL database/);
  assert.match(markup, /Redis cache/);
  assert.match(markup, /Nginx web server/);
});

test("preset summary keeps credentials private and Advanced retains editable launch settings", async () => {
  const props = { ...appDialogProps().run, onPreset: noop };
  props.draft = { ...props.draft, image: "postgres:17-alpine", name: "ferro-postgres-test", ports: [{ host: "55432", container: "5432" }], volumes: [{ source: "db-data", target: "/var/lib/postgresql/data" }], environment: "POSTGRES_PASSWORD=generated-secret" };
  props.onDraftChange = draft => { props.draft = draft; };
  let payload;
  props.onRun = value => { payload = value; };
  let tree = RunContainerDialog(props);
  const summary = findElement(tree, node => node.props?.["aria-label"] === "Launch setup");
  const markup = renderToStaticMarkup(summary);
  assert.match(markup, /postgres:17-alpine/);
  assert.match(markup, /localhost:55432/);
  assert.match(markup, /db-data/);
  assert.doesNotMatch(markup, /generated-secret/);
  findElement(tree, node => node.props?.id === "run-container-image").props.onChange({ target: { value: "postgres:18-alpine" } });
  tree = RunContainerDialog(props);
  assert.equal(findElement(tree, node => node.props?.id === "run-container-submit").props.disabled, false);
  await findElement(tree, node => node.props?.id === "run-container-submit").props.onClick();
  assert.equal(payload.image, "postgres:18-alpine");
  assert.deepEqual(payload.ports, ["55432:5432"]);
  assert.deepEqual(payload.volumes, ["db-data:/var/lib/postgresql/data"]);
  assert.deepEqual(payload.environment, ["POSTGRES_PASSWORD=generated-secret"]);
  assert.equal("launcherPreset" in payload, false);
  props.error = "Memory must be a positive number of MB";
  tree = RunContainerDialog(props);
  assert.equal(findElement(tree, node => node.type === "details" && node.props.className?.includes("launcher-advanced")).props.open, true);
});
