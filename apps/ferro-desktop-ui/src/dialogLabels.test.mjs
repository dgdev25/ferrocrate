import test from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { AccountDialog, BuildImageDialog, DoctorDialog, InstallDialog, RegistryDialog, RunContainerDialog } from "./dialogForms.mjs";
import { BuildLicensingDialog } from "./imageBuild.mjs";
import { PullImageDialog } from "./imageView.mjs";
import { LicensingDialog, ResourceCreateDialog } from "./resourcePages.mjs";
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
