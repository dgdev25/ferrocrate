import { createElement as h } from "react";
import { DialogFocusScope } from "./modalFocus.mjs";
import { Icon } from "./iconSystem.mjs";
import { buildRunContainerInvokeArgs, LAUNCHER_PRESETS } from "./runContainer.mjs";
import { ActionErrorNotice, HostPathField, hostPathError } from "./resourcePages.mjs";

function field(id, label, inputProps, className, element = "input") {
  return h("label", { htmlFor: id, className },
    h("span", null, label),
    h(element, { id, ...inputProps }),
  );
}

export function credentialErrorMessage(error) {
  const detail = String(error || "").replace(/^error:\s*/i, "");
  const url = detail.match(/^(Release|Token|Session) service URL must be/);
  if (url) return `${url[1]} service URL must use HTTP or HTTPS, with no credentials or fragment.`;
  if (/session token must be a signed JWT|session token is required|session.*expired/i.test(detail)) return "Enter a valid, unexpired session token.";
  if (/issuance_endpoint is not configured/i.test(detail)) return "Enter and save the Session service URL before connecting an account.";
  if (/customer_id is required/i.test(detail)) return "Enter your Customer ID before connecting an account.";
  if (/Save the service connection before saving a session/i.test(detail)) return "Save the service connection before saving a session.";
  if (/keyring|secret service|NoStorageAccess/i.test(detail)) return "The credential store is unavailable. Unlock your keyring and try again.";
  if (/token endpoint request failed|session issuance request failed|error sending request|connection refused/i.test(detail)) return "The service cannot be reached. Check the service address and try again.";
  if (/token endpoint rejected session|session issuance failed/i.test(detail)) return "The account service rejected the session. Check your token or account details and try again.";
  if (/registry rejected credentials/i.test(detail)) return "Registry sign-in failed. Check the username and password or token, then try again.";
  return undefined;
}

function dialog(open, id, className, eyebrow, title, closeLabel, onClose, content, actions) {
  if (!open) return null;
  return h(DialogFocusScope, { dialogId: id, onClose },
    h("div", { className: "modal-backdrop", role: "presentation" },
      h("section", { className, role: "dialog", "aria-modal": true, "aria-labelledby": id, tabIndex: -1 },
        h("div", { className: "drawer-header" },
          h("div", null, h("p", { className: "eyebrow" }, eyebrow), h("h2", { id }, title)),
          h("button", { className: "btn btn-secondary", onClick: onClose }, closeLabel),
        ),
        content,
        actions,
      ),
    ),
  );
}

export function DoctorDialog({ open, fix, bootstrap, dryRun, confirm, busy, onFixChange, onBootstrapChange, onDryRunChange, onConfirmChange, onCancel, onRun }) {
  const option = (id, label, checked, onChange) => h("label", { htmlFor: id },
    h("input", { id, type: "checkbox", checked, onChange }), h("span", null, label),
  );
  return dialog(open, "doctor-dialog-title", "run-dialog", "Guided diagnostics", "Run Doctor", "Cancel", onCancel,
    h("div", { className: "dialog-content" },
      h("p", { className: "muted" }, "Choose how Ferrocrate should check this installation."),
      h("div", { className: "dialog-options" },
        option("doctor-fix", "Apply safe fixes", fix, onFixChange),
        option("doctor-bootstrap", "Prepare missing components", bootstrap, onBootstrapChange),
        option("doctor-dry-run", "Preview changes only", dryRun, onDryRunChange),
        option("doctor-confirm", "Allow changes that need confirmation", confirm, onConfirmChange),
      ),
    ),
    h("div", { className: "panel-actions dialog-actions" },
      h("button", { className: "btn btn-primary", onClick: onRun, disabled: busy }, h(Icon, { name: "pulse", size: 16 }), busy ? "Checking…" : "Run Doctor"),
    ),
  );
}

export function AccountDialog({ open, error, releaseBaseUrl, tokenEndpoint, issuanceEndpoint, customerId, accessToken, sessionToken, authLoading, accountConnected, plan, expiresText, entitlement, onReleaseBaseUrlChange, onTokenEndpointChange, onIssuanceEndpointChange, onCustomerIdChange, onAccessTokenChange, onSessionTokenChange, onClose, onSaveBackend, onConnect, onDisconnect, onRefresh, onSaveSession }) {
  const accountError = error || (entitlement?.status === "error" ? entitlement.message : null);
  return dialog(open, "account-dialog-title", "run-dialog", "Account connection", "Account and plan", "Close", onClose,
    h("div", null,
      h("div", { className: "dialog-content form-stack" },
        h(ActionErrorNotice, { error: accountError, humanMessage: credentialErrorMessage(accountError) }),
        field("account-release-service-url", "Release service URL", { value: releaseBaseUrl, onChange: onReleaseBaseUrlChange, placeholder: "https://releases.example.com" }),
        field("account-token-service-url", "Token service URL", { value: tokenEndpoint, onChange: onTokenEndpointChange, placeholder: "https://accounts.example.com/token" }),
        field("account-session-service-url", "Session service URL", { value: issuanceEndpoint, onChange: onIssuanceEndpointChange, placeholder: "https://accounts.example.com/session" }),
        h("button", { className: "btn btn-secondary", onClick: onSaveBackend }, "Save service connection"),
        field("account-customer-id", "Customer ID", { value: customerId, onChange: onCustomerIdChange, placeholder: "Customer ID" }),
        field("account-access-token", "Access token (optional)", { type: "password", value: accessToken, onChange: onAccessTokenChange, placeholder: "Access token" }),
        h("button", { className: "btn btn-secondary", onClick: onConnect }, "Connect account"),
        field("account-session-token", "Session token", { type: "password", value: sessionToken, onChange: onSessionTokenChange, placeholder: "Paste session token" }),
      ),
      h("div", { className: "account-summary" },
        h("strong", null, accountConnected ? "Account connected" : "No account connected"),
        h("span", null, plan ? `Plan: ${plan}` : "Plan information unavailable"),
        h("span", null, expiresText || "No active session expiry"),
        h("details", null, h("summary", null, "Plan diagnostics"), h("pre", null, JSON.stringify(entitlement ?? {}, null, 2))),
      ),
    ),
    h("div", { className: "panel-actions dialog-actions" },
      h("button", { className: "btn btn-danger", onClick: onDisconnect }, "Disconnect"),
      h("button", { className: "btn btn-secondary", onClick: onRefresh, disabled: authLoading }, authLoading ? "Refreshing…" : "Refresh"),
      h("button", { className: "btn btn-primary", onClick: onSaveSession, disabled: !sessionToken.trim() }, "Save session"),
    ),
  );
}

export function InstallDialog({ open, installerResult, busy, onClose, onPreview, onInstall }) {
  return dialog(open, "install-dialog-title", "run-dialog", "Local setup", "Install and bootstrap", "Close", onClose,
    h("div", { className: "dialog-content" },
      h("p", null, "Prepare the local Ferrocrate stack with the saved account connection."),
      installerResult
        ? h("details", null, h("summary", null, "Last install details"), h("pre", null, JSON.stringify(installerResult, null, 2)))
        : h("p", { className: "muted" }, "No install has run in this session."),
    ),
    h("div", { className: "panel-actions dialog-actions" },
      h("button", { className: "btn btn-secondary", onClick: onPreview, disabled: busy }, "Preview install"),
      h("button", { className: "btn btn-primary", onClick: onInstall, disabled: busy }, "Run full install"),
    ),
  );
}

export function RunContainerDialog({ open, draft, busy, error, onDraftChange, onCancel, onRun, onInvalid, onStart, onReviewLicensing, onDoctor, onPreset, conflict, confirmation = '', onConfirmationChange, onAlternative, onReplace, onBack }) {
  if (conflict) return dialog(open, "port-conflict-title", "run-dialog", "Port conflict", `Port ${conflict.port} is already in use`, "Cancel", onCancel,
    h("div", { className: "editor-grid" },
      h("p", { className: "detail-span" }, conflict.conflict ? `${conflict.conflict.name} (${conflict.conflict.image}) publishes this port.` : 'Another process uses this port. Its identity cannot be verified as a container.'),
      h("p", { className: "detail-span" }, `The runtime host suggests port ${conflict.suggested}. Availability will be checked again before launch.`),
      conflict.conflict ? h("div", { className: "detail-span" }, h("p", null, 'Replacement stops and removes this container. Named volumes are retained.'), field("replacement-confirmation", `Type ${conflict.conflict.name} to confirm replacement`, { value: confirmation, onChange: event => onConfirmationChange?.(event.target.value), autoComplete: 'off' })) : null,
      error ? h(ActionErrorNotice, { error }) : null),
    h("div", { className: "panel-actions dialog-actions" },
      h("button", { className: "btn btn-secondary", disabled: busy, onClick: onBack }, 'Back to settings'),
      h("button", { className: "btn btn-primary", disabled: busy, onClick: onAlternative }, `Use port ${conflict.suggested}`),
      conflict.conflict ? h("button", { className: "btn btn-danger", disabled: busy || confirmation !== conflict.conflict.name, onClick: onReplace }, `Replace ${conflict.conflict.name}`) : null));
  const { image, name, command, pullIfMissing, ports, volumes, environment, memoryMb, cpus } = draft;
  const customMode = !onPreset || draft.launcherMode === "custom";
  const selectedPreset = customMode ? null : LAUNCHER_PRESETS.find(preset => draft.launcherPreset ? preset.id === draft.launcherPreset : preset.image === image);
  const presetDescriptions = { postgres: "PostgreSQL database", redis: "Redis cache", nginx: "Nginx web server" };
  const change = (field, value) => onDraftChange({ ...draft, [field]: value });
  const submit = () => {
    try {
      return onRun(buildRunContainerInvokeArgs({ image, name, command, pullIfMissing, ports, volumes, environment, memoryMb, cpus }));
    } catch (error) {
      onInvalid?.(error);
    }
  };
  const mapping = (kind, rows) => h("fieldset", { className: "detail-span mapping-fieldset" },
    h("legend", null, kind === "port" ? "Ports" : "Volumes"),
    rows.map((row, index) => h("div", { className: "mapping-row", key: `${kind}-${index}` },
      h("input", { "aria-label": kind === "port" ? `Host port ${index + 1}` : `Volume source ${index + 1}`, value: kind === "port" ? row.host : row.source, onChange: (event) => change(kind === "port" ? "ports" : "volumes", rows.map((value, rowIndex) => rowIndex === index ? { ...value, ...(kind === "port" ? { host: event.target.value } : { source: event.target.value }) } : value)), placeholder: kind === "port" ? "Host port" : "Host path or volume" }),
      h("span", null, "→"),
      h("input", { "aria-label": kind === "port" ? `Container port ${index + 1}` : `Container path ${index + 1}`, value: kind === "port" ? row.container : row.target, onChange: (event) => change(kind === "port" ? "ports" : "volumes", rows.map((value, rowIndex) => rowIndex === index ? { ...value, ...(kind === "port" ? { container: event.target.value } : { target: event.target.value }) } : value)), placeholder: kind === "port" ? "Container port" : "Container path" }),
    )),
    h("button", { className: "btn btn-ghost", onClick: () => change(kind === "port" ? "ports" : "volumes", [...rows, kind === "port" ? { host: "", container: "" } : { source: "", target: "" }]) }, kind === "port" ? "Add port" : "Add volume"),
  );
  return dialog(open, "run-dialog-title", "run-dialog run-container-dialog", "New workload", "Run container", "Cancel", onCancel,
    h("div", { className: "editor-grid" },
      onPreset ? h("div", { className: "detail-span launcher-choices" }, h("p", { className: "eyebrow" }, "What would you like to run?"), h("div", { className: "launcher-preset-grid" },
        LAUNCHER_PRESETS.map(preset => h("button", { key: preset.id, className: "btn btn-secondary launcher-choice", "aria-pressed": selectedPreset?.id === preset.id, disabled: busy, onClick: () => onPreset(preset.id) }, presetDescriptions[preset.id])),
        h("button", { className: "btn btn-secondary launcher-choice", "aria-pressed": customMode, disabled: busy, onClick: () => change("launcherMode", "custom") }, "Custom image")),
        h("p", { className: "muted" }, "Choose a preset to set up a free port and persistent storage automatically.")) : null,
      customMode ? field("run-container-image", "Image", { value: image, onChange: (event) => change("image", event.target.value), placeholder: "alpine:latest" }) : null,
      selectedPreset || customMode ? field("run-container-name", "Name", { value: name, onChange: (event) => change("name", event.target.value), placeholder: "optional name" }, customMode ? undefined : "detail-span") : null,
      selectedPreset ? h("section", { className: "detail-span launcher-summary", "aria-label": "Launch setup" },
        h("strong", null, selectedPreset.label), h("span", { className: "mono" }, image),
        h("p", null, "Connection: ", ports.filter(row => row.host && row.container).map(row => `localhost:${row.host} → container port ${row.container}`).join(", ") || "No published ports"),
        h("p", null, "Persistent storage: ", volumes.filter(row => row.source && row.target).map(row => `${row.source} → ${row.target}`).join(", ") || "No volumes configured"),
        selectedPreset.id !== "nginx" ? h("p", { className: "muted" }, "A password is generated automatically; view it under Advanced.") : null,
        h("p", { className: "muted" }, "Review or change these settings in Advanced.")) : null,
      h("details", { className: "detail-span advanced-fields launcher-advanced", key: `${customMode ? "custom" : selectedPreset?.id || "choose"}:${Boolean(error)}`, open: error ? true : undefined }, h("summary", null, "Advanced"), h("div", { className: "editor-grid" },
      !customMode ? field("run-container-image", "Image", { value: image, onChange: (event) => onDraftChange({ ...draft, image: event.target.value, launcherPreset: selectedPreset?.id }), placeholder: "alpine:latest" }) : null,
      field("run-container-command", "Command (optional)", { value: command, onChange: (event) => change("command", event.target.value), placeholder: 'sh -c "echo ready"' }, "detail-span"),
      h("label", { className: "detail-span checkbox-row", htmlFor: "run-container-pull-missing" }, h("input", { id: "run-container-pull-missing", type: "checkbox", checked: pullIfMissing, onChange: (event) => change("pullIfMissing", event.target.checked) }), h("span", null, "Pull image if it is not available locally")),
      mapping("port", ports), mapping("volume", volumes),
      field("run-container-environment", "Environment (one KEY=value per line)", { value: environment, onChange: (event) => change("environment", event.target.value), rows: 5 }, "detail-span", "textarea"),
      h("fieldset", { className: "detail-span mapping-fieldset" }, h("legend", null, "Resource limits"), h("div", { className: "editor-grid" },
        field("run-container-memory", "Memory (MB)", { inputMode: "decimal", value: memoryMb, onChange: (event) => change("memoryMb", event.target.value), placeholder: "Unlimited" }),
        field("run-container-cpus", "CPUs", { inputMode: "decimal", value: cpus, onChange: (event) => change("cpus", event.target.value), placeholder: "Unlimited" }),
      )),
      )),
      error ? h(ActionErrorNotice, { error, onStart, onReviewLicensing, onDoctor }) : null,
    ),
    h("div", { className: "panel-actions dialog-actions" }, h("button", { id: "run-container-submit", className: "btn btn-primary", onClick: submit, disabled: busy || !image.trim() || (!customMode && !selectedPreset) }, h(Icon, { name: "play", size: 16 }), busy ? "Starting…" : selectedPreset ? `Start ${selectedPreset.label}` : "Start container")),
  );
}

export function BuildImageDialog({ open, context, tag, dialogAvailable, busy, onContextChange, onChooseContext, onTagChange, onCancel, onBuild }) {
  return dialog(open, "build-image-dialog-title", "run-dialog", "Build pipeline", "New build", "Cancel", onCancel,
    h("div", { className: "editor-grid" },
      h(HostPathField, { label: "Build context directory", kind: "directory", value: context, dialogAvailable, busy, onChange: onContextChange, onChoose: onChooseContext }),
      field("build-image-reference", "Image reference", { value: tag, onChange: onTagChange, placeholder: "image:tag" }, "detail-span"),
    ),
    h("div", { className: "panel-actions dialog-actions" }, h("button", { className: "btn btn-primary", onClick: onBuild, disabled: busy || Boolean(hostPathError(context, "directory")) || !tag.trim() }, "Start build")),
  );
}

export function RegistryDialog({ open, error, target, username, password, status, accountName, busy, loading, onTargetChange, onUsernameChange, onPasswordChange, onCancel, onCheck, onLogout, onLogin }) {
  const statusText = status ? status.logged_in ? `Signed in to ${status.registry} as ${accountName}` : `Not signed in to ${status.registry}` : "Check this registry to load keyring status";
  return dialog(open, "registry-dialog-title", "run-dialog", "Credentials", "Registry access", "Cancel", onCancel,
    h("div", { className: "editor-grid" },
      error ? h("div", { className: "detail-span" }, h(ActionErrorNotice, { error, humanMessage: credentialErrorMessage(error) })) : null,
      field("registry-server", "Registry server", { value: target, onChange: onTargetChange, placeholder: "registry.example.com" }, "detail-span"),
      field("registry-username", "Username", { value: username, onChange: onUsernameChange, placeholder: "username", autoComplete: "username" }),
      field("registry-password", "Password or token", { type: "password", value: password, onChange: onPasswordChange, placeholder: "password or token", autoComplete: "current-password" }),
      h("p", { className: `registry-status detail-span ${status?.logged_in ? "status-running" : ""}` }, statusText),
    ),
    h("div", { className: "panel-actions dialog-actions" },
      h("button", { className: "btn btn-secondary", onClick: onCheck, disabled: busy || loading || !target.trim() }, "Check status"),
      h("button", { className: "btn btn-danger", onClick: onLogout, disabled: busy || loading || !status?.logged_in }, "Logout"),
      h("button", { className: "btn btn-primary", onClick: onLogin, disabled: busy || loading || !target.trim() || !username.trim() || !password }, loading ? "Working…" : "Login"),
    ),
  );
}
