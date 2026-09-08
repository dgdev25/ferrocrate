import { DialogFocusScope } from "./modalFocus.mjs";
import { createElement } from "react";
import { Icon } from "./iconSystem.mjs";

const EMPTY_STATES = {
  containers: {
    icon: "box",
    copy: "Run a container to start an isolated workload.",
    action: "Run a container",
  },
  images: {
    icon: "images",
    copy: "Pull an image to run or build containers.",
    action: "Pull an image",
  },
  volumes: {
    icon: "disk",
    copy: "Create a volume to keep container data between runs.",
    action: "Create a volume",
  },
  networks: {
    icon: "globe",
    copy: "Create a network to connect containers privately.",
    action: "Create a network",
  },
  compose: {
    icon: "compose",
    copy: "Choose a Compose file to manage an application stack.",
    action: "Choose a Compose file",
  },
};

const PRIMARY_ACTIONS = {
  containers: "run-container",
  images: "pull-image",
  volumes: "create-volume",
  networks: "create-network",
  compose: "choose-compose-file",
};

export function resourcePageState(section, itemCount, { loaded = false } = {}) {
  if (itemCount === 0 && !loaded) return { content: "empty", primaryAction: null };
  return { content: "table", primaryAction: PRIMARY_ACTIONS[section] };
}

export function containerContentState(totalCount, visibleCount, query) {
  if (totalCount === 0) return "empty";
  if (query.trim() && visibleCount === 0) return "filtered-empty";
  return "table";
}

export function filterNamedResources(rows, query, getName = (row) => row.name) {
  const needle = query.trim().toLowerCase();
  if (!needle) return rows;
  return rows.filter((row) => String(getName(row)).toLowerCase().includes(needle));
}

export function nextResourceDialog(current, command) {
  if (command === "open-volume") return "volume";
  if (command === "open-network") return "network";
  if (command === "close-dialog") return null;
  return current;
}

export function resourceDialogTransition(current, command) {
  if (command === "open-volume" || command === "open-network") {
    return {
      kind: command === "open-volume" ? "volume" : "network",
      name: "",
      subnet: "",
      error: null,
    };
  }
  if (command === "close-dialog") {
    return { kind: null, name: "", subnet: "", error: null };
  }
  return current;
}

export function isDaemonUnavailable(error) {
  const detail = String(error || "").toLowerCase();
  return /connection refused|cannot connect[^\n]*daemon|daemon[^\n]*(?:not running|unreachable)|(?:ferrocrate|docker)\.sock[^\n]*(?:no such file|failed|missing)/.test(detail);
}

export function shouldShowFirstRun(snapshot, activeSection) {
  if (!snapshot || activeSection === "doctor" || activeSection === "settings") return false;
  if (snapshot.daemon && snapshot.daemon.state !== "running") return true;
  return [snapshot.containers, snapshot.images].some((command) => (
    command?.ok === false && isDaemonUnavailable(command.stderr)
  ));
}

export function runtimeSurfaceState(snapshot, activeSection, loadError = null) {
  if (activeSection === "doctor" || activeSection === "settings") return "resource";
  if (!snapshot) return loadError ? "unavailable" : "loading";
  return shouldShowFirstRun(snapshot, activeSection) ? "first-run" : "resource";
}

export function snapshotFailureDetail(snapshot, activeSection) {
  if (!snapshot || shouldShowFirstRun(snapshot, "containers")) return null;
  const commands = activeSection === "containers"
    ? [snapshot.containers]
    : activeSection === "images"
      ? [snapshot.images]
      : activeSection == null
        ? [snapshot.containers, snapshot.images]
        : [];
  const failed = commands.find((command) => command?.ok === false);
  return failed?.stderr?.trim() || (failed ? `A runtime command did not complete successfully (status ${failed.code ?? "unknown"}).` : null);
}

export function applyRuntimeSurfaceTransition(surface, callbacks) {
  if (surface !== "first-run") return false;
  callbacks.closeRun?.();
  callbacks.closePull?.();
  callbacks.closeBuild?.();
  callbacks.closeRegistry?.();
  callbacks.closeResource?.();
  callbacks.closeLicensing?.();
  return true;
}

export async function runFirstRunRecovery({
  start,
  refreshSnapshot,
  refreshVolumes,
  refreshNetworks,
  refreshCompose,
}) {
  const result = await start();
  if (!result.ok) return result;
  await Promise.all([
    refreshSnapshot?.(),
    refreshVolumes?.(),
    refreshNetworks?.(),
    refreshCompose?.(),
  ]);
  return result;
}

export function ResourceEmptyState({ section, disabled = false, onAction }) {
  const state = EMPTY_STATES[section];
  if (!state) return null;
  return createElement("div", { className: "empty-state resource-empty-state" },
    createElement("span", { className: "empty-state-icon", "aria-hidden": true }, createElement(Icon, { name: state.icon, size: 20 })),
    createElement("span", { className: "empty-state-copy" }, state.copy),
    createElement("button", { className: "btn btn-primary", disabled, onClick: onAction }, state.action),
  );
}

export function hostPathError(value, kind = "path") {
  const path = String(value ?? "").trim();
  const absolute = path.startsWith("/")
    || /^[A-Za-z]:[\\/]/.test(path)
    || /^\\\\[^\\]/.test(path);
  if (!path || !absolute || path.includes("\0")) {
    return `Enter an absolute ${kind} path on the daemon host.`;
  }
  return null;
}

export function HostPathField({
  label,
  kind = "path",
  value = "",
  dialogAvailable = false,
  busy = false,
  submitLabel,
  onChange,
  onChoose,
  onSubmit,
}) {
  const validationError = hostPathError(value, kind);
  const visibleError = value.trim() ? validationError : null;
  const inputId = `host-${kind}-path`;
  return createElement("div", { className: "host-path-field detail-span" },
    createElement("label", { htmlFor: inputId },
      createElement("span", null, label),
      createElement("div", { className: "field-row" },
        createElement("input", {
          id: inputId,
          value,
          onChange,
          placeholder: `absolute ${kind} path on the daemon host`,
          "aria-invalid": visibleError ? true : undefined,
          "aria-describedby": visibleError ? "host-path-error" : "host-path-help",
        }),
        dialogAvailable
          ? createElement("button", { className: "btn btn-secondary", type: "button", onClick: onChoose, disabled: busy }, `Choose ${kind}`)
          : null,
      ),
    ),
    dialogAvailable
      ? null
      : createElement("p", { id: "host-path-help", className: "host-path-help" }, `Enter an absolute ${kind} path on the daemon host.`),
    visibleError
      ? createElement("p", { id: "host-path-error", className: "host-path-error", role: "alert" }, visibleError)
      : null,
    submitLabel
      ? createElement("button", { className: "btn btn-primary", type: "button", onClick: onSubmit, disabled: busy || Boolean(validationError) }, submitLabel)
      : null,
  );
}

export function ResourceToolbar({ count, label, overflowLabel, actions = [] }) {
  return createElement("div", { className: "table-toolbar" },
    label ? createElement("span", { className: "toolbar-label mono", title: label }, label) : null,
    count == null ? null : createElement("span", { className: "count-badge" }, count),
    createElement("details", { className: "image-toolbar-overflow" },
      createElement("summary", { "aria-label": overflowLabel }, createElement(Icon, { name: "more", size: 16 })),
      createElement("div", { className: "overflow-menu" }, actions.map((action) => (
        createElement("button", {
          key: action.label,
          className: action.danger ? "danger-action" : undefined,
          disabled: action.disabled,
          onClick: action.onAction,
        }, action.label)
      ))),
    ),
  );
}

export function EmptyResourcePage({
  section,
  count = 0,
  overflowLabel,
  actions,
  disabled = false,
  onPrimary,
}) {
  return createElement("section", { className: "panel empty-page-panel", "aria-label": EMPTY_STATES[section]?.action },
    createElement(ResourceToolbar, { count, overflowLabel, actions }),
    createElement(ResourceEmptyState, { section, disabled, onAction: onPrimary }),
  );
}

export function RuntimeLoadingState() {
  return createElement("section", { className: "panel runtime-loading-state", role: "status", "aria-live": "polite" },
    createElement("span", { className: "first-run-icon", "aria-hidden": true }, createElement(Icon, { name: "box", size: 20 })),
    createElement("strong", null, "Loading Ferrocrate…"),
    createElement("span", null, "Checking the local runtime and resources."),
  );
}

export function failurePresentation(error, messages = {}) {
  const detail = String(error || "No technical detail was returned.");
  const normalized = detail.toLowerCase();
  if (isDaemonUnavailable(normalized)) {
    return { kind: "daemon", message: messages.daemon || "Ferrocrate isn't running", detail };
  }
  if (/(entitlement|license required|not licensed|not entitled)/.test(normalized)) {
    return { kind: "license", message: messages.license || "Your current plan doesn't include this action.", detail };
  }
  if (/(?:ferrocrate[^\n]*(?:command not found|no such file)|spawn[^\n]*enoent|executable[^\n]*not found)/.test(normalized)) {
    return { kind: "binary", message: "Ferrocrate isn't installed", detail };
  }
  return { kind: "generic", message: messages.generic || "Something went wrong", detail };
}

export function ActionErrorNotice({ error, humanMessage, technicalDetail, onDismiss, onStart, onReviewLicensing, onDoctor }) {
  if (!error) return null;
  const failure = failurePresentation(error);
  return createElement("section", { className: `action-error action-error-${failure.kind}`, role: failure.kind === "license" ? "status" : "alert" },
    createElement("div", { className: "action-error-heading" },
      createElement("strong", null, humanMessage || failure.message),
      onDismiss ? createElement("button", { className: "error-dismiss", onClick: onDismiss, "aria-label": "Dismiss error" }, createElement(Icon, { name: "close", size: 16 })) : null,
    ),
    failure.kind === "daemon" && onStart
      ? createElement("button", { className: "btn btn-secondary", onClick: onStart }, "Start Ferrocrate")
      : null,
    failure.kind === "license" && onReviewLicensing
      ? createElement("button", { className: "btn btn-secondary", onClick: () => onReviewLicensing(failure.detail) }, "Review licensing")
      : null,
    failure.kind === "binary" && onDoctor
      ? createElement("button", { className: "btn btn-secondary", onClick: onDoctor }, "Open Doctor")
      : null,
    createElement("details", null,
      createElement("summary", null, "Technical details"),
      createElement("pre", null, technicalDetail || failure.detail),
    ),
  );
}

export function FirstRunState({ busy = false, error = null, onStart, onDoctor }) {
  return createElement("section", { className: "panel first-run-state", "aria-labelledby": "first-run-title" },
    createElement("span", { className: "first-run-icon", "aria-hidden": true }, createElement(Icon, { name: "box", size: 20 })),
    createElement("p", { className: "eyebrow" }, "Local container runtime"),
    createElement("h1", { id: "first-run-title" }, "Ferrocrate isn't running"),
    createElement("p", null, "Ferrocrate runs containers and images on your machine with a native, security-focused engine."),
    createElement("div", { className: "first-run-actions" },
      createElement("button", { className: "btn btn-primary", disabled: busy, onClick: onStart }, busy ? "Starting…" : "Start Ferrocrate"),
      createElement("button", { className: "btn btn-ghost", onClick: onDoctor }, "Open Doctor"),
    ),
    error ? createElement(ActionErrorNotice, { error }) : null,
  );
}

export function ResourceCreateDialog({
  kind,
  name,
  subnet = "",
  busy = false,
  error = null,
  onNameChange,
  onSubnetChange,
  onCancel,
  onCreate,
  onStart,
  onReviewLicensing,
}) {
  if (kind !== "volume" && kind !== "network") return null;
  const isNetwork = kind === "network";
  const title = isNetwork ? "Create network" : "Create volume";
  return createElement(DialogFocusScope, { dialogId: `${kind}-dialog-title`, onClose: onCancel },
    createElement("div", { className: "modal-backdrop", role: "presentation" },
    createElement("section", { className: "run-dialog", role: "dialog", "aria-modal": true, "aria-labelledby": `${kind}-dialog-title` },
      createElement("div", { className: "drawer-header" },
        createElement("div", null,
          createElement("p", { className: "eyebrow" }, isNetwork ? "Container connectivity" : "Persistent storage"),
          createElement("h2", { id: `${kind}-dialog-title` }, title),
        ),
        createElement("button", { className: "btn btn-secondary", onClick: onCancel }, "Cancel"),
      ),
      createElement("div", { className: "editor-grid" },
        createElement("label", { className: "detail-span", htmlFor: `${kind}-name` },
          createElement("span", null, isNetwork ? "Network name" : "Volume name"),
          createElement("input", { id: `${kind}-name`, value: name, onChange: onNameChange, placeholder: isNetwork ? "app-network" : "app-data" }),
        ),
        isNetwork ? createElement("label", { className: "detail-span", htmlFor: "network-subnet" },
          createElement("span", null, "Subnet (optional)"),
          createElement("input", { id: "network-subnet", value: subnet, onChange: onSubnetChange, placeholder: "172.20.0.0/16" }),
        ) : null,
        error ? createElement(ActionErrorNotice, { error, onStart, onReviewLicensing }) : null,
      ),
      createElement("div", { className: "panel-actions dialog-actions" },
        createElement("button", { className: "btn btn-primary", onClick: onCreate, disabled: busy || !name.trim() }, busy ? "Creating…" : title),
      ),
    ),
    ),
  );
}

export function LicensingDialog({ open, detail, onClose, onOpenSettings }) {
  if (!open) return null;
  return createElement(DialogFocusScope, { dialogId: "licensing-dialog-title", onClose: onClose },
    createElement("div", { className: "modal-backdrop", role: "presentation" },
    createElement("section", { className: "run-dialog licensing-dialog", role: "dialog", "aria-modal": true, "aria-labelledby": "licensing-dialog-title" },
      createElement("div", { className: "drawer-header" },
        createElement("div", null,
          createElement("p", { className: "eyebrow" }, "Plan access"),
          createElement("h2", { id: "licensing-dialog-title" }, "This action isn't included in your current plan."),
        ),
        createElement("button", { className: "btn btn-secondary", onClick: onClose }, "Close"),
      ),
      createElement("div", { className: "licensing-dialog-content" },
        createElement("p", null, "Use an account with access to this feature, then try again."),
        createElement("details", null,
          createElement("summary", null, "Technical details"),
          createElement("pre", null, detail || "No technical detail was returned."),
        ),
      ),
      createElement("div", { className: "panel-actions dialog-actions" },
        createElement("button", { className: "btn btn-secondary", onClick: onOpenSettings }, "Open technical settings"),
      ),
    ),
    ),
  );
}
