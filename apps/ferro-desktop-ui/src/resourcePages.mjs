import { createElement } from "react";

const EMPTY_STATES = {
  containers: {
    icon: "▣",
    copy: "Run a container to start an isolated workload.",
    action: "Run a container",
  },
  images: {
    icon: "▧",
    copy: "Pull an image to run or build containers.",
    action: "Pull an image",
  },
  volumes: {
    icon: "▤",
    copy: "Create a volume to keep container data between runs.",
    action: "Create a volume",
  },
  networks: {
    icon: "◎",
    copy: "Create a network to connect containers privately.",
    action: "Create a network",
  },
  compose: {
    icon: "◇",
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

export function resourcePageState(section, itemCount) {
  if (itemCount === 0) return { content: "empty", primaryAction: null };
  return { content: "table", primaryAction: PRIMARY_ACTIONS[section] };
}

export function nextResourceDialog(current, command) {
  if (command === "open-volume") return "volume";
  if (command === "open-network") return "network";
  if (command === "close-dialog") return null;
  return current;
}

export function shouldShowFirstRun(snapshot, activeSection) {
  if (!snapshot || activeSection === "doctor" || activeSection === "settings") return false;
  return snapshot.containers?.ok !== true || snapshot.images?.ok !== true;
}

export function ResourceEmptyState({ section, disabled = false, onAction }) {
  const state = EMPTY_STATES[section];
  if (!state) return null;
  return createElement("div", { className: "empty-state resource-empty-state" },
    createElement("span", { className: "empty-state-icon", "aria-hidden": true }, state.icon),
    createElement("span", { className: "empty-state-copy" }, state.copy),
    createElement("button", { className: "btn btn-primary", disabled, onClick: onAction }, state.action),
  );
}

export function failurePresentation(error) {
  const detail = String(error || "No technical detail was returned.");
  const normalized = detail.toLowerCase();
  if (/(daemon|connection refused|not running|no such file|socket)/.test(normalized)) {
    return { kind: "daemon", message: "Ferrocrate isn't running", detail };
  }
  if (/(entitlement|license required|not licensed|not entitled)/.test(normalized)) {
    return { kind: "license", message: "Your current plan doesn't include this action.", detail };
  }
  return { kind: "generic", message: "We couldn't complete that action.", detail };
}

export function ActionErrorNotice({ error, onDismiss, onStart, onReviewLicensing }) {
  if (!error) return null;
  const failure = failurePresentation(error);
  return createElement("section", { className: "action-error", role: "alert" },
    createElement("div", { className: "action-error-heading" },
      createElement("strong", null, failure.message),
      onDismiss ? createElement("button", { className: "error-dismiss", onClick: onDismiss, "aria-label": "Dismiss error" }, "×") : null,
    ),
    failure.kind === "daemon" && onStart
      ? createElement("button", { className: "btn btn-secondary", onClick: onStart }, "Start Ferrocrate")
      : null,
    failure.kind === "license" && onReviewLicensing
      ? createElement("button", { className: "btn btn-secondary", onClick: onReviewLicensing }, "Review licensing")
      : null,
    createElement("details", null,
      createElement("summary", null, "Technical details"),
      createElement("pre", null, failure.detail),
    ),
  );
}

export function FirstRunState({ busy = false, error = null, onStart, onDoctor }) {
  return createElement("section", { className: "panel first-run-state", "aria-labelledby": "first-run-title" },
    createElement("span", { className: "first-run-icon", "aria-hidden": true }, "▣"),
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
}) {
  if (kind !== "volume" && kind !== "network") return null;
  const isNetwork = kind === "network";
  const title = isNetwork ? "Create network" : "Create volume";
  return createElement("div", { className: "modal-backdrop", role: "presentation" },
    createElement("section", { className: "run-dialog", role: "dialog", "aria-modal": true, "aria-labelledby": `${kind}-dialog-title` },
      createElement("div", { className: "drawer-header" },
        createElement("div", null,
          createElement("p", { className: "eyebrow" }, isNetwork ? "Container connectivity" : "Persistent storage"),
          createElement("h2", { id: `${kind}-dialog-title` }, title),
        ),
        createElement("button", { className: "btn btn-secondary", onClick: onCancel }, "Cancel"),
      ),
      createElement("div", { className: "editor-grid" },
        createElement("label", { className: "detail-span" },
          createElement("span", null, isNetwork ? "Network name" : "Volume name"),
          createElement("input", { value: name, onChange: onNameChange, placeholder: isNetwork ? "app-network" : "app-data", autoFocus: true }),
        ),
        isNetwork ? createElement("label", { className: "detail-span" },
          createElement("span", null, "Subnet (optional)"),
          createElement("input", { value: subnet, onChange: onSubnetChange, placeholder: "172.20.0.0/16" }),
        ) : null,
        error ? createElement(ActionErrorNotice, { error }) : null,
      ),
      createElement("div", { className: "panel-actions dialog-actions" },
        createElement("button", { className: "btn btn-primary", onClick: onCreate, disabled: busy || !name.trim() }, busy ? "Creating…" : title),
      ),
    ),
  );
}
