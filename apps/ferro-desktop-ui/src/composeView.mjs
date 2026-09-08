import { createElement } from "react";
import { ActionErrorNotice, HostPathField } from "./resourcePages.mjs";
import { Icon } from "./iconSystem.mjs";
import { DialogFocusScope } from "./modalFocus.mjs";

export function composeChooserMode(dialogAvailable) {
  return dialogAvailable ? "native-dialog" : "host-path";
}

export function ComposeFileDialog({ open, value, busy, error, onChange, onSubmit, onCancel }) {
  if (!open) return null;
  return createElement(DialogFocusScope, { dialogId: "compose-file-dialog-title", onClose: onCancel },
    createElement("div", { className: "modal-backdrop", role: "presentation" },
    createElement("section", { className: "run-dialog", role: "dialog", "aria-modal": true, "aria-labelledby": "compose-file-dialog-title", tabIndex: -1 },
      createElement("div", { className: "drawer-header" },
        createElement("div", null,
          createElement("p", { className: "eyebrow" }, "Compose project"),
          createElement("h2", { id: "compose-file-dialog-title" }, "Choose a Compose file"),
        ),
        createElement("button", { className: "btn btn-secondary", type: "button", onClick: onCancel, disabled: busy }, "Cancel"),
      ),
      createElement("div", { className: "editor-grid" },
        createElement(HostPathField, {
          label: "Compose file",
          kind: "file",
          value,
          busy,
          submitLabel: busy ? "Loading…" : "Load Compose file",
          onChange,
          onSubmit,
        }),
        error ? createElement("div", { className: "detail-span" }, createElement(ActionErrorNotice, { error })) : null,
      ),
    ),
    ),
  );
}

export function ComposeServiceLogsButton({ service, busy = false, onLogs }) {
  return createElement("button", {
    className: "btn btn-ghost",
    "aria-label": `Logs for Compose service ${service.name}`,
    disabled: busy || service.status === "not_created",
    onClick: () => onLogs(service),
  }, createElement(Icon, { name: "terminal", size: 16 }), "Logs");
}

export function composeStatusClass(status) {
  if (status === "running") return "status-running";
  if (status === "paused") return "status-paused";
  return "status-stopped";
}

export function composeLogTarget(service) {
  return service.container_id || service.name;
}
