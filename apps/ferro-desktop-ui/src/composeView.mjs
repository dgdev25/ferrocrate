import { createElement } from "react";
import { HostPathField } from "./resourcePages.mjs";

export function composeChooserMode(dialogAvailable) {
  return dialogAvailable ? "native-dialog" : "host-path";
}

export function ComposeFileDialog({ open, value, busy, onChange, onSubmit, onCancel }) {
  if (!open) return null;
  return createElement("div", { className: "modal-backdrop", role: "presentation" },
    createElement("section", { className: "run-dialog", role: "dialog", "aria-modal": true, "aria-labelledby": "compose-file-dialog-title" },
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
      ),
    ),
  );
}

export function composeStatusClass(status) {
  if (status === "running") return "status-running";
  if (status === "paused") return "status-paused";
  return "status-stopped";
}

export function composeLogTarget(service) {
  return service.container_id || service.name;
}
