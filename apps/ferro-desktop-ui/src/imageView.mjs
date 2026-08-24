import { createElement } from "react";
import { failurePresentation } from "./resourcePages.mjs";

export function formatImageSize(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value) || value < 0) return "—";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let amount = value / 1024;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount.toFixed(amount >= 10 ? 0 : 1)} ${units[unit]}`;
}

export function formatImageCreated(value) {
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds > 0) {
    return `${new Date(seconds * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC`;
  }
  const date = new Date(String(value));
  if (!Number.isNaN(date.valueOf())) {
    return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
  }
  return "—";
}

export function pullFailurePresentation(error) {
  return failurePresentation(error, {
    license: "Your current plan doesn't include image pulls.",
  });
}

export function ImagePagePullAction({ hasImages, disabled, onOpen }) {
  if (!hasImages) return null;
  return createElement("button", { className: "btn btn-primary", onClick: onOpen, disabled }, "Pull image");
}

export function ImageEmptyState({ hasImages, disabled, onOpen }) {
  if (hasImages) return null;
  return createElement("div", { className: "empty-state" },
    createElement("strong", null, "There are no local images."),
    createElement("span", null, "Pull an image to run or build containers."),
    createElement("button", { className: "btn btn-primary", onClick: onOpen, disabled }, "Pull image"),
  );
}

export function PullImageDialog({
  open,
  imageTarget,
  progress,
  failure,
  busy,
  onCancel,
  onImageTargetChange,
  onPull,
  onStart,
  onReviewLicensing,
  onDoctor,
}) {
  if (!open) return null;
  const failureContent = failure ? createElement("section", { className: "pull-failure detail-span", role: "alert" },
    createElement("strong", null, failure.message),
    failure.kind === "daemon" ? createElement("button", { className: "btn btn-secondary", onClick: onStart, disabled: busy }, "Start") : null,
    failure.kind === "license" ? createElement("button", { className: "btn btn-secondary", onClick: onReviewLicensing }, "Review licensing") : null,
    failure.kind === "binary" ? createElement("button", { className: "btn btn-secondary", onClick: onDoctor }, "Open Doctor") : null,
    createElement("details", null,
      createElement("summary", null, "Technical details"),
      createElement("pre", null, failure.detail),
    ),
  ) : null;

  return createElement("div", { className: "modal-backdrop", role: "presentation" },
    createElement("section", { className: "run-dialog", role: "dialog", "aria-modal": true, "aria-labelledby": "pull-image-dialog-title" },
      createElement("div", { className: "drawer-header" },
        createElement("div", null,
          createElement("p", { className: "eyebrow" }, "Image library"),
          createElement("h2", { id: "pull-image-dialog-title" }, "Pull image"),
        ),
        createElement("button", { className: "btn btn-secondary", onClick: onCancel }, "Cancel"),
      ),
      createElement("div", { className: "editor-grid" },
        createElement("label", { className: "detail-span" },
          createElement("span", null, "Image reference"),
          createElement("input", { value: imageTarget, onChange: onImageTargetChange, placeholder: "alpine:latest", autoFocus: true }),
        ),
        progress ? createElement("p", { className: "pull-progress detail-span", role: "status" },
          createElement("strong", null, "Pull progress"),
          progress,
        ) : null,
        failureContent,
      ),
      createElement("div", { className: "panel-actions dialog-actions" },
        createElement("button", { className: "btn btn-primary", onClick: onPull, disabled: busy || !imageTarget.trim() }, busy ? "Pulling…" : "Pull image"),
      ),
    ),
  );
}

export function parseImageRows(output) {
  try {
    const records = JSON.parse(output || "[]");
    if (!Array.isArray(records)) return [];
    return records.map((record) => ({
      id: String(record.Id || record.id || record.RepoTags?.[0] || "unknown"),
      reference: String(record.RepoTags?.[0] || record.reference || "untagged"),
      size: formatImageSize(record.Size ?? record.size),
      created: formatImageCreated(record.Created ?? record.created),
    }));
  } catch {
    return [];
  }
}
