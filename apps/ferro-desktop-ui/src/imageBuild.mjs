import { createElement } from "react";

export function buildStepText(text) {
  const trimmed = text.trim();
  try {
    const frame = JSON.parse(trimmed);
    if (typeof frame.stream === "string") return frame.stream.trim();
    if (typeof frame.error === "string") return frame.error.trim();
  } catch {
    // Native CLI output is already human-readable.
  }
  return trimmed;
}

export function formatBuildDuration(durationMs) {
  if (durationMs == null) return "Building…";
  if (durationMs < 1000) return "<1 s";
  return `${(durationMs / 1000).toFixed(durationMs >= 10_000 ? 0 : 1)} s`;
}

export function buildFailurePresentation(error) {
  const detail = String(error || "No technical detail was returned.");
  const normalized = detail.toLowerCase();
  if (/(daemon|connection refused|not running|no such file)/.test(normalized)) {
    return { kind: "daemon", message: "Ferrocrate isn't running", detail };
  }
  if (/(entitlement|license required|not licensed|not entitled)/.test(normalized)) {
    return { kind: "license", message: "Your current plan doesn't include image builds.", detail };
  }
  return { kind: "generic", message: "We couldn't build this image.", detail };
}

export function appendBuildProgress(history, frame) {
  return history.map((build) => build.id === frame.build_id
    ? { ...build, progress: [...build.progress, frame] }
    : build);
}

export function BuildHistoryList({ builds, disabled, onNewBuild, onStart, onReviewLicensing }) {
  if (!builds.length) {
    return createElement("section", { className: "panel table-panel build-history-panel", "aria-label": "Builds" },
      createElement("div", { className: "empty-state" },
        createElement("strong", null, "Ready to build an image."),
        createElement("span", null, "Choose a directory and image tag to start a new build."),
        createElement("button", { className: "btn btn-primary", onClick: onNewBuild, disabled }, "New build"),
      ),
    );
  }

  return createElement("section", { className: "panel table-panel build-history-panel", "aria-label": "Builds" },
    createElement("div", { className: "table-toolbar" },
      createElement("button", { className: "btn btn-primary", onClick: onNewBuild, disabled }, "New build"),
    ),
    createElement("div", { className: "table-scroll" },
      createElement("table", null,
        createElement("thead", null, createElement("tr", null,
          createElement("th", null, "Image"),
          createElement("th", null, "Status"),
          createElement("th", null, "Duration"),
        )),
        createElement("tbody", null, builds.map((build) => {
          const progress = build.progress.at(-1);
          const failure = build.status === "failed" && build.error ? buildFailurePresentation(build.error) : null;
          const status = createElement("span", { className: `build-status build-status-${build.status}` },
            build.status === "building" ? "Building" : build.status === "succeeded" ? "Succeeded" : "Failed",
          );
          return createElement("tr", { key: build.id },
            createElement("td", { className: "container-name mono" }, build.image),
            createElement("td", null,
              build.status === "building" ? createElement("div", { className: "build-live", role: "status" },
                status,
                progress ? createElement("p", { className: "build-progress" }, buildStepText(progress.text)) : null,
              ) : status,
              failure ? createElement("div", { className: "build-failure" },
                createElement("strong", null, failure.message),
                failure.kind === "daemon" ? createElement("button", { className: "btn btn-secondary", onClick: onStart, disabled }, "Start") : null,
                failure.kind === "license" ? createElement("button", { className: "btn btn-secondary", onClick: () => onReviewLicensing?.(failure.detail) }, "Review licensing") : null,
                createElement("details", null,
                  createElement("summary", null, "Technical details"),
                  createElement("pre", null, failure.detail),
                ),
              ) : null,
            ),
            createElement("td", { className: "muted" }, formatBuildDuration(build.durationMs)),
          );
        })),
      ),
    ),
  );
}

export function BuildLicensingDialog({ open, detail, onClose, onOpenSettings }) {
  if (!open) return null;
  return createElement("div", { className: "modal-backdrop", role: "presentation" },
    createElement("section", { className: "run-dialog licensing-dialog", role: "dialog", "aria-modal": true, "aria-labelledby": "build-licensing-dialog-title" },
      createElement("div", { className: "drawer-header" },
        createElement("div", null,
          createElement("p", { className: "eyebrow" }, "Image builds"),
          createElement("h2", { id: "build-licensing-dialog-title" }, "Image builds aren't included in your current plan."),
        ),
        createElement("button", { className: "btn btn-secondary", onClick: onClose }, "Close"),
      ),
      createElement("div", { className: "licensing-dialog-content" },
        createElement("p", null, "Use an account with image-build access, then try again."),
        createElement("details", null,
          createElement("summary", null, "Technical details"),
          createElement("pre", null, detail || "No technical detail was returned."),
        ),
      ),
      createElement("div", { className: "panel-actions dialog-actions" },
        createElement("button", { className: "btn btn-secondary", onClick: onOpenSettings }, "Open technical settings"),
      ),
    ),
  );
}
