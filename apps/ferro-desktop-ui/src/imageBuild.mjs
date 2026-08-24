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
          return createElement("tr", { key: build.id },
            createElement("td", { className: "container-name mono" }, build.image),
            createElement("td", null,
              createElement("span", { className: `build-status build-status-${build.status}`, role: build.status === "building" ? "status" : undefined },
                build.status === "building" ? "Building" : build.status === "succeeded" ? "Succeeded" : "Failed",
              ),
              progress ? createElement("p", { className: "build-progress" }, buildStepText(progress.text)) : null,
              failure ? createElement("div", { className: "build-failure" },
                createElement("strong", null, failure.message),
                failure.kind === "daemon" ? createElement("button", { className: "btn btn-secondary", onClick: onStart, disabled }, "Start") : null,
                failure.kind === "license" ? createElement("button", { className: "btn btn-secondary", onClick: onReviewLicensing }, "Review licensing") : null,
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
