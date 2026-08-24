import { createElement } from "react";
import { Icon } from "./iconSystem.mjs";

export async function completeDoctorRun({ execute, refresh, setResult, setError, close, scheduleResultsFocus, finish }) {
  let receivedResult = false;
  try {
    const result = await execute();
    setResult(result);
    receivedResult = true;
    await refresh();
  } catch (error) {
    setError(String(error));
  } finally {
    close();
    if (receivedResult) scheduleResultsFocus();
    finish();
  }
}

function MoreMenu({ label, actions }) {
  return createElement("details", { className: "image-toolbar-overflow" },
    createElement("summary", { "aria-label": label }, createElement(Icon, { name: "more", size: 16 })),
    createElement("div", { className: "overflow-menu" }, actions.map((action) => (
      createElement("button", {
        key: action.label,
        onClick: action.onClick,
        disabled: action.disabled,
      }, action.icon ? createElement(Icon, { name: action.icon, size: 16 }) : null, action.label)
    ))),
  );
}

export function DoctorPage({ result, busy = false, resultsTableRef, onRun, onStart, onStop }) {
  if (!result) {
    return createElement("section", { className: "panel empty-page-panel", "aria-label": "Doctor" },
      createElement("div", { className: "empty-state resource-empty-state" },
        createElement("span", { className: "empty-state-icon", "aria-hidden": true }, createElement(Icon, { name: "pulse", size: 20 })),
        createElement("span", { className: "empty-state-copy" }, "Check this installation and get guided fixes for anything that needs attention."),
        createElement("button", { className: "btn btn-primary", disabled: busy, onClick: onRun }, "Run Doctor"),
      ),
    );
  }
  const checks = result.raw?.checks || [];
  return createElement("section", { className: "panel table-panel resource-table-panel", "aria-label": "Doctor checks" },
    createElement("div", { className: "table-toolbar" },
      createElement("span", { className: `count-badge ${result.ok ? "ok" : "bad"}` }, result.ok ? "Healthy" : `${checks.filter((check) => !check.ok).length} need attention`),
      createElement("button", { className: "btn btn-secondary", disabled: busy, onClick: onRun }, createElement(Icon, { name: "pulse", size: 16 }), "Run again"),
      createElement(MoreMenu, { label: "Runtime actions", actions: [
        { label: "Start Ferrocrate", icon: "play", onClick: onStart, disabled: busy },
        { label: "Stop Ferrocrate", icon: "stop", onClick: onStop, disabled: busy },
      ] }),
    ),
    createElement("div", { className: "table-scroll" }, createElement("table", { ref: resultsTableRef, tabIndex: -1 },
      createElement("thead", null, createElement("tr", null,
        createElement("th", null, "Check"),
        createElement("th", null, "Status"),
        createElement("th", null, "Message"),
        createElement("th", null, "Guidance"),
      )),
      createElement("tbody", null, checks.map((check) => createElement("tr", { key: check.id },
        createElement("td", { className: "container-name" }, check.id.replace(/[-_]/g, " ")),
        createElement("td", null, createElement("span", { className: check.ok ? "ok-text" : "bad-text" }, check.ok ? "Passed" : check.remediated ? "Fixed" : "Needs attention")),
        createElement("td", null, check.message),
        createElement("td", { className: "muted" }, check.hint || "No action needed"),
      ))),
    )),
  );
}

export function SettingsPage({ authState, installerResult, nativeLinux = false, daemonStatus, onOpenAccount, onOpenInstall }) {
  const session = authState?.session;
  const accountStatus = session?.token_present ? `Connected${session.plan ? ` · ${session.plan}` : ""}` : "Not connected";
  const installStatus = installerResult ? (installerResult.ok ? "Last install completed" : "Last install needs attention") : "Not run in this session";
  const rows = [{ key: "account", name: "Account and plan", description: "Backend connection, session, and plan access", status: accountStatus, action: onOpenAccount }];
  if (nativeLinux) {
    rows.push({ key: "runtime", name: "Local Ferrocrate runtime", description: "Installed native engine and rootless API daemon", status: daemonStatus?.state === "running" ? "Running" : "Installed · not running", action: null });
  } else {
    rows.push({ key: "install", name: "Install and bootstrap", description: "Download and prepare the local Ferrocrate stack", status: installStatus, action: onOpenInstall });
  }
  return createElement("section", { className: "panel table-panel resource-table-panel", "aria-label": "Settings" },
    createElement("div", { className: "table-scroll" }, createElement("table", null,
      createElement("thead", null, createElement("tr", null,
        createElement("th", null, "Area"),
        createElement("th", null, "What it controls"),
        createElement("th", null, "Status"),
        createElement("th", { "aria-label": "Actions" }),
      )),
      createElement("tbody", null, rows.map((row) => createElement("tr", { key: row.key },
        createElement("td", { className: "container-name" }, row.name),
        createElement("td", { className: "muted" }, row.description),
        createElement("td", null, row.status),
        createElement("td", { className: "row-actions" }, row.action ? createElement("button", { className: "btn btn-secondary", onClick: row.action }, "Configure") : null),
      ))),
    )),
  );
}
