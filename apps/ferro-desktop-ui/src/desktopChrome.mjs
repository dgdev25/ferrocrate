import { createElement } from "react";
import { Icon } from "./iconSystem.mjs";

const RESOURCE_TABS = [
  ["containers", "box", "Workspaces"],
  ["images", "images", "Images"],
  ["builds", "pulse", "Build activity"],
];
const ADVANCED_TABS = [
  ["compose", "compose", "Compose"],
  ["volumes", "disk", "Volumes"],
  ["networks", "globe", "Networks"],
  ["fleet", "servers", "Fleet"],
];

export function showGlobalRunAction(activeSection) {
  return activeSection === "containers";
}

function tabButton(section, icon, label, activeSection, onSelect, count, iconOnly = false) {
  const active = activeSection === section;
  return createElement("button", {
    key: section,
    className: `desktop-tab${active ? " active" : ""}`,
    onClick: () => onSelect(section),
    "aria-current": active ? "page" : undefined,
    "aria-label": label,
  },
  createElement(Icon, { name: icon, size: 16, className: "tab-icon" }),
  createElement("span", { className: iconOnly ? "visually-hidden" : undefined }, label),
  count == null ? null : createElement("span", { className: "tab-count" }, count));
}

export function DesktopTabBar({ activeSection, counts, onSelect }) {
  return createElement("nav", { className: "desktop-tabs", "aria-label": "Primary" },
    createElement("div", { className: "sidebar-brand" },
      createElement("img", { src: "/brand/folded-forge-mark.png", alt: "", width: 38, height: 38 }),
      createElement("div", null, createElement("strong", null, "FerroCrate"), createElement("span", null, "Local development"))),
    createElement("p", { className: "sidebar-label" }, "Workspace"),
    RESOURCE_TABS.map(([section, icon, label]) => (
      tabButton(section, icon, label, activeSection, onSelect, counts[section])
    )),
    createElement("details", { className: "sidebar-resources", open: ADVANCED_TABS.some(([section]) => section === activeSection) || undefined },
      createElement("summary", null, createElement(Icon, { name: "box", size: 16 }), createElement("span", null, "Resources")),
      ADVANCED_TABS.map(([section, icon, label]) => tabButton(section, icon, label, activeSection, onSelect, counts[section]))),
    createElement("span", { className: "tab-spacer", "aria-hidden": true }),
    tabButton("doctor", "pulse", "Doctor", activeSection, onSelect, null),
    tabButton("settings", "gear", "Settings", activeSection, onSelect, null),
  );
}
