import { createElement } from "react";
import { Icon } from "./iconSystem.mjs";

const RESOURCE_TABS = [
  ["containers", "box", "Containers"],
  ["images", "images", "Images"],
  ["builds", "hammer", "Builds"],
  ["compose", "compose", "Compose"],
  ["volumes", "disk", "Volumes"],
  ["networks", "globe", "Networks"],
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
    RESOURCE_TABS.map(([section, icon, label]) => (
      tabButton(section, icon, label, activeSection, onSelect, counts[section])
    )),
    createElement("span", { className: "tab-spacer", "aria-hidden": true }),
    tabButton("doctor", "pulse", "Doctor", activeSection, onSelect, null),
    tabButton("settings", "gear", "Settings", activeSection, onSelect, null, true),
  );
}
