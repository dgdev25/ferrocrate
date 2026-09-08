# Shared UI
Custom React primitives composed with plain CSS.
## apps/ferro-desktop-ui/src/iconSystem.mjs
```mjs
import { createElement } from "react";

const ICON_PATHS = {
  box: [
    ["path", { d: "m4 7 8-4 8 4-8 4-8-4Z" }],
    ["path", { d: "M4 7v10l8 4 8-4V7M12 11v10" }],
  ],
  images: [
    ["rect", { x: 5, y: 3, width: 14, height: 14, rx: 2 }],
    ["path", { d: "M3 7v12a2 2 0 0 0 2 2h12" }],
  ],
  hammer: [
    ["path", { d: "m14 5 5 5M13 6l2-2 5 5-2 2M14 9 5 18" }],
    ["path", { d: "m3 20 3-3" }],
  ],
  compose: [
    ["path", { d: "m12 3 8 4-8 4-8-4 8-4Z" }],
    ["path", { d: "m4 12 8 4 8-4M4 17l8 4 8-4" }],
  ],
  disk: [
    ["path", { d: "M5 3h12l3 3v15H4V4a1 1 0 0 1 1-1Z" }],
    ["path", { d: "M8 3v6h8V3M8 21v-7h8v7" }],
  ],
  globe: [
    ["circle", { cx: 12, cy: 12, r: 9 }],
    ["path", { d: "M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" }],
  ],
  servers: [
    ["rect", { x: 4, y: 4, width: 16, height: 6, rx: 2 }],
    ["rect", { x: 4, y: 14, width: 16, height: 6, rx: 2 }],
    ["path", { d: "M8 7h.01M8 17h.01M12 7h5M12 17h5" }],
  ],
  pulse: [
    ["path", { d: "M3 12h4l2-5 4 10 2-5h6" }],
  ],
  gear: [
    ["circle", { cx: 12, cy: 12, r: 3 }],
    ["path", { d: "M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3A1.7 1.7 0 0 0 10 3V2.8h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z" }],
  ],
  play: [["path", { d: "m8 5 11 7-11 7V5Z" }]],
  stop: [["rect", { x: 6, y: 6, width: 12, height: 12, rx: 1 }]],
  trash: [
    ["path", { d: "M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6" }],
  ],
  terminal: [
    ["rect", { x: 3, y: 4, width: 18, height: 16, rx: 2 }],
    ["path", { d: "m7 9 3 3-3 3M13 15h4" }],
  ],
  search: [
    ["circle", { cx: 11, cy: 11, r: 6 }],
    ["path", { d: "m16 16 4 4" }],
  ],
  sun: [
    ["circle", { cx: 12, cy: 12, r: 4 }],
    ["path", { d: "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" }],
  ],
  moon: [["path", { d: "M20 15.4A9 9 0 0 1 8.6 4 9 9 0 1 0 20 15.4Z" }]],
  refresh: [
    ["path", { d: "M20 11a8 8 0 0 0-14.9-4M4 3v5h5M4 13a8 8 0 0 0 14.9 4M20 21v-5h-5" }],
  ],
  more: [
    ["circle", { cx: 5, cy: 12, r: 1 }],
    ["circle", { cx: 12, cy: 12, r: 1 }],
    ["circle", { cx: 19, cy: 12, r: 1 }],
  ],
  close: [
    ["path", { d: "m6 6 12 12M18 6 6 18" }],
  ],
  pause: [
    ["path", { d: "M9 6v12M15 6v12" }],
  ],
};

export function Icon({ name, size = 18, className }) {
  const paths = ICON_PATHS[name];
  if (!paths) return null;
  return createElement(
    "svg",
    {
      className,
      width: size,
      height: size,
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      strokeWidth: 1.75,
      strokeLinecap: "round",
      strokeLinejoin: "round",
      "aria-hidden": true,
      focusable: false,
    },
    paths.map(([tag, props], index) => createElement(tag, { ...props, key: index })),
  );
}

```

## apps/ferro-desktop-ui/src/desktopChrome.mjs
```mjs
import { createElement } from "react";
import { Icon } from "./iconSystem.mjs";

const RESOURCE_TABS = [
  ["containers", "box", "Containers"],
  ["images", "images", "Images"],
  ["builds", "hammer", "Builds"],
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
    RESOURCE_TABS.map(([section, icon, label]) => (
      tabButton(section, icon, label, activeSection, onSelect, counts[section])
    )),
    createElement("span", { className: "tab-spacer", "aria-hidden": true }),
    tabButton("doctor", "pulse", "Doctor", activeSection, onSelect, null),
    tabButton("settings", "gear", "Settings", activeSection, onSelect, null, true),
  );
}

```