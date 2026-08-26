import type { ReactElement } from "react";

export type AppSection = "containers" | "images" | "builds" | "compose" | "volumes" | "networks" | "fleet" | "doctor" | "settings";

export function DesktopTabBar(props: {
  activeSection: AppSection;
  counts: Record<"containers" | "images" | "builds" | "compose" | "volumes" | "networks" | "fleet", number>;
  doctorIssues?: number;
  onSelect: (section: AppSection) => void;
}): ReactElement;
export function showGlobalRunAction(activeSection: AppSection): boolean;
