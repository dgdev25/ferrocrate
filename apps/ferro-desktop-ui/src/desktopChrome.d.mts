import type { ReactElement } from "react";

export type AppSection = "containers" | "images" | "builds" | "compose" | "volumes" | "networks" | "doctor" | "settings";

export function DesktopTabBar(props: {
  activeSection: AppSection;
  counts: Record<"containers" | "images" | "builds" | "compose" | "volumes" | "networks", number>;
  doctorIssues?: number;
  onSelect: (section: AppSection) => void;
}): ReactElement;
