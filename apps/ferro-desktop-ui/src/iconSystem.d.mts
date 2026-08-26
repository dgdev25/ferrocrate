import type { ReactElement } from "react";

export type IconName =
  | "box"
  | "images"
  | "hammer"
  | "compose"
  | "disk"
  | "globe"
  | "servers"
  | "pulse"
  | "gear"
  | "play"
  | "stop"
  | "trash"
  | "terminal"
  | "search"
  | "sun"
  | "moon"
  | "refresh"
  | "more"
  | "close"
  | "pause";

export function Icon(props: {
  name: IconName;
  size?: number;
  className?: string;
}): ReactElement | null;
