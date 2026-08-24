import type { ReactElement } from "react";
import type { RegistryAuthStatus } from "./types";

export function registryStatusText(status: RegistryAuthStatus): string;
export function RegistryAccountControl(props: { status: RegistryAuthStatus | null; onOpen?: () => void }): ReactElement;
