import type { NetworkContainerAttachment, NetworkSummary } from "./types";

export function formatNetworkAttachment(attachment: NetworkContainerAttachment): string;
export function networkIsRemovable(network: Pick<NetworkSummary, "name">): boolean;
export function customNetworkCreateAvailable(daemon: { custom_networks?: boolean } | null | undefined): boolean;
export function NetworkCapabilityNotice(props: { customNetworks: boolean; onDoctor: () => void }): import("react").ReactElement | null;
