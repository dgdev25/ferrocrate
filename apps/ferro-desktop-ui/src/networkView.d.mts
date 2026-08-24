import type { NetworkContainerAttachment, NetworkSummary } from "./types";

export function formatNetworkAttachment(attachment: NetworkContainerAttachment): string;
export function networkIsRemovable(network: Pick<NetworkSummary, "name">): boolean;
