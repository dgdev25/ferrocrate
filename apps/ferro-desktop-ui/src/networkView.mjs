export function formatNetworkAttachment(attachment) {
  const details = [
    attachment.name || attachment.container_id,
    attachment.ipv4_address,
    attachment.ipv6_address,
    ...attachment.ports,
  ].filter(Boolean);
  return details.join(" · ");
}

export function networkIsRemovable(network) {
  return network.name !== "bridge";
}
