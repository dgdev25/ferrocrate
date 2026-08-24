import { createElement } from "react";

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

export function customNetworkCreateAvailable(daemon) {
  return daemon?.custom_networks === true;
}

export function NetworkCapabilityNotice({ customNetworks, onDoctor }) {
  if (customNetworks) return null;
  return createElement("section", { className: "network-capability-notice", role: "status" },
    createElement("div", null,
      createElement("strong", null, "Custom networks need host setup"),
      createElement("p", null, "Run Ferrocrate with a privileged (rootful) daemon, or configure the Ferrocrate AppArmor profile for rootless operation."),
    ),
    createElement("button", { className: "btn btn-secondary", onClick: onDoctor }, "Open Doctor"),
  );
}
