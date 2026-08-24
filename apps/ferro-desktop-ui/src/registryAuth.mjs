import { createElement, Fragment } from "react";

export function registryStatusText(status) {
  return status.logged_in
    ? status.username || "Signed in"
    : "Sign in";
}

export function RegistryAccountControl({ status, onOpen }) {
  const signedIn = Boolean(status?.logged_in);
  const accountName = signedIn ? registryStatusText(status) : "Sign in";

  return createElement("button", {
    className: "registry-account",
    onClick: onOpen,
    "aria-label": signedIn ? `Registry account: ${accountName}` : "Sign in to a registry",
  }, signedIn
    ? createElement(Fragment, null,
      createElement("span", { className: "registry-avatar", "aria-hidden": true }, accountName.slice(0, 1).toUpperCase()),
      createElement("span", null, accountName),
    )
    : "Sign in");
}
