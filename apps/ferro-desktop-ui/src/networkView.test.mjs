import test from "node:test";
import assert from "node:assert/strict";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import * as networkView from "./networkView.mjs";

const { formatNetworkAttachment, networkIsRemovable } = networkView;

test("network attachment text preserves addresses and published ports", () => {
  assert.equal(
    formatNetworkAttachment({
      name: "web",
      container_id: "container-1",
      ipv4_address: "172.30.0.2",
      ipv6_address: "",
      ports: ["0.0.0.0:8080→80/tcp"],
    }),
    "web · 172.30.0.2 · 0.0.0.0:8080→80/tcp",
  );
});

test("the built-in bridge network cannot be removed", () => {
  assert.equal(networkIsRemovable({ name: "bridge" }), false);
  assert.equal(networkIsRemovable({ name: "frontend" }), true);
});

test("rootless networks explain both supported paths and link to Doctor", () => {
  assert.equal(typeof networkView.NetworkCapabilityNotice, "function");
  assert.equal(networkView.customNetworkCreateAvailable({ custom_networks: false }), false);
  assert.equal(networkView.customNetworkCreateAvailable({ custom_networks: true }), true);

  let doctorRuns = 0;
  const notice = createElement(networkView.NetworkCapabilityNotice, {
    customNetworks: false,
    onDoctor: () => { doctorRuns += 1; },
  });
  const markup = renderToStaticMarkup(notice);
  assert.match(markup, /privileged|rootful/i);
  assert.match(markup, /AppArmor profile/i);
  assert.match(markup, />Open Doctor<\/button>/);
  notice.type(notice.props).props.children.at(-1).props.onClick();
  assert.equal(doctorRuns, 1);

  assert.equal(renderToStaticMarkup(createElement(networkView.NetworkCapabilityNotice, {
    customNetworks: true,
    onDoctor: () => {},
  })), "");
});
