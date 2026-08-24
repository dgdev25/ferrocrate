import test from "node:test";
import assert from "node:assert/strict";

import { formatNetworkAttachment, networkIsRemovable } from "./networkView.mjs";

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
