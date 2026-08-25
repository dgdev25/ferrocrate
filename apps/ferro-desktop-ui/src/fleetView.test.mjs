import test from "node:test";
import assert from "node:assert/strict";

import {
  canOperateFleet,
  fleetContainerRows,
  fleetHostState,
  normalizeFleetSnapshot,
} from "./fleetView.mjs";

test("fleet roles preserve read access while exposing actions only to operate", () => {
  assert.equal(canOperateFleet("operate"), true);
  assert.equal(canOperateFleet("view"), false);
  assert.equal(canOperateFleet(null), false);
});

test("fleet snapshot normalizes host state and flattens per-host containers", () => {
  const snapshot = normalizeFleetSnapshot({
    cluster_epoch: 3,
    hosts: [
      {
        node_id: "lab-x86",
        enrollment_state: "enrolled",
        connected: true,
        health: "healthy",
        containers: [{ Id: "abc", Names: ["/fleet-lab"], Image: "alpine", State: "running" }],
      },
      {
        node_id: "oracle-arm",
        enrollment_state: "revoked",
        connected: false,
        containers: [],
      },
    ],
    deploys: [],
  });
  assert.equal(snapshot.hosts.length, 2);
  assert.equal(fleetHostState(snapshot.hosts[0]), "online");
  assert.equal(fleetHostState(snapshot.hosts[1]), "revoked");
  assert.deepEqual(fleetContainerRows(snapshot.hosts), [
    {
      hostId: "lab-x86",
      id: "abc",
      name: "fleet-lab",
      image: "alpine",
      status: "running",
    },
  ]);
});

test("malformed fleet snapshot fails closed to empty lists", () => {
  assert.deepEqual(normalizeFleetSnapshot(null), { cluster_epoch: 0, hosts: [], deploys: [] });
  assert.deepEqual(normalizeFleetSnapshot({ hosts: "wrong", deploys: {} }), {
    cluster_epoch: 0,
    hosts: [],
    deploys: [],
  });
});
