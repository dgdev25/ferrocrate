import test from "node:test";
import assert from "node:assert/strict";

import {
  canOperateFleet,
  chooseRunHost,
  fleetContainerRows,
  fleetHostState,
  isFleetSessionExpired,
  normalizeFleetSnapshot,
  shouldShowFleetRefreshError,
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

test("expired snapshot authorization is recognized without masking other refresh errors", () => {
  assert.equal(isFleetSessionExpired("Error: command get_fleet_snapshot failed (HTTP 401)"), true);
  assert.equal(isFleetSessionExpired("Error: command fleet_command failed (HTTP 401)"), false);
  assert.equal(isFleetSessionExpired("Error: command get_fleet_snapshot failed (HTTP 502)"), false);
});

test("fleet refresh preserves an explicitly selected connected run host", () => {
  const refreshedHosts = [
    { node_id: "lab-x86", connected: true },
    { node_id: "oracle-arm", connected: true },
  ];

  assert.equal(chooseRunHost("oracle-arm", refreshedHosts), "oracle-arm");
  assert.equal(chooseRunHost("", refreshedHosts), "lab-x86");
});

test("unauthenticated automatic fleet refresh stays silent until sign-in", () => {
  assert.equal(shouldShowFleetRefreshError(null), false);
  assert.equal(shouldShowFleetRefreshError("operate"), true);
});

test("run host selection discards disconnected, removed, and revoked targets", () => {
  const hosts = [
    { node_id: "offline", connected: false },
    { node_id: "revoked", connected: true, enrollment_state: "revoked" },
    { node_id: "online", connected: true },
  ];
  for (const current of ["offline", "revoked", "removed", ""]) {
    assert.equal(chooseRunHost(current, hosts), "online");
  }
  assert.equal(chooseRunHost("online", []), "");
});
