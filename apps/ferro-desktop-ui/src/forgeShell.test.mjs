import test from "node:test";
import assert from "node:assert/strict";

import {
  daemonIsAvailable,
  filterContainers,
  filterContainersByStatus,
  formatContainerPorts,
  groupContainers,
  parseContainerRows,
  shellKeyboardCommand,
  statusLabel,
  statusTone,
} from "./forgeShell.mjs";

const records = JSON.stringify([
  {
    id: "abc123",
    name: "web-frontend",
    image: "nginx:1.27-alpine",
    status: "running",
    health_status: "healthy",
    last_exit_code: null,
    created_at_unix: 1_700_000_000,
    cpu_percent: 0.4,
    labels: {
      "com.docker.compose.project": "storefront",
      "com.docker.compose.service": "web",
    },
    ports: [{ host_port: 8080, container_port: 80, protocol: "tcp" }],
  },
  {
    id: "def456",
    name: null,
    image: "worker:latest",
    status: "exited",
    health_status: "none",
    last_exit_code: 137,
    created_at_unix: 1_699_900_000,
    labels: {},
    ports: [],
  },
]);

test("parseContainerRows preserves runtime identity and derives table labels", () => {
  const rows = parseContainerRows(records);

  assert.deepEqual(rows, [
    {
      id: "abc123",
      name: "web-frontend",
      image: "nginx:1.27-alpine",
      state: "running",
      status: "Running",
      health: "healthy",
      ports: "8080→80/tcp",
      composeProject: "storefront",
      composeService: "web",
      startedAt: 1_700_000_000,
      cpu: "0.4%",
    },
    {
      id: "def456",
      name: "def456",
      image: "worker:latest",
      state: "exited",
      status: "Exited (137)",
      health: "none",
      ports: "—",
      composeProject: null,
      composeService: null,
      startedAt: 1_699_900_000,
      cpu: "—",
    },
  ]);
});

test("parseContainerRows safely rejects non-array or malformed snapshots", () => {
  assert.deepEqual(parseContainerRows("not json"), []);
  assert.deepEqual(parseContainerRows('{"id":"one"}'), []);
});

test("formatContainerPorts joins mappings and supplies an em dash when absent", () => {
  assert.equal(formatContainerPorts([]), "—");
  assert.equal(
    formatContainerPorts([
      { host_port: 3000, container_port: 3000, protocol: "tcp" },
      { host_port: 5353, container_port: 53, protocol: "udp" },
    ]),
    "3000→3000/tcp, 5353→53/udp",
  );
});

test("filterContainers searches names, images, status, and ports case-insensitively", () => {
  const rows = parseContainerRows(records);
  assert.deepEqual(filterContainers(rows, "NGINX").map((row) => row.id), ["abc123"]);
  assert.deepEqual(filterContainers(rows, "137").map((row) => row.id), ["def456"]);
  assert.deepEqual(filterContainers(rows, "8080").map((row) => row.id), ["abc123"]);
});

test("statusTone distinguishes running, unhealthy, and stopped rows", () => {
  assert.equal(statusTone({ state: "running", health: "healthy" }), "running");
  assert.equal(statusTone({ state: "running", health: "starting" }), "degraded");
  assert.equal(statusTone({ state: "running", health: "unhealthy" }), "unhealthy");
  assert.equal(statusTone({ state: "exited", health: "none" }), "exited");
  assert.equal(statusLabel({ state: "running", health: "starting", status: "Running" }), "Degraded");
  assert.equal(statusLabel({ state: "running", health: "unhealthy", status: "Running" }), "Unhealthy");
  assert.equal(statusLabel({ state: "exited", health: "none", status: "Exited (3)" }), "Exited (3)");
});

test("status filters use the binding All, Running, Degraded, Unhealthy, and Exited vocabulary", () => {
  const rows = [
    { id: "healthy", state: "running", health: "healthy" },
    { id: "starting", state: "running", health: "starting" },
    { id: "unhealthy", state: "running", health: "unhealthy" },
    { id: "exited", state: "exited", health: "none" },
  ];
  assert.deepEqual(filterContainersByStatus(rows, "all").map((row) => row.id), ["healthy", "starting", "unhealthy", "exited"]);
  assert.deepEqual(filterContainersByStatus(rows, "running").map((row) => row.id), ["healthy"]);
  assert.deepEqual(filterContainersByStatus(rows, "degraded").map((row) => row.id), ["starting"]);
  assert.deepEqual(filterContainersByStatus(rows, "unhealthy").map((row) => row.id), ["unhealthy"]);
  assert.deepEqual(filterContainersByStatus(rows, "exited").map((row) => row.id), ["exited"]);
});

test("containers group by Compose project with Standalone last", () => {
  const rows = [
    { id: "worker", composeProject: null, state: "exited" },
    { id: "web", composeProject: "storefront", state: "running" },
    { id: "db", composeProject: "storefront", state: "running" },
    { id: "admin", composeProject: "backoffice", state: "running" },
  ];
  assert.deepEqual(groupContainers(rows).map((group) => ({
    name: group.name,
    compose: group.compose,
    ids: group.rows.map((row) => row.id),
    running: group.running,
  })), [
    { name: "backoffice", compose: true, ids: ["admin"], running: 1 },
    { name: "storefront", compose: true, ids: ["web", "db"], running: 2 },
    { name: "Standalone", compose: false, ids: ["worker"], running: 0 },
  ]);
});

test("shellKeyboardCommand maps Escape and the advertised search shortcut", () => {
  assert.equal(shellKeyboardCommand({ key: "Escape", metaKey: false, ctrlKey: false }), "close-dialog");
  assert.equal(shellKeyboardCommand({ key: "k", metaKey: true, ctrlKey: false }), "focus-search");
  assert.equal(shellKeyboardCommand({ key: "K", metaKey: false, ctrlKey: true }), "focus-search");
  assert.equal(shellKeyboardCommand({ key: "k", metaKey: false, ctrlKey: false }), null);
});

test("daemonIsAvailable reflects successful runtime data commands, not optional VM status", () => {
  assert.equal(daemonIsAvailable({ containers: { ok: true }, images: { ok: true } }), true);
  assert.equal(daemonIsAvailable({ containers: { ok: false }, images: { ok: true } }), false);
  assert.equal(daemonIsAvailable(null), false);
});
