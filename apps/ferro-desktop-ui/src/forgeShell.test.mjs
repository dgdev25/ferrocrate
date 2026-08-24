import test from "node:test";
import assert from "node:assert/strict";

import {
  filterContainers,
  formatContainerPorts,
  parseContainerRows,
  shellKeyboardCommand,
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
    ports: [{ host_port: 8080, container_port: 80, protocol: "tcp" }],
  },
  {
    id: "def456",
    name: null,
    image: "worker:latest",
    status: "exited",
    health_status: "none",
    last_exit_code: 137,
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
    },
    {
      id: "def456",
      name: "def456",
      image: "worker:latest",
      state: "exited",
      status: "Exited (137)",
      health: "none",
      ports: "—",
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
  assert.equal(statusTone({ state: "running", health: "unhealthy" }), "unhealthy");
  assert.equal(statusTone({ state: "exited", health: "none" }), "stopped");
});

test("shellKeyboardCommand maps Escape and the advertised search shortcut", () => {
  assert.equal(shellKeyboardCommand({ key: "Escape", metaKey: false, ctrlKey: false }), "close-dialog");
  assert.equal(shellKeyboardCommand({ key: "k", metaKey: true, ctrlKey: false }), "focus-search");
  assert.equal(shellKeyboardCommand({ key: "K", metaKey: false, ctrlKey: true }), "focus-search");
  assert.equal(shellKeyboardCommand({ key: "k", metaKey: false, ctrlKey: false }), null);
});
