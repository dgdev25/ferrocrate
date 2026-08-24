import test from "node:test";
import assert from "node:assert/strict";

import {
  daemonIsAvailable,
  daemonStatusPresentation,
  containerStatsUnavailableMessage,
  containerRemoveAvailability,
  filterContainers,
  filterContainersByStatus,
  formatContainerPorts,
  groupContainers,
  mergeContainerStats,
  parseContainerStats,
  parseContainerRows,
  resourceTotals,
  shouldPollContainerStats,
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
    memory_usage: 67_108_864,
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
      cpuPercent: 0.4,
      memory: "64.0 MiB",
      memoryUsage: 67_108_864,
      memoryLimit: null,
      statsAvailable: null,
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
      cpuPercent: null,
      memory: "—",
      memoryUsage: null,
      memoryLimit: null,
      statsAvailable: null,
    },
  ]);
});

test("live stats parse and merge usage, limits, and availability by container id", () => {
  const rows = parseContainerRows(records);
  const stats = parseContainerStats({
    samples: [
      { id: "abc123", available: true, cpu_percent: 12.25, memory_usage: 67_108_864, memory_limit: 134_217_728 },
      { id: "def456", available: false, cpu_percent: null, memory_usage: null, memory_limit: null },
    ],
  });

  const merged = mergeContainerStats(rows, stats);
  assert.deepEqual(merged[0], {
    ...rows[0],
    statsAvailable: true,
    cpu: "12.3%",
    cpuPercent: 12.25,
    memory: "64.0 MiB / 128.0 MiB",
    memoryUsage: 67_108_864,
    memoryLimit: 134_217_728,
  });
  assert.equal(merged[1].statsAvailable, false);
  assert.equal(merged[1].cpu, "");
  assert.equal(merged[1].memory, "");
});

test("container stats polling only runs for a visible Containers section", () => {
  assert.equal(shouldPollContainerStats("containers", "visible"), true);
  assert.equal(shouldPollContainerStats("images", "visible"), false);
  assert.equal(shouldPollContainerStats("containers", "hidden"), false);
});

test("unavailable live stats use one explicit human message instead of placeholder cells", () => {
  assert.equal(containerStatsUnavailableMessage(), "Live resource stats unavailable for one or more running containers.");
  const [running] = parseContainerRows('[{"id":"live","status":"running"}]');
  assert.equal(running.cpu, "");
  assert.equal(running.memory, "");
});

test("resource totals aggregate live usage and limits", () => {
  assert.deepEqual(resourceTotals([
    { cpuPercent: 4.25, memoryUsage: 64, memoryLimit: 256 },
    { cpuPercent: 5.75, memoryUsage: 32, memoryLimit: 256 },
  ]), { cpu: "10.0%", memory: "96 B / 512 B" });
});

test("running containers explain why removal is unavailable", () => {
  assert.deepEqual(containerRemoveAvailability({ state: "running" }), { allowed: false, reason: "Stop this container before removing it." });
  assert.deepEqual(containerRemoveAvailability({ state: "exited" }), { allowed: true, reason: null });
});

test("resourceTotals aggregates available live samples and hides absent metrics", () => {
  const rows = parseContainerRows(records);
  assert.deepEqual(resourceTotals(rows), {
    cpu: "0.4%",
    memory: "64.0 MiB",
  });
  assert.deepEqual(resourceTotals([{ cpuPercent: null, memoryUsage: null }]), {
    cpu: null,
    memory: null,
  });
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

test("daemonIsAvailable reflects the real API health state", () => {
  assert.equal(daemonIsAvailable({ daemon: { state: "running" } }), true);
  assert.equal(daemonIsAvailable({ daemon: { state: "starting" } }), false);
  assert.equal(daemonIsAvailable({ daemon: { state: "failed", reason: "exit 1" } }), false);
  assert.equal(daemonIsAvailable(null), false);
});

test("daemon status presentation preserves lifecycle state and failure reason", () => {
  assert.deepEqual(daemonStatusPresentation({ state: "starting", reason: null }), { label: "daemon starting", tone: "starting", title: "Ferrocrate API daemon is starting" });
  assert.deepEqual(daemonStatusPresentation({ state: "failed", reason: "exit status 1" }), { label: "daemon failed", tone: "failed", title: "exit status 1" });
});
