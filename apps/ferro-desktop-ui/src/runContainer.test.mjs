import test from "node:test";
import assert from "node:assert/strict";

import { buildRunContainerInvokeArgs, buildRunContainerOptions, initialRunContainerDraft } from "./runContainer.mjs";

test('partially configured storage cannot silently launch without the requested mount', () => {
  for (const volumes of [[{source:'data',target:''}], [{source:'',target:'/data'}]]) {
    assert.throws(() => buildRunContainerOptions({command:'',ports:[],volumes,memoryMb:'',cpus:''}), /source and.*path/i);
  }
});

test("successful-launch reset returns a fresh choice without credentials, resource bindings, or preset state", () => {
  const previous = initialRunContainerDraft();
  previous.image = "postgres:17-alpine";
  previous.environment = "POSTGRES_PASSWORD=old-secret";
  previous.ports[0].host = "5432";
  previous.volumes[0].source = "existing-database";
  previous.launcherPreset = "postgres";
  previous.launcherMode = "custom";
  const reset = initialRunContainerDraft();
  assert.deepEqual(reset, {
    image: "alpine:latest", name: "", command: "", pullIfMissing: true,
    ports: [{ host: "", container: "" }], volumes: [{ source: "", target: "" }],
    environment: "", memoryMb: "", cpus: "",
  });
  assert.notEqual(reset.ports[0], previous.ports[0]);
  assert.notEqual(reset.volumes[0], previous.volumes[0]);
  assert.equal(previous.environment, "POSTGRES_PASSWORD=old-secret", "reset must not mutate a retained failure/cancel draft");
});

test("launch permits image downloads to exceed the ordinary request timeout", async () => {
  const { submitRunContainer } = await import('./runContainer.mjs');
  let options;
  let finished = false;
  await submitRunContainer({
    invoke: async (_command, _payload, config) => { options = config; return { ok: true }; },
    payload: {}, begin: () => true, onBegin: () => {}, onResult: () => {},
    onError: assert.fail, onSuccess: () => {}, finish: () => { finished = true; },
  });
  assert.equal(options?.timeoutMs, 600_000);
  assert.equal(finished, true);
});

test("run dialog converts friendly fields into daemon run options", () => {
  assert.deepEqual(buildRunContainerOptions({
    command: "sh -c echo-ready",
    ports: [{ host: "8080", container: "80" }, { host: "", container: "" }],
    volumes: [{ source: "data", target: "/data" }],
    memoryMb: "128",
    cpus: "0.5",
  }), {
    command: ["sh", "-c", "echo-ready"],
    ports: ["8080:80"],
    volumes: ["data:/data"],
    memory: 134217728,
    cpuQuota: 50000,
    cpuPeriod: 100000,
  });
});

test("run invocation forwards the entered name and parsed command", () => {
  assert.deepEqual(buildRunContainerInvokeArgs({
    image: "alpine:latest",
    name: "  named-worker  ",
    command: "sh -c echo-ready",
    ports: [],
    volumes: [],
    environment: "MODE=test",
    pullIfMissing: true,
    memoryMb: "",
    cpus: "",
  }), {
    image: "alpine:latest",
    name: "named-worker",
    command: ["sh", "-c", "echo-ready"],
    ports: [],
    volumes: [],
    pullIfMissing: true,
    environment: ["MODE=test"],
    memory: null,
    cpuQuota: null,
    cpuPeriod: null,
  });
});

test("run command parsing preserves quotes, escaped spaces, and empty arguments", () => {
  assert.deepEqual(buildRunContainerOptions({
    command: 'sh -c "echo ready" hello\\ world \'\'',
    ports: [],
    volumes: [],
    memoryMb: "",
    cpus: "",
  }).command, ["sh", "-c", "echo ready", "hello world", ""]);
  assert.throws(() => buildRunContainerOptions({
    command: 'sh -c "unterminated',
    ports: [],
    volumes: [],
    memoryMb: "",
    cpus: "",
  }), /Unterminated quote/);
});

test("double-quoted commands preserve ordinary backslashes", () => {
  assert.deepEqual(buildRunContainerOptions({
    command: String.raw`grep "\d+" file "a\"b" "c\\d"`,
    ports: [],
    volumes: [],
    memoryMb: "",
    cpus: "",
  }).command, ["grep", String.raw`\d+`, "file", 'a"b', String.raw`c\d`]);
});

test('preset chooses actual host suggestion and a named persistent volume', async () => {
  const module = await import('./runContainer.mjs');
  assert.equal(typeof module.applyLauncherPreset, 'function');
  const calls = [];
  const draft = await module.applyLauncherPreset('postgres', async (command, payload) => {
    calls.push([command, payload]);
    return [{ port: 5432, available: false, suggested: 15432, conflict: null }];
  }, 'session42');
  assert.deepEqual(calls, [['preflight_container_ports', { ports: [5432] }]]);
  assert.deepEqual(draft.ports, [{ host: '15432', container: '5432' }]);
  assert.deepEqual(draft.volumes, [{ source: 'ferro-postgres-session42-data', target: '/var/lib/postgresql/data' }]);
  assert.match(draft.environment, /^POSTGRES_PASSWORD=/);
});

test('invalid or partial port mappings fail instead of being silently dropped', () => {
  for (const ports of [[{ host: '8080', container: '' }], [{ host: '70000', container: '80' }], [{ host: 'bad', container: '80' }]]) {
    assert.throws(() => buildRunContainerOptions({ command: '', ports, volumes: [], memoryMb: '', cpus: '' }), /port/i);
  }
});

test('preset propagates runtime-host probe failures without inventing a free port', async () => {
  const { applyLauncherPreset } = await import('./runContainer.mjs');
  await assert.rejects(applyLauncherPreset('redis', async () => { throw new Error('host unavailable'); }, 'test'), /host unavailable/);
  await assert.rejects(applyLauncherPreset('redis', async () => [{ port: 6379, suggested: 0 }], 'test'), /valid port/);
});

test('replacement dialog requires the exact current owner name and hides replacement for unknown processes', async () => {
  const { createElement } = await import('react');
  const { renderToStaticMarkup } = await import('react-dom/server');
  const { RunContainerDialog } = await import('./dialogForms.mjs');
  const props = { open: true, busy: false, draft: {}, onCancel() {}, conflict: { port: 5432, suggested: 15432, conflict: { id: 'exact', name: 'db', image: 'postgres' } } };
  const unconfirmed = renderToStaticMarkup(createElement(RunContainerDialog, props));
  assert.match(unconfirmed, /disabled="">Replace db/);
  const confirmed = renderToStaticMarkup(createElement(RunContainerDialog, { ...props, confirmation: 'db' }));
  assert.doesNotMatch(confirmed, /disabled="">Replace db/);
  assert.match(confirmed, /Use port 15432/);
  const unknown = renderToStaticMarkup(createElement(RunContainerDialog, { ...props, conflict: { ...props.conflict, conflict: null } }));
  assert.doesNotMatch(unknown, /Replace db/);
});

test('launch-time bind races recheck current host ownership without retrying or deleting', async () => {
  const module = await import('./runContainer.mjs');
  assert.equal(typeof module.recoverPortConflict, 'function');
  const conflict = { port: 8080, available: false, suggested: 18080, conflict: { id: 'new-owner', name: 'new-service', image: 'nginx' } };
  const calls = [];
  const invoke = async (command, payload) => { calls.push([command, payload]); return [conflict]; };
  assert.equal(await module.recoverPortConflict('bind: address already in use', { ports: ['8080:80'] }, invoke), conflict);
  assert.deepEqual(calls, [['preflight_container_ports', { ports: [8080] }]]);
  assert.equal(await module.recoverPortConflict('image not found', { ports: ['8080:80'] }, invoke), null);
  assert.equal(calls.length, 1);
});
