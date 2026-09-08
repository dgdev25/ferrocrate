import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

// Execute the actual desktop invoke boundary; only the native/web transports
// are controlled, so a missing queue in either production branch is detected.
async function desktopInvoke(native, transport) {
  const path = new URL('desktopRuntime.ts', import.meta.url);
  const source = fs.readFileSync(path, 'utf8');
  const tree = ts.createSourceFile(path.pathname, source, ts.ScriptTarget.Latest, true);
  const modules = {
    '@tauri-apps/api/core': { invoke: transport },
    '@tauri-apps/api/event': {},
    '@tauri-apps/plugin-dialog': {},
    './webBridgeRuntime.mjs': {
      createWebBridgeRuntime: () => ({ invoke: transport, capabilities: {} }),
      installWebBridgeRuntime: (_window, runtime) => runtime,
    },
  };
  for (const node of tree.statements) {
    if (!ts.isImportDeclaration(node)) continue;
    const name = node.moduleSpecifier.text;
    if (name.startsWith('./') && !modules[name]) modules[name] = await import(new URL(name, import.meta.url));
  }
  const exports = {};
  const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  vm.runInNewContext(code, { exports, require: name => modules[name], window: native ? { __TAURI_INTERNALS__: {} } : {} });
  return exports.invoke;
}
const deferred = () => { let resolve; let reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const settle = () => new Promise(resolve => setImmediate(resolve));

for (const native of [true, false]) {
  test(`${native ? 'native' : 'web'} terminal writes preserve keystroke order despite transport latency`, async () => {
    const first = deferred();
    const calls = []; const received = [];
    const invoke = await desktopInvoke(native, async (command, args) => {
      calls.push(command === 'write_terminal' ? args.data[0] : command);
      if (args?.data?.[0] === 'a') await first.promise;
      if (command === 'write_terminal') received.push(args.data[0]);
    });
    const a = invoke('write_terminal', { data: ['a'] });
    const b = invoke('write_terminal', { data: ['b'] });
    await settle();
    assert.deepEqual(calls, ['a']);
    await invoke('get_desktop_snapshot');
    assert.deepEqual(calls, ['a', 'get_desktop_snapshot']);
    first.resolve();
    await Promise.all([a, b]);
    assert.deepEqual(received, ['a', 'b']);
  });
}

test('terminal close and next start cannot overtake queued input from the previous shell', async () => {
  const first = deferred(); const calls = [];
  const invoke = await desktopInvoke(false, async (command, args) => {
    calls.push(command === 'write_terminal' ? args.data[0] : command);
    if (args?.data?.[0] === 'old') await first.promise;
  });
  const requests = [invoke('write_terminal', { data: ['old'] }), invoke('close_terminal'), invoke('start_terminal'), invoke('write_terminal', { data: ['new'] })];
  await settle();
  assert.deepEqual(calls, ['old']);
  first.resolve();
  await Promise.all(requests);
  assert.deepEqual(calls, ['old', 'close_terminal', 'start_terminal', 'new']);
});

test('failed terminal input suppresses trailing bytes but a new shell recovers', async () => {
  const calls = []; const failure = new Error('input transport failed');
  const invoke = await desktopInvoke(true, async (command, args) => {
    calls.push(command === 'write_terminal' ? args.data[0] : command);
    if (args?.data?.[0] === 'bad') throw failure;
  });
  const outcomes = await Promise.allSettled([invoke('write_terminal', { data: ['bad'] }), invoke('write_terminal', { data: ['unsafe-tail'] })]);
  assert.deepEqual(outcomes.map(value => value.status), ['rejected', 'rejected']);
  assert.deepEqual(calls, ['bad']);
  await invoke('close_terminal');
  await invoke('start_terminal');
  await invoke('write_terminal', { data: ['new'] });
  assert.deepEqual(calls, ['bad', 'close_terminal', 'start_terminal', 'new']);
});
