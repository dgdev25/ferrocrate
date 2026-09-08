import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

// Execute the actual component handlers with controlled deferred backend replies.
function handlers(file, names, context) {
  const path = process.env.SAFETY_BASELINE ? `${process.env.SAFETY_BASELINE}/apps/ferro-desktop-ui/src/${file}` : new URL(file, import.meta.url);
  const source = fs.readFileSync(path, 'utf8');
  const tree = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const found = [];
  function visit(node) {
    if (ts.isFunctionDeclaration(node) && names.includes(node.name?.text)) found.push(node.getText(tree));
    ts.forEachChild(node, visit);
  }
  visit(tree);
  const code = ts.transpileModule(found.join('\n'), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  return vm.runInNewContext(`${code}\n({${names.join(',')}})`, context);
}
const deferred = () => { let resolve; let reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const noop = () => {};

test('fleet refresh preserves a narrowed selection and an explicitly empty selection', async () => {
  let selection = [];
  const context = {
    session: { current: { active: true, generation: 0 } }, deploymentInitialized: { current: false },
    deployHosts: [], invoke: async () => ({ hosts: [{ node_id: 'a', connected: true }, { node_id: 'b', connected: true }] }),
    normalizeFleetSnapshot: value => value, setSnapshot: noop, setError: noop, setRunHost: noop,
    chooseRunHost: noop, setDeployHosts: value => { selection = typeof value === 'function' ? value(selection) : value; }, setLoading: noop,
  };
  const { refresh } = handlers('FleetApp.tsx', ['refresh'], context);
  await refresh();
  assert.deepEqual([...selection], ['a', 'b']);
  selection = ['a'];
  await refresh();
  assert.deepEqual([...selection], ['a']);
  selection = [];
  await refresh();
  assert.deepEqual([...selection], []);
});

test('sign out prevents in-flight polling from restoring fleet data', async () => {
  const reply = deferred();
  let snapshot = null;
  let cleared = false;
  const context = {
    session: { current: { active: true, generation: 0 } }, deploymentInitialized: { current: false },
    pollTimer: { current: 4 }, window: { clearInterval: noop }, clearSession: () => { cleared = true; },
    sessionStorage: { removeItem: noop }, TOKEN_KEY: 'token', ROLE_KEY: 'role',
    setRole: noop, setResult: noop, setDeployHosts: noop, setLoading: noop, setError: noop, setRunHost: noop,
    invoke: () => reply.promise, normalizeFleetSnapshot: value => value, setSnapshot: value => { snapshot = value; }, deployHosts: [],
  };
  const { refresh, signOut } = handlers('FleetApp.tsx', ['refresh', 'signOut'], context);
  const request = refresh();
  signOut();
  reply.resolve({ hosts: [] });
  await request;
  assert.equal(snapshot, null);
  assert.equal(cleared, true);
});

test('failed and out-of-order Compose reads cannot leave stale actionable services', async () => {
  const replies = [deferred(), deferred()];
  let snapshot = { services: ['old'] };
  let file = 'old.yml';
  const context = {
    composeGeneration: { current: 0 }, setComposeLoading: noop,
    setComposeSnapshot: value => { snapshot = value; }, setComposeFile: value => { file = value; },
    invoke: () => replies.shift().promise,
  };
  const firstReply = replies[0]; const secondReply = replies[1];
  const { readComposeSnapshot } = handlers('App.tsx', ['readComposeSnapshot'], context);
  const first = readComposeSnapshot('first.yml');
  assert.equal(snapshot, null);
  const second = readComposeSnapshot('second.yml');
  secondReply.resolve({ services: ['second'] });
  await second;
  firstReply.resolve({ services: ['first'] });
  await first;
  assert.equal(file, 'second.yml');
  assert.deepEqual(snapshot.services, ['second']);
  context.invoke = async () => { throw new Error('invalid compose'); };
  await assert.rejects(readComposeSnapshot('bad.yml'), /invalid compose/);
  assert.equal(snapshot, null);
  assert.equal(file, 'second.yml');
});

test('inspector retarget waits for prior log stream shutdown before changing identity', async () => {
  const stop = deferred(); const calls = [];
  const context = {
    inspectorOpening: { current: false }, runtimeActionRef: { current: false },
    containerTarget: 'a', logFollowRef: { current: true }, activeLogStream: { current: 'a-generation' },
    terminalActiveRef: { current: false }, stopLogFollow: async () => { calls.push('stop'); await stop.promise; context.logFollowRef.current = false; },
    setLogOutput: noop, inspectorTriggerRef: {}, document: { activeElement: null }, HTMLElement: class {},
    setInspectorOpen: noop, setDetailTab: noop, inspectContainer: async target => { calls.push(`inspect:${target}`); },
    startLogFollow: async target => { calls.push(`start:${target}`); }, requestAnimationFrame: noop,
  };
  const { openServiceInspector } = handlers('App.tsx', ['openServiceInspector'], context);
  const switching = openServiceInspector('b', 'logs');
  assert.deepEqual(calls, ['stop']);
  stop.resolve(); await switching;
  assert.deepEqual(calls, ['stop', 'inspect:b', 'start:b']);
  assert.equal(context.activeLogStream.current, null);
});

test('log events from a previous stream cannot overwrite output, errors, or following state', async () => {
  const source = fs.readFileSync(new URL('App.tsx', import.meta.url), 'utf8');
  const tree = ts.createSourceFile('App.tsx', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  let callback;
  function visit(node) {
    if (ts.isCallExpression(node) && node.expression.getText(tree) === 'useEffect' && node.getText(tree).includes('container-log-batch')) callback = node.arguments[0].getText(tree);
    ts.forEachChild(node, visit);
  }
  visit(tree);
  const registered = new Map(); const changes = [];
  const context = {
    activeLogStream: { current: 'new' }, logFollowRef: { current: true },
    listen: async (name, handler) => { registered.set(name, handler); return noop; },
    setLogOutput: value => changes.push(value), setError: value => changes.push(value),
    setLogsFollowing: value => changes.push(value), setLogsPaused: value => changes.push(value),
  };
  vm.runInNewContext(ts.transpileModule(`(${callback})();`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText, context);
  await new Promise(resolve => setImmediate(resolve));
  for (const [name, handler] of registered) handler({ payload: { stream_id: 'old', payload: name === 'container-log-batch' ? { text: 'old output' } : false } });
  assert.deepEqual(changes, []);
  assert.equal(context.logFollowRef.current, true);
  registered.get('container-log-batch')({ payload: { stream_id: 'new', payload: { text: 'new output' } } });
  assert.deepEqual(changes, ['new output']);
});

test('Compose lifecycle refreshes workspace network ownership and attachments', async () => {
  const refreshed = [];
  const context = {composeSnapshot:{services:[]},composeLoading:false,composeFile:'project.yml',beginRuntimeAction:()=>true,finishRuntimeAction:noop,setError:noop,setActionLabel:noop,setLastAction:noop,invoke:async()=>({ok:true}),readComposeSnapshot:async()=>refreshed.push('compose'),refresh:async()=>refreshed.push('containers'),refreshVolumes:async()=>refreshed.push('volumes'),refreshNetworks:async()=>refreshed.push('networks')};
  const {runComposeAction} = handlers('App.tsx',['runComposeAction'],context);
  await runComposeAction('down','Down');
  assert.deepEqual(refreshed.sort(),['compose','containers','networks','volumes']);
});

test('Fleet tab keyboard handler ignores Tab and other unhandled keys', () => {
  const source=fs.readFileSync(new URL('FleetApp.tsx',import.meta.url),'utf8');
  const tree=ts.createSourceFile('FleetApp.tsx',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
  let callback;
  function visit(node) {
    if(ts.isJsxAttribute(node) && node.name.text==='onKeyDown' && node.getText(tree).includes('tabKeyboardTarget')) callback=node.initializer.expression.getText(tree);
    ts.forEachChild(node,visit);
  }
  visit(tree);
  const changes=[];
  const context={FLEET_SECTIONS:['hosts','deploys'],target:'deploys',tabKeyboardTarget:()=>null,setSection:value=>changes.push(value)};
  const handler=vm.runInNewContext(ts.transpileModule(`(${callback})`,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText,context);
  handler({key:'Tab',preventDefault:()=>changes.push('prevented')});
  assert.deepEqual(changes,[]);
});
