import test from 'node:test';
import assert from 'node:assert/strict';
import { createWebBridgeRuntime } from './webBridgeRuntime.mjs';
test('sign out clears active bearer and rejects a stale successful response', async () => {
  const requests = [];
  let release;
  const runtime = createWebBridgeRuntime({ token: 'old-token', target: { sessionStorage: { removeItem() {} } }, fetchImpl: async (_url, options) => {
    requests.push(options);
    if (requests.length === 1) await new Promise(resolve => { release = resolve; });
    return { ok: true, json: async () => ({ private: true }) };
  }});
  const pending = runtime.invoke('get_fleet_snapshot');
  runtime.clearSession();
  release();
  await assert.rejects(pending, /session/i);
  await runtime.invoke('get_fleet_snapshot');
  assert.equal(requests[1].headers.authorization, undefined);
});
