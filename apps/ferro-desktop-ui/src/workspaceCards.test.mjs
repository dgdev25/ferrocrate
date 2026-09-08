import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import * as cards from './workspaceCards.mjs';
const rows = [{ id: 'one', name: 'shop-db', image: 'postgres', composeProject: 'shop', state: 'running', health: 'healthy', status: 'Running' }, { id: 'two', name: 'other', image: 'redis', composeProject: 'other', state: 'exited', health: 'none', status: 'Exited' }];
test('workspace resources follow exact container attachments, never name guesses', () => {
  const groups = cards.workspaceGroups(rows, [{ name: 'data', mounts: [{ container_id: 'one' }] }, { name: 'shop_orphan', mounts: [] }], [{ name: 'shared', containers: [{ container_id: 'one' }, { container_id: 'two' }] }]);
  const shop = groups.find(group => group.name === 'shop');
  assert.deepEqual(shop.volumes.map(volume => volume.name), ['data']);
  assert.deepEqual(shop.networks.map(network => network.name), ['shared']);
  assert.equal(groups.find(group => group.name === 'other').volumes.length, 0);
});
test('workspace card exposes service actions and associated resources', () => {
  const group = cards.workspaceGroups(rows.slice(0, 1), [{ name: 'database-data', mounts: [{ container_id: 'one' }] }], [])[0];
  const markup = renderToStaticMarkup(createElement(cards.WorkspaceCard, { group, busy: false, onAction() {}, onInspect() {} }));
  assert.match(markup, /database-data/);
  for (const label of ['Stop shop-db', 'Logs for shop-db', 'Terminal for shop-db']) assert.ok(markup.includes(label), label);
  assert.doesNotMatch(markup, /<table/);
});
test('primary actions send exact service identity and stopped terminals are disabled', () => {
  const calls = [];
  const buttons = cards.ServiceActions({ row: rows[1], busy: false, onAction: (...args) => calls.push(args), onInspect: (...args) => calls.push(args) }).props.children.flat();
  buttons[0].props.onClick();
  buttons[1].props.onClick();
  assert.deepEqual(calls, [['start_container', 'Container Start', 'two'], ['two', 'logs']]);
  assert.equal(buttons[2].props.disabled, true);
});
test('filtering services retains attached resources belonging to the visible workspace', () => {
  const sibling = { ...rows[0], id: 'db', name: 'db' };
  const groups = cards.workspaceGroups(rows.slice(0, 1), [{ name: 'db-data', mounts: [{ container_id: 'db' }] }], [], [...rows, sibling]);
  assert.deepEqual(groups[0].volumes.map(volume => volume.name), ['db-data']);
  assert.equal(groups[0].rows.length, 1);
});
test('workspace search matches project and service labels', async () => {
  const { filterContainers } = await import('./forgeShell.mjs');
  const service = { ...rows[0], name: 'random-runtime-name', composeProject: 'customer-portal', composeService: 'database' };
  assert.equal(filterContainers([service], 'customer-portal').length, 1);
  assert.equal(filterContainers([service], 'database').length, 1);
});
