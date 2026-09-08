import test from 'node:test';
import assert from 'node:assert/strict';
import * as modal from './modalFocus.mjs';
const first = { name: 'cancel' };
const last = { name: 'submit' };
test('Tab and Shift-Tab wrap within the modal', () => {
  assert.equal(modal.dialogKeyboardTarget([first, last], last, { key: 'Tab', shiftKey: false }), first);
  assert.equal(modal.dialogKeyboardTarget([first, last], first, { key: 'Tab', shiftKey: true }), last);
  assert.equal(modal.dialogKeyboardTarget([first, last], first, { key: 'Tab', shiftKey: false }), null);
});
test('keyboard focus entering from outside is directed inside', () => {
  assert.equal(modal.dialogKeyboardTarget([first, last], {}, { key: 'Tab' }), first);
  assert.equal(modal.dialogKeyboardTarget([first, last], {}, { key: 'Tab', shiftKey: true }), last);
});
test('non-Tab keys and empty focus scopes do not invent focus targets', () => {
  assert.equal(modal.dialogKeyboardTarget([first], first, { key: 'ArrowRight' }), null);
  assert.equal(modal.dialogKeyboardTarget([], first, { key: 'Tab' }), null);
});

test('modal activation focuses inside, isolates Escape, restores background and opener on cleanup', () => {
  const handlers = new Map();
  const document = { activeElement: null, addEventListener: (name, fn) => handlers.set(name, fn), removeEventListener: name => handlers.delete(name) };
  const focusable = name => ({ name, tabIndex: 0, isConnected: true, closest: () => null, getClientRects: () => [1], focus() { document.activeElement = this; } });
  const opener = focusable('open-launcher');
  const cancel = focusable('cancel');
  const submit = focusable('submit');
  const dialog = { querySelectorAll: () => [cancel, submit], getClientRects: () => [1], contains: node => [cancel, submit].includes(node), focus() { document.activeElement = this; } };
  const sibling = { inert: false };
  const body = { parentElement: null, children: [] };
  const root = { ownerDocument: document, querySelector: () => dialog, parentElement: body };
  body.children = [sibling, root];
  document.body = body;
  document.querySelectorAll = () => [dialog];
  document.activeElement = opener;
  let closed = 0;
  const cleanup = modal.activateDialogFocus(root, () => closed++, opener);
  assert.equal(document.activeElement, cancel);
  assert.equal(sibling.inert, true);
  let prevented = 0;
  let stopped = 0;
  handlers.get('keydown')({ key: 'Escape', preventDefault: () => prevented++, stopPropagation: () => stopped++ });
  assert.deepEqual([closed, prevented, stopped], [1, 1, 1]);
  cleanup();
  assert.equal(sibling.inert, false);
  assert.equal(document.activeElement, opener);
  assert.equal(handlers.size, 0);
});
