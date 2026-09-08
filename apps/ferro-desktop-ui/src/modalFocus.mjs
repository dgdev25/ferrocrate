import { cloneElement, useEffect, useRef } from 'react';

export function dialogKeyboardTarget(controls, active, event) {
  if (event.key !== 'Tab' || controls.length === 0) return null;
  if (!controls.includes(active)) return event.shiftKey ? controls.at(-1) : controls[0];
  if (event.shiftKey && active === controls[0]) return controls.at(-1);
  if (!event.shiftKey && active === controls.at(-1)) return controls[0];
  return null;
}

function focusableControls(root) {
  return [...root.querySelectorAll('button, input, select, textarea, a[href], summary, [tabindex]')]
    .filter(element => !element.disabled && element.tabIndex >= 0 && !element.closest('[hidden], [inert]') && element.getClientRects().length > 0);
}

export function activateDialogFocus(root, onClose, returnTarget) {
  const document = root.ownerDocument;
  const dialog = root.querySelector('[role="dialog"]');
  if (!dialog) return () => {};
  const topmost = () => [...document.querySelectorAll('[role="dialog"]')].filter(element => element.getClientRects().length > 0).at(-1) === dialog;
  const inertSiblings = [];
  for (let branch = root; branch.parentElement && branch !== document.body; branch = branch.parentElement) {
    for (const sibling of branch.parentElement.children) {
      if (sibling === branch) continue;
      inertSiblings.push([sibling, sibling.inert]);
      sibling.inert = true;
    }
  }
  const focusFirst = () => (focusableControls(dialog)[0] ?? dialog).focus();
  const onKeyDown = event => {
    if (!topmost()) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      onClose();
      return;
    }
    const controls = focusableControls(dialog);
    const target = dialogKeyboardTarget(controls, document.activeElement, event);
    if (target || (event.key === 'Tab' && controls.length === 0)) {
      event.preventDefault();
      (target ?? dialog).focus();
    }
  };
  const onFocusIn = event => { if (topmost() && !dialog.contains(event.target)) focusFirst(); };
  document.addEventListener('keydown', onKeyDown, true);
  document.addEventListener('focusin', onFocusIn);
  focusFirst();
  return () => {
    document.removeEventListener('keydown', onKeyDown, true);
    document.removeEventListener('focusin', onFocusIn);
    for (const [sibling, inert] of inertSiblings) sibling.inert = inert;
    if (returnTarget?.isConnected && !returnTarget.closest('[inert]')) returnTarget.focus();
  };
}

export function DialogFocusScope({ children, dialogId, onClose }) {
  const root = useRef(null);
  const close = useRef(onClose);
  const returnTarget = useRef(null);
  close.current = onClose;
  useEffect(() => {
    if (!root.current) return undefined;
    returnTarget.current ??= root.current.ownerDocument.activeElement;
    return activateDialogFocus(root.current, () => close.current?.(), returnTarget.current);
  }, [dialogId]);
  return cloneElement(children, { ref: root });
}
