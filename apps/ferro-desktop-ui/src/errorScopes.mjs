export function setSectionError(errors, section, error) {
  if (!error) {
    const next = { ...errors };
    delete next[section];
    return next;
  }
  return { ...errors, [section]: String(error) };
}

export function errorForSection(errors, section) {
  return errors[section] || null;
}

export function clearErrorsForNavigation() {
  return {};
}
