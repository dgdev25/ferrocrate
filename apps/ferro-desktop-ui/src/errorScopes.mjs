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

export function resourceActionState(action, result, detail) {
  if (!result.ok && action === "create") {
    return { actionResult: null, dialogError: detail, pageError: null };
  }
  return {
    actionResult: result,
    dialogError: null,
    pageError: result.ok ? null : detail,
  };
}

export function navigationTransientState(sectionErrors) {
  return {
    actionLabel: "",
    actionResult: null,
    sectionErrors: clearErrorsForNavigation(sectionErrors),
  };
}
