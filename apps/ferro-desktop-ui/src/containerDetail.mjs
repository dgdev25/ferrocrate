export function maskEnvironment(environment) {
  return environment.map((entry) => `${entry.split("=", 1)[0]}=••••••`);
}

export function parseOptionalLimit(value) {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (!/^\d+$/.test(trimmed)) {
    throw new Error("Resource limits must be a non-negative whole number");
  }
  const parsed = Number(trimmed);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error("Resource limit is outside the supported whole number range");
  }
  return parsed;
}

export async function loadContainerSelection(target, loadDetail) {
  try {
    return { target, detail: await loadDetail(target), error: null };
  } catch (error) {
    return { target, detail: null, error: String(error) };
  }
}
