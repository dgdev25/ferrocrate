export function buildStepText(text) {
  const trimmed = text.trim();
  try {
    const frame = JSON.parse(trimmed);
    if (typeof frame.stream === "string") return frame.stream.trim();
    if (typeof frame.error === "string") return frame.error.trim();
  } catch {
    // Native CLI output is already human-readable.
  }
  return trimmed;
}
