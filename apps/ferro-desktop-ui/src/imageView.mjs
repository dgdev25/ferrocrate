export function formatImageSize(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value) || value < 0) return "—";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let amount = value / 1024;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount.toFixed(amount >= 10 ? 0 : 1)} ${units[unit]}`;
}

export function formatImageCreated(value) {
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds > 0) {
    return `${new Date(seconds * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC`;
  }
  const date = new Date(String(value));
  if (!Number.isNaN(date.valueOf())) {
    return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
  }
  return "—";
}

export function pullFailurePresentation(error) {
  const detail = String(error || "No technical detail was returned.");
  const normalized = detail.toLowerCase();
  if (/(daemon|connection refused|not running|no such file)/.test(normalized)) {
    return { kind: "daemon", message: "Ferrocrate isn't running", detail };
  }
  if (/(entitlement|license required|not licensed|not entitled)/.test(normalized)) {
    return { kind: "license", message: "Your current plan doesn't include image pulls.", detail };
  }
  return { kind: "generic", message: "We couldn't pull this image.", detail };
}

export function parseImageRows(output) {
  try {
    const records = JSON.parse(output || "[]");
    if (!Array.isArray(records)) return [];
    return records.map((record) => ({
      id: String(record.Id || record.id || record.RepoTags?.[0] || "unknown"),
      reference: String(record.RepoTags?.[0] || record.reference || "untagged"),
      size: formatImageSize(record.Size ?? record.size),
      created: formatImageCreated(record.Created ?? record.created),
    }));
  } catch {
    return [];
  }
}
