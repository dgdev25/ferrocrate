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

export function parseImageRows(output) {
  try {
    const records = JSON.parse(output || "[]");
    if (!Array.isArray(records)) return [];
    return records.map((record) => ({
      id: String(record.Id || record.id || record.RepoTags?.[0] || "unknown"),
      reference: String(record.RepoTags?.[0] || record.reference || "untagged"),
      size: formatImageSize(record.Size ?? record.size),
      created: String(record.Created || record.created || "—"),
    }));
  } catch {
    return [];
  }
}
