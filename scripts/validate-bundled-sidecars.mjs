#!/usr/bin/env node
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const marker = "FERROCRATE NON-BUNDLE SIDECAR PLACEHOLDER";
const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const binaries = join(repoRoot, "apps", "ferro-desktop-ui", "src-tauri", "binaries");

let entries = [];
try {
  entries = readdirSync(binaries);
} catch {
  // The diagnostic below intentionally covers a fresh checkout too.
}

for (const name of ["ferrocrate", "ferro-desktop"]) {
  const matches = entries.filter((entry) => entry.startsWith(`${name}-`));
  if (matches.length === 0) {
    throw new Error(`missing bundled ${name} sidecar; run scripts/bundle-sidecars.sh`);
  }
  for (const entry of matches) {
    const contents = readFileSync(join(binaries, entry));
    if (contents.subarray(0, marker.length).toString() === marker) {
      throw new Error(
        `${entry} is a non-bundle placeholder; run scripts/bundle-sidecars.sh before tauri build`,
      );
    }
  }
}

console.log("validated real Ferrocrate bundle sidecars");
