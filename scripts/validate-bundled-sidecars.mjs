#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const marker = "FERROCRATE NON-BUNDLE SIDECAR PLACEHOLDER";
const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const binaries = join(repoRoot, "apps", "ferro-desktop-ui", "src-tauri", "binaries");

function targetTriple(platform, architecture) {
  const arch = { x64: "x86_64", arm64: "aarch64" }[architecture] ?? architecture;
  switch (platform) {
    case "windows":
      return `${arch}-pc-windows-msvc`;
    case "darwin":
      return `${arch}-apple-darwin`;
    case "linux":
      return `${arch}-unknown-linux-gnu`;
    default:
      throw new Error(`unsupported sidecar platform: ${platform}`);
  }
}

const target = targetTriple(
  process.env.TAURI_ENV_PLATFORM ?? process.platform,
  process.env.TAURI_ENV_ARCH ?? process.arch,
);
const extension = target.includes("windows") ? ".exe" : "";

for (const name of ["ferrocrate", "ferro-desktop-sidecar"]) {
  const entry = `${name}-${target}${extension}`;
  let contents;
  try {
    contents = readFileSync(join(binaries, entry));
  } catch {
    throw new Error(`missing bundled ${entry}; run scripts/bundle-sidecars.sh before tauri build`);
  }
  if (contents.subarray(0, marker.length).toString() === marker) {
    throw new Error(
      `${entry} is a non-bundle placeholder; run scripts/bundle-sidecars.sh before tauri build`,
    );
  }
}

console.log(`validated real Ferrocrate bundle sidecars for ${target}`);
