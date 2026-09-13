import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));

async function validatorFixture(t, files) {
  const root = await mkdtemp(join(tmpdir(), 'ferro-sidecar-validator-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const scriptDir = join(root, 'scripts');
  const binaries = join(root, 'apps', 'ferro-desktop-ui', 'src-tauri', 'binaries');
  await mkdir(scriptDir, { recursive: true });
  await mkdir(binaries, { recursive: true });
  await cp(join(repoRoot, 'scripts', 'validate-bundled-sidecars.mjs'), join(scriptDir, 'validate-bundled-sidecars.mjs'));
  await Promise.all(files.map(name => writeFile(join(binaries, name), 'real sidecar bytes')));
  return { root, script: join(scriptDir, 'validate-bundled-sidecars.mjs') };
}

test('Windows validation rejects Linux sidecars', async t => {
  const fixture = await validatorFixture(t, [
    'ferrocrate-x86_64-unknown-linux-gnu',
    'ferro-desktop-sidecar-x86_64-unknown-linux-gnu',
  ]);
  const result = spawnSync(process.execPath, [fixture.script], {
    encoding: 'utf8',
    env: { ...process.env, TAURI_ENV_PLATFORM: 'windows', TAURI_ENV_ARCH: 'x86_64' },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ferrocrate-x86_64-pc-windows-msvc\.exe/);
});

test('Windows validation accepts Windows sidecars', async t => {
  const fixture = await validatorFixture(t, [
    'ferrocrate-x86_64-pc-windows-msvc.exe',
    'ferro-desktop-sidecar-x86_64-pc-windows-msvc.exe',
  ]);
  const result = spawnSync(process.execPath, [fixture.script], {
    encoding: 'utf8',
    env: { ...process.env, TAURI_ENV_PLATFORM: 'windows', TAURI_ENV_ARCH: 'x86_64' },
  });
  assert.equal(result.status, 0, result.stderr);
});
