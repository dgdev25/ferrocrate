import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const artifacts = ['FerroCrate.AppImage', 'FerroCrate_aarch64.app.tar.gz', 'FerroCrate_x86_64.app.tar.gz', 'FerroCrate_x64-setup.exe'];
async function manifest(t, { omit, empty, duplicate } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'ferro-release-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  for (const name of [...artifacts, ...(duplicate ? ['Other.AppImage'] : [])]) {
    if (name === omit) continue;
    await writeFile(join(dir, name), 'fixture payload');
    if (`${name}.sig` !== omit) await writeFile(join(dir, `${name}.sig`), name === empty ? ' \n' : 'fixture signature');
  }
  const out = join(dir, 'latest.json');
  const result = spawnSync(process.execPath, ['scripts/build-updater-manifest.mjs', '--dir', dir, '--repo', 'owner/repo', '--tag', 'v1.0.0', '--version', '1.0.0', '--out', out], { encoding: 'utf8' });
  return { ...result, out };
}
test('complete manifest contains both macOS architectures and all supported targets', async t => {
  const r = await manifest(t);
  assert.equal(r.status, 0, r.stderr);
  const data = JSON.parse(await readFile(r.out));
  assert.deepEqual(Object.keys(data.platforms).sort(), ['darwin-aarch64', 'darwin-x86_64', 'linux-x86_64', 'windows-x86_64']);
});
for (const name of artifacts) {
  test(`missing ${name} refuses partial publication`, async t => assert.notEqual((await manifest(t, { omit: name })).status, 0));
  test(`missing ${name} signature fails`, async t => assert.notEqual((await manifest(t, { omit: `${name}.sig` })).status, 0));
}
test('empty signatures fail', async t => assert.notEqual((await manifest(t, { empty: artifacts[0] })).status, 0));
test('ambiguous platform payloads fail', async t => assert.notEqual((await manifest(t, { duplicate: true })).status, 0));
test('macOS release uses an available signer command and architecture-specific archive', async () => {
  const workflow = await readFile('.github/workflows/release.yml', 'utf8');
  assert.doesNotMatch(workflow, /npm run --prefix apps\/ferro-desktop-ui tauri --/);
  assert.match(workflow, /FerroCrate_Desktop_\$\{\{ matrix.arch \}\}\.app\.tar\.gz/);
  const result = spawnSync('npm', ['exec', '--prefix', 'apps/ferro-desktop-ui', '--no', '--', 'tauri', 'signer', 'sign', '--help'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});
test('Windows updater signatures are regenerated after Authenticode', async () => {
  const workflow = await readFile('.github/workflows/release.yml', 'utf8');
  const windows = workflow.split('  windows-desktop:')[1].split('  publish:')[0];
  assert.match(windows, /sign-windows-artifacts\.ps1[\s\S]*tauri signer sign/);
});
test('native signer checks exit status, verifies, and cleans certificate in finally', async () => {
  const script = await readFile('scripts/sign-windows-artifacts.ps1', 'utf8');
  assert.match(script, /finally\s*\{[\s\S]*Remove-Item/);
  assert.equal((script.match(/\$LASTEXITCODE/g) ?? []).length >= 2, true);
  assert.match(script, /verify \/pa[\s\S]*Write-Host/);
});
test('PowerShell signer fault injection', t => {
  const available = spawnSync('pwsh', ['-NoProfile', '-Command', 'exit 0']);
  if (available.error?.code === 'ENOENT') return t.skip('pwsh is not installed; Windows workflow executes this test');
  const result = spawnSync('pwsh', ['-NoProfile', '-File', 'scripts/test-windows-signing.ps1'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
test('installed release signer signs an archive with a disposable key', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'ferro-signer-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const key = join(dir, 'test.key');
  const artifact = join(dir, 'FerroCrate_Desktop_aarch64.app.tar.gz');
  await writeFile(artifact, 'archive fixture bytes');
  const run = args => spawnSync('npm', ['exec', '--prefix', 'apps/ferro-desktop-ui', '--no', '--', 'tauri', 'signer', ...args], { encoding: 'utf8' });
  const generated = run(['generate', '--ci', '--password', 'fixture-only', '--write-keys', key]);
  // Do not include key-generating command output in assertions: it contains private key material.
  assert.equal(generated.status, 0, 'disposable signing key generation failed');
  const signed = run(['sign', '--private-key-path', key, '--password', 'fixture-only', artifact]);
  assert.equal(signed.status, 0, 'installed Tauri CLI signer failed');
  assert.ok((await readFile(`${artifact}.sig`, 'utf8')).trim().length > 0);
});
