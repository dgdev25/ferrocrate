#!/usr/bin/env node
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';

const args = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, index, all) => {
  if (value.startsWith('--')) pairs.push([value.slice(2), all[index + 1]]);
  return pairs;
}, []));
for (const key of ['dir', 'repo', 'tag', 'version', 'out']) {
  if (!args[key]) throw new Error(`missing --${key}`);
}
const files = await readdir(args.dir, { recursive: true });
const platforms = {};
const patterns = [
  ['linux-x86_64', /\.AppImage$/],
  ['darwin-aarch64', /aarch64.*\.app\.tar\.gz$/i],
  ['darwin-x86_64', /x86_64.*\.app\.tar\.gz$/i],
  ['windows-x86_64', /setup\.exe$/i],
];
for (const [platform, pattern] of patterns) {
  const file = files.find((candidate) => pattern.test(candidate));
  if (!file) continue;
  const signature = `${file}.sig`;
  if (!files.includes(signature)) throw new Error(`missing signature for ${file}`);
  platforms[platform] = {
    signature: (await readFile(join(args.dir, signature), 'utf8')).trim(),
    url: `https://github.com/${args.repo}/releases/download/${args.tag}/${basename(file)}`,
  };
}
if (Object.keys(platforms).length === 0) throw new Error('no signed updater artifacts found');
await writeFile(args.out, JSON.stringify({
  version: args.version,
  notes: args.notes ?? `FerroCrate ${args.version}`,
  pub_date: args.date ?? new Date().toISOString(),
  platforms,
}, null, 2) + '\n');
