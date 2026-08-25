#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';

const path = process.argv[2] ?? 'apps/ferro-desktop-ui/src-tauri/tauri.conf.json';
const key = process.env.TAURI_UPDATER_PUBLIC_KEY;
if (!key) throw new Error('TAURI_UPDATER_PUBLIC_KEY is required');
const config = JSON.parse(await readFile(path, 'utf8'));
config.plugins.updater.pubkey = key;
await writeFile(path, JSON.stringify(config, null, 2) + '\n');
