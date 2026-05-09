// Copies static assets (manifest, side panel HTML/CSS, icons) into dist/
// so that loading dist/ as an unpacked extension works directly.

import { mkdir, copyFile, readdir, stat, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const ROOT = __dirname;
const DIST = resolve(ROOT, 'dist');

async function ensureDir(path) {
  await mkdir(path, { recursive: true });
}

async function copyTree(src, dst) {
  if (!existsSync(src)) return;
  await ensureDir(dst);
  const entries = await readdir(src);
  for (const name of entries) {
    const s = join(src, name);
    const d = join(dst, name);
    const st = await stat(s);
    if (st.isDirectory()) {
      await copyTree(s, d);
    } else {
      await copyFile(s, d);
    }
  }
}

await ensureDir(DIST);

// 1) manifest.json
await copyFile(resolve(ROOT, 'manifest.json'), resolve(DIST, 'manifest.json'));

// 2) side panel static files (HTML/CSS) live alongside the TS source
await ensureDir(resolve(DIST, 'sidepanel'));
for (const name of ['index.html', 'index.css']) {
  const src = resolve(ROOT, 'src/sidepanel', name);
  if (existsSync(src)) {
    await copyFile(src, resolve(DIST, 'sidepanel', name));
  }
}

// 3) icons
await copyTree(resolve(ROOT, 'public/icons'), resolve(DIST, 'icons'));

// 4) Generate placeholder icons if none exist so chrome:loadextension does
// not warn. These are deliberately empty 1x1 PNG bytes; the real icons can
// drop in later without changes to the manifest.
const PLACEHOLDER_PNG = Buffer.from(
  '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da6300010000000500010d0a2db40000000049454e44ae426082',
  'hex',
);
for (const size of [16, 32, 48, 128]) {
  const dst = resolve(DIST, 'icons', `icon-${size}.png`);
  if (!existsSync(dst)) {
    await ensureDir(dirname(dst));
    await writeFile(dst, PLACEHOLDER_PNG);
  }
}

console.log('[vibeguard-chrome] static assets copied to dist/');
