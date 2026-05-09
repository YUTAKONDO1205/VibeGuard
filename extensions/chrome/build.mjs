// esbuild driver for the VibeGuard Chrome extension.
//
// Two entry points:
//   - src/background.ts       → dist/background.js  (service worker, ESM)
//   - src/sidepanel/index.ts  → dist/sidepanel/index.js (side panel UI)
//
// Both bundle @vibeguard/analyzer-core via the ./browser subpath so no
// node:fs / node:path leaks into the extension.

import { build, context } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const watch = process.argv.includes('--watch');

/** @type {import('esbuild').BuildOptions} */
const common = {
  bundle: true,
  format: 'esm',
  target: 'chrome114',
  platform: 'browser',
  sourcemap: true,
  logLevel: 'info',
  // Side panels and service workers are sandboxed; keep names stable for debugging.
  minify: false,
  // analyzer-core/browser is the fs-free subpath; no aliasing needed because
  // package.json `exports` already routes the subpath. We just need to make
  // sure node-only entries (file-scanner) are never reached.
  conditions: ['import', 'browser'],
};

const entries = [
  {
    entryPoints: [resolve(__dirname, 'src/background.ts')],
    outfile: resolve(__dirname, 'dist/background.js'),
  },
  {
    entryPoints: [resolve(__dirname, 'src/sidepanel/index.ts')],
    outfile: resolve(__dirname, 'dist/sidepanel/index.js'),
  },
];

if (watch) {
  for (const entry of entries) {
    const ctx = await context({ ...common, ...entry });
    await ctx.watch();
  }
  console.log('[vibeguard-chrome] esbuild watching…');
} else {
  for (const entry of entries) {
    await build({ ...common, ...entry });
  }
  console.log('[vibeguard-chrome] esbuild done.');
}
