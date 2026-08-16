// site-export-meta — hand the site the one version number it is allowed to show.
//
// WHY THIS EXISTS
//
// The footer says `Latest: v0.3.5`. That string is the single most likely thing
// on the whole site to become a lie, because it changes on every release and
// nothing about a stale copy looks broken — a wrong version renders exactly as
// beautifully as a right one. So it is not written anywhere a human edits: it
// is read out of the root `package.json` at build time, by this file, and
// injected through `site/src/data/meta.json`.
//
// WHY ONLY ONE NUMBER
//
// The product has three version axes (README's release table): `tool` (the
// distributed artefacts), `engine` (what the detection actually does), and the
// cross-file analysis package, which moves independently of both. Printing all
// three in a footer gives a visitor three numbers and no way to rank them; the
// site therefore shows `tool` alone, and leaves the engine/analysis distinction
// to the README and the release notes, where the surrounding text can explain
// why it matters. Chapter 9.4 of the site design settles this.
//
// That decision is why this file exports one field instead of dumping the whole
// package.json. Anything present in the data file is something a page can
// silently start rendering; keeping the payload to what the design actually
// asked for means a second version number cannot appear on the site by
// accident, only by an edit here that someone has to justify.
//
//   node scripts/site-export-meta.mjs
//
// Exit 0 when meta.json was written, 1 with a named reason otherwise.
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_FILE = join(REPO_ROOT, 'site', 'src', 'data', 'meta.json');

/** Fail loudly and specifically. A generator that half-succeeds is worse than one that stops. */
function die(message) {
  process.stderr.write(`site-export-meta: ${message}\n`);
  process.exit(1);
}

let pkg;
try {
  pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'));
} catch (error) {
  die(`cannot read the root package.json: ${error.message}`);
}

const toolVersion = pkg.version;

// The shape check is not paranoia about JSON parsing — it is about the footer.
// `Latest: v{version}` with an undefined version renders as `Latest: vundefined`
// and deploys perfectly happily, so the only place that can catch it is here,
// before the page ever gets the value.
if (typeof toolVersion !== 'string' || !/^\d+\.\d+\.\d+/.test(toolVersion)) {
  die(
    `the root package.json "version" is ${JSON.stringify(toolVersion)}, which is not a ` +
      'semantic version. The site footer renders it verbatim as `Latest: v<version>`, ' +
      'so a malformed value would ship as text.',
  );
}

mkdirSync(dirname(OUT_FILE), { recursive: true });
writeFileSync(OUT_FILE, `${JSON.stringify({ toolVersion }, null, 2)}\n`, 'utf8');

process.stdout.write(`site-export-meta: toolVersion ${toolVersion} -> site/src/data/meta.json\n`);
