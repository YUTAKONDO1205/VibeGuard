// E6 (extended) — apply VibeGuard, unmodified, to public OSS repositories
// covering all 8 supported languages, and measure per repo: total findings,
// crit+high, LOC, finding density D = findings/KLOC, test/doc localization
// ratio T = testdoc/total, and the effect of the context-window confidence
// correction (how many findings it down-ranks, and how many it demotes below
// the actionable medium threshold).
//
// For reproducibility the script records the exact commit (HEAD of the shallow
// clone) each repository was scanned at; clones are deleted after measurement.
//
// Run from the repo root (after `npm run build`):
//   node scripts/e6-extended-eval.mjs
// Writes paper_data/e6_extended.json and prints one line per repo.
import { execSync } from 'node:child_process';
import { readdirSync, readFileSync, writeFileSync, rmSync, mkdirSync, existsSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import {
  DEFAULT_IGNORE,
  MAX_FILE_BYTES,
  detectLanguageFromPath,
  scanPath,
} from '@vibeguard/analyzer-core';
import { allRules } from '@vibeguard/rules';

const REPOS = [
  ['flask', 'https://github.com/pallets/flask', 'Python'],
  ['requests', 'https://github.com/psf/requests', 'Python'],
  ['click', 'https://github.com/pallets/click', 'Python'],
  ['express', 'https://github.com/expressjs/express', 'JavaScript'],
  ['axios', 'https://github.com/axios/axios', 'JavaScript'],
  ['zod', 'https://github.com/colinhacks/zod', 'TypeScript'],
  ['gin', 'https://github.com/gin-gonic/gin', 'Go'],
  ['gson', 'https://github.com/google/gson', 'Java'],
  ['sinatra', 'https://github.com/sinatra/sinatra', 'Ruby'],
  ['guzzle', 'https://github.com/guzzle/guzzle', 'PHP'],
  ['Newtonsoft.Json', 'https://github.com/JamesNK/Newtonsoft.Json', 'C#'],
];

// ── ONE FILE MANIFEST DRIVES BOTH THE NUMERATOR AND THE DENOMINATOR ─────────
//
// Density is findings-per-KLOC, so the two halves have to describe the same set
// of files. They did not. `loc()` counted twelve source extensions under its own
// skip list, while `scanPath` was called WITHOUT `knownLanguagesOnly` and with
// the analyzer's own ignore set — so the numerator counted findings from files
// the denominator had never measured, and the mismatch ran three ways at once:
//
//   1. EXTENSIONS. The scan read `.md`, `.svg`, `.png`, `.pdf`, `.aml` and
//      anything else on disk; the LOC count read twelve code extensions. On the
//      published Table 9 numbers that is 889 of 2,533 findings — 844 of them
//      `VG-CRYPTO-003` on documents and binaries — sitting above a denominator
//      that never saw those files. Density 5.88 → 3.82 once restricted.
//   2. SKIP LISTS. `SKIP_DIR` here vs `DEFAULT_IGNORE` in the scanner. `vendor`,
//      `.github`, `target`, `bin`, `obj` were scanned but not counted; `.next`,
//      `.turbo`, `coverage`, `.venv`, `venv`, `__pycache__`, `.idea`, `.vscode`
//      were counted but not scanned. The error ran in BOTH directions.
//   3. FILE SIZE. The scanner skips files over `MAX_FILE_BYTES`; `loc()` had no
//      cap, so an oversized file added lines to the denominator and no findings
//      to the numerator.
//
// The manifest below is built with the SCANNER's own primitives — its ignore
// set, its language mapping, its size cap — so "a file in the manifest" and "a
// file the scan could open" are the same statement. Anything the scan reports
// from outside it is counted and REPORTED rather than silently dropped: a
// mismatch is a bug in this script, and burying it is how the first one lasted.
const SKIP_DIR = new Set(DEFAULT_IGNORE);
const NL = /\r?\n/;

// test / fixture / mock / spec, OR docs / examples / samples / .md|.rst|.txt
const TESTDOC_RE = /(?:^|[\\/])(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|mocks?|docs?|examples?|samples?)(?:[\\/]|$)|\.(?:test|spec)\.[a-z]+$|\.(?:md|rst|txt|adoc)$/i;

const RANK = { low: 0, medium: 1, high: 2 };
const defConf = Object.fromEntries(allRules.map((r) => [r.ruleId, r.defaultConfidence]));

/**
 * Every file the scanner would open under `dir`, as scan-relative POSIX paths.
 * Returns the paths and their non-blank line count, so KLOC and the finding
 * filter cannot drift apart.
 */
function buildManifest(dir) {
  const files = new Set();
  let lines = 0;
  const stack = [dir];
  while (stack.length) {
    const d = stack.pop();
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = join(d, e.name);
      if (e.isDirectory()) { if (!SKIP_DIR.has(e.name)) stack.push(full); continue; }
      // The scanner's admission rules, in the scanner's own order.
      if (!detectLanguageFromPath(full)) continue;
      let size;
      try { size = statSync(full).size; } catch { continue; }
      if (size > MAX_FILE_BYTES) continue;
      let txt;
      try { txt = readFileSync(full, 'utf8'); } catch { continue; }
      files.add(relative(dir, full).split(sep).join('/'));
      for (const ln of txt.split(NL)) if (ln.trim() !== '') lines++;
    }
  }
  return { files, lines };
}

/**
 * Optional `{ "<repo>": "<full sha>" }` map that pins each corpus repository.
 *
 * Absent by default so a first run works with no setup; present, it makes the
 * run reproducible. Write it from a previous run's `commit` fields to freeze a
 * published table.
 */
const PINS_PATH = 'paper_data/e6_pins.json';
const pins = existsSync(PINS_PATH) ? JSON.parse(readFileSync(PINS_PATH, 'utf8')) : {};
if (Object.keys(pins).length > 0) {
  console.log(`pins: ${Object.keys(pins).length} repo(s) pinned from ${PINS_PATH}`);
} else {
  console.log(`pins: none (${PINS_PATH} absent) — this run floats on upstream HEAD and is NOT reproducible`);
}

const base = 'paper_data/e6clones';
if (!existsSync(base)) mkdirSync(base, { recursive: true });
const results = [];

for (const [name, url, lang] of REPOS) {
  const dir = join(base, name);
  const row = { repo: name, lang, url };
  try {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
    // ── PINNING ─────────────────────────────────────────────────────────────
    //
    // A `--depth 1` clone takes whatever the upstream default branch points at
    // TODAY, so re-running this script reproduces the METHOD but not the
    // NUMBERS: every repository has moved since the figures were published, and
    // nothing in the output said which commit a published number came from
    // beyond a field nobody fed back in.
    //
    // `pins` closes the loop. When `paper_data/e6_pins.json` holds a commit for
    // a repository, the clone is deepened to that commit and checked out, so a
    // published table can be regenerated byte-for-byte. Absent, the run floats
    // and records the SHA it landed on — writing that file is how a floating
    // run becomes a reproducible one.
    const pinned = pins[name];
    execSync(`git clone --quiet ${pinned ? '' : '--depth 1 '}${url} "${dir}"`, {
      stdio: 'ignore',
      timeout: 240000,
    });
    if (pinned) {
      execSync(`git -C "${dir}" checkout --quiet ${pinned}`, { stdio: 'ignore', timeout: 120000 });
    }
    row.commit = execSync(`git -C "${dir}" rev-parse HEAD`, { stdio: 'pipe' }).toString().trim();
    row.pinned = Boolean(pinned);
    if (pinned && row.commit !== pinned) {
      throw new Error(`pin mismatch: asked for ${pinned}, got ${row.commit}`);
    }
    const manifest = buildManifest(dir);
    row.kloc = +(manifest.lines / 1000).toFixed(1);
    row.manifestFiles = manifest.files.size;
    // `knownLanguagesOnly` makes the scan's own admission match the manifest's
    // first rule; the filter below enforces the rest.
    const scan = await scanPath(dir, { mode: 'standard', config: false, knownLanguagesOnly: true });
    const inManifest = (x) => manifest.files.has(String(x.filePath || '').split(sep).join('/'));
    const f = scan.findings.filter(inManifest);
    // Reported, never hidden. A non-zero value means the scan opened something
    // the denominator did not measure — the exact defect this rewrite closes.
    row.findingsOutsideManifest = scan.findings.length - f.length;
    if (row.findingsOutsideManifest > 0) {
      console.log(`WARN ${name}: ${row.findingsOutsideManifest} finding(s) outside the KLOC manifest`);
    }
    row.total = f.length;
    row.critHigh = f.filter((x) => x.severity === 'critical' || x.severity === 'high').length;
    const testdoc = f.filter((x) => TESTDOC_RE.test(x.filePath || ''));
    row.testdoc = testdoc.length;
    row.T = f.length ? +(testdoc.length / f.length).toFixed(3) : 0;
    row.D = row.kloc ? +(f.length / row.kloc).toFixed(2) : 0;
    // context-window effect: compare final confidence vs rule defaultConfidence
    let downranked = 0, demotedBelowMedium = 0;
    for (const x of f) {
      const base0 = defConf[x.ruleId];
      if (base0 == null) continue;
      if (RANK[x.confidence] < RANK[base0]) downranked++;
      if (RANK[base0] >= RANK.medium && RANK[x.confidence] < RANK.medium) demotedBelowMedium++;
    }
    row.downranked = downranked;
    row.downrankPct = f.length ? +(downranked / f.length * 100).toFixed(1) : 0;
    row.demotedBelowMedium = demotedBelowMedium;
    const conf = { high: 0, medium: 0, low: 0 };
    for (const x of f) conf[x.confidence] = (conf[x.confidence] || 0) + 1;
    row.confAfter = conf;
    console.log(`OK  ${name.padEnd(16)} ${String(lang).padEnd(11)} @${row.commit.slice(0, 8)} KLOC=${row.kloc} total=${row.total} crit/high=${row.critHigh} T=${row.T} D=${row.D} downrank=${downranked}(${row.downrankPct}%) demoted<med=${demotedBelowMedium}`);
  } catch (e) {
    row.error = String(e.message || e).slice(0, 120);
    console.log(`ERR ${name}: ${row.error}`);
  } finally {
    try { if (existsSync(dir)) rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  results.push(row);
}

// Aggregate
const ok = results.filter((r) => !r.error);
const sum = (k) => ok.reduce((a, r) => a + (r[k] || 0), 0);
const agg = {
  repos: ok.length,
  totalKLOC: +sum('kloc').toFixed(1),
  totalFindings: sum('total'),
  totalCritHigh: sum('critHigh'),
  totalTestdoc: sum('testdoc'),
  overallT: sum('total') ? +(sum('testdoc') / sum('total')).toFixed(3) : 0,
  totalDownranked: sum('downranked'),
  overallDownrankPct: sum('total') ? +(sum('downranked') / sum('total') * 100).toFixed(1) : 0,
  totalDemotedBelowMedium: sum('demotedBelowMedium'),
  Trange: ok.length ? [Math.min(...ok.map((r) => r.T)), Math.max(...ok.map((r) => r.T))] : [],
};
if (!existsSync('paper_data')) mkdirSync('paper_data', { recursive: true });
writeFileSync('paper_data/e6_extended.json', JSON.stringify({ results, agg }, null, 2) + '\n');
console.log('\n=== AGGREGATE ===');
console.log(JSON.stringify(agg, null, 2));
try { rmSync(base, { recursive: true, force: true }); } catch { /* ignore */ }
