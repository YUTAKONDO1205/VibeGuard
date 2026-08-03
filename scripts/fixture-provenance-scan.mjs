// fixture-provenance-scan — are the crossfile fixtures copies of third-party code?
//
// Promoted from paper_data/ceiling-probes-2026-08-03/laneG_scan.mjs (#43 / #47).
// The detection method below is UNCHANGED from the version whose numbers the
// ledger quotes; the only edit was replacing two hardcoded absolute paths with
// arguments, which is the single thing that kept it out of scripts/. It carries
// no NUL bytes and writes only to the path named on the command line, so the
// other two blockers #43 records did not apply to this probe.
//
// Usage:
//   node scripts/fixture-provenance-scan.mjs <out.json> <list.txt> [--corpus <dir>]
//     <list.txt>  repo-relative fixture paths, one per line
//     --corpus    corpus root to compare against (default paper_data/corpus1k)
//
// ⚠ DO NOT QUOTE A ZERO WITHOUT CHECKING THE ORACLE IS ALIVE. A run reporting no
// matches is evidence only if this scanner can still find one. Verify by copying a
// fixture, splicing a known 6-line run out of the corpus into the copy, and
// confirming the scan reports it — a zero from a broken scanner is indistinguishable
// from a zero from clean fixtures. That check passed on 2026-08-04; it is not
// optional the next time either.
//
// ⚠ AND STATE WHAT k=6 CANNOT SEE. A file with fewer than 6 substantive lines forms
// no 6-line shingle at all, so it is not EXAMINED at k=6 rather than cleared by it.
// Measured over the 463 published fixtures: 126 files (27.2%) under the generous
// definition of "substantive" used here, and more under a stricter one. Report the
// measurable population, not the raw file count.
import fs from 'node:fs';
import path from 'node:path';

const REPO = process.cwd();
const corpusFlag = process.argv.indexOf('--corpus');
const CORPUS =
  corpusFlag !== -1 && process.argv[corpusFlag + 1]
    ? path.resolve(process.argv[corpusFlag + 1])
    : path.join(REPO, 'paper_data', 'corpus1k');
const OUT = process.argv[2];
const LIST = process.argv[3]; // file containing repo-relative fixture paths

const KS = [6, 4, 3]; // 6 = primary contract, 4/3 = sensitivity
const KMAX = Math.max(...KS);
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_EXAMPLES_PER_K = 60;

const EXTS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.pyi',
  '.c', '.h', '.cpp', '.hpp', '.cc', '.cxx', '.hh',
  '.java', '.go', '.rs', '.rb', '.php', '.kt', '.cs', '.swift', '.scala',
  '.md', '.mdx',
]);

function norm(s) {
  return s.replace(/\s+/g, ' ').trim();
}

// returns { lines: [normalized...], orig: [1-based original line numbers...] }
function substantive(text) {
  const raw = text.split(/\r\n|\n|\r/);
  const lines = [];
  const orig = [];
  for (let i = 0; i < raw.length; i++) {
    const n = norm(raw[i]);
    if (n.length < 10) continue;
    lines.push(n);
    orig.push(i + 1);
  }
  return { lines, orig };
}

// ---------- phase 1: fixture index ----------
const fixturePaths = fs.readFileSync(LIST, 'utf8').split(/\r?\n/).filter(Boolean);
const maps = new Map(KS.map((k) => [k, new Map()]));
const lineGate = new Set();
const fixtureStats = [];
let fixtureSubstantiveLines = 0;
let fixtureRawLines = 0;

for (const rel of fixturePaths) {
  const abs = path.join(REPO, rel.replace(/\//g, path.sep));
  let text;
  try { text = fs.readFileSync(abs, 'utf8'); } catch (e) {
    fixtureStats.push({ file: rel, error: String(e.message) });
    continue;
  }
  const { lines, orig } = substantive(text);
  fixtureRawLines += text.split(/\r\n|\n|\r/).length;
  fixtureSubstantiveLines += lines.length;
  const shinglesByK = {};
  for (const k of KS) {
    let c = 0;
    const m = maps.get(k);
    for (let i = 0; i + k <= lines.length; i++) {
      const key = lines.slice(i, i + k).join('\n');
      let arr = m.get(key);
      if (!arr) { arr = []; m.set(key, arr); }
      arr.push({ file: rel, startLine: orig[i], endLine: orig[i + k - 1] });
      c++;
    }
    shinglesByK[k] = c;
  }
  for (const l of lines) lineGate.add(l);
  fixtureStats.push({
    file: rel,
    substantiveLines: lines.length,
    shingles: shinglesByK,
    checkableAtK6: shinglesByK[6] > 0,
  });
}

process.stderr.write(
  `[index] fixtures=${fixturePaths.length} substantiveLines=${fixtureSubstantiveLines} ` +
  `k6shingles=${maps.get(6).size} k4=${maps.get(4).size} k3=${maps.get(3).size} gate=${lineGate.size}\n`
);

// ---------- phase 2: corpus stream ----------
const hits = new Map(KS.map((k) => [k, []]));
const hitCounts = new Map(KS.map((k) => [k, 0]));
const pairSets = new Map(KS.map((k) => [k, new Set()]));

let scanned = 0, skippedBig = 0, skippedBinary = 0, readErrs = 0;
let corpusSubstantiveLines = 0, corpusBytes = 0, gateHits = 0;

function scanFile(abs, size) {
  let buf;
  try { buf = fs.readFileSync(abs); } catch { readErrs++; return; }
  const probe = buf.subarray(0, Math.min(4096, buf.length));
  if (probe.includes(0)) { skippedBinary++; return; }
  const text = buf.toString('utf8');
  const { lines, orig } = substantive(text);
  scanned++;
  corpusBytes += size;
  corpusSubstantiveLines += lines.length;
  const n = lines.length;
  if (n < KS[KS.length - 1]) return;
  const relCorpus = path.relative(CORPUS, abs).replace(/\\/g, '/');
  for (let i = 0; i < n; i++) {
    if (!lineGate.has(lines[i])) continue;
    gateHits++;
    for (const k of KS) {
      if (i + k > n) continue;
      const key = lines.slice(i, i + k).join('\n');
      const found = maps.get(k).get(key);
      if (!found) continue;
      hitCounts.set(k, hitCounts.get(k) + 1);
      for (const f of found) {
        pairSets.get(k).add(f.file + '||' + relCorpus);
      }
      if (hits.get(k).length < MAX_EXAMPLES_PER_K) {
        hits.get(k).push({
          k,
          corpusFile: relCorpus,
          corpusStartLine: orig[i],
          corpusEndLine: orig[i + k - 1],
          fixtureMatches: found.slice(0, 5),
          text: lines.slice(i, i + k),
        });
      }
    }
  }
}

function walk(dir) {
  let ents;
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { readErrs++; return; }
  for (const e of ents) {
    const p = path.join(dir, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) {
      if (e.name === '.git') continue;
      walk(p);
      continue;
    }
    if (!e.isFile()) continue;
    if (!EXTS.has(path.extname(e.name).toLowerCase())) continue;
    let st;
    try { st = fs.statSync(p); } catch { readErrs++; continue; }
    if (st.size > MAX_FILE_BYTES) { skippedBig++; continue; }
    scanFile(p, st.size);
    if (scanned % 20000 === 0) {
      process.stderr.write(`[scan] files=${scanned} lines=${corpusSubstantiveLines} k6hits=${hitCounts.get(6)}\n`);
    }
  }
}

const t0 = Date.now();
walk(CORPUS);
const secs = (Date.now() - t0) / 1000;

const result = {
  generatedAt: new Date().toISOString(),
  method: {
    normalization: 'collapse whitespace runs to single space, trim; drop lines with normalized length < 10',
    kValues: KS,
    primaryK: 6,
    shingleKeying: 'exact joined string (no hashing, no collisions)',
    corpusExtensions: [...EXTS],
    maxFileBytes: MAX_FILE_BYTES,
  },
  fixtureSide: {
    files: fixturePaths.length,
    rawLines: fixtureRawLines,
    substantiveLines: fixtureSubstantiveLines,
    distinctShingles: Object.fromEntries(KS.map((k) => [k, maps.get(k).size])),
    filesWithZeroK6Shingles: fixtureStats.filter((f) => !f.error && f.shingles && f.shingles[6] === 0).map((f) => ({ file: f.file, substantiveLines: f.substantiveLines })),
    readErrors: fixtureStats.filter((f) => f.error),
  },
  corpusSide: {
    root: 'paper_data/corpus1k',
    filesScanned: scanned,
    bytesScanned: corpusBytes,
    substantiveLinesIndexed: corpusSubstantiveLines,
    skippedTooLarge: skippedBig,
    skippedBinary,
    readErrors: readErrs,
    scanSeconds: +secs.toFixed(1),
  },
  gateHits,
  matchCounts: Object.fromEntries(KS.map((k) => [k, hitCounts.get(k)])),
  distinctFixtureCorpusPairs: Object.fromEntries(KS.map((k) => [k, pairSets.get(k).size])),
  examples: Object.fromEntries(KS.map((k) => [k, hits.get(k)])),
  perFixture: fixtureStats,
};

fs.writeFileSync(OUT, JSON.stringify(result, null, 2), 'utf8');
process.stderr.write(`[done] ${secs.toFixed(1)}s -> ${OUT}\n`);
console.log(JSON.stringify({
  filesScanned: scanned,
  corpusSubstantiveLines,
  matchCounts: result.matchCounts,
  distinctPairs: result.distinctFixtureCorpusPairs,
  gateHits,
  fixtureFiles: fixturePaths.length,
  fixtureSubstantiveLines,
  k6shingles: maps.get(6).size,
  zeroK6Files: result.fixtureSide.filesWithZeroK6Shingles.length,
  scanSeconds: +secs.toFixed(1),
}, null, 2));
