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
import { readdirSync, readFileSync, writeFileSync, rmSync, mkdirSync, existsSync } from 'node:fs';
import { join, extname } from 'node:path';
import { scanPath } from '@vibeguard/analyzer-core';
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

const CODE_EXT = new Set(['.py', '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.go', '.java', '.rb', '.php', '.cs']);
const SKIP_DIR = new Set(['.git', 'node_modules', 'dist', 'build', 'vendor', '.github', 'out', 'target', 'bin', 'obj']);
const RANK = { low: 0, medium: 1, high: 2 };
const defConf = Object.fromEntries(allRules.map((r) => [r.ruleId, r.defaultConfidence]));

// test / fixture / mock / spec, OR docs / examples / samples / .md|.rst|.txt
const TESTDOC_RE = /(?:^|[\\/])(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|mocks?|docs?|examples?|samples?)(?:[\\/]|$)|\.(?:test|spec)\.[a-z]+$|\.(?:md|rst|txt|adoc)$/i;

function loc(dir) {
  let lines = 0;
  const stack = [dir];
  while (stack.length) {
    const d = stack.pop();
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (e.isDirectory()) { if (!SKIP_DIR.has(e.name)) stack.push(join(d, e.name)); continue; }
      if (!CODE_EXT.has(extname(e.name).toLowerCase())) continue;
      try {
        const txt = readFileSync(join(d, e.name), 'utf8');
        for (const ln of txt.split('\n')) if (ln.trim() !== '') lines++;
      } catch { /* skip unreadable */ }
    }
  }
  return lines;
}

const base = 'paper_data/e6clones';
if (!existsSync(base)) mkdirSync(base, { recursive: true });
const results = [];

for (const [name, url, lang] of REPOS) {
  const dir = join(base, name);
  const row = { repo: name, lang, url };
  try {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
    execSync(`git clone --depth 1 --quiet ${url} "${dir}"`, { stdio: 'ignore', timeout: 240000 });
    row.commit = execSync(`git -C "${dir}" rev-parse HEAD`, { stdio: 'pipe' }).toString().trim();
    row.kloc = +(loc(dir) / 1000).toFixed(1);
    const scan = await scanPath(dir, { mode: 'standard', config: false });
    const f = scan.findings;
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
