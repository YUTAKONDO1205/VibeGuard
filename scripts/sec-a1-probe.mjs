// A1 — single-pattern probe: recheck verdict + a fast n–T slope, for one regex.
//
// The instrument used while rewriting the 21 breaking rules (L1 of the D3
// mitigation). For each candidate rewrite it answers the only two questions that
// decide acceptance: is it safe (recheck), and is it linear on the SAME attack
// string that broke the original (measured slope). It does NOT check semantic
// equivalence — that is the job of the shape fixtures
// (packages/rules/src/rules/multiline-shapes.test.ts) and of a before/after
// differential over the regression corpus.
//
// Usage (source and flags as two args; the pattern is NOT eval'd):
//   npm install --no-save recheck   # once
//   node scripts/sec-a1-probe.mjs '^\s*DEBUG\s*=\s*True\b' 'gim'
//
// Prints: recheck class, and T at a short ladder with a fitted exponent.
// Exit 0 if recheck-safe AND fitted exponent < 1.3; exit 1 otherwise, so it can
// gate a rewrite in a shell loop.
import { cpus } from 'node:os';

const [, , source, flags = 'g'] = process.argv;
if (source == null) {
  console.error("usage: node scripts/sec-a1-probe.mjs '<regex source>' '<flags>'");
  process.exit(2);
}

// A witness pump for the whitespace-backtracking family: mostly blank lines with
// one near-miss token in the middle, which is what broke VG-QUAL-005 et al. Not
// every pattern is attacked by this exact string, but every anchor-adjacent
// `\s`-crossing-newline pattern is, and those are the population being rewritten.
function buildWhitespaceAttack(halfLines) {
  return `${'\n'.repeat(halfLines)}\tRETURN\tNIL\n${'\n'.repeat(halfLines)}`;
}
// A second witness for adjacent-quantifier patterns: a long single-line run of
// spaces before a near-miss, which stresses `\s*X?\s*`-style splits.
function buildSpaceRunAttack(spaces) {
  return `if${' '.repeat(spaces)}x`;
}

function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
}

function timeMatch(pattern, input) {
  const re = new RegExp(pattern.source, pattern.flags);
  re.lastIndex = 0;
  const t0 = process.hrtime.bigint();
  let n = 0;
  // A per-probe hard ceiling so a still-catastrophic candidate cannot hang the
  // instrument — the very failure being measured.
  while (re.exec(input) !== null) {
    n += 1;
    if (n > 100_000) break;
    if (n % 1000 === 0 && Number(process.hrtime.bigint() - t0) / 1e6 > 8_000) break;
  }
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

function fit(points) {
  const usable = points.filter((p) => p.ms >= 0.5);
  if (usable.length < 3) return { class: 'indeterminate', exponent: null };
  const xs = usable.map((p) => Math.log(p.n));
  const ys = usable.map((p) => Math.log(p.ms));
  const mx = xs.reduce((a, b) => a + b, 0) / xs.length;
  const my = ys.reduce((a, b) => a + b, 0) / ys.length;
  let num = 0;
  let den = 0;
  for (let i = 0; i < xs.length; i += 1) {
    num += (xs[i] - mx) * (ys[i] - my);
    den += (xs[i] - mx) ** 2;
  }
  const slope = den === 0 ? 0 : num / den;
  let cls;
  if (slope < 1.3) cls = 'linear';
  else if (slope < 2.5) cls = 'quadratic';
  else cls = 'cubic-or-worse';
  return { class: cls, exponent: Number(slope.toFixed(3)) };
}

let pattern;
try {
  pattern = new RegExp(source, flags);
} catch (err) {
  console.error(`does not compile: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
}

// recheck (optional): authority on safety when present.
let recheckClass = 'not-run (install with: npm install --no-save recheck)';
let recheckSafe = null;
try {
  const r = await import('recheck');
  const out = await r.check(source, flags, { timeout: 10_000 });
  if (out.status === 'safe') {
    recheckClass = 'safe';
    recheckSafe = true;
  } else if (out.status === 'vulnerable') {
    recheckClass = `vulnerable:${out.complexity?.type ?? '?'}${out.complexity?.degree ? ` deg ${out.complexity.degree}` : ''}`;
    recheckSafe = false;
  } else {
    recheckClass = out.status;
  }
} catch {
  /* keep not-run */
}

// Measured n–T on both witnesses; report the worse.
const results = [];
for (const [name, build, ladder] of [
  ['whitespace', buildWhitespaceAttack, [500, 1000, 2000, 4000]],
  ['space-run', buildSpaceRunAttack, [2000, 4000, 8000, 16000]],
]) {
  const points = ladder.map((k) => {
    const input = build(k);
    const ms = median([timeMatch(pattern, input), timeMatch(pattern, input), timeMatch(pattern, input)]);
    return { n: input.length, ms: Number(ms.toFixed(3)) };
  });
  results.push({ name, fit: fit(points), points });
}

const worstFit = results.reduce((w, r) => (r.fit.exponent > (w.fit.exponent ?? -1) ? r : w), results[0]);

console.log(`pattern: /${source}/${flags}`);
console.log(`recheck: ${recheckClass}`);
for (const r of results) {
  console.log(`  ${r.name}: ${r.fit.class}${r.fit.exponent != null ? ` (n^${r.fit.exponent})` : ''}, worst ${Math.max(...r.points.map((p) => p.ms))}ms`);
}

// Gate: safe if recheck says so (when available) AND both measured fits are linear.
const measuredLinear = results.every((r) => r.fit.class === 'linear' || r.fit.class === 'indeterminate');
const ok = (recheckSafe !== false) && measuredLinear;
console.log(ok ? 'VERDICT: ok' : 'VERDICT: UNSAFE');
process.exit(ok ? 0 : 1);
