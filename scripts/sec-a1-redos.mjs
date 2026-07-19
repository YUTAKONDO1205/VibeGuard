// A1 — n–T measurement of rule regexes under ReDoS attack strings
// (SCOPE §3 A1 steps 2–3: 「攻撃文字列生成 → n を増やし T(n) 実測・計算量フィット」,
// vibeguard-updates.md §2 M6).
//
// Reads the triage in a1-regex-catalog.json, builds an attack string per
// super-linear pattern, measures T at a ladder of input lengths, fits a
// complexity class, and reports the smallest n that breaks the DESIGN §11.1
// performance contract. This is the BEFORE half of the D3 A/B: run it before
// the bound lands and again after.
//
// WHAT IS TIMED, AND WHY IT IS `runRegex` AND NOT `exec`.
// The contract in DESIGN §11.1 is about scanning a file, so the measurement has
// to cover the function VibeGuard actually calls. Timing `pattern.exec` alone
// would miss two amplifiers that live in `runRegex` itself and that a reader
// would otherwise attribute to backtracking:
//   - `content.split('\n')` runs per match under `skipCommentLines` — O(n) work
//     repeated m times;
//   - `indexToPosition` scans from index 0 for every match, twice — O(n·m).
// Both inflate T(n) independently of the regex. Timing `runRegex` measures the
// real cost; the harness additionally records a bare-`exec` time per point so
// the two can be separated in the write-up rather than conflated.
//
// ATTACK STRINGS COME FROM recheck, NOT FROM THIS SCRIPT.
// Hand-written attack strings are the classic way to overstate a ReDoS result:
// the author picks a string that happens to be slow and calls it a witness.
// recheck derives a witness from the automaton and reports it as
// `attack.pattern`, e.g. `'IFDEBUG:I'.repeat(18258) + '}'`. This script parses
// that pump structure and re-instantiates it at each ladder length, so the
// string at every n is the checker's witness, scaled — not this script's guess.
// A pattern with no witness is reported as `notMeasured`, never quietly skipped.
//
// REUSING WITNESSES FOR THE "AFTER" HALF — a correctness point, not just speed.
// `--witnesses <file>` takes the attack strings from an earlier run instead of
// deriving fresh ones. For an A/B that is the RIGHT question to ask: "does the
// string that broke the old pattern still break the fixed one?" Deriving a new
// witness for the fixed pattern answers something else — it asks whether that
// pattern has any worst case at all, which is what the CI invariant and the
// static triage are for. Reusing also removes the dominant cost of the after
// run (recheck spends its full timeout on a bounded pattern it cannot decide),
// and makes before/after comparable point-for-point because both halves are
// measured on the SAME input.
// Patterns absent from the witness file still fall back to deriving one, so a
// rule added since the before run is not silently skipped.
//
// SELF-BOUNDING. The harness measures a function with no time bound, from a
// script that must not hang (the failure mode under study). It therefore climbs
// the ladder and STOPS as soon as a point exceeds ABORT_MS, recording the
// ladder as truncated. A truncated ladder is a positive result — it means the
// pattern got slow — so the stop is reported, not hidden.
//
// Run from the repo root, AFTER `npm run build` and sec-a1-catalog.mjs:
//   npm install --no-save recheck
//   node scripts/sec-a1-catalog.mjs
//   node scripts/sec-a1-redos.mjs            # writes a1-before.json
//   node scripts/sec-a1-redos.mjs --label after --out a1-after.json \
//     --witnesses a1-before.json             # reuse the before run's attacks
//
// Timing is machine-dependent by nature; per SCOPE §2.3 the report leads with
// the complexity CLASS (linear / quadratic / worse), which is not, and records
// the host so absolute seconds can be read in context.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { cpus, totalmem, platform, arch, release } from 'node:os';

const RESULTS = 'security-experiment/_results';
const CATALOG = `${RESULTS}/a1-regex-catalog.json`;
const MATCHER_ENTRY = 'packages/rules/dist/matcher-utils.js';

// Ladder of input lengths, in characters. Chosen to span the region that
// matters: 10k is a large-but-ordinary source file, 1M is the existing
// file-scanner ceiling (MAX_FILE_BYTES in analyzer-core/src/file-scanner.ts), so
// the ladder covers every input the node path admits today.
const LADDER = [1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 200_000, 500_000, 1_000_000];
const REPEATS = 3;          // SCOPE §2.3: median of >=3
// Stop climbing once a point costs this much. Set BELOW the contract-breaking
// threshold on purpose: the ladder is quadratic, so the point after a 5 s one
// costs ~20 s, and attempting it would multiply the harness runtime by the
// number of targets for a datum that adds nothing — the class and the breaking n
// are both already established by then. This is a deliberate truncation of
// coverage and is recorded as `ladderAborted` on every affected row rather than
// left for the reader to infer.
const ABORT_MS = 5_000;
const WARMUP = 1;           // one discarded run per point, to let JIT settle

// DESIGN §11.1. The single-file budget is the one an attacker attacks with one
// file, so it is the headline; the others are recorded for completeness.
const CONTRACT = { singleFileMs: 3_000, selectionMs: 1_000, prDiffMs: 10_000, repoMs: 300_000 };

const args = process.argv.slice(2);
const argOf = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};
const LABEL = argOf('--label', 'before');
const OUT_JSON = `${RESULTS}/${argOf('--out', `a1-${LABEL}.json`)}`;
const OUT_MD = OUT_JSON.replace(/\.json$/, '.md');
const WITNESS_FILE = argOf('--witnesses', null);

// ---------------------------------------------------------------------------
// recheck attack-witness parsing
// ---------------------------------------------------------------------------

/**
 * Parse recheck's `attack.pattern` into pump segments.
 *
 * The format is a JS expression: `'lit'.repeat(k) + 'lit' + 'lit'.repeat(k)`.
 * Parsed structurally rather than eval'd — this string comes from a checker
 * operating on attacker-shaped input, and `eval` on it would be its own
 * vulnerability in a script whose subject is untrusted input.
 *
 * Returns `{ fixed, pumps }` where `fixed` is the total length of the
 * non-repeated parts and `pumps` are the repeatable segments, or null when the
 * shape is not recognised (reported as notMeasured rather than guessed at).
 */
function parseAttackPattern(patternExpr) {
  if (typeof patternExpr !== 'string') return null;
  const segments = [];
  // Split on top-level ` + `. The literals are single-quoted with escapes; a
  // ' + ' cannot occur inside one unescaped, so a simple split is sound here,
  // but each piece is validated below and any surprise aborts the parse.
  for (const raw of patternExpr.split(' + ')) {
    const piece = raw.trim();
    const rep = piece.match(/^'((?:[^'\\]|\\.)*)'\.repeat\((\d+)\)$/);
    if (rep) {
      segments.push({ kind: 'pump', text: unquote(rep[1]), count: Number(rep[2]) });
      continue;
    }
    const lit = piece.match(/^'((?:[^'\\]|\\.)*)'$/);
    if (lit) {
      segments.push({ kind: 'fixed', text: unquote(lit[1]) });
      continue;
    }
    return null; // unrecognised shape — do not guess
  }
  if (!segments.some((s) => s.kind === 'pump')) return null; // nothing to scale
  return segments;
}

function unquote(s) {
  return s.replace(/\\(u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|n|r|t|0|\\|'|")/g, (m, _a, u1, u2, x, ) => {
    if (u1) return String.fromCodePoint(parseInt(u1, 16));
    if (u2) return String.fromCharCode(parseInt(u2, 16));
    if (x) return String.fromCharCode(parseInt(x, 16));
    const tail = m.slice(1);
    return { n: '\n', r: '\r', t: '\t', 0: '\0', '\\': '\\', "'": "'", '"': '"' }[tail] ?? tail;
  });
}

/**
 * Instantiate the witness at (approximately) `targetLen` characters by scaling
 * every pump segment proportionally. The result is the checker's string shape at
 * a new size, so the ladder measures ONE attack getting longer rather than a
 * series of unrelated inputs.
 */
function buildAttack(segments, targetLen) {
  const fixedLen = segments.filter((s) => s.kind === 'fixed').reduce((a, s) => a + s.text.length, 0);
  const pumpUnit = segments.filter((s) => s.kind === 'pump').reduce((a, s) => a + s.text.length, 0);
  if (pumpUnit === 0) return null;
  const reps = Math.max(1, Math.floor((targetLen - fixedLen) / pumpUnit));
  return segments.map((s) => (s.kind === 'pump' ? s.text.repeat(reps) : s.text)).join('');
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
};

function timeOnce(fn) {
  const t0 = process.hrtime.bigint();
  const out = fn();
  const t1 = process.hrtime.bigint();
  return { ms: Number(t1 - t0) / 1e6, out };
}

/**
 * Fit a complexity class from the ladder by least-squares slope on log n vs
 * log T. Reported as a CLASS, with the raw exponent alongside, because SCOPE
 * §2.3 asks for a class that survives being run on a different machine.
 *
 * Only points above NOISE_FLOOR_MS are fitted: below it, timer granularity and
 * JIT warm-up dominate and would flatten a real slope toward zero.
 */
const NOISE_FLOOR_MS = 1.0;
function fitComplexity(points) {
  const usable = points.filter((p) => p.medianMs >= NOISE_FLOOR_MS && p.n > 0);
  if (usable.length < 3) return { class: 'indeterminate', exponent: null, fittedPoints: usable.length };
  const xs = usable.map((p) => Math.log(p.n));
  const ys = usable.map((p) => Math.log(p.medianMs));
  const mx = xs.reduce((a, b) => a + b, 0) / xs.length;
  const my = ys.reduce((a, b) => a + b, 0) / ys.length;
  let num = 0;
  let den = 0;
  for (let i = 0; i < xs.length; i += 1) {
    num += (xs[i] - mx) * (ys[i] - my);
    den += (xs[i] - mx) ** 2;
  }
  if (den === 0) return { class: 'indeterminate', exponent: null, fittedPoints: usable.length };
  const slope = num / den;
  // Bands are deliberately wide. A measured exponent of 1.9 on a noisy host is
  // the same phenomenon as 2.1; claiming "degree 2.07" would be false precision.
  let cls;
  if (slope < 1.3) cls = 'linear';
  else if (slope < 2.5) cls = 'quadratic';
  else if (slope < 3.5) cls = 'cubic';
  else cls = 'super-cubic-or-exponential';
  return { class: cls, exponent: Number(slope.toFixed(3)), fittedPoints: usable.length };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

for (const [label, p] of [['catalog', CATALOG], ['matcher build', MATCHER_ENTRY]]) {
  if (!existsSync(p)) {
    console.error(
      `${label} not found at ${p}\n` +
        'Fix: run `npm run build` then `node scripts/sec-a1-catalog.mjs` first.',
    );
    process.exit(1);
  }
}

const catalog = JSON.parse(readFileSync(CATALOG, 'utf8'));
const { runRegex } = await import(pathToFileURL(resolve(MATCHER_ENTRY)).href);

let recheck = null;
try {
  recheck = await import('recheck');
} catch {
  console.error(
    'recheck is required to obtain attack witnesses.\nFix: npm install --no-save recheck',
  );
  process.exit(1);
}

// Targets: everything the catalogue did not clear as linear, applied to file
// content. `unknown` (recheck timed out) is INCLUDED — an undecided pattern is
// not a safe pattern, and excluding it would quietly shrink the attack surface.
const SUPER_LINEAR = (c) => c === 'exponential' || c === 'super-linear' || c.startsWith('polynomial-');
const targets = catalog.entries.filter(
  (e) => e.reached && e.compiles && (SUPER_LINEAR(e.recheck.class) || e.recheck.class === 'unknown'),
);

// Witnesses carried over from an earlier run, keyed by rule+pattern. Loaded
// strictly: an entry that does not parse is DROPPED rather than reused, so a
// truncated or malformed record falls through to deriving a fresh witness
// instead of silently measuring a broken attack string.
const reusedWitnesses = new Map();
if (WITNESS_FILE) {
  const p = WITNESS_FILE.includes('/') ? WITNESS_FILE : `${RESULTS}/${WITNESS_FILE}`;
  if (!existsSync(p)) {
    console.error(`witness file not found at ${p}`);
    process.exit(1);
  }
  const prior = JSON.parse(readFileSync(p, 'utf8'));
  let dropped = 0;
  for (const m of prior.measured ?? []) {
    if (m.witness && parseAttackPattern(m.witness)) {
      reusedWitnesses.set(`${m.ruleId}#${m.patternIndex}`, m.witness);
    } else if (m.witness) {
      dropped += 1;
    }
  }
  console.log(
    `[a1-redos] reusing ${reusedWitnesses.size} witness(es) from ${p}` +
      (dropped ? `; ${dropped} unusable and will be re-derived` : ''),
  );
}

console.log(`[a1-redos] ${targets.length} target patterns (label=${LABEL})`);

const measured = [];
const notMeasured = [];

for (const [i, t] of targets.entries()) {
  const tag = `${t.ruleId}#${t.patternIndex}`;
  let witness;
  let witnessSource;
  const carried = reusedWitnesses.get(tag);
  if (carried) {
    // Attack the current pattern with the string that broke the previous one.
    // recheck is not consulted at all here — deriving a fresh witness would
    // change the question being asked and, on a bounded pattern it cannot
    // decide, costs its whole timeout.
    witness = carried;
    witnessSource = 'reused';
  } else {
    witnessSource = 'derived';
    try {
      const out = await recheck.check(t.source, t.flags, { timeout: 30_000 });
      witness = out?.attack?.pattern ?? null;
    } catch (err) {
      witness = null;
      notMeasured.push({ ...idOf(t), reason: `recheck threw: ${err instanceof Error ? err.message : String(err)}` });
      continue;
    }
  }
  const segments = witness ? parseAttackPattern(witness) : null;
  if (!segments) {
    // Honest hole, not a pass: this pattern was flagged and then not measured.
    notMeasured.push({
      ...idOf(t),
      reason: witness ? `unrecognised witness shape: ${String(witness).slice(0, 120)}` : 'recheck produced no attack witness',
    });
    console.log(`[a1-redos] (${i + 1}/${targets.length}) ${tag}: no usable witness — recorded as notMeasured`);
    continue;
  }

  const points = [];
  let aborted = false;
  for (const n of LADDER) {
    const attack = buildAttack(segments, n);
    if (attack == null) break;
    const pattern = new RegExp(t.source, t.flags);

    // Bare exec, to separate backtracking cost from runRegex bookkeeping.
    const execSamples = [];
    // runRegex, the cost the performance contract actually governs.
    const fullSamples = [];
    for (let r = 0; r < REPEATS + WARMUP; r += 1) {
      const re = new RegExp(t.source, t.flags);
      re.lastIndex = 0;
      const e = timeOnce(() => re.exec(attack));
      const f = timeOnce(() => runRegex(attack, pattern, { skipCommentLines: true, language: 'javascript' }));
      if (r >= WARMUP) {
        execSamples.push(e.ms);
        fullSamples.push(f.ms);
      }
    }
    const medianMs = median(fullSamples);
    points.push({
      n: attack.length,
      medianMs: Number(medianMs.toFixed(3)),
      execMedianMs: Number(median(execSamples).toFixed(3)),
      samplesMs: fullSamples.map((x) => Number(x.toFixed(3))),
    });
    if (medianMs >= ABORT_MS) {
      aborted = true;
      break;
    }
  }

  const fit = fitComplexity(points);
  const breaking = points.find((p) => p.medianMs > CONTRACT.singleFileMs) ?? null;
  measured.push({
    ...idOf(t),
    // Stored whole, not truncated: a later run reuses this string, and a witness
    // cut mid-token cannot be re-instantiated. (An earlier version sliced it to
    // 200 chars, which happened to be long enough for every pump expression seen
    // so far — but that was luck, not a guarantee.)
    witness: String(witness),
    // 'reused' means this attack came from the run named in `witnessSourceFile`
    // — i.e. the string that broke the PREVIOUS version of this pattern, which
    // is the comparison an A/B wants. 'derived' means recheck produced it here.
    witnessSource,
    points,
    ladderAborted: aborted,
    ladderAbortMs: ABORT_MS,
    fit,
    breaksSingleFileContractAtN: breaking ? breaking.n : null,
    maxMedianMs: points.length ? Math.max(...points.map((p) => p.medianMs)) : null,
  });
  const worst = points.length ? points[points.length - 1] : null;
  console.log(
    `[a1-redos] (${i + 1}/${targets.length}) ${tag}: fit=${fit.class}${fit.exponent != null ? ` (n^${fit.exponent})` : ''}` +
      `${worst ? `, worst ${worst.medianMs}ms @ n=${worst.n}` : ''}${aborted ? ' [ladder aborted]' : ''}` +
      `${breaking ? `, breaks 3s at n=${breaking.n}` : ''}`,
  );
}

function idOf(t) {
  return {
    ruleId: t.ruleId,
    patternIndex: t.patternIndex,
    severity: t.severity,
    source: t.source,
    flags: t.flags,
    staticClass: t.recheck.class,
  };
}

const breaking = measured.filter((m) => m.breaksSingleFileContractAtN != null);
const summary = {
  label: LABEL,
  contract: CONTRACT,
  ladder: LADDER,
  repeats: REPEATS,
  abortMs: ABORT_MS,
  totalRules: catalog.summary.totalRules,
  targetPatterns: targets.length,
  measuredPatterns: measured.length,
  witnessSourceFile: WITNESS_FILE ?? null,
  witnessesReused: measured.filter((m) => m.witnessSource === 'reused').length,
  witnessesDerived: measured.filter((m) => m.witnessSource === 'derived').length,
  notMeasuredPatterns: notMeasured.length,
  // The headline: how many RULES can be pushed past the single-file budget.
  rulesBreakingSingleFileContract: [...new Set(breaking.map((m) => m.ruleId))].sort(),
  smallestBreakingN: breaking.length ? Math.min(...breaking.map((m) => m.breaksSingleFileContractAtN)) : null,
  measuredClassHistogram: measured.reduce((acc, m) => {
    acc[m.fit.class] = (acc[m.fit.class] ?? 0) + 1;
    return acc;
  }, {}),
  host: {
    platform: platform(),
    release: release(),
    arch: arch(),
    cpu: cpus()[0]?.model ?? 'unknown',
    cores: cpus().length,
    totalMemGb: Number((totalmem() / 1024 ** 3).toFixed(1)),
    node: process.version,
  },
};

mkdirSync(RESULTS, { recursive: true });
writeFileSync(OUT_JSON, `${JSON.stringify({ summary, measured, notMeasured }, null, 2)}\n`);

// --- Markdown view -------------------------------------------------------
const esc = (s) => String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');
const trunc = (s, n) => (s.length > n ? `${s.slice(0, n)}…` : s);
const md = [];
md.push(`# A1 — n–T measurement (${LABEL})`);
md.push('');
md.push('Generated by `scripts/sec-a1-redos.mjs`. Do not hand-edit (SCOPE §5).');
md.push('');
md.push(`Host: ${summary.host.cpu} / ${summary.host.cores} cores / ${summary.host.platform} ${summary.host.arch} / node ${summary.host.node}.`);
md.push('Absolute times are host-dependent; the complexity CLASS is the portable result.');
md.push('');
md.push(`- Target patterns (static triage not-linear): **${summary.targetPatterns}**`);
md.push(`- Measured: **${summary.measuredPatterns}**, not measured (no usable witness): **${summary.notMeasuredPatterns}**`);
md.push(`- Rules pushed past the ${CONTRACT.singleFileMs / 1000}s single-file budget: **${summary.rulesBreakingSingleFileContract.length} / ${summary.totalRules}**`);
if (summary.smallestBreakingN != null) {
  md.push(`- Smallest breaking input: **n = ${summary.smallestBreakingN.toLocaleString()} chars**`);
}
md.push(`- Measured class histogram: ${JSON.stringify(summary.measuredClassHistogram)}`);
md.push('');
md.push('## Measured patterns');
md.push('');
md.push('| rule | static | measured fit | worst median | @ n | breaks 3s at n |');
md.push('|---|---|---|---|---|---|');
for (const m of [...measured].sort((a, b) => (b.maxMedianMs ?? 0) - (a.maxMedianMs ?? 0))) {
  const worst = m.points.length ? m.points[m.points.length - 1] : null;
  md.push(
    `| ${m.ruleId}#${m.patternIndex} | ${m.staticClass} | ${m.fit.class}${m.fit.exponent != null ? ` (n^${m.fit.exponent})` : ''} | ${worst ? `${worst.medianMs} ms` : '—'} | ${worst ? worst.n.toLocaleString() : '—'} | ${m.breaksSingleFileContractAtN ? m.breaksSingleFileContractAtN.toLocaleString() : '—'} |`,
  );
}
md.push('');
if (notMeasured.length) {
  md.push('## Not measured');
  md.push('');
  md.push('Flagged by static triage but no usable attack witness. **Not evidence of safety** — these are unresolved.');
  md.push('');
  for (const nm of notMeasured) md.push(`- \`${nm.ruleId}#${nm.patternIndex}\` — ${esc(trunc(nm.reason, 160))}`);
  md.push('');
}
writeFileSync(OUT_MD, `${md.join('\n')}\n`);

console.log(`[a1-redos] rules breaking the ${CONTRACT.singleFileMs}ms single-file budget: ${summary.rulesBreakingSingleFileContract.length}/${summary.totalRules}`);
if (summary.smallestBreakingN != null) console.log(`[a1-redos] smallest breaking n = ${summary.smallestBreakingN}`);
console.log(`[a1-redos] wrote ${OUT_JSON} and ${OUT_MD}`);
