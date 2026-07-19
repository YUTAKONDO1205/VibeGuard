// B1 — transform catalogue generator (SCOPE §3 B1 named deliverable: 「変換カタロ
// グ」, and C3's reusable artifact).
//
// SCOPE §3 B1 asks for a "変換カタログ＋変異コーパス＋ER ヒートマップ" and §2.1
// makes the CATALOGUED equivalence the primary warrant for semantics preservation.
// The taxonomy lives as `category` fields scattered across sec-b1-transforms.mjs
// (1300+ lines); a reader/reviewer/re-user cannot see the equivalence claim
// without reading all of it. This script projects that taxonomy plus the measured
// ER contribution into one table, generated (never hand-transcribed, per §5) from:
//   - sec-b1-transforms.mjs  — id / family / languages / d2Predicted / cost
//   - b1-er-eval.json        — paired ΔER, ER false/true, n, predicted-vs-observed
//   - b1-corpus-manifest.json — median changed-lines and a before→after example
//
// Run from the repo root AFTER gen-corpus + er-eval:
//   node scripts/sec-b1-gen-corpus.mjs && node scripts/sec-b1-er-eval.mjs && node scripts/sec-b1-catalog.mjs
//
// Writes b1-transform-catalog.{json,md}. Deterministic: no clock, no RNG, inputs
// sorted, examples chosen by sorted pairId so the pick never wobbles.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { TRANSFORMS } from './sec-b1-transforms.mjs';

const RESULTS = 'security-experiment/_results';
const MANIFEST = `${RESULTS}/b1-corpus-manifest.json`;
const EVAL = `${RESULTS}/b1-er-eval.json`;
const OUT_JSON = `${RESULTS}/b1-transform-catalog.json`;
const OUT_MD = `${RESULTS}/b1-transform-catalog.md`;

for (const [label, p] of [['manifest', MANIFEST], ['eval', EVAL]]) {
  if (!existsSync(p)) {
    console.error(`${label} not found at ${p}\nFix: run sec-b1-gen-corpus.mjs then sec-b1-er-eval.mjs first.`);
    process.exit(1);
  }
}

const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
const evalOut = JSON.parse(readFileSync(EVAL, 'utf8'));

// The equivalence class each family preserves — the WHY behind "semantics-
// preserving", stated once per family instead of per transform.
const FAMILY_EQUIVALENCE = {
  lexical:
    'Lexical rewrites: constant-string concatenation split, hex/unicode encoding, whitespace/comment insertion, and an inert delimiter-lexed literal bound above the payload. The payload spells the same program either way — the change is in how the source is lexed, not in what runs (the one added binding is unused and unobservable).',
  'name-resolution':
    'Name-resolution detours: import aliases, local rebinding, dynamic attribute access (getattr / bracket / send / variable functions). The same object or function is resolved under a different name. D2 folds the inner constant but not the resolved call edge — this is the taint layer’s job (Rice’s wall).',
  structural:
    'Structural equivalences: hoisting an argument to a temp, wrapping in a tautological branch, spreading a call across lines. Evaluation order and values are unchanged; only the statement shape differs.',
  'negative-control':
    'Controls, excluded from the pooled ER. NC1 (fix-real) genuinely repairs the vulnerability (payloadExecutable=false) — a sensitivity check that the metric detects real removal. NC2 (noop-reformat) is byte-identical to the original — ER must be 0 or the harness is fabricating evasions.',
};

const slash = (p) => String(p).replace(/\\/g, '/');
const median = (xs) => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
};

// Pairs grouped by transform, sorted by pairId so the example pick is stable.
const byTransform = new Map();
for (const p of [...manifest.pairs].sort((a, b) => String(a.pairId).localeCompare(String(b.pairId)))) {
  if (!byTransform.has(p.transformId)) byTransform.set(p.transformId, []);
  byTransform.get(p.transformId).push(p);
}

// One before→after example per transform: the first pair (sorted) whose payload
// line can be read from both the original and the transformed file.
function exampleFor(pairs) {
  for (const p of pairs) {
    const orig = p.origPath;
    const xf = p.transformedPath;
    if (!orig || !xf || !existsSync(orig) || !existsSync(xf)) continue;
    const oLine = p.origPayloadLine;
    if (oLine == null) continue;
    try {
      const before = readFileSync(orig, 'utf8').split('\n')[oLine - 1];
      // The transformed payload can span lines; show the first changed line.
      const xfLines = readFileSync(xf, 'utf8').split('\n');
      const at = (p.expectedPayloadLine ?? oLine) - 1;
      const after = xfLines[at];
      if (before == null || after == null) continue;
      return { before: before.trim(), after: after.trim(), from: slash(orig), to: slash(xf) };
    } catch {
      continue;
    }
  }
  return null;
}

const rows = [];
for (const t of TRANSFORMS) {
  const et = evalOut.byTransform?.[t.id] ?? {};
  const paired = et.paired?.exists ?? null;
  const pairs = byTransform.get(t.id) ?? [];
  const changed = pairs.map((p) => (Array.isArray(p.changedLines) ? p.changedLines.length : p.changedLines)).filter((n) => typeof n === 'number');
  const ledger = (evalOut.predictionLedger ?? []).find((l) => l.transformId === t.id);
  rows.push({
    id: t.id,
    name: t.name,
    family: t.category,
    languages: t.languages,
    d2Predicted: t.d2Predicted,
    d2Observed: ledger?.observed ?? null,
    // er-eval's ledger entry exposes the match as `matches` (bool) alongside
    // `observed` and `d2Predicted` (sec-b1-er-eval.mjs). Reuse it rather than
    // re-deriving — an earlier version read `ledger.predicted`/`ledger.match`,
    // fields that do not exist, so this was silently false for every transform.
    predictionMatch: ledger ? ledger.matches === true : null,
    adversarialCost: t.adversarialCost, // 'M' single mechanical / 'R' per-site reasoning
    medianChangedLines: median(changed),
    payloadExecutableClaim: t.payloadExecutableClaim,
    pairs: pairs.length,
    erFalse: paired?.false?.er ?? null,
    erTrue: paired?.true?.er ?? null,
    deltaEr: paired?.deltaEr ?? null,
    n: paired?.false?.denominator ?? null,
    example: exampleFor(pairs),
  });
}

const catalog = {
  generatedBy: 'sec-b1-catalog.mjs',
  source: { manifest: slash(MANIFEST), eval: slash(EVAL) },
  provenance: manifest.provenance ?? null,
  basis: 'paired / exists (the headline ER; see b1-er-eval.json)',
  familyEquivalence: FAMILY_EQUIVALENCE,
  costLegend: { M: 'single mechanical transform (site-independent)', R: 'per-site reasoning (LLM-1-instruction class)' },
  transforms: rows,
};
writeFileSync(OUT_JSON, `${JSON.stringify(catalog, null, 2)}\n`);

// --- Markdown -------------------------------------------------------------
const fam = (f) => f;
const num = (x) => (x == null ? 'n/a' : Number(x).toFixed(3));
const lines = [];
lines.push('# B1 transform catalogue\n');
lines.push(`Generated from \`${slash(EVAL)}\` (paired/exists basis). Cost: **M** = single mechanical transform, **R** = per-site reasoning.\n`);
lines.push('Semantics preservation is warranted per family (SCOPE §2.1):\n');
for (const [f, desc] of Object.entries(FAMILY_EQUIVALENCE)) lines.push(`- **${f}** — ${desc}`);
lines.push('');
lines.push('| id | transform | family | langs | D2 pred→obs | cost | Δlines | n | ER false | ER true | ΔER |');
lines.push('|---|---|---|---|---|---|---|---|---|---|---|');
for (const r of rows) {
  const predObs = `${r.d2Predicted ?? '?'}→${r.d2Observed ?? '?'}`;
  lines.push(
    `| ${r.id} | ${r.name} | ${fam(r.family)} | ${r.languages.length} | ${predObs} | ${r.adversarialCost ?? '?'} | ` +
      `${r.medianChangedLines ?? 'n/a'} | ${r.n ?? 0} | ${num(r.erFalse)} | ${num(r.erTrue)} | ${num(r.deltaEr)} |`,
  );
}
lines.push('');
lines.push('## before → after examples\n');
for (const r of rows) {
  if (!r.example) continue;
  lines.push(`- **${r.id} ${r.name}** (${slash(r.example.from)})`);
  lines.push('  ```');
  lines.push(`  - ${r.example.before}`);
  lines.push(`  + ${r.example.after}`);
  lines.push('  ```');
}
lines.push('');
writeFileSync(OUT_MD, lines.join('\n'));

console.log(`# B1 transform catalogue — ${rows.length} transforms`);
console.log(`wrote ${slash(OUT_JSON)}`);
console.log(`wrote ${slash(OUT_MD)}`);
