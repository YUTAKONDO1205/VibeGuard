// A1 — reliable rewrite verifier for the L1 static fix.
//
// WHY THIS FILE EXISTS AND IS NOT A ONE-LINER. Verifying a regex rewrite by
// passing its source through `node -e "...\\\\s..."` is UNRELIABLE: the shell and
// the JS string literal each consume backslashes, so `\s` silently arrives as a
// literal `s` and `\b` as `b`. A mangled pattern does not backtrack, measures
// fast, and yields a false PASS. (This bit us: an early "the rewrite is linear"
// reading was measuring `^s*...`, not `^\s*...`.) Candidates therefore live here
// as REAL RegExp LITERALS — the compiler sees them, nothing re-escapes them.
//
// WHAT "SAFE" MEANS HERE, AND WHY NOT "recheck says safe". recheck is the
// discovery oracle but its verdict is not the gate, for two opposite reasons:
//   - It is conservative on the atomic-group emulation `(?=(X))\1`: backreferences
//     defeat its automaton model, so it reports a nominal polynomial degree with
//     a witness that does not actually exploit the pattern.
//   - Its DEGREE alone does not say whether the worst case is reachable within
//     the input the scanner accepts.
// The gate is therefore MEASURED wall-clock time on recheck's OWN derived attack
// string, scaled up — the string recheck believes is worst, not one we guessed.
// A rewrite passes when that measured curve is flat (linear) across the ladder.
//
// Run from repo root, after `npm install --no-save recheck`:
//   node scripts/sec-a1-rewrite-check.mjs
import { cpus } from 'node:os';

// ---------------------------------------------------------------------------
// Candidates: { id, original, rewrite }. Literals only — never build from a
// string with escapes. `null` rewrite = "not yet proposed", checked as original.
// ---------------------------------------------------------------------------
const CANDIDATES = [
  {
    id: 'VG-FW-001',
    note: 'anchor-adjacent ^\\s*; try horizontal-only, then atomic emulation',
    original: /^\s*DEBUG\s*=\s*True\b/gim,
    rewrites: {
      'horizontal-class': /^[^\S\r\n]*DEBUG[^\S\r\n]*=[^\S\r\n]*True\b/gim,
      'atomic-emul': /^(?=([^\S\r\n]*))\1DEBUG[^\S\r\n]*=[^\S\r\n]*True\b/gim,
    },
  },
  {
    id: 'VG-QUAL-005#3',
    note: 'the cubic worst case',
    original: /^\s*(?:return\s+(?:null|None|nil|undefined|true|false))\s*[;]?\s*(?:#|\/\/)\s*(?:TODO|FIXME|stub|implement\b)/gim,
    rewrites: {
      'horizontal-class': /^[^\S\r\n]*(?:return[^\S\r\n]+(?:null|None|nil|undefined|true|false))[^\S\r\n]*[;]?[^\S\r\n]*(?:#|\/\/)[^\S\r\n]*(?:TODO|FIXME|stub|implement\b)/gim,
      'atomic-emul': /^(?=([^\S\r\n]*))\1(?:return[^\S\r\n]+(?:null|None|nil|undefined|true|false))(?=([^\S\r\n]*))\2[;]?(?=([^\S\r\n]*))\3(?:#|\/\/)[^\S\r\n]*(?:TODO|FIXME|stub|implement\b)/gim,
      // Restructure: collapse every adjacent `\s*X?\s*` into `\s*(?:X\s*)?` so no
      // two variable-length whitespace runs are ever adjacent, and use the
      // horizontal class so none crosses a newline.
      'restructured': /^[^\S\r\n]*return[^\S\r\n]+(?:null|None|nil|undefined|true|false)[^\S\r\n]*(?:;[^\S\r\n]*)?(?:#|\/\/)[^\S\r\n]*(?:TODO|FIXME|stub|implement\b)/gim,
    },
  },
];

// Correctness fixtures: strings that MUST still match (true positives) after the
// rewrite. A rewrite that goes fast by not matching real stubs is not a fix.
const MUST_MATCH = {
  'VG-FW-001': ['DEBUG = True', '   DEBUG=True', '\tDEBUG  =  True'],
  'VG-QUAL-005#3': ['  return null // TODO', 'return None  # FIXME', '\treturn nil // stub'],
};
// Strings that must NOT match — guards against a rewrite that over-broadens.
const MUST_NOT_MATCH = {
  'VG-FW-001': ['DEBUGGING = True', '// DEBUG = True is fine'],
  'VG-QUAL-005#3': ['return userValue // ok', 'returnValue = 1'],
};

const RECHECK_TIMEOUT_MS = 15_000;
const LADDER_MULTIPLIERS = [1, 2, 4, 8, 16];
const PASS_MS_AT_MAX = 500; // flat curve stays well under this even at 16x

function parseAttack(patternExpr) {
  if (typeof patternExpr !== 'string') return null;
  const segs = [];
  for (const raw of patternExpr.split(' + ')) {
    const piece = raw.trim();
    const rep = piece.match(/^'((?:[^'\\]|\\.)*)'\.repeat\((\d+)\)$/);
    if (rep) { segs.push({ pump: unquote(rep[1]), count: Number(rep[2]) }); continue; }
    const lit = piece.match(/^'((?:[^'\\]|\\.)*)'$/);
    if (lit) { segs.push({ fixed: unquote(lit[1]) }); continue; }
    return null;
  }
  return segs.some((s) => s.pump) ? segs : null;
}
function unquote(s) {
  return s.replace(/\\(u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|c([A-Za-z])|n|r|t|f|v|0|\\|'|")/g,
    (m, _a, u1, u2, x, c) => {
      if (u1) return String.fromCodePoint(parseInt(u1, 16));
      if (u2) return String.fromCharCode(parseInt(u2, 16));
      if (x) return String.fromCharCode(parseInt(x, 16));
      if (c) return String.fromCharCode(c.toUpperCase().charCodeAt(0) - 64); // \cH -> 0x08
      return { n: '\n', r: '\r', t: '\t', f: '\f', v: '\v', 0: '\0', '\\': '\\', "'": "'", '"': '"' }[m.slice(1)] ?? m.slice(1);
    });
}
function scaleAttack(segs, mult) {
  return segs.map((s) => (s.pump ? s.pump.repeat(s.count * mult) : s.fixed)).join('');
}

function timeExec(re, input) {
  const r = new RegExp(re.source, re.flags);
  r.lastIndex = 0;
  const t0 = process.hrtime.bigint();
  let n = 0;
  while (r.exec(input) !== null) { n += 1; if (n > 50_000) break; if (Number(process.hrtime.bigint() - t0) / 1e6 > 2500) break; }
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

let recheck = null;
try { recheck = await import('recheck'); } catch {
  console.error('recheck required: npm install --no-save recheck');
  process.exit(2);
}

async function assess(label, re, id, isOriginal) {
  // recheck verdict + its own witness
  let verdict = 'unknown';
  let witness = null;
  try {
    const out = await recheck.check(re.source, re.flags, { timeout: RECHECK_TIMEOUT_MS });
    verdict = out.status === 'safe' ? 'safe'
      : out.status === 'vulnerable' ? `vuln:${out.complexity?.type}${out.complexity?.degree ? `/${out.complexity.degree}` : ''}`
      : out.status;
    witness = out.attack?.pattern ?? null;
  } catch (e) { verdict = `recheck-threw:${e instanceof Error ? e.message : e}`; }

  // Measure recheck's own witness, scaled, AND a battery of generic adversarial
  // inputs — because recheck often returns "unknown" (no witness) for the
  // atomic/restructured rewrites, and "no witness" must not be read as "safe".
  // The battery targets the two families that break these patterns: `\s`
  // crossing newlines (blank-line runs) and adjacent variable quantifiers (long
  // single-line whitespace runs, with and without a near-miss separator).
  let curve = [];
  const segs = witness ? parseAttack(witness) : null;
  const inputsAt = (k) => {
    const blanks = '\n'.repeat(k) + '\treturn nil\n' + '\n'.repeat(k);
    const spaces = 'return null' + ' '.repeat(k) + 'x';
    const tabs = 'return null' + '\t'.repeat(k) + 'x';
    const semis = 'return null' + ' '.repeat(k) + ';' + ' '.repeat(k) + 'x';
    const list = [blanks, spaces, tabs, semis];
    if (segs) list.push(scaleAttack(segs, Math.max(1, Math.round(k / 2000))));
    return list;
  };
  // Originals are already proven catastrophic in a1-before.json; measuring them
  // at large k would just hang on a single uninterruptible exec. Probe them only
  // at small k to confirm, and let rewrites climb the full ladder to prove
  // flatness.
  const ladder = isOriginal ? [1000, 4000] : [2000, 8000, 32000, 128000];
  for (const k of ladder) {
    let worst = 0;
    for (const input of inputsAt(k)) worst = Math.max(worst, timeExec(re, input));
    curve.push({ n: k, ms: Number(worst.toFixed(1)) });
    if (worst > 2_000) break;
  }
  const maxMs = curve.length ? Math.max(...curve.map((p) => p.ms)) : null;
  // linear if the curve stayed flat, OR recheck found no exploitable witness
  const measuredSafe = maxMs == null ? null : maxMs < PASS_MS_AT_MAX;

  // correctness (only when checking a rewrite of a known id)
  let correctness = null;
  if (MUST_MATCH[id]) {
    const pos = MUST_MATCH[id].map((s) => { const r = new RegExp(re.source, re.flags); return r.test(s); });
    const neg = (MUST_NOT_MATCH[id] ?? []).map((s) => { const r = new RegExp(re.source, re.flags); return r.test(s); });
    correctness = { allPos: pos.every(Boolean), noNeg: neg.every((x) => !x), pos, neg };
  }
  return { label, source: re.source, verdict, witness: witness ? String(witness).slice(0, 90) : null, curve, maxMs, measuredSafe, correctness };
}

for (const c of CANDIDATES) {
  console.log(`\n### ${c.id} — ${c.note}`);
  const orig = await assess("ORIGINAL", c.original, c.id, true);
  console.log(`  ORIGINAL   recheck=${orig.verdict}  measured worst=${orig.maxMs}ms ${orig.measuredSafe === false ? 'CATASTROPHIC' : ''}`);
  if (orig.curve.length) console.log(`    curve: ${orig.curve.map((p) => `${p.n}:${p.ms}ms`).join('  ')}`);
  for (const [name, re] of Object.entries(c.rewrites)) {
    const r = await assess(name, re, c.id);
    const corr = r.correctness ? `pos=${r.correctness.allPos} noNeg=${r.correctness.noNeg}` : '';
    console.log(`  ${name.padEnd(18)} recheck=${r.verdict}  measured worst=${r.maxMs}ms  ${r.measuredSafe ? 'SAFE(measured)' : r.measuredSafe === false ? 'STILL CATASTROPHIC' : 'no-witness'}  ${corr}`);
    if (r.curve.length) console.log(`    curve: ${r.curve.map((p) => `${p.n}:${p.ms}ms`).join('  ')}`);
    if (r.correctness && (!r.correctness.allPos || !r.correctness.noNeg)) {
      console.log(`    ⚠ correctness: pos=${JSON.stringify(r.correctness.pos)} neg=${JSON.stringify(r.correctness.neg)}`);
    }
  }
}
console.log('\nGate: a rewrite is acceptable iff measured worst < ' + PASS_MS_AT_MAX + 'ms across the ladder AND pos=true,noNeg=true.');
