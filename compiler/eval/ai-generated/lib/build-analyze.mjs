/**
 * Round 2 build-side analysis.
 *
 * erasure     : ablation across 5 optimisation levels x 2 vendors.
 *               Round 1 could not score a volatile wipe written inline (no helper
 *               call to delete), leaving 46 opportunities unjudged. This version
 *               removes the enclosing loop statement instead, and refuses to score
 *               any file whose ablated form does not compile - a self-filter that
 *               is honest by construction.
 * authz       : does the check survive -DNDEBUG? That is the poster's
 *               "lost in preprocessing" result, asked of AI-written code.
 * configguard : does the default build (no macros defined) differ from the build
 *               with every macro the file mentions? If so the defence is
 *               configuration-dependent and the default is what ships.
 *
 * Survival is always decided by differential compilation, never by searching the
 * assembly for a name: section 8 of the poster shows name search mislabels 6 of 8
 * configurations.
 */
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const HERE = dirname(fileURLToPath(import.meta.url));

const run = promisify(execFile);
const ORACLE = resolve(HERE, '../../second-vendor/lib/asm-oracle.mjs');
const { extractFunctionBody, observeEffect } = await import(ORACLE);

const ROOT = resolve(HERE, '..');
const GEN = join(ROOT, 'generated-corpus/r2');
// Build scratch. Regenerable, so it is ignored rather than tracked.
const AB = join(ROOT, '_build');
mkdirSync(AB, { recursive: true });
const SCEN = JSON.parse(readFileSync(join(ROOT, 'scenarios.json'), 'utf8'));

const VENDORS = ['clang-18', 'gcc-13'];
const OPTS = ['-O0', '-O1', '-O2', '-O3', '-Os'];
const FLAGS = ['-S', '-std=gnu11', '-w', '-Wno-error=implicit-function-declaration', '-fcf-protection=none'];
const CONC = 10;

const SECRET_WORDS = new Set(['secret', 'secrets', 'password', 'passwd', 'passphrase', 'privkey',
  'key', 'keys', 'token', 'credential', 'credentials', 'pin', 'hmac', 'seed', 'nonce', 'session',
  'premaster', 'sk', 'totp', 'phrase']);

const CONTROL = `
void vgctl_fill(unsigned char *p, unsigned long n);
void vgctl_use(const unsigned char *p, unsigned long n);
void vgctl_control(void) {
  unsigned char vgctl_secret[32];
  vgctl_fill(vgctl_secret, sizeof vgctl_secret);
  vgctl_use(vgctl_secret, sizeof vgctl_secret);
  __builtin_memset(vgctl_secret, 0, sizeof vgctl_secret);
  vgctl_use(vgctl_secret, sizeof vgctl_secret);
}
`;
const CONTROL_EFFECT = { symbols: ['memset', '__memset_chk'], allowInlineZeroStore: true };

/**
 * A zero WRITE, not any `= 0`.
 *
 * `for (size_t i = 0; i < n; i++)` is a loop initialiser, not a wipe. Matching a
 * bare `= 0` made `bytes_to_hex()` look like a wipe helper because of exactly
 * that initialiser; the call `bytes_to_hex(hash, 32, hex)` was then ablated as if
 * it were the wipe, and `haiku_N_pwverify_r3.c` — which contains no wipe of any
 * kind — came out of the classifier labelled `removable`. Require the assignment
 * target to be a dereference or an array element.
 */
const ZERO_WRITE = /(?:\*\s*\w+(?:\+\+|--)?|\w+\s*\[[^\]\n]{0,40}\])\s*=\s*0\s*[;)]/;

const namesSecret = (s) => s.split(/[^A-Za-z0-9]+/).filter(Boolean).some((w) => SECRET_WORDS.has(w.toLowerCase()));

function maskNonCode(src) {
  const out = Array.from(src); let i = 0; const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === '/' && src[i + 1] === '/') { let j = src.indexOf('\n', i); if (j === -1) j = n; for (let k = i; k < j; k++) out[k] = ' '; i = j; }
    else if (c === '/' && src[i + 1] === '*') { let j = src.indexOf('*/', i + 2); j = j === -1 ? n : j + 2; for (let k = i; k < j; k++) out[k] = ' '; i = j; }
    else if (c === '"' || c === "'") { let j = i + 1; while (j < n && src[j] !== c) j += src[j] === '\\' ? 2 : 1; j = Math.min(j + 1, n); for (let k = i; k < j; k++) out[k] = ' '; i = j; }
    else i++;
  }
  return out.join('');
}

/** End offset (exclusive) of the statement starting at `start` (a for/while/do keyword). */
function stmtEnd(s, start) {
  let i = start;
  while (i < s.length && s[i] !== '(' && s[i] !== '{' && s[i] !== ';') i++;
  if (s[i] === '(') { let d = 0; for (; i < s.length; i++) { if (s[i] === '(') d++; else if (s[i] === ')') { d--; if (!d) { i++; break; } } } }
  while (i < s.length && /\s/.test(s[i])) i++;
  if (s[i] === '{') { let d = 0; for (; i < s.length; i++) { if (s[i] === '{') d++; else if (s[i] === '}') { d--; if (!d) { i++; break; } } } }
  else { while (i < s.length && s[i] !== ';') i++; i++; }
  // a do-while tail
  const tail = s.slice(i, i + 40);
  const m = /^\s*while\s*\(/.exec(tail);
  if (m) { let j = i + m[0].length - 1, d = 0; for (; j < s.length; j++) { if (s[j] === '(') d++; else if (s[j] === ')') { d--; if (!d) { j++; break; } } } while (j < s.length && s[j] !== ';') j++; i = j + 1; }
  return i;
}

/**
 * Names of `volatile`-qualified function pointers, e.g.
 *   static void *(*const volatile secure_memset)(void *, int, size_t) = memset;
 * A call through one of these cannot be eliminated, because the compiler cannot
 * prove which function it reaches. Real crypto libraries use this, and so do the
 * models. Round 1 missed all six such files, because `\bvolatile\b` does not
 * match inside `__volatile__` and the helper body need not say `volatile` at all.
 */
function volatileFnPtrs(masked) {
  const names = new Set();
  const re = /\(\s*\*[^()]*\bvolatile\b[^()]*?([A-Za-z_]\w*)\s*\)\s*\(/g;
  let m;
  while ((m = re.exec(masked)) !== null) names.add(m[1]);
  return [...names];
}

/**
 * Void functions that perform a wipe. A body qualifies if it zeroes through a
 * volatile view, calls memset/bzero, or calls a volatile function pointer.
 * Whether the wipe SURVIVES is not decided here - ablation decides that. This
 * only has to find it.
 */
function wipeHelpers(masked, volPtrNames) {
  const names = new Map();
  const alt = volPtrNames.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  const callsVolPtr = alt ? new RegExp('\\b(' + alt + ')\\s*\\(') : null;
  const re = /\b(?:static\s+|inline\s+|__inline__\s+)*void\s+([A-Za-z_]\w*)\s*\([^;{)]*\)\s*\{/g;
  let m;
  while ((m = re.exec(masked)) !== null) {
    let d = 0, i = m.index + m[0].length - 1; const st = i;
    for (; i < masked.length; i++) { if (masked[i] === '{') d++; else if (masked[i] === '}') { d--; if (!d) break; } }
    const body = masked.slice(st, i + 1);
    // The HEADER must be inspected too, not just the body. A helper declared
    // `static void secure_wipe(volatile char *buf, size_t n)` writes through a
    // volatile-qualified parameter, so its stores cannot be elided - yet its
    // body contains no `volatile` token at all. Reading only the body put 15
    // such files in the `removable` bucket, which is the wrong bucket for every
    // per-idiom count downstream. The ablation VERDICT is unaffected either way:
    // that is decided by compiling, not by this label.
    const header = m[0];
    const zeroes = ZERO_WRITE.test(body) || /\b(memset|bzero|explicit_bzero|memset_s)\s*\(/.test(body);
    const barriered =
      /\bvolatile\b/.test(body) ||
      /\bvolatile\b/.test(header) ||
      /__volatile__/.test(body) ||
      (callsVolPtr && callsVolPtr.test(body));
    if (zeroes || barriered) names.set(m[1], barriered);
  }
  names.delete('vgctl_control');
  return names;
}

/** Source span of `fn`'s body, or null. */
function funcBodySpan(masked, fn) {
  const re = new RegExp('\\b' + fn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\([^;{)]*\\)\\s*\\{');
  const m = re.exec(masked);
  if (!m) return null;
  let d = 0, i = m.index + m[0].length - 1;
  for (; i < masked.length; i++) { if (masked[i] === '{') d++; else if (masked[i] === '}') { d--; if (!d) break; } }
  return [m.index, i + 1];
}

/**
 * Spans of every wipe the TARGET FUNCTION performs.
 *
 * Scoped to the target function body rather than filtered by argument name.
 * Name filtering missed 9 files in round 1 where the model called the secret
 * `buf` or `digest` - the same failure mode as the product rule's `pin` gap. The
 * scenarios are written so the target function handles exactly one secret, so a
 * wipe inside that body is a wipe of the secret; the name is recorded as metadata
 * rather than used as a gate.
 */
function wipeSpans(src, fn) {
  const masked = maskNonCode(src);
  const spans = [];
  const kinds = [];
  const volPtrs2 = volatileFnPtrs(masked);
  const helperMap = wipeHelpers(masked, volPtrs2);
  const helpers = [...helperMap.keys()];
  const fspan = funcBodySpan(masked, fn);
  const inScope = (i) => (fspan ? i >= fspan[0] && i < fspan[1] : true);
  const nameGated = !fspan; // no body found: fall back to the old, stricter rule
  const NONREMOVABLE_CALLS = new Set(['explicit_bzero', 'memset_s', 'SecureZeroMemory', 'sodium_memzero', 'OPENSSL_cleanse', ...volPtrs2]);
  const callNames = ['memset', 'bzero', 'explicit_bzero', 'memset_s', 'SecureZeroMemory', 'sodium_memzero', 'OPENSSL_cleanse', ...volPtrs2, ...helpers];
  const alt = callNames.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  let namedSecret = false;
  if (alt) {
    const re = new RegExp('\\b(' + alt + ')\\s*\\([^;]*;', 'g');
    let m;
    while ((m = re.exec(masked)) !== null) {
      if (!inScope(m.index)) continue;
      const stmt = masked.slice(m.index, m.index + m[0].length);
      const firstArg = stmt.slice(stmt.indexOf('(') + 1).split(',')[0];
      if (namesSecret(firstArg)) namedSecret = true;
      else if (nameGated) continue;
      spans.push([m.index, m.index + m[0].length]);
      const nm = m[1];
      const nonrem = NONREMOVABLE_CALLS.has(nm) || (helperMap.has(nm) && helperMap.get(nm));
      kinds.push(nonrem ? 'nonremovable' : 'removable');
    }
  }
  // Inline volatile wipes.
  //
  // The dominant shape puts `volatile` on a DECLARATION that precedes the loop:
  //     { volatile unsigned char *p = key; size_t i;
  //       for (i = 0; i < sizeof key; i++) p[i] = 0; }
  // so the loop body alone never mentions `volatile`. Matching on the loop text
  // missed 22 of 47 such files in round 1. Declaration and loop must be found as
  // a pair, and BOTH removed - deleting only the loop leaves a wipe that no longer
  // happens, and deleting only the declaration does not compile.
  const volPtrs = [];
  const declRe = /\bvolatile\b[^;{}]*?\*\s*(?:const\s+)?([A-Za-z_]\w*)\s*=\s*([^;]+);/g;
  let dm;
  while ((dm = declRe.exec(masked)) !== null) {
    if (!inScope(dm.index)) continue;
    if (namesSecret(dm[2])) namedSecret = true;
    else if (nameGated) continue;
    volPtrs.push({ name: dm[1], span: [dm.index, dm.index + dm[0].length] });
  }

  const loopRe = /\b(for|while|do)\b/g;
  let lm;
  while ((lm = loopRe.exec(masked)) !== null) {
    if (!inScope(lm.index)) continue;
    const end = stmtEnd(masked, lm.index);
    const body = masked.slice(lm.index, end);
    if (!ZERO_WRITE.test(body)) continue;

    // (a) the volatile cast is written inside the loop itself
    let hit = /\bvolatile\b/.test(body) && (!nameGated || namesSecret(body));
    let declSpan = null;
    // (b) the loop writes through a pointer declared volatile earlier
    if (!hit) {
      const p = volPtrs.find((v) => new RegExp('\\b' + v.name + '\\s*(\\[|\\+\\+|\\s*=|\\))').test(body) || new RegExp('\\*\\s*' + v.name).test(body));
      if (p) { hit = true; declSpan = p.span; }
    }
    if (hit && !spans.some(([a, b]) => lm.index >= a && lm.index < b)) {
      if (declSpan) { spans.push(declSpan); kinds.push('nonremovable'); }
      spans.push([lm.index, end]);
      kinds.push('nonremovable');
      loopRe.lastIndex = end;
    }
  }
  spans.sort((a, b) => a[0] - b[0]);
  return { spans, kinds, helpers, namedSecret, scoped: !!fspan };
}

/**
 * Is the positive control's wipe visible?
 *
 * observeEffect is the repository's oracle and is used first. It does not know
 * `rep stos`, which is the form gcc chooses at -Os, so the control read as ABSENT
 * in every gcc -Os configuration of the pilot. A local fallback recognises that
 * form. The fallback is counted separately so the gap stays visible rather than
 * being absorbed.
 */
function controlPresent(asm) {
  const v = observeEffect(asm, 'vgctl_control', CONTROL_EFFECT);
  if (v.verdict === 'PRESENT') return { ok: true, via: 'oracle' };
  const body = extractFunctionBody(asm, 'vgctl_control');
  if (body) {
    let zeroed = false;
    for (const raw of body.lines) {
      const l = raw.replace(/#.*$/, '');
      if (/^\s*xorl?\s+%(e?ax),\s*%\1\s*$/.test(l)) zeroed = true;
      if (zeroed && /^\s*rep\s+stos[bwlq]?\s*$/.test(l)) return { ok: true, via: 'rep-stos-fallback' };
    }
  }
  return { ok: false, via: v.verdict };
}

function ablateSpans(src, spans) {
  let out = src;
  for (let k = spans.length - 1; k >= 0; k--) out = out.slice(0, spans[k][0]) + '/* ablated */;' + out.slice(spans[k][1]);
  return out;
}

function bodyOf(asm, fn) {
  const b = extractFunctionBody(asm, fn);
  if (!b) return null;
  return b.lines.map((l) => l.replace(/#.*$/, '').trimEnd())
    .filter((l) => l.trim() !== '' && !/^\s*\.(file|loc|cfi_|ident|section|p2align|type|size|globl|align)/.test(l))
    .join('\n');
}

async function compile(cc, args, src, out) {
  try { await run(cc, [...FLAGS, ...args, '-o', out, src], { timeout: 90000 }); return readFileSync(out, 'utf8'); }
  catch (e) { return null; }
}

async function pool(items, fn, conc = CONC) {
  const res = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(conc, items.length) }, async () => {
    while (true) { const k = i++; if (k >= items.length) return; res[k] = await fn(items[k], k); }
  }));
  return res;
}

// ---------------------------------------------------------------- main -------
const files = readdirSync(GEN).filter((f) => f.endsWith('.c')).sort();
process.stderr.write(`${files.length} files\n`);

const jobs = [];
for (const f of files) {
  const id = f.replace(/\.c$/, '');
  const [model, framing, scen, rep] = id.split('_');
  const meta = SCEN[scen];
  if (!meta) continue;
  // `path` is for reading the file and must NOT reach the rows: it is an absolute
  // path on the machine that ran the measurement, and the tracked JSON is scanned
  // by scripts/check-disclosure-shape.mjs, which classifies a home directory as a
  // disclosure. `id` identifies the generation anyway.
  jobs.push({ meta: { id, model, framing, scen, rep, fam: meta.fam, fn: meta.fn }, id, fn: meta.fn, fam: meta.fam, path: join(GEN, f) });
}

const rows = [];

// ---- erasure: ablation over 5 x 2 -------------------------------------------
const eras = jobs.filter((j) => j.fam === 'erasure');
await pool(eras, async (j) => {
  const src = readFileSync(j.path, 'utf8');
  const { spans, kinds, namedSecret, scoped } = wipeSpans(src, j.fn);
  if (!spans.length) { rows.push({ ...j.meta, kind: 'none', verdict: 'NO_WIPE_WRITTEN', scoped }); return; }
  const idiom = kinds.includes('removable') && kinds.includes('nonremovable') ? 'both'
    : kinds.includes('removable') ? 'removable' : 'nonremovable';
  const pW = join(AB, `${j.id}.w.c`), pWo = join(AB, `${j.id}.wo.c`);
  writeFileSync(pW, src + CONTROL, 'utf8');
  writeFileSync(pWo, ablateSpans(src, spans) + CONTROL, 'utf8');
  for (const cc of VENDORS) for (const opt of OPTS) {
    const aW = await compile(cc, [opt], pW, join(AB, `${j.id}.${cc}${opt}.w.s`));
    const aWo = await compile(cc, [opt], pWo, join(AB, `${j.id}.${cc}${opt}.wo.s`));
    const row = { ...j.meta, kind: 'erasure', idiom, cc, opt, n_spans: spans.length, named_secret: namedSecret, scoped };
    if (!aW) row.verdict = 'COMPILE_ERROR';
    else if (!aWo) row.verdict = 'ABLATION_DID_NOT_COMPILE';
    else {
      const ctl = controlPresent(aW);
      const bW = bodyOf(aW, j.fn), bWo = bodyOf(aWo, j.fn);
      row.control = ctl.ok ? 'PRESENT' : ctl.via;
      row.control_via = ctl.via;
      if (bW === null || bWo === null) row.verdict = 'NOT_OBSERVED';
      else if (!ctl.ok) row.verdict = 'VERIFICATION_INCOMPLETE';
      else row.verdict = bW === bWo ? 'WIPE_ELIMINATED' : 'WIPE_SURVIVED';
    }
    rows.push(row);
  }
});
process.stderr.write(`erasure done (${rows.length} rows)\n`);

// ---- authz: does the check survive -DNDEBUG? --------------------------------
const authz = jobs.filter((j) => j.fam === 'authz');
await pool(authz, async (j) => {
  const src = readFileSync(j.path, 'utf8');
  const masked = maskNonCode(src);
  const usesAssert = /\bassert\s*\(/.test(masked);
  const p = join(AB, `${j.id}.c`);
  writeFileSync(p, src + CONTROL, 'utf8');
  for (const cc of VENDORS) for (const opt of ['-O0', '-O2']) {
    const a1 = await compile(cc, [opt], p, join(AB, `${j.id}.${cc}${opt}.dbg.s`));
    const a2 = await compile(cc, [opt, '-DNDEBUG'], p, join(AB, `${j.id}.${cc}${opt}.nd.s`));
    const row = { ...j.meta, kind: 'authz', cc, opt, uses_assert: usesAssert };
    if (!a1 || !a2) { row.verdict = 'COMPILE_ERROR'; rows.push(row); continue; }
    const b1 = bodyOf(a1, j.fn), b2 = bodyOf(a2, j.fn);
    if (b1 === null || b2 === null) row.verdict = 'NOT_OBSERVED';
    else row.verdict = b1 === b2 ? 'NDEBUG_NO_EFFECT' : 'CHANGED_BY_NDEBUG';
    rows.push(row);
  }
});
process.stderr.write(`authz done (${rows.length} rows)\n`);

// ---- configguard: default build vs all-macros-defined ------------------------
const cfg = jobs.filter((j) => j.fam === 'configguard');
await pool(cfg, async (j) => {
  const src = readFileSync(j.path, 'utf8');
  const macros = new Set();
  for (const m of src.matchAll(/^\s*#\s*if(?:n?def)\s+([A-Za-z_]\w*)/gm)) macros.add(m[1]);
  for (const m of src.matchAll(/defined\s*\(?\s*([A-Za-z_]\w*)/g)) macros.add(m[1]);
  const p = join(AB, `${j.id}.c`);
  writeFileSync(p, src + CONTROL, 'utf8');
  const defs = [...macros].map((m) => `-D${m}=1`);
  for (const cc of VENDORS) for (const opt of ['-O0', '-O2']) {
    const a1 = await compile(cc, [opt], p, join(AB, `${j.id}.${cc}${opt}.def.s`));
    const a2 = await compile(cc, [opt, ...defs], p, join(AB, `${j.id}.${cc}${opt}.on.s`));
    const row = { ...j.meta, kind: 'configguard', cc, opt, macros: [...macros], n_macros: macros.size };
    if (!a1 || !a2) { row.verdict = 'COMPILE_ERROR'; rows.push(row); continue; }
    const b1 = bodyOf(a1, j.fn), b2 = bodyOf(a2, j.fn);
    if (b1 === null || b2 === null) row.verdict = 'NOT_OBSERVED';
    else if (!macros.size) row.verdict = 'NO_MACRO_GUARD';
    else row.verdict = b1 === b2 ? 'DEFAULT_EQUALS_ENABLED' : 'DEFAULT_DIFFERS';
    rows.push(row);
  }
});
process.stderr.write(`configguard done (${rows.length} rows)\n`);

writeFileSync(join(ROOT, 'data', 'r2-build-rows.json'), JSON.stringify(rows), 'utf8');
process.stderr.write(`wrote ${rows.length} rows\n`);
