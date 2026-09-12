/**
 * The 48-of-48 split, as a tool rather than as a hand count.
 *
 * WHY THIS FILE EXISTS
 *
 * The README's section "The 23 exclusions are the boundary of what O2 can be
 * ASKED" rests on one table: every cell O2 refused has ZERO wipe call sites in
 * the `-O0` LLVM IR of its generation, and every cell both oracles graded has at
 * least one. That table was counted by hand on 2026-09-12. A hand count is a
 * measurement whose provenance is a sentence -- nobody can re-run it, nobody can
 * tell whether it moved when the corpus did, and the number it produced is the
 * load-bearing one in the lane's central claim (*the two oracles have different
 * DOMAINS*, and the intersection is 25 of 48).
 *
 * So it is counted here instead, and the record says `provenance: "tool"` when
 * it was. Two decisions in it are worth stating, because both are places where a
 * shorter implementation would have produced a number that looks the same and
 * means something else.
 *
 * 1. A CALL SITE IS NOT A NAME. `../../schema/interfaces.md` section 4 forbids
 *    deciding presence by searching for a symbol name, and this lane's README
 *    records what happens when you do: a first pass grepped the SOURCE for
 *    `memset(`, found five of the twenty-three exclusions apparently calling it,
 *    and was matching the word inside the files' own comments. So this module
 *    only counts a name that appears as the callee of a `call`/`invoke`, and
 *    never counts a `declare` line -- which is exactly the shape the grep would
 *    have miscounted, since every module that mentions an intrinsic declares it.
 *
 * 2. THE SYMBOL LIST IS NOT SPELLED HERE. It is a parameter, and the runner
 *    passes what `effectSymbols()` reads out of
 *    `compiler/schema/effect-symbol-lists.json` (group `wipe-5-observer`) -- the
 *    same list the plugin itself is configured with. Two instruments asking
 *    about different symbol sets while reporting in one vocabulary is the
 *    failure that registry was written after finding ten times in this tree, and
 *    a diagnosis of O2's domain that used a different list than O2 would be an
 *    instance of it. The README names three symbols because three are what this
 *    corpus uses; the counts here are per symbol, so that subtotal stays
 *    derivable without the list being frozen into prose.
 *
 * WHAT IS NOT DECIDED HERE. Whether the file-scoped or the function-scoped count
 * is the right one to compare against O2. Both are returned. O2 watches the
 * SUBJECT function's call site, so the function-scoped count is the closer
 * question; the README counted "the `-O0` LLVM IR of each corpus file", so the
 * file-scoped count is the one its table is about. They are recorded separately
 * and `test/data.test.mjs` checks the README against the scope the README names.
 * If they ever disagree, that is a finding and not a rounding error.
 *
 * Nothing in this module writes a file. `emitIrAtO0` runs the compiler and asks
 * it to write into the lab; the caller has already checked that the lab is
 * outside the repository.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { readFileSync, mkdirSync, existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';

import { insideRepo, vendorLabel } from '../../spike/lib/measure.mjs';

const run = promisify(execFile);

/**
 * The symbol list, as an array, from the registry's comma-separated literal.
 *
 * Taken as a string rather than an array because that is the shape the plugin is
 * handed (`OBS_EFFECT_SYMBOLS`), so the two configurations are the same bytes.
 */
export function symbolsOf(literal) {
  if (typeof literal !== 'string') throw new TypeError('symbolsOf: the effect-symbol list must be the registry literal, a string');
  const list = literal.split(',').map((s) => s.trim()).filter(Boolean);
  if (!list.length) throw new Error('symbolsOf: the effect-symbol list is empty');
  return list;
}

/**
 * Does an IR callee name match one of the effect symbols?
 *
 * Exact, with ONE exception: an LLVM intrinsic is overloaded in its name, so the
 * registry's `llvm.memset` appears in IR as `llvm.memset.p0.i64`. The suffix
 * rule is confined to names that already begin `llvm.`, deliberately. Applied
 * generally it would let `memset` swallow a hypothetical `memset.part.0`, and a
 * matcher that is generous by default is how a count grows without anyone
 * choosing to grow it.
 */
export function calleeMatches(callee, symbols) {
  for (const sym of symbols) {
    if (callee === sym) return sym;
    if (sym.startsWith('llvm.') && callee.startsWith(`${sym}.`)) return sym;
  }
  return null;
}

/** `define ... @name(` -- the function a following call site is inside. */
const DEFINE_RE = /^define\b[^@]*@(?:"([^"]+)"|([\w.$\-]+))\s*\(/;

/**
 * A call or invoke, and the callee it names.
 *
 * The callee is the LAST `@name(` on the line, because the argument list can
 * carry `@` globals of its own (`call void @memset(ptr @buffer, ...)`), and the
 * callee in an IR call comes after the return type and before the arguments --
 * so a first-match regex reads an argument as the callee on exactly the lines
 * where the answer matters. An indirect call (`call void %fp(...)`) names no
 * global and is not counted: there is no resolved callee to compare.
 */
const CALL_RE = /\b(?:tail\s+|musttail\s+|notail\s+)?(?:call|invoke)\b/;
const AT_NAME_RE = /@(?:"([^"]+)"|([\w.$\-]+))\s*\(/g;

/**
 * Count effect-symbol call sites in one module's `-O0` IR.
 *
 * @param {string} irText   the `.ll` text
 * @param {string[]} symbols the effect symbols, from the registry
 * @param {string|null} fn  the subject function, for the function-scoped count
 * @returns {{inFile: number, inFunction: number, bySymbol: object, functionSeen: boolean}}
 */
export function countIrCallSites(irText, symbols, fn = null) {
  if (typeof irText !== 'string') throw new TypeError('countIrCallSites: no IR text');
  const bySymbol = Object.fromEntries(symbols.map((s) => [s, 0]));
  let inFile = 0;
  let inFunction = 0;
  let functionSeen = false;
  let current = null;

  for (const line of irText.split('\n')) {
    const def = DEFINE_RE.exec(line);
    if (def) {
      current = def[1] !== undefined ? def[1] : def[2];
      if (fn !== null && current === fn) functionSeen = true;
      continue;
    }
    // A closing brace in column 0 ends a definition. Inside a body every line is
    // indented, so this cannot be confused with a brace in an instruction.
    if (line.startsWith('}')) { current = null; continue; }
    if (!CALL_RE.test(line)) continue;
    // `declare` never carries `call`, so it is already excluded; this keeps that
    // true if a comment on a declare line ever mentions one.
    if (line.trimStart().startsWith('declare')) continue;

    let callee = null;
    AT_NAME_RE.lastIndex = 0;
    for (let m = AT_NAME_RE.exec(line); m; m = AT_NAME_RE.exec(line)) {
      callee = m[1] !== undefined ? m[1] : m[2];
    }
    if (callee === null) continue;
    const sym = calleeMatches(callee, symbols);
    if (sym === null) continue;
    inFile += 1;
    bySymbol[sym] += 1;
    if (fn !== null && current === fn) inFunction += 1;
  }

  return { inFile, inFunction, bySymbol, functionSeen };
}

/**
 * The 2x2 the README prints: were the cells O2 refused exactly the cells with no
 * call site to watch?
 *
 * `cells` are `{excluded: boolean, count: number}`. The four figures are counts
 * of CELLS, so they are integers and they sum to the number of cells -- which is
 * the property that makes "48 of 48" checkable rather than quotable.
 */
export function splitByCallSites(cells) {
  const split = { excludedZero: 0, excludedNonZero: 0, gradedZero: 0, gradedNonZero: 0 };
  for (const c of cells) {
    const zero = c.count === 0;
    if (c.excluded) split[zero ? 'excludedZero' : 'excludedNonZero'] += 1;
    else split[zero ? 'gradedZero' : 'gradedNonZero'] += 1;
  }
  return split;
}

/** Is the split perfect -- every refused cell at zero, every graded cell above it? */
export const splitIsPerfect = (s) => s.excludedNonZero === 0 && s.gradedZero === 0
  && (s.excludedZero + s.gradedNonZero) > 0;

/** Cells in a split, the denominator behind "48 of 48". */
export const splitTotal = (s) => s.excludedZero + s.excludedNonZero + s.gradedZero + s.gradedNonZero;

/**
 * Emit one generation's `-O0` IR into the lab and read it back.
 *
 * WITHOUT the appended `CONTROL`. The control defines a wipe of its own, so a
 * module compiled with it appended has at least one wipe call site by
 * construction and the zero/non-zero split would be all non-zero -- the
 * diagnosis would return "perfect" while measuring nothing but the control. The
 * O2 channel appends it because the control is what proves the instrument was
 * alive; this count must not.
 *
 * `-O0` and not the cell's level, also deliberately: the question is whether
 * there was EVER a call site for the observer to watch, which is a question
 * about what the front end emitted, not about what the pipeline did to it.
 */
export const irPathOf = ({ lab, id, cc }) => join(lab, `oa.ir.${id}.${vendorLabel(cc)}.ll`);

/**
 * The driver arguments, split out so they can be tested without a compiler.
 *
 * `../observe.mjs` splits `observerArgs` out for the same reason: the one place
 * a flag reaches the toolchain should be one function, and the flag that is
 * wrong here (`-O2` instead of `-O0`, or the source with the control appended)
 * produces a plausible count rather than an error.
 */
export const irArgs = ({ srcPath, llPath }) => ['-O0', '-S', '-emit-llvm', srcPath, '-o', llPath];

export async function emitIrAtO0({ cc, srcPath, lab, id, timeout = 120000 }) {
  if (insideRepo(lab)) throw new Error('emitIrAtO0: the lab directory is inside the repository');
  mkdirSync(lab, { recursive: true });
  const llPath = irPathOf({ lab, id, cc });
  await run(cc, irArgs({ srcPath, llPath }), { timeout });
  if (!existsSync(llPath)) throw new Error(`emitIrAtO0: ${cc} wrote no IR for ${id}`);
  return readFileSync(llPath, 'utf8');
}
