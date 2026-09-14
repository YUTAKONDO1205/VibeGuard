/**
 * How many bytes should the wipe have written? -- and why that question needs
 * its own module, its own positive control and its own outcome word.
 *
 * WHY THIS FILE EXISTS
 *
 * O3 (`../../lto-window/tools/read-wipe.py`, through
 * `../../../gcc-repair/scripts/objdump_fill.py`) reads the zero fill of one
 * function in a linked program and grades it against a byte count it is handed:
 *
 *     PRESENT  the fill covers exactly `nbytes`, or a memset call is still there
 *     ABSENT   no zero store and no such call
 *     PARTIAL  some fill, but not `nbytes` worth
 *
 * `nbytes` is not in the tracked rows. `../../ai-generated/data/r2-build-rows.json`
 * carries `id, model, framing, scen, rep, fam, fn, kind, idiom, cc, opt,
 * n_spans, named_secret, scoped, control, control_via, verdict` and no buffer
 * size, because the corpus oracle never needed one: `verdictOf` compares two
 * assembly listings as text and does not care how big the buffer was. The
 * lto-window lane gets its `bufferBytes` from the generator that wrote its
 * fixtures. This corpus has no generator -- 720 files written by three models --
 * so the number has to come from somewhere else, and WHERE is the first thing
 * this lane had to decide.
 *
 * WHAT WAS REJECTED, AND WHY IT IS NAMED HERE RATHER THAN JUST NOT DONE
 *
 *   A DEFAULT. Handing O3 a fixed 32 would turn every surviving wipe of another
 *   size into `PARTIAL` and every reading into a statement about the default.
 *   There is no default in this module and no argument that supplies one.
 *
 *   A NUMBER READ OUT OF THE SOURCE TEXT. This repository has been burned by
 *   exactly that: a first pass at the O2 exclusion split grepped the corpus for
 *   `memset(` and matched the word inside the files' own comments (the README's
 *   "A false trail worth recording"), and section 2.20(c)3 of the implementation
 *   order got twenty cells wrong the same way. `../../../schema/interfaces.md`
 *   section 4 states the general form of the rule: never decide a fact about
 *   compiled code by searching for a name.
 *
 *   READING THE `-O0` ZERO FILL BACK OUT OF A DISASSEMBLY, which is the
 *   corroboration that first suggests itself. It does not work on this corpus
 *   and the reason is worth recording: at `-O0` a `memset` of 32 bytes is a
 *   CALL, so the byte count read back is 0, and a `volatile` pointer loop is a
 *   LOOP with one one-byte store in it, so the byte count read back is 1. In
 *   neither shape is the number the buffer's size. A corroboration that returns
 *   0 or 1 for the two commonest idioms in the corpus is not a corroboration.
 *
 * WHERE THE NUMBER ACTUALLY COMES FROM
 *
 * From the COMPILER, by constant-expression evaluation, using `_Static_assert`
 * as the read-out. The source text supplies only the EXPRESSION -- the wipe's
 * own length argument, at the span `wipeSpans` (the shared oracle's own span
 * finder, not a new grep) already located -- and every digit of the answer is
 * the compiler's:
 *
 *   1. THE APPARATUS CONTROL, first and always. `_Static_assert(1, ...)` is
 *      inserted at the probe point and must COMPILE, and `_Static_assert(0, ...)`
 *      at the same point must FAIL. This is the positive control for the
 *      read-out itself: an assertion inserted somewhere that is not compiled --
 *      inside a comment, inside a branch the front end never analyses, after a
 *      `#if 0` -- succeeds for every question anybody asks it. Without this pair
 *      the module would confirm any number at all and report it with a straight
 *      face. It is read BEFORE the length is ever probed.
 *
 *   2. IS THE LENGTH A CONSTANT AT ALL? `(LEN) <= 65536` and `(LEN) > 65536` are
 *      complementary: for an integer constant expression EXACTLY ONE compiles.
 *      Neither compiling means `LEN` is not a constant expression -- a runtime
 *      `n`, a parameter -- and the cell leaves by name. Both compiling is
 *      impossible after step 1 and is still checked, because "impossible" is
 *      what a silent pass is made of.
 *
 *   3. THE VALUE, by bisection on `(LEN) <= mid`. Seventeen compiles at most,
 *      `-fsyntax-only`, and the result is a number no part of which was read out
 *      of the text.
 *
 *   4. THE VALUE, CONFIRMED, by the same complementary trick at the answer:
 *      `(LEN) == N` must compile and `(LEN) == N + 1` must fail.
 *
 *   5. THE NUMBER IS THE WIPED OBJECT'S SIZE, not merely some constant in the
 *      last argument position. `(LEN) == sizeof(OBJ)` must compile, where `OBJ`
 *      is the identifier the wipe's FIRST argument names. This is the check that
 *      makes `secure_memset(seed, 0, sizeof seed)` and `explicit_bzero(token, 32)`
 *      both mean what O3 needs them to mean, and it is the compiler that decides
 *      it. A wipe of a pointer parameter fails it (`sizeof` a pointer is 8) and
 *      leaves by name, which is right: a buffer whose size is not in the
 *      translation unit has no byte count for a disassembly reader to grade
 *      against.
 *
 * WHAT IS STILL TEXT-DERIVED, SAID PLAINLY. The LOCATION of the wipe and the
 * CHOICE of "the last argument is the length" are text. They are not the number.
 * The location comes from `wipeSpans`, which is the function the corpus run
 * itself ablated with -- so O3 is pointed at the same wipe O1 ablated, by the
 * same code, rather than by a second opinion about where the wipe is -- and
 * `test/bufferbytes.test.mjs` re-derives every tracked `n_spans` from it to show
 * it has not drifted from the frozen rows. The "last argument" rule is checked by
 * step 5 for every cell that is graded: a last argument that is not the wiped
 * object's size never becomes a byte count.
 *
 * A CELL WHOSE NUMBER CANNOT BE ESTABLISHED LEAVES BY NAME.
 * `REASON.O3_BYTES_UNESTABLISHED` and `REASON.O3_NO_SINGLE_WIPE` are that cell's
 * own words; it is counted, listed with its id, and kept out of the denominator.
 * It is never defaulted and never guessed.
 *
 * Nothing here writes into the repository. The probe sources go to the lab, and
 * a lab inside the repository is refused.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';

import {
  CONTROL, FLAGS, maskNonCode, wipeSpans, volatileFnPtrs,
} from '../../ai-generated/lib/ablation-cell.mjs';
import { insideRepo, vendorLabel } from '../../spike/lib/measure.mjs';
import { REASON } from './agreement.mjs';

const run = promisify(execFile);

/**
 * The largest length this module will bisect for.
 *
 * A bound, not a cap that silently clamps: a length above it is reported and the
 * cell leaves by name, exactly as a non-constant length does. The number is
 * generous for a stack secret; the corpus's scenarios are keys, tokens and
 * passphrases.
 */
export const MAX_PROBE_BYTES = 65536;

/** The probe's flags: the corpus run's, without `-S`, and syntax only. */
export const PROBE_FLAGS = Object.freeze([...FLAGS.filter((f) => f !== '-S'), '-O0', '-fsyntax-only']);

/** The tag every inserted assertion carries, so a diagnostic can be recognised. */
export const PROBE_TAG = 'vg-oa-bytes';

/**
 * The control function's own buffer, re-derived from the control's source.
 *
 * Not spelled as a number here. `CONTROL` is imported from the corpus lane and
 * the size is read out of it, so that a control whose buffer changed size cannot
 * leave this lane grading it against the old one -- which would read `PARTIAL`,
 * fell the control, and report every cell in the run as a broken apparatus with
 * no indication that the apparatus was fine and the constant was stale.
 */
export function controlBytes(controlSource = CONTROL) {
  const m = /\bunsigned\s+char\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]/.exec(controlSource);
  if (!m) throw new Error('controlBytes: the control source no longer declares a sized unsigned char buffer');
  return { name: m[1], bytes: Number.parseInt(m[2], 10) };
}

/**
 * Split a call's argument list at top level.
 *
 * Depth-counted rather than split on commas, because `memset(p, 0, sizeof(a[i]))`
 * and a cast `( void * )` both carry parentheses a naive split gets wrong -- and
 * gets wrong quietly, by handing back an expression that still compiles.
 */
export function splitArgs(callText) {
  const open = callText.indexOf('(');
  if (open < 0) return null;
  const args = [];
  let depth = 0;
  let cur = '';
  for (let i = open; i < callText.length; i++) {
    const c = callText[i];
    if (c === '(' || c === '[') { depth++; if (depth === 1 && c === '(') continue; }
    else if (c === ')' || c === ']') { depth--; if (depth === 0) { args.push(cur); return args; } }
    if (depth === 1 && c === ',') { args.push(cur); cur = ''; continue; }
    cur += c;
  }
  return null;
}

/**
 * The identifier a wipe's first argument names, with one leading cast removed.
 *
 * `key`, `(void *)vkey`, `( unsigned char * ) buf`. Anything else -- an offset,
 * a field, an expression -- returns null and the cell leaves by name. Being
 * narrow here is the point: this identifier is what step 5's `sizeof` is taken
 * of, and a generous parse would take the size of the wrong object and be
 * confirmed by the compiler for it.
 */
export function wipedObject(firstArg) {
  if (typeof firstArg !== 'string') return null;
  const withoutCast = firstArg.replace(/^\s*\(\s*[A-Za-z_][A-Za-z_0-9\s*]*\)\s*/, '');
  const m = /^\s*([A-Za-z_]\w*)\s*$/.exec(withoutCast);
  return m ? m[1] : null;
}

/**
 * Where is this cell's ONE wipe, and what are the two expressions O3 needs?
 *
 * PURE: no compiler, no file. Returns either a located wipe or a refusal with
 * the lane's own reason word attached, so the caller never has to invent one.
 *
 * The span comes from `wipeSpans` -- the corpus run's own span finder. A cell
 * with more than one span has no single wipe for a (caller, helper, bytes)
 * triple to describe, and a cell whose wipe goes through a `volatile` function
 * POINTER has no symbol for the disassembly reader to follow: the call is
 * indirect, `objdump_branches` resolves no target, and read-wipe.py would read
 * the caller, find no zero store and report `ABSENT` -- an elimination
 * manufactured out of an instrument that could not see the call. Both leave by
 * name.
 */
export function locateWipe(src, fn) {
  const refuse = (reason, why) => ({ located: false, reason, why });
  const { spans, kinds, helpers } = wipeSpans(src, fn);
  if (spans.length === 0) return refuse(REASON.O3_NO_SINGLE_WIPE, 'no wipe span was found in the subject function');
  if (spans.length > 1) return refuse(REASON.O3_NO_SINGLE_WIPE, `the subject performs ${spans.length} wipes; O3 reads one`);

  const masked = maskNonCode(src);
  const [start, end] = spans[0];
  const text = masked.slice(start, end);
  const m = /^\s*([A-Za-z_]\w*)\s*\(/.exec(text);
  if (!m) return refuse(REASON.O3_NO_SINGLE_WIPE, 'the wipe is not a call, so it has no length argument');
  const callee = m[1];
  if (volatileFnPtrs(masked).includes(callee)) {
    return refuse(REASON.O3_NO_SINGLE_WIPE,
      'the wipe goes through a volatile function pointer: the call is indirect and the disassembly reader resolves no target');
  }
  const args = splitArgs(text);
  if (!args || args.length < 2) return refuse(REASON.O3_NO_SINGLE_WIPE, 'the wipe call has no length argument');

  // The length is the LAST argument for every wipe spelling in this corpus --
  // memset(p, 0, n), explicit_bzero(p, n), memset_s(p, smax, 0, n), and a
  // model-written helper(p, n) or helper(p, 0, n). It is a reading of the text
  // and it is not trusted: `establishBytes` makes the compiler agree that this
  // argument equals `sizeof` the wiped object before any number is used.
  const lenExpr = args[args.length - 1].trim();
  const object = wipedObject(args[0]);
  if (!lenExpr) return refuse(REASON.O3_NO_SINGLE_WIPE, 'the wipe call has an empty length argument');
  if (!object) {
    return refuse(REASON.O3_BYTES_UNESTABLISHED,
      'the wiped object is not a plain identifier, so its size cannot be put to the compiler');
  }
  return {
    located: true,
    span: [start, end],
    callee,
    // A helper is a function this file defines and `wipeSpans` recognised as a
    // wipe helper. read-wipe.py needs its name to tell "the helper was inlined
    // into the caller" from "the fill is in the helper the caller branches to";
    // it is handed `-` when the wipe is a direct call to an effect symbol, which
    // is read-wipe.py's own spelling for "there is nothing to inline".
    helper: helpers.includes(callee) ? callee : null,
    lenExpr,
    object,
    kind: kinds[0],
  };
}

/** The source with one `_Static_assert` inserted immediately before the wipe. */
export function probeSource(src, at, expr) {
  return `${src.slice(0, at)}_Static_assert((${expr}), "${PROBE_TAG}");\n${src.slice(at)}`;
}

/**
 * Does one probe compile?
 *
 * `true` / `false`, never a throw for a rejected assertion: a rejected assertion
 * is the READING. A driver that could not be started at all is a different thing
 * and is raised, because a run in which every probe silently read `false` would
 * establish nothing and report it as a length that is not constant.
 */
export async function probeCompiles({ cc, lab, id, src, at, expr, tag, timeout = 60000 }) {
  const path = join(lab, `oa.bytes.${id}.${vendorLabel(cc)}.${tag}.c`);
  writeFileSync(path, probeSource(src, at, expr), 'utf8');
  try {
    await run(cc, [...PROBE_FLAGS, path], { timeout });
    return true;
  } catch (err) {
    // A driver that is not on PATH, or a timeout: `code` is a string (`ENOENT`,
    // `ETIMEDOUT`) rather than an exit status. A compiler that ran and rejected
    // the assertion exits non-zero with a numeric code.
    if (typeof err.code !== 'number') {
      throw new Error(`the probe compiler could not be run (${String(err.code || err.message).slice(0, 40)})`);
    }
    return false;
  }
}

/**
 * Establish one cell's byte count, or refuse it by name.
 *
 * @returns {Promise<object>} either
 *   `{ established: true, bytes, helper, object, lenExpr, probes, provenance }`
 *   or `{ established: false, reason, why, probes }` where `reason` is one of
 *   this lane's own words and the caller files the cell under it.
 */
export async function establishBytes({ cc, lab, id, src, fn, timeout = 60000 }) {
  if (insideRepo(lab)) throw new Error('establishBytes: the lab directory is inside the repository');
  mkdirSync(lab, { recursive: true });

  const located = locateWipe(src, fn);
  if (!located.located) return { established: false, reason: located.reason, why: located.why, probes: 0 };

  // The SAME translation unit O3 will build: the generation with the corpus
  // run's control appended. A length probed in a different unit is a length
  // probed in a different program.
  const unit = src + CONTROL;
  const at = located.span[0];
  let probes = 0;
  const ask = async (expr, tag) => {
    probes += 1;
    return probeCompiles({ cc, lab, id, src: unit, at, expr, tag, timeout });
  };

  // ---- 1. the apparatus control, before the length is ever mentioned --------
  const live = await ask('1', 'live');
  const dead = await ask('0', 'dead');
  if (!live || dead) {
    return {
      established: false,
      reason: REASON.O3_BYTES_UNESTABLISHED,
      why: live
        ? 'a deliberately false assertion at the probe point COMPILED: the read-out is not being evaluated, so no number it returns means anything'
        : 'a trivially true assertion at the probe point did not compile: the probe point is not a declaration context in this unit',
      probes,
    };
  }

  // ---- 2. is the length a constant expression at all? ----------------------
  const inRange = await ask(`(${located.lenExpr}) <= ${MAX_PROBE_BYTES}`, 'range-lo');
  const aboveRange = await ask(`(${located.lenExpr}) > ${MAX_PROBE_BYTES}`, 'range-hi');
  if (inRange && aboveRange) {
    return {
      established: false,
      reason: REASON.O3_BYTES_UNESTABLISHED,
      why: 'both halves of a complementary pair compiled, which cannot happen for a constant: the read-out is unsound for this cell',
      probes,
    };
  }
  if (!inRange && !aboveRange) {
    return {
      established: false,
      reason: REASON.O3_BYTES_UNESTABLISHED,
      why: 'the wipe length is not an integer constant expression in this unit, so there is no byte count for O3 to grade against',
      probes,
    };
  }
  if (aboveRange) {
    return {
      established: false,
      reason: REASON.O3_BYTES_UNESTABLISHED,
      why: `the wipe length is above ${MAX_PROBE_BYTES}, which is this module's probe range; it is refused rather than clamped`,
      probes,
    };
  }

  // ---- 3. the value, by bisection ------------------------------------------
  let lo = 0;
  let hi = MAX_PROBE_BYTES;
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    // eslint-disable-next-line no-await-in-loop
    if (await ask(`(${located.lenExpr}) <= ${mid}`, `bisect-${mid}`)) hi = mid; else lo = mid + 1;
  }
  const bytes = lo;

  // ---- 4. the value, confirmed by a complementary pair at the answer -------
  const isN = await ask(`(${located.lenExpr}) == ${bytes}`, 'eq');
  const isNext = await ask(`(${located.lenExpr}) == ${bytes + 1}`, 'eq-next');
  if (!isN || isNext) {
    return {
      established: false,
      reason: REASON.O3_BYTES_UNESTABLISHED,
      why: `the bisection settled on ${bytes} and the confirming pair did not agree with it`,
      probes,
    };
  }
  if (bytes === 0) {
    return {
      established: false,
      reason: REASON.O3_BYTES_UNESTABLISHED,
      why: 'the wipe length is zero, so there is nothing for the disassembly reader to find or to miss',
      probes,
    };
  }

  // ---- 5. it is the WIPED OBJECT's size, not merely a constant -------------
  const isObjectSize = await ask(`(${located.lenExpr}) == sizeof(${located.object})`, 'sizeof');
  if (!isObjectSize) {
    return {
      established: false,
      reason: REASON.O3_BYTES_UNESTABLISHED,
      why: `the length does not equal sizeof(${located.object}), the object the wipe's first argument names, so this constant is not the buffer's size`,
      probes,
    };
  }

  return {
    established: true,
    bytes,
    helper: located.helper,
    object: located.object,
    lenExpr: located.lenExpr,
    kind: located.kind,
    probes,
    /**
     * The word the record carries. `compiler` means every digit came out of a
     * constant-expression evaluation with a live positive control beside it;
     * there is no second value of this field, because a byte count from anywhere
     * else is not written.
     */
    provenance: 'compiler',
  };
}
