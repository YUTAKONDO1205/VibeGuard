/**
 * The O3 side: the same cell, BUILT AND LINKED, read out of its disassembly.
 *
 * WHY THIS EXISTS AT ALL
 *
 * The README's "Running it" section says plainly that `gcc-13` is accepted by
 * `--cc` and will not work, because the PropertyObserver is an LLVM pass plugin
 * and gcc does not load it, and that cross-vendor comparison here needs O3
 * instead -- "which this lane does not implement". It does now. Until it did,
 * the corpus's gcc half -- a bit over 2,300 of the 4,689 tracked rows -- had NO
 * second instrument, so every statement this lane made about two oracles was a
 * statement about clang.
 *
 * WHAT IS DELIBERATELY THE SAME AS THE O2 CHANNEL
 *
 *   The unit. `../../ai-generated/lib/ablation-cell.mjs`'s `CONTROL` is appended
 *   to the generation exactly as `lib/observe.mjs` appends it and exactly as the
 *   corpus run appends it, so the positive control both oracles read is one
 *   function compiled once.
 *   The flags. `FLAGS` comes from the same module, with `-S` dropped because
 *   this channel needs an object file rather than a listing.
 *   The order. The control is read before the subject verdict is looked at, and
 *   `classifyPair` -- not this module -- is what enforces it.
 *
 * WHAT IS DELIBERATELY DIFFERENT
 *
 *   The artefact. O1 compares two assembly LISTINGS as text and O2 counts IR
 *   call sites BETWEEN PASSES; this reads instructions in a LINKED program.
 *   That is the point of a third instrument, and making it more alike than that
 *   would be making it the same instrument again.
 *
 * THE LINK, AND WHY IT IS NOT OPTIONAL
 *
 * A corpus generation is a fragment: it declares `kdf` and `aes256_encrypt` and
 * defines neither, and it has no `main`. The obvious shortcut is to disassemble
 * the object file and skip the link. IT PRODUCES A FABRICATED ELIMINATION. In an
 * unlinked object a call to an undefined symbol carries no resolved target, so
 * `objdump -d` prints it as an offset inside the containing function
 * (`call ... <encrypt_blob+0x34>`), and `objdump_branches` -- whose pattern
 * deliberately excludes a `+` -- sees no branch to `memset` at all. The reading
 * comes back `ABSENT` for a wipe that is plainly there, silently, on exactly the
 * cells where the answer matters. So this module links, and a cell it cannot
 * link leaves the denominator by name rather than being read anyway.
 *
 * The link is made to succeed WITHOUT GUESSING what the fragment needs. The
 * first attempt is the object on its own; when the linker refuses, the symbols
 * it NAMED as unresolved are the ones stubbed, and nothing else is. Stubs are in
 * their own translation unit, so no prototype in the generation is contradicted,
 * and they are never optimised into the subject: this is not an LTO link and the
 * stubs are opaque to it. The program is never RUN -- it is disassembled -- so a
 * stub with the wrong signature is a link-time convenience and not a behaviour.
 *
 * THE READER CONTROL, AND THE FABRICATION IT EXISTS TO STOP
 *
 * `objdump_fill.py` recognises exactly three things: a vector register zeroed
 * against itself and stored, an immediate zero stored, and a call to `memset` or
 * `__memset_chk`. A wipe written any other way is INVISIBLE to it. Two shapes in
 * this corpus are:
 *
 *   explicit_bzero(token, 32)     a call to a symbol that is not on that list,
 *                                 so the function holds no recognised fill and
 *                                 the reading is `ABSENT`.
 *   a volatile byte loop          ONE one-byte store, so the reading is
 *                                 `bytes = 1` against a buffer of 32: `PARTIAL`.
 *
 * Graded, the first of those is an ELIMINATION MANUFACTURED OUT OF THE READER'S
 * SYMBOL LIST -- a wipe that is plainly in the program, reported as gone, on
 * exactly the cells (`nonremovable`) where O1 says it survived. It would appear
 * in the table as an off-diagonal entry and read as a finding.
 *
 * So every cell is read TWICE: once at its own level, and once at `-O0`, where
 * the wipe is certainly present -- the tracked rows have never recorded an
 * elimination at `-O0`, over 319 gcc cells and 319 clang ones, and
 * `../test/rows.test.mjs` re-derives that from the frozen record. The `-O0`
 * reading is taken BEFORE the cell's own verdict is looked at:
 *
 *   `-O0` subject reads PRESENT      the reader recognised this wipe AS IT IS
 *                                    WRITTEN AT `-O0`. Whatever it says at the
 *                                    cell's level is a reading.
 *   anything else                    the reader cannot see this wipe even where
 *                                    it certainly exists. The cell leaves the
 *                                    denominator as `o3-reader-blind-to-this-wipe`
 *                                    -- never as an elimination.
 *
 * It doubles the builds and it is not optional. A per-cell control that can be
 * turned off is a per-cell control that is off in the run somebody quotes.
 *
 * WHAT IT DOES NOT QUALIFY, and the sentence this file used to carry.
 *
 * It called the `-O0` reading the reader's positive control FOR THE CELL --
 * flatly, for every cell. Two things are wrong with that and both are recorded
 * per reading now, in `readerControl.qualification`, rather than argued. (The
 * exact old sentence is not quoted here: `../test/second-oracle.test.mjs` greps
 * this file for it, and a quotation would fail the test on a corrected file.)
 *
 *   1. AT `-O0` IT IS NOT A CONTROL AT ALL. The cell's level and the control's
 *      level are the same level, so it is the same build and the same read --
 *      `observeCellO3` returns one of them twice. And `observeCellO3` cannot
 *      return a `-O0` reading at all unless the `-O0` read was PRESENT, because
 *      the branch above turns anything else into `o3-reader-blind-to-this-wipe`.
 *      So no `-O0` cell can be graded `ABSENT` and this control cannot fail on
 *      one. A check that cannot fail is not a check; `independent: false` says
 *      so in the reading.
 *   2. ABOVE `-O0` IT MAY EXERCISE A DIFFERENT RECOGNIZER BRANCH. `objdump_fill`
 *      recognises three things and they are three separate pieces of code: a
 *      call to `memset`/`__memset_chk`, an immediate zero stored, and a vector
 *      register zeroed against itself and stored. At `-O0` a wipe written as
 *      `memset(...)` is usually a CALL; at `-O2` the same wipe is usually
 *      INLINED into stores. Reading the call at `-O0` says nothing about whether
 *      the reader would have recognised the stores, which is the branch an `-O2`
 *      reading depends on. `branchRelevant` records whether the two readings
 *      came through the same branch, and it is FALSE on the cell that matters
 *      most: a subject that read no fill at all fired no branch, so nothing
 *      about the branch it would have needed was qualified.
 *
 * Both are limitations of this control, not defects in the cell, and neither
 * excludes anything: the qualification travels WITH the reading so that an
 * off-diagonal `ABSENT` can be read with the control's reach beside it instead
 * of on the strength of a sentence in a header. `../README.md` states it in
 * prose under "The reader's own control, per cell".
 *
 * Nothing here writes into the repository: the appended source, the object, the
 * stubs and the executable all go to the lab, and a lab inside the repository is
 * refused.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CONTROL, FLAGS } from '../../ai-generated/lib/ablation-cell.mjs';
import { CONTROL_FN } from '../../spike/lib/observer.mjs';
import { insideRepo, vendorLabel } from '../../spike/lib/measure.mjs';
import { REASON } from './agreement.mjs';
import { controlBytes } from './bufferbytes.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * The disassembly reader, in the lane that owns it.
 *
 * Spelled as a path rather than reimplemented, for the reason `read-wipe.py`'s
 * own header gives: "There is one disassembly oracle in this tree and this lane
 * is not going to be the second." It is `../../lto-window`'s tool and it imports
 * `../../../gcc-repair/scripts/objdump_fill.py`; both are read, neither is edited.
 */
export const READ_WIPE = resolve(HERE, '../../lto-window/tools/read-wipe.py');

/** The interpreter and the disassembler, both overridable for a host that spells them differently. */
export const PYTHON = process.env.OA_PYTHON || 'python3';
export const OBJDUMP = process.env.LTOW_OBJDUMP || 'objdump';

/** Object-file flags: the corpus run's, minus the one that asks for a listing. */
export const OBJECT_FLAGS = Object.freeze(FLAGS.filter((f) => f !== '-S'));

/** `read-wipe.py`'s own spelling for "there is no helper, so there is nothing to inline". */
export const NO_HELPER = '-';

/**
 * Is the O3 channel able to run at all?
 *
 * A REASON rather than a boolean, and the runner turns a negative into exit 3 --
 * a check that could not be completed -- rather than into a table of
 * `BROKEN_MEASUREMENT` cells. A run in which every cell is broken because
 * `objdump` is not installed and a run in which every wipe was eliminated
 * produce very different tables, and only one of them is a reading.
 */
export async function channelAvailableO3({ python = PYTHON, objdump = OBJDUMP } = {}) {
  if (!existsSync(READ_WIPE)) {
    return { available: false, reason: 'the disassembly reader (read-wipe.py, in the lto-window lane) is not present' };
  }
  try {
    // No arguments: the reader prints its usage and exits 4. That it exits 4
    // rather than failing to start is the check -- it proves the interpreter ran
    // it AND that its import of the gcc-repair objdump oracle resolved, which is
    // the half that breaks when a lane moves.
    await run(python, [READ_WIPE], { timeout: 30000 });
    return { available: false, reason: 'read-wipe.py exited 0 with no arguments, which it must not; the reader is not the one this lane expects' };
  } catch (err) {
    if (typeof err.code !== 'number') {
      return { available: false, reason: `the interpreter for read-wipe.py could not be run (${String(err.code || '').slice(0, 24)})` };
    }
    if (err.code !== 4) {
      return { available: false, reason: `read-wipe.py exited ${err.code} on its usage path; its import of the objdump oracle did not resolve` };
    }
  }
  try {
    await run(objdump, ['--version'], { timeout: 30000 });
  } catch {
    return { available: false, reason: 'objdump could not be run, so there is no disassembly to read' };
  }
  return { available: true, reason: null };
}

/**
 * The symbols a linker named as unresolved, from its own message.
 *
 * Two spellings, because two linkers are in this tree: BFD/gold say
 * "undefined reference to `name'" and lld says "undefined symbol: name". Only
 * what the linker NAMED is stubbed -- a stub for anything else would be this
 * module deciding what the fragment needs.
 */
export function unresolvedSymbols(stderrText) {
  const out = new Set();
  const text = String(stderrText || '');
  for (const m of text.matchAll(/undefined reference to [`'"]([A-Za-z_]\w*)['"]/g)) out.add(m[1]);
  for (const m of text.matchAll(/undefined symbol:\s*([A-Za-z_]\w*)/g)) out.add(m[1]);
  return [...out].sort();
}

/**
 * A translation unit that defines exactly the symbols the linker asked for.
 *
 * `main` is special-cased because it is the one symbol whose absence is normal
 * for a fragment and whose presence in the generation would make a second
 * definition a duplicate-symbol error. Everything else is a niladic void
 * function: C does not check a definition against another unit's prototype, the
 * program is never run, and this link is not an LTO link, so nothing here can
 * reach the subject's code.
 */
export function stubSource(symbols) {
  const lines = [
    '/* Link stubs for one corpus fragment. Generated from the symbols the linker',
    ' * named as unresolved, and from nothing else. Never executed: the program',
    ' * this unit completes is disassembled, not run. */',
  ];
  for (const s of symbols) {
    if (s === 'main') lines.push('int main(void) { return 0; }');
    else lines.push(`void ${s}(void) { }`);
  }
  return `${lines.join('\n')}\n`;
}

/** The driver arguments, split out so they can be tested without a compiler. */
export const objectArgs = ({ opt, srcPath, objPath }) => [...OBJECT_FLAGS, opt, '-c', srcPath, '-o', objPath];
export const linkArgs = ({ objects, exePath }) => [...objects, '-o', exePath];
export const readWipeArgs = ({ exePath, caller, helper, bytes, controlFn, controlBytesCount }) => [
  READ_WIPE, exePath, caller, helper || NO_HELPER, String(bytes), controlFn, String(controlBytesCount),
];

const broken = (reason, detail) => ({
  finalState: 'NOT_OBSERVED',
  control: null,
  brokenReason: reason,
  brokenDetail: detail === undefined ? null : detail,
});

/**
 * The level at which the reader's own control is taken.
 *
 * `-O0`, because that is where the tracked rows have never recorded an
 * elimination: 319 gcc cells and 319 clang ones, re-derived from the frozen
 * record by `../test/rows.test.mjs`. A wipe the reader cannot see THERE is a
 * wipe the reader cannot see.
 */
export const READER_CONTROL_OPT = '-O0';

/**
 * WHICH OF `objdump_fill`'s THREE RECOGNIZERS PRODUCED A READING.
 *
 * The reader is not one matcher: it is a call matcher, an immediate-store
 * matcher and a vector-store matcher, and a wipe written any fourth way is
 * invisible to all three. A control that exercised one of them has said nothing
 * about the other two, so "the reader can see this wipe" is only ever true of
 * the FORM the reader was shown.
 *
 * `objdump_fill` reports the two shapes it counts separately -- `memsetCalls`
 * and `stores` -- so the branch can be read off a reading without parsing
 * anything.
 *
 * @param {{stores?: number, memsetCalls?: number}|null|undefined} fill
 * @returns {string|null} null when there was no reading to take a branch from
 */
export const BRANCH = Object.freeze({
  MEMSET_CALL: 'memset-call',
  STORE: 'store',
  BOTH: 'both',
  NONE: 'none',
});

export function recognizerBranch(fill) {
  if (!fill || typeof fill !== 'object') return null;
  const calls = Number(fill.memsetCalls) || 0;
  const stores = Number(fill.stores) || 0;
  if (calls > 0 && stores > 0) return BRANCH.BOTH;
  if (calls > 0) return BRANCH.MEMSET_CALL;
  if (stores > 0) return BRANCH.STORE;
  return BRANCH.NONE;
}

/** The two sentences a `-O0` control at the cell's own level cannot say. */
export const SAME_BUILD_LIMITATION =
  'the cell IS at the control level, so the control and the subject are one build and one read: '
  + 'observeCellO3 cannot return a reading at this level unless that read was PRESENT, so no cell here '
  + 'can be graded ABSENT and this control cannot fail';
export const NO_BRANCH_LIMITATION =
  'the subject reading recognised no fill at all, so no recognizer branch fired in it: the control shows '
  + 'the reader recognised the -O0 FORM of this wipe, not that it would have recognised the form the '
  + 'optimiser left behind';

/**
 * WHAT THIS CELL'S `-O0` READING QUALIFIES, AND WHAT IT DOES NOT.
 *
 * Pure, and exported, so the claim can be tested on a host with no compiler and
 * so the record carries it per cell instead of the README carrying it once for
 * every cell in the corpus.
 *
 * `establishes` is null when the control established nothing -- which is the
 * honest answer at `-O0`, where the control and the subject are the same read.
 *
 * @param {object} o
 * @param {string} o.cellOpt      the level the cell was graded at
 * @param {string} [o.controlOpt] the level the control was taken at
 * @param {object|null} [o.controlFill]  the control reading's fill counts
 * @param {object|null} [o.subjectFill]  the cell reading's fill counts
 */
export function qualificationOf({ cellOpt, controlOpt = READER_CONTROL_OPT, controlFill = null, subjectFill = null }) {
  const controlBranch = recognizerBranch(controlFill);
  const subjectBranch = recognizerBranch(subjectFill);
  const independent = cellOpt !== controlOpt;
  const doesNotEstablish = [];
  let branchRelevant = null;
  if (!independent) {
    doesNotEstablish.push(SAME_BUILD_LIMITATION);
  } else if (subjectBranch === BRANCH.NONE) {
    branchRelevant = false;
    doesNotEstablish.push(NO_BRANCH_LIMITATION);
  } else if (subjectBranch !== null && controlBranch !== null) {
    // `both` on either side covers the other: the reading exercised that branch
    // among others.
    branchRelevant = controlBranch === subjectBranch
      || controlBranch === BRANCH.BOTH || subjectBranch === BRANCH.BOTH;
    if (!branchRelevant) {
      doesNotEstablish.push(`the control was read through the ${controlBranch} recognizer and the subject `
        + `through the ${subjectBranch} one, so the branch the subject reading depends on was not the branch `
        + 'the control exercised');
    }
  }
  return {
    controlOpt,
    controlBranch,
    subjectBranch,
    // The control is a second build read separately from the subject's.
    independent,
    // The control came through the recognizer the subject's reading depends on.
    // null when there is no subject branch to compare against.
    branchRelevant,
    establishes: independent ? 'the reader recognised this wipe in the -O0 build' : null,
    doesNotEstablish,
  };
}

/**
 * Build, link and read one cell at one level. No judgement -- that is the
 * caller's, and `classifyPair`'s.
 *
 * Split out from `observeCellO3` so the same code takes the cell's reading and
 * the reader's control. Two code paths for one measurement is how a control
 * stops measuring what the subject measures.
 */
async function readAt({ cc, opt, lab, id, fn, srcPath, bytes, helper, python, objdump, timeout }) {
  const tag = `oa3.${id}.${vendorLabel(cc)}${opt}`;
  const labSrc = join(lab, `${tag}.c`);
  const objPath = join(lab, `${tag}.o`);
  const stubSrc = join(lab, `${tag}.stubs.c`);
  const stubObj = join(lab, `${tag}.stubs.o`);
  const exePath = join(lab, `${tag}.elf`);

  // The same append the corpus run and the O2 channel make.
  writeFileSync(labSrc, readFileSync(srcPath, 'utf8') + CONTROL, 'utf8');

  try {
    await run(cc, objectArgs({ opt, srcPath: labSrc, objPath }), { timeout });
  } catch (err) {
    // The message is the compiler's and can name the lab, so it is returned to
    // the caller for stderr only. `brokenDetail` -- which reaches the report --
    // carries no text the compiler produced.
    return { ...broken(REASON.O3_BUILD_FAILED, 'the object file was not produced'), diagnostics: String(err.stderr || err.message).slice(0, 200) };
  }

  let linked = false;
  let stubbed = [];
  try {
    await run(cc, linkArgs({ objects: [objPath], exePath }), { timeout });
    linked = true;
  } catch (err) {
    const text = String(err.stderr || err.message);
    stubbed = unresolvedSymbols(text);
    if (!stubbed.length) {
      return { ...broken(REASON.O3_LINK_FAILED, 'the link failed and named no unresolved symbol'), diagnostics: text.slice(0, 200) };
    }
  }
  if (!linked) {
    writeFileSync(stubSrc, stubSource(stubbed), 'utf8');
    try {
      await run(cc, objectArgs({ opt, srcPath: stubSrc, objPath: stubObj }), { timeout });
      await run(cc, linkArgs({ objects: [objPath, stubObj], exePath }), { timeout });
      linked = true;
    } catch (err) {
      return {
        ...broken(REASON.O3_LINK_FAILED, `${stubbed.length} symbol(s) were stubbed and the link still failed`),
        diagnostics: String(err.stderr || err.message).slice(0, 200),
      };
    }
  }
  if (!existsSync(exePath)) return broken(REASON.O3_LINK_FAILED, 'the linker exited 0 and wrote no program');

  const control = controlBytes();
  let out;
  try {
    const { stdout } = await run(python, readWipeArgs({
      exePath, caller: fn, helper, bytes, controlFn: CONTROL_FN, controlBytesCount: control.bytes,
    }), { env: { ...process.env, LTOW_OBJDUMP: objdump }, timeout });
    out = JSON.parse(stdout);
  } catch (err) {
    return {
      ...broken(REASON.O3_READER_FAILED, typeof err.code === 'number' ? `read-wipe.py exited ${err.code}` : 'read-wipe.py could not be run'),
      diagnostics: String(err.stderr || err.message).slice(0, 200),
    };
  }

  return {
    // O3's own word, passed through. `PARTIAL` is not folded into anything and
    // `NOT_OBSERVED` is not turned into an absence -- read-wipe.py's header says
    // it passes its own NOT_OBSERVED case through and so does this.
    finalState: out.subject.verdict,
    control: out.control.verdict,
    // There is no pass pipeline here to name, and a null is the honest answer
    // rather than an omitted field: O3 reads a finished program, so "which pass
    // removed it" is a question it cannot be asked.
    firstLossPass: null,
    // What the words were folded from, so a reading can be reconciled rather
    // than only quoted. `../../lto-window/run-lto-window.mjs` keeps the same three.
    fill: {
      verdict: out.subject.verdict,
      bytes: out.subject.bytes,
      stores: out.subject.stores,
      memsetCalls: out.subject.memsetCalls,
      inlined: out.subject.inlined,
    },
    controlFill: {
      verdict: out.control.verdict,
      bytes: out.control.bytes,
      stores: out.control.stores,
      memsetCalls: out.control.memsetCalls,
    },
    // The count this reading was graded against, carried with it: `PARTIAL`
    // without the number it was partial OF is not a reading anybody can check.
    bytesAskedFor: bytes,
    helper,
    stubbed,
    compiled: true,
    objdump: out.objdump,
  };
}

/**
 * Observe one corpus cell through the disassembly reader.
 *
 * TWO READINGS AND ONE VERDICT. The cell is read at `-O0` first -- the reader's
 * control for this wipe, whose reach is argued at length in this file's header
 * and recorded per reading in `readerControl.qualification` -- and only then at
 * the level asked for. A cell whose wipe the reader cannot see at `-O0` is
 * returned as `o3-reader-blind-to-this-wipe` and never as an elimination,
 * because `ABSENT` from an instrument that has just been shown not to recognise
 * this wipe is not a reading about the wipe.
 *
 * The control is not described as a positive control for the CELL, because for
 * two kinds of cell it is not one: a cell at the control's own level (the same
 * build, the same read, a control that cannot fail) and a cell whose reading
 * came through a recognizer branch the control never exercised. Both are stated
 * in the reading rather than left to a reader.
 *
 * @param {object} args
 * @param {string} args.cc       the driver
 * @param {string} args.opt      the level
 * @param {string} args.lab      scratch directory, OUTSIDE the repository
 * @param {string} args.id       the generation's id; names the scratch files
 * @param {string} args.fn       the subject function -- read-wipe.py's `caller`
 * @param {string} args.srcPath  the generation, inside the repository, read only
 * @param {number} args.bytes    the byte count, ESTABLISHED by lib/bufferbytes.mjs
 * @param {string|null} args.helper the wipe helper, or null for a direct call
 * @returns {Promise<object>} a reading in the shape `classifyPair` wants, with
 *   `finalState` one of O3's words and `control` the appended control's verdict.
 *   A reading this channel could not take carries `brokenReason`, which is one
 *   of this lane's REASON words and never a state invented for it.
 */
export async function observeCellO3(args) {
  const {
    cc, opt, lab, id, fn, srcPath, bytes, helper = null,
    python = PYTHON, objdump = OBJDUMP, timeout = 120000,
  } = args;
  if (insideRepo(lab)) throw new Error('observeCellO3: the lab directory is inside the repository');
  if (!Number.isInteger(bytes) || bytes <= 0) {
    // Not a default and not a guess: a caller that reaches here without an
    // established count has skipped lib/bufferbytes.mjs, and the cell has to
    // leave by name rather than be graded against a number nobody established.
    throw new Error('observeCellO3: no established byte count was given; a cell without one leaves the denominator by name');
  }
  mkdirSync(lab, { recursive: true });
  const one = (at) => readAt({ cc, opt: at, lab, id, fn, srcPath, bytes, helper, python, objdump, timeout });

  // ---- the reader's control, BEFORE the cell's own level -------------------
  const ctl = await one(READER_CONTROL_OPT);
  if (ctl.brokenReason) {
    // The control could not be built, linked or read. Nothing about the cell's
    // own level is worth measuring, and the failure is reported as the
    // control's rather than as the subject's.
    return { ...ctl, brokenDetail: `${ctl.brokenDetail} (taken at ${READER_CONTROL_OPT}, as the reader's control)` };
  }
  if (ctl.control !== 'PRESENT') {
    return {
      ...broken(REASON.O3_CONTROL_LOST, ctl.control),
      readerControl: {
        opt: READER_CONTROL_OPT,
        subject: ctl.finalState,
        control: ctl.control,
        fill: ctl.fill,
        qualification: qualificationOf({ cellOpt: opt, controlFill: ctl.fill }),
      },
      diagnostics: ctl.diagnostics,
    };
  }
  if (ctl.finalState !== 'PRESENT') {
    return {
      ...broken(REASON.O3_READER_BLIND, `${READER_CONTROL_OPT} reads ${ctl.finalState}`),
      readerControl: {
        opt: READER_CONTROL_OPT,
        subject: ctl.finalState,
        control: ctl.control,
        // The numbers, so "blind" can be checked rather than taken: a volatile
        // byte loop shows one store and one byte against a buffer of `bytes`,
        // and a call to a symbol the reader does not know shows none of either.
        fill: ctl.fill,
        bytesAskedFor: ctl.bytesAskedFor,
        qualification: qualificationOf({ cellOpt: opt, controlFill: ctl.fill }),
      },
      helper,
      bytesAskedFor: bytes,
    };
  }

  // ---- the cell's own level ------------------------------------------------
  if (opt === READER_CONTROL_OPT) {
    // The control IS the reading here. Returning a second build of the same
    // thing would be two measurements of one question, and the second one would
    // be the one reported.
    //
    // AND SO THERE IS NO CONTROL ON THIS CELL. The reading reached this line
    // only because the `-O0` read was PRESENT -- the branch above returns
    // `o3-reader-blind-to-this-wipe` otherwise -- so a cell at this level can
    // never be graded ABSENT and the control can never fail on one. The
    // qualification says that rather than the reading carrying a `sameBuild`
    // flag whose consequence nobody wrote down.
    return {
      ...ctl,
      readerControl: {
        opt: READER_CONTROL_OPT,
        subject: ctl.finalState,
        control: ctl.control,
        fill: ctl.fill,
        sameBuild: true,
        qualification: qualificationOf({ cellOpt: opt, controlFill: ctl.fill, subjectFill: ctl.fill }),
      },
    };
  }
  const r = await one(opt);
  return {
    ...r,
    readerControl: {
      opt: READER_CONTROL_OPT,
      subject: ctl.finalState,
      control: ctl.control,
      fill: ctl.fill,
      sameBuild: false,
      // Which recognizer each of the two readings came through, and therefore
      // whether this control touched the branch the cell's own reading rests on.
      qualification: qualificationOf({ cellOpt: opt, controlFill: ctl.fill, subjectFill: r.fill }),
    },
  };
}
