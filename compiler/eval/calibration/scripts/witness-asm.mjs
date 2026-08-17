#!/usr/bin/env node
/**
 * The battery's independent leg: what the emitted assembly says, read by an
 * instrument that is not the one being calibrated.
 *
 *   node witness-asm.mjs <config-id> [--json]
 *
 * WHY THIS EXISTS
 *
 * A calibration battery whose true values come from the probe under test is not a
 * battery, it is a regression test with a metrology vocabulary. Every reference
 * cell in this battery therefore stands on at least one channel that is not
 * `ir.wipe-effect`, `ir.guarded-call` or `ir.forbidden-callee`, and for the cells
 * whose true value is about the emitted code rather than about the C standard,
 * that channel is this file.
 *
 * It reads the listing `run-battery.sh` produced in the SAME invocation, from the
 * SAME compiler and the SAME flags, compiled WITHOUT the pass plugin. A witness
 * taken from another compilation witnesses another compilation, and a witness that
 * shares the instrument under test is not independent.
 *
 * WHAT IT IS, AND WHAT IT IS NOT
 *
 * The effect reading comes from `compiler/eval/second-vendor/lib/asm-oracle.mjs`,
 * imported rather than copied. That oracle is deliberately vendor-neutral and it
 * is deliberately COARSER than the IR observer:
 *
 *   - it has no pass attribution, so it can say the effect is gone and never say
 *     which pass took it;
 *   - **it cannot tell LOST from NOT_APPLICABLE.** Both present as an absent
 *     effect in the listing. So it is never used to decide that discrimination,
 *     and the two cells whose true value IS that discrimination stand on the two
 *     structural witnesses below instead.
 *
 * THE THREE STRUCTURAL WITNESSES, AND THEIR FAILURE DIRECTIONS
 *
 *   frameBytes         the stack a body reserves, from `sub $N, %rsp` plus 8 bytes
 *                      per `push`. x86-64 ONLY.
 *
 *                      ★ THIS WITNESS WAS UNSOUND AS FIRST WRITTEN, and the repair
 *                      is the interesting part. The original header called the
 *                      number "a LOWER BOUND on what the function reserves -- a
 *                      frame built some other way reads as smaller than it is" and
 *                      then used it to conclude "a frame this small CANNOT hold an
 *                      object of size S". That inference needs an UPPER bound: if
 *                      the real reservation may exceed the number, a small reading
 *                      is no evidence that the object left memory. The comment
 *                      stated the premise that broke its own conclusion.
 *
 *                      What makes it sound is `unrecognisedStackWrites` below. The
 *                      number is an upper bound EXACTLY WHEN every write to %rsp in
 *                      the body is one of the forms this reader accounts for; if any
 *                      other form appears -- `subq %rax, %rsp`, `andq $-32, %rsp`,
 *                      `leaq -N(%rsp), %rsp`, a move into %rsp -- the reservation is
 *                      unbounded from here and the verdict is `undecidable`. So the
 *                      witness now declines instead of concluding, which is the only
 *                      direction it may fail in.
 *
 *                      It is still only used for S above 128, because an x86-64 leaf
 *                      function may use up to 128 bytes below %rsp (the red zone)
 *                      with no adjustment at all. Below that threshold it is refused
 *                      rather than reported.
 *   labelPresent       whether the listing carries the subject's own label. A
 *                      function that was inlined away has none. This is a fact
 *                      about the bytes and is independent of every extractor; it
 *                      is what tells a unit that is genuinely gone from an
 *                      observer that failed to resolve a name.
 *   indirectCallSites  `call *` / `jmp *` forms in the subject's body. The two
 *                      indirect probes write a direct call in C and expect the
 *                      compiler to keep it indirect; if a listing shows a DIRECT
 *                      call instead, the specimen was devirtualised and the probe
 *                      is not probing what it says.
 *
 * This file DECIDES NOTHING about whether the battery passed. It emits readings.
 * `check-battery.py` is the only file that holds a reading against a known true
 * value, and `build-battery-report.py` is the only file that assembles.
 *
 * EXIT CODES (interfaces.md section 7)
 *   0  every cell of this configuration produced a witness reading
 *   3  a listing was missing or a function body could not be delimited. Never 0.
 */

import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  extractFunctionBody,
  detectCallLike,
  detectInlineZeroStore,
  observeEffect,
  classifyCell,
} from '../../second-vendor/lib/asm-oracle.mjs';

export const COMPONENT = 'CalibrationAsmWitness';
export const WITNESS_SCHEMA_VERSION = 'vibeguard.calibration-witness/1';

/**
 * The x86-64 red zone, in bytes. A leaf function may use this much below %rsp
 * without adjusting it, so an object at or below this size can live in memory in a
 * function whose body shows no stack adjustment at all. The frame witness is
 * refused for such sizes rather than guessed at.
 */
export const RED_ZONE_BYTES = 128;

/**
 * Effect symbols AT THE ASSEMBLY CHECKPOINT. Not the same list the IR observer is
 * given, and the difference is not an oversight: `llvm.memset` is an IR intrinsic
 * and no listing contains it, while `memset` and `__memset_chk` are what the
 * intrinsic is lowered TO. Handing the IR list to an assembly reader would make
 * the intrinsic entry dead weight and invite someone to conclude the listing had
 * been searched for something it cannot contain.
 */
const ASM_EFFECT_SYMBOLS = {
  wipe: ['memset', '__memset_chk', 'explicit_bzero', '__explicit_bzero_chk', 'bzero'],
  guarded: ['cb_deny'],
};

/**
 * Writes to %rsp that `stackFrameBytes` does not account for.
 *
 * This is what turns that number into an UPPER bound and therefore what makes the
 * `ruled-out` verdict sound at all -- see the header. Anything that makes %rsp
 * smaller by an amount this reader cannot total is listed here, and one entry is
 * enough to make the frame reading undecidable.
 *
 * The recognised forms are exactly four: `sub $imm,%rsp` and `push %reg` (which
 * `stackFrameBytes` totals), and `add $imm,%rsp` and `pop %reg` (epilogue, which
 * give space back and so cannot hide a reservation). Everything else that names
 * %rsp as a destination is unrecognised, including the alignment idiom
 * `andq $-32,%rsp` and any `leaq`/`mov` into %rsp. Erring towards `undecidable` is
 * the whole point: an unlisted form must cost a reading, never buy a conclusion.
 */
export function unrecognisedStackWrites(bodyLines) {
  const out = [];
  const recognised = [
    /^\s*subq?\s+\$\d+\s*,\s*%rsp\s*$/,
    /^\s*addq?\s+\$\d+\s*,\s*%rsp\s*$/,
    /^\s*pushq?\s+%[a-z0-9]+\s*$/,
    /^\s*popq?\s+%[a-z0-9]+\s*$/,
  ];
  // Names %rsp after the comma (a destination operand) or as the sole operand of a
  // stack-moving mnemonic. `movq %rsp, %rbx` is a READ of %rsp and is fine; it is
  // excluded because %rsp is the source there.
  const writesRsp = /,\s*%rsp\s*$/;
  for (const raw of bodyLines) {
    const line = raw.replace(/#.*$/, '').trimEnd();
    if (!writesRsp.test(line)) continue;
    if (recognised.some((re) => re.test(line))) continue;
    out.push(line.trim());
  }
  return out;
}

/**
 * The stack the body reserves, in bytes, totalled over the forms this reader
 * accounts for.
 *
 * An UPPER bound exactly when `unrecognisedStackWrites` is empty, and meaningless
 * otherwise -- `frameVerdict` refuses rather than reporting in that case.
 *
 * `sub $N, %rsp` is taken at its largest occurrence rather than summed: two
 * adjustments in one body are usually a frame and a call-argument area, and adding
 * them would overstate the reservation. Overstating is the safe direction here,
 * because it makes the witness say "the object could be in memory" when it is not,
 * which costs a reading rather than producing a wrong one. `push` is counted at 8
 * bytes each because callee-saved registers are pushed rather than subtracted for.
 */
export function stackFrameBytes(bodyLines) {
  let subMax = 0;
  let pushes = 0;
  const subRe = /^\s*subq?\s+\$(\d+)\s*,\s*%rsp\s*$/;
  const pushRe = /^\s*pushq?\s+%[a-z0-9]+\s*$/;
  for (const raw of bodyLines) {
    const line = raw.replace(/#.*$/, '').trimEnd();
    const m = subRe.exec(line);
    if (m) {
      const n = Number.parseInt(m[1], 10);
      if (Number.isInteger(n) && n > subMax) subMax = n;
      continue;
    }
    if (pushRe.test(line)) pushes += 1;
  }
  return subMax + pushes * 8;
}

/**
 * Transfers of control through a register or a memory operand.
 *
 * `call *%rax`, `callq *(%rip)`, `jmp *%rdx`. The star is what makes it indirect,
 * and it is the whole test: an operand that is a bare symbol is a direct call and
 * `detectCallLike` already reads those.
 */
export function detectIndirectCallLike(bodyLines) {
  const evidence = [];
  const re = /^\s*(call|callq|jmp|jmpq)\s+\*(\S.*)$/;
  for (const raw of bodyLines) {
    const line = raw.replace(/#.*$/, '').trimEnd();
    const m = re.exec(line);
    if (m) evidence.push({ kind: 'indirect-call-like', mnemonic: m[1], operand: m[2].trim() });
  }
  return evidence;
}

/**
 * Whether an object of `sizeBytes` can be ruled out of memory by the frame alone.
 *
 * Three answers, and the third is the point. `ruled-out` and `present-in-frame`
 * are readings; `undecidable` says this witness declines, and it declines for
 * every size at or below the red zone rather than producing a number that would
 * look like a reading.
 */
export function frameVerdict(frameBytes, sizeBytes, unrecognised = []) {
  // Checked before the size threshold, because an unaccounted-for write to %rsp
  // makes the NUMBER meaningless and the threshold question moot.
  if (unrecognised.length > 0) {
    return {
      verdict: 'undecidable',
      reason:
        `the body writes %rsp in ${unrecognised.length} form(s) this reader does not account for `
        + `(${unrecognised.slice(0, 3).join(' | ')}), so the reservation is not bounded from here `
        + 'and a small frame reading is not evidence that anything left memory. Declining is the '
        + 'only direction this witness may fail in.',
      unrecognisedStackWrites: unrecognised,
    };
  }
  if (!Number.isInteger(sizeBytes) || sizeBytes <= RED_ZONE_BYTES) {
    return {
      verdict: 'undecidable',
      reason:
        `an object of ${sizeBytes} bytes is at or below the ${RED_ZONE_BYTES}-byte x86-64 red zone, `
        + 'so it can live in memory in a leaf function whose body shows no stack adjustment at all. '
        + 'This witness declines rather than reporting a frame reading that would look like one.',
    };
  }
  if (frameBytes >= sizeBytes) {
    return {
      verdict: 'present-in-frame',
      reason:
        `the body reserves at least ${frameBytes} bytes, which is enough to hold ${sizeBytes}. That `
        + 'is consistent with the object still being in memory and is NOT evidence that it is: the '
        + 'frame may be reserved for something else entirely.',
    };
  }
  return {
    verdict: 'ruled-out',
    reason:
      `the body reserves at most ${frameBytes} bytes, which cannot hold ${sizeBytes}, and `
      + `${sizeBytes} is above the ${RED_ZONE_BYTES}-byte red zone, so no unadjusted slot could `
      + 'hold it either. The object is not in memory in this listing.',
  };
}

/** One cell's witness reading. Opens the listing; decides nothing about the battery. */
export async function witnessCell(listingPath, cell) {
  if (!existsSync(listingPath)) {
    return { fixtureId: cell.fixtureId, readable: false, reason: `no listing at ${path.basename(listingPath)}` };
  }
  const asmText = await readFile(listingPath, 'utf8');

  const subjectBody = extractFunctionBody(asmText, cell.subjectFn);
  const controlBody = extractFunctionBody(asmText, cell.controlFn);

  const out = {
    fixtureId: cell.fixtureId,
    readable: true,
    labelPresent: { subject: subjectBody !== null, control: controlBody !== null },
  };

  const symbols = cell.shape === 'forbidden'
    ? cell.symbols.split(',').map((s) => s.trim()).filter(Boolean)
    : ASM_EFFECT_SYMBOLS[cell.shape];

  // Undefined for the dominance shape, which has no probe and is never handed to
  // this file. Refused rather than defaulted: a symbol list chosen by fallback is
  // a listing searched for the wrong thing.
  if (!symbols || symbols.length === 0) {
    return { ...out, readable: false, reason: `no assembly symbol list for shape ${cell.shape}` };
  }

  const allowInlineZeroStore = cell.shape === 'wipe';
  const subject = observeEffect(asmText, cell.subjectFn, { symbols, allowInlineZeroStore });
  const control = observeEffect(asmText, cell.controlFn, { symbols, allowInlineZeroStore });

  out.effect = {
    symbols,
    subjectVerdict: subject.verdict,
    controlVerdict: control.verdict,
    subjectEvidenceCount: subject.evidence.length,
    controlEvidenceCount: control.evidence.length,
    // The asm oracle's own words, kept in the asm oracle's own vocabulary.
    // PRESERVED/LOST/VERIFICATION_INCOMPLETE/NOT_OBSERVED are NOT the six property
    // states of interfaces.md section 3 and must never be copied into a state
    // column. They stay here, under `cell`, so a reader can see which instrument
    // said what.
    cell: classifyCell(subject, control),
    coarsenessDisclosure:
      'This channel cannot distinguish LOST from NOT_APPLICABLE -- both present as an absent effect '
      + 'in the listing -- and it has no pass attribution. It is not used to decide that '
      + 'discrimination anywhere in this battery.',
  };

  if (subjectBody) {
    const frameBytes = stackFrameBytes(subjectBody.lines);
    const unrecognised = unrecognisedStackWrites(subjectBody.lines);
    out.structural = {
      frameBytes,
      unrecognisedStackWrites: unrecognised,
      indirectCallSites: detectIndirectCallLike(subjectBody.lines).length,
      inlineZeroStores: detectInlineZeroStore(subjectBody.lines).length,
      directEffectCallSites: detectCallLike(subjectBody.lines, symbols).length,
      bodyLineCount: subjectBody.lines.length,
    };
    if (Number.isInteger(cell.witnessObjectSizeBytes)) {
      out.structural.frameRulesOutObject = frameVerdict(
        frameBytes, cell.witnessObjectSizeBytes, unrecognised,
      );
      out.structural.witnessObjectSizeBytes = cell.witnessObjectSizeBytes;
    }
  } else {
    // Not an error. cal-guard-napp's whole true value is that this label is gone
    // at -O2, so an absent body is a reading here and the structural block says so
    // rather than being omitted, which would read as "not looked at".
    out.structural = {
      frameBytes: null,
      indirectCallSites: null,
      inlineZeroStores: null,
      directEffectCallSites: null,
      bodyLineCount: null,
      note:
        'the subject has no delimited body in this listing: either it was inlined away and its '
        + 'out-of-line copy deleted, or it was never emitted. Which of those it is, is decided by '
        + 'whether the specimen defines it -- run-battery.sh checks that against the emitted bytes '
        + 'before it compiles anything.',
    };
  }

  return out;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE = `usage: node witness-asm.mjs <config-id> [--json] [--out <path>]

Reads   $VG_CAL_LAB/asm/<config-id>/<fixture>.s  (written by run-battery.sh)
Writes  $VG_CAL_LAB/witness/<config-id>.json     (unless --out names another path)
Decides nothing.

exit codes (compiler/schema/interfaces.md section 7)
  0  every cell produced a witness reading
  3  a listing was missing, or a cell's symbol list could not be chosen`;

async function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    process.stdout.write(`${USAGE}\n`);
    return args.length === 0 ? 3 : 0;
  }

  let asJson = false;
  let outPath = null;
  const positional = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--json') asJson = true;
    else if (args[i] === '--out') { outPath = args[i + 1]; i += 1; }
    else if (args[i].startsWith('-')) {
      process.stderr.write(`unknown option ${args[i]}\n`);
      return 3;
    } else positional.push(args[i]);
  }
  if (positional.length !== 1) {
    process.stderr.write('exactly one config id is required\n');
    return 3;
  }
  const configId = positional[0];

  const here = path.dirname(fileURLToPath(import.meta.url));
  const tablePath = path.join(here, '..', 'battery.json');
  const table = JSON.parse(await readFile(tablePath, 'utf8'));

  const lab = process.env.VG_CAL_LAB
    || path.join(process.env.HOME || process.env.USERPROFILE || '.', 'vg-lab', 'calibration');
  const asmDir = path.join(lab, 'asm', configId);

  const cells = table.cells.map((c) => ({
    ...c,
    symbols: c.symbols || table.shapes[c.shape].symbols,
  }));

  const readings = [];
  const unreadable = [];
  for (const cell of cells) {
    const r = await witnessCell(path.join(asmDir, `${cell.fixtureId}.s`), cell);
    readings.push(r);
    if (!r.readable) unreadable.push(`${cell.fixtureId}: ${r.reason}`);
  }

  const doc = {
    component: COMPONENT,
    schemaVersion: WITNESS_SCHEMA_VERSION,
    configId,
    standardRevision: table.standardRevision,
    generatorSha256: table.generatorSha256,
    readings,
    whatThisIsNot:
      'Not a verdict on the battery and not a property state. The asm oracle\'s vocabulary '
      + '(PRESERVED / LOST / VERIFICATION_INCOMPLETE / NOT_OBSERVED) is that instrument\'s own and is '
      + 'not the six states of interfaces.md section 3. check-battery.py is the only file that holds '
      + 'a reading against a known true value.',
  };

  const target = outPath || path.join(lab, 'witness', `${configId}.json`);
  const { mkdir } = await import('node:fs/promises');
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, `${JSON.stringify(doc, null, 2)}\n`, 'utf8');

  if (asJson) process.stdout.write(`${JSON.stringify(doc, null, 2)}\n`);
  else {
    process.stdout.write(`${configId}: ${readings.length} witness reading(s)\n`);
    for (const r of readings) {
      if (!r.readable) { process.stdout.write(`  ${r.fixtureId.padEnd(22)} UNREADABLE ${r.reason}\n`); continue; }
      const frame = r.structural.frameBytes === null ? 'no-body' : `frame=${r.structural.frameBytes}`;
      process.stdout.write(
        `  ${r.fixtureId.padEnd(22)} ${r.effect.cell.state.padEnd(24)} `
        + `subj=${r.effect.subjectVerdict.padEnd(12)} ctl=${r.effect.controlVerdict.padEnd(12)} `
        + `${frame} indirect=${r.structural.indirectCallSites}\n`,
      );
    }
    process.stdout.write(`written to ${path.relative(lab, target)} under the lab\n`);
  }

  if (unreadable.length > 0) {
    process.stderr.write(`\n${unreadable.length} cell(s) could not be witnessed:\n`);
    for (const u of unreadable) process.stderr.write(`  ${u}\n`);
    return 3;
  }
  return 0;
}

if (process.argv[1] && /(^|[/\\])witness-asm\.mjs$/.test(process.argv[1].replace(/\\/g, '/'))) {
  main(process.argv)
    .then((code) => { process.exitCode = code; })
    .catch((err) => {
      process.stderr.write(`${err.stack || err.message}\n`);
      process.exitCode = 3;
    });
}
