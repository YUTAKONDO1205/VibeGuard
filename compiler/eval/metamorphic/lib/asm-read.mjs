#!/usr/bin/env node
/**
 * One assembly reading of one (specimen, subject, control) pair, for the
 * cross-vendor channel.
 *
 *   node asm-read.mjs --asm <file.s> --subject <fn> --control <fn>
 *                     --symbols a,b,c [--inline-zero] --out <reading.json>
 *
 * WHY THIS FILE EXISTS AND WHY IT IS THIS SMALL
 *
 * The oracle is `compiler/eval/second-vendor/lib/asm-oracle.mjs`, IMPORTED and
 * not copied. That file is deliberately vendor-neutral with no per-vendor branch
 * anywhere in it, because a per-vendor branch is how a comparison quietly stops
 * being a comparison, and a second copy of it here would be a second place for
 * such a branch to appear. Everything this file adds is I/O and a record shape.
 *
 * Two details of that oracle are load-bearing and are restated because getting
 * either wrong produced wrong answers before it was written:
 *
 *   - TAIL CALLS COUNT. gcc at -O2 emits `jmp report_denied@PLT` for a
 *     tail-called reporter, and a call-only detector reported that defence as
 *     removed when it is plainly present.
 *   - INLINED ZEROING COUNTS. At -O1 and above neither vendor necessarily keeps a
 *     memset call; clang emits xorps/movaps and gcc emits pxor/movaps. The
 *     destination must be a memory operand, because `movl $0, %esi` is argument
 *     setup and not a wipe.
 *
 * THIS INSTRUMENT IS COARSER THAN THE IR OBSERVER, AND THE DIFFERENCE MATTERS
 *
 * It reads ONE listing rather than a checkpoint pair, so:
 *
 *   - it has NO pass attribution, on either vendor. There is no firstLossPass in
 *     this channel and no field from which one could be inferred.
 *   - it CANNOT distinguish LOST from NOT_APPLICABLE. It has no alloca census and
 *     no pre-optimisation reading, so a promoted buffer, a deleted wipe and a
 *     wipe that was never written all present as the single word `LOST` from
 *     classifyCell. interfaces.md section 3 keeps those three apart; this
 *     instrument cannot, and every document that carries its output says so.
 *   - pass attribution under gcc is UNSUPPORTED BY CONSTRUCTION, not merely
 *     not-observed: gcc cannot load an LLVM -fpass-plugin at all.
 *
 * And the control comes first, always. `classifyCell` checks the control before
 * it looks at the subject because calling a blind cell LOST is the single most
 * attractive way to manufacture a result here.
 *
 * WHAT IS AND IS NOT IN THE OUTPUT
 *
 * The reading carries the assembly's sha-256 and the BASENAME of the listing,
 * never its path: interfaces.md section 5 forbids an absolute path anywhere in a
 * digested document, and this reading is digested into the report. Every number
 * is an integer (section 5 rule 4); `bodyLineCount` is null when the body could
 * not be delimited, which is an absence rather than a zero.
 *
 * Exit codes (interfaces.md section 7): 0 a reading was written. 1 the arguments
 * were wrong. 3 the listing could not be read at all, which is never reported as
 * a clean reading.
 */

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { basename, dirname } from 'node:path';

import { observeEffect, classifyCell } from '../../second-vendor/lib/asm-oracle.mjs';

export const COMPONENT = 'MetamorphicAsmRead';
export const SCHEMA = 'vibeguard.metamorphic-asm-reading/1';

/**
 * Restated in the reading itself rather than left to whoever assembles it. The
 * one thing most easily misread about a coarse instrument is what its words
 * cannot tell apart, and a reading that travels without that sentence is a
 * reading somebody will over-quote.
 */
export const INSTRUMENT_LIMITS = Object.freeze([
  'no pass attribution on either vendor; this channel has no firstLossPass and emits no field from which one could be inferred',
  'cannot distinguish LOST from NOT_APPLICABLE: one listing, no checkpoint pair, no alloca census, so interfaces.md section 3\'s ABSENT, LOST and NOT_APPLICABLE all present here as the single word LOST',
  'pass attribution under gcc is UNSUPPORTED by construction, because gcc cannot load an LLVM -fpass-plugin',
  'the clang-defined reference configuration is not automatically a witness configuration under gcc, so a cell whose own control did not show its effect is VERIFICATION_INCOMPLETE and carries no information about the subject',
]);

function usage() {
  process.stderr.write(
    'usage: asm-read.mjs --asm <file.s> --subject <fn> --control <fn> '
    + '--symbols a,b,c [--inline-zero] --out <reading.json>\n',
  );
  return 1;
}

function parse(argv) {
  const out = { inlineZero: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--inline-zero') { out.inlineZero = true; continue; }
    if (!a.startsWith('--')) return null;
    const v = argv[i + 1];
    if (v === undefined) return null;
    i += 1;
    if (a === '--asm') out.asm = v;
    else if (a === '--subject') out.subject = v;
    else if (a === '--control') out.control = v;
    else if (a === '--symbols') out.symbols = v.split(',').filter((s) => s.length > 0);
    else if (a === '--out') out.out = v;
    else return null;
  }
  if (!out.asm || !out.subject || !out.control || !out.out) return null;
  if (!out.symbols || out.symbols.length === 0) return null;
  return out;
}

function reading(observation) {
  return {
    // `evidenceCount` and not the evidence itself: the evidence lines are
    // assembly text from a host toolchain, and a whole line of it in a digested
    // document is a byte sequence nobody has checked for a path. The count and
    // the kinds are what a reader needs to see that the oracle matched
    // something rather than nothing.
    evidenceCount: observation.evidence.length,
    evidenceKinds: [...new Set(observation.evidence.map((e) => e.kind))].sort(),
    mnemonics: [...new Set(observation.evidence.map((e) => e.mnemonic).filter(Boolean))].sort(),
    bodyLineCount: observation.bodyLineCount === null ? null : observation.bodyLineCount,
    reason: observation.reason,
    verdict: observation.verdict,
  };
}

function main(argv) {
  const args = parse(argv.slice(2));
  if (args === null) return usage();

  let asmText;
  try {
    asmText = readFileSync(args.asm, 'utf8');
  } catch (err) {
    // Never a clean reading. interfaces.md section 7: a check that could not be
    // completed is 3 and is never conflated with 0.
    process.stderr.write(`asm-read.mjs: could not read the listing: ${err.message}\n`);
    return 3;
  }

  const effect = { symbols: args.symbols, allowInlineZeroStore: args.inlineZero };
  const subject = observeEffect(asmText, args.subject, effect);
  const control = observeEffect(asmText, args.control, effect);
  const cell = classifyCell(subject, control);

  const doc = {
    schemaVersion: SCHEMA,
    component: COMPONENT,
    checkpoint: 'asm',
    instrument: {
      module: 'compiler/eval/second-vendor/lib/asm-oracle.mjs',
      limits: INSTRUMENT_LIMITS,
      passAttribution: 'UNSUPPORTED',
      vendorNeutral: true,
    },
    oracle: {
      allowInlineZeroStore: args.inlineZero,
      // Array order is significant and is the order it was asked for
      // (interfaces.md section 5 rule 2), so two readings of one symbol list
      // digest identically and a reordered list is visibly a different question.
      symbols: args.symbols,
      tailCallsCount: true,
    },
    listing: {
      // Basename and digest only. Section 5: no absolute path in a digested
      // document, and this reading is digested into the report.
      name: basename(args.asm),
      sha256: createHash('sha256').update(asmText, 'utf8').digest('hex'),
    },
    subject: { fn: args.subject, ...reading(subject) },
    control: { fn: args.control, ...reading(control) },
    cell: { rationale: cell.rationale, state: cell.state },
  };

  mkdirSync(dirname(args.out), { recursive: true });
  writeFileSync(args.out, `${JSON.stringify(doc, null, 1)}\n`, 'utf8');
  process.stdout.write(`${args.subject}: ${cell.state}\n`);
  return 0;
}

// Matched on the entry path rather than by comparing import.meta.url to a file
// URL, for the reason frontier-match.mjs gives: the URL forms disagree across
// platforms on drive-letter case, and a mismatch there leaves the CLI silently
// inert instead of loudly broken.
if (process.argv[1] && /(^|[/\\])asm-read\.mjs$/.test(process.argv[1].replace(/\\/g, '/'))) {
  process.exitCode = main(process.argv);
}
