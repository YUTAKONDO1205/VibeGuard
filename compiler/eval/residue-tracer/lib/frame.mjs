/**
 * How deep the SUBJECT's own frame goes, read out of the binary that was run.
 *
 * WHY THIS FILE EXISTS. The lane's safety argument used to rest on one thing: a
 * co-resident control tracer held unwiped in the same frame, so that a cell whose
 * control could not be read was BROKEN_MEASUREMENT rather than a clean wipe. That
 * argument has a hole, and it was demonstrated rather than imagined. Declare the
 * buffers as `keep[32]; pad[8192]; secret[32];` and clang-18 -O0 puts `keep` near
 * the top of the frame and `secret` 8 KiB deeper. With the default window the
 * observer then reads control = 32/32 (HELD) and subject = 1 byte (NONE): a
 * silent false clean, landing in the (WIPE_SURVIVED, NONE) square that a reader
 * takes for "the wipe worked". Widening the same run to --below 16384 reads the
 * subject at 32/32, so the secret was there the whole time. The control being
 * inside the window never proved the subject was.
 *
 * So the window is now checked against an EXTERNAL, MEASURED bound: how far below
 * its entry rsp the subject function's own code can move rsp, taken from
 * `objdump -d` of the linked executable. A window that does not cover that is not
 * a reading -- lib/grade.mjs turns it into BROKEN_MEASUREMENT with the required
 * size in the reason -- and a frame that could not be parsed is not a reading
 * either. "We could not establish that we looked where the secret was" is the
 * same case as "we did not look", and this lane refuses to report either as "it
 * was not there".
 *
 * WHAT IS COUNTED, AND WHY THE COUNT IS AN UPPER BOUND. Every instruction in the
 * function body that can move rsp DOWN by a constant is summed, and every
 * instruction that moves it up (pop, leave, add of a positive immediate) is
 * ignored. Simulating the control flow would be the only way to get the exact
 * depth; summing the decrements and ignoring the increases needs no control flow
 * and can only over-state the depth, which costs a wider window and never a false
 * clean. Anything that moves rsp by an amount this file cannot bound --
 * `sub %rdx,%rsp` and `mov %rbx,%rsp` (both real: that is what a VLA compiles
 * to), `enter`, or a decrement sitting inside a backward branch (gcc
 * -fstack-clash-protection emits exactly that for a large frame -- measured on
 * this box: probes unrolled at an 8 KiB frame, a loop at 128 KiB) -- makes the
 * frame UNPARSED rather than a number that would be too small.
 *
 * THE FORMS ARE THE ONES ACTUALLY SEEN, not the ones assumed. Each was read off
 * `objdump -d` of a binary built from this lane's own fixtures on this box:
 *
 *   push+sub      clang-18 -O0:  push %rbp / mov %rsp,%rbp / sub $0x50,%rsp
 *                 gcc-13   -O2:  endbr64 / push %r12 / mov $0x20,%edx / push %rbp
 *                                / push %rbx / ... / sub $0x50,%rsp   <- the
 *                                pushes are INTERLEAVED with ordinary work, so a
 *                                parser that stopped at the first non-prologue
 *                                instruction would miss two of them.
 *   push+sub+and  clang-18 -O2 with an over-aligned local:
 *                                and $0xffffffffffffffc0,%rsp
 *   push+add+and  gcc-13 -O2 with the same: and $0xffffffffffffffc0,%rsp followed
 *                                by add $0xffffffffffffff80,%rsp -- an ADD of a
 *                                negative immediate, which is a subtraction.
 *   (unparsed)    gcc-13 -O2 with a 128 KiB frame: sub $0x1000,%rsp inside a
 *                                probe loop (at 8 KiB the same compiler unrolls
 *                                the probes and the frame parses); clang-18 with
 *                                a VLA: mov %rbx,%rsp.
 *
 * Nothing here runs objdump, reads a file or knows what a cell is: the caller
 * hands in text. That is what makes the forms above testable without a compiler.
 */

/**
 * The margin the window must carry beyond the frame itself.
 *
 *   8    the return-address word. The window is anchored at the rsp the process
 *        has AFTER the `ret`, which is eight bytes above the entry rsp the frame
 *        depth is measured from.
 *   128  the red zone. The System V AMD64 ABI lets a leaf function use the 128
 *        bytes below rsp without allocating them, so residue can sit that far
 *        below the deepest rsp the subject itself ever held.
 */
export const FRAME_MARGIN_BYTES = 136;

/**
 * The largest window the observer will accept, mirrored from WINDOW_MAX in
 * observer/residue-observer.c. A required window larger than this cannot be asked
 * for, so such a cell is BROKEN_MEASUREMENT rather than silently shallow --
 * test/observer-record.test.mjs holds the two constants equal.
 */
export const WINDOW_MAX_BYTES = 1 << 20;

/** Mnemonics that name %rsp as their last operand without writing it. */
const READ_ONLY = new Set(['cmp', 'cmpq', 'cmpl', 'cmpw', 'cmpb', 'test', 'testq', 'testl']);

const unparsed = (why) => ({
  parsed: false, subjectBytes: null, pushBytes: null, subBytes: null, alignSlackBytes: null,
  form: null, insnCount: 0, why,
});

/**
 * The lines of one function's body in `objdump -d` output.
 *
 * @param {string} text   whole objdump output, or any slice containing the block
 * @param {string} symbol
 * @returns {string[]|null} null when the symbol has no block
 */
export function functionBlock(text, symbol) {
  if (typeof text !== 'string' || typeof symbol !== 'string' || !symbol) return null;
  const lines = text.split(/\r?\n/);
  const head = new RegExp(`^[0-9a-f]+\\s+<${symbol.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}>:$`);
  const start = lines.findIndex((l) => head.test(l.trim()));
  if (start < 0) return null;
  const body = [];
  for (let i = start + 1; i < lines.length; i++) {
    const t = lines[i].trim();
    if (!t) break;                               // objdump separates bodies with a blank line
    if (/^[0-9a-f]+\s+<[^>]+>:$/.test(t)) break; // ... and a missing blank line is not trusted
    body.push(lines[i]);
  }
  return body;
}

/** One disassembly line, or null. Tolerates the raw-bytes column being present. */
function insnOf(line) {
  const m = /^\s*([0-9a-f]+):\s*(.*)$/.exec(line);
  if (!m) return null;
  const fields = m[2].split('\t');
  let body = fields[fields.length - 1].trim();
  const hash = body.indexOf('#');
  if (hash >= 0) body = body.slice(0, hash).trim();
  if (!body) return null;
  const sp = body.search(/\s/);
  const mnemonic = sp < 0 ? body : body.slice(0, sp);
  const ops = sp < 0 ? '' : body.slice(sp).trim();
  return { addr: Number.parseInt(m[1], 16), mnemonic, ops };
}

/** `$0x50`, `$0xffffffffffffff80`, `$-0x10` -> a signed BigInt, or null. */
function imm(tok) {
  const m = /^\$(-?)(0x[0-9a-fA-F]+|\d+)$/.exec(tok);
  if (!m) return null;
  let v = BigInt(m[2]);
  if (m[1] === '-') v = -v;
  if (v >= 1n << 63n) v -= 1n << 64n;  // objdump prints a sign-extended immediate as unsigned hex
  return v;
}

/** The alignment an `and $mask,%rsp` enforces, or null when the mask is not -2^k. */
function alignOfMask(v) {
  if (v === null || v >= 0n) return null;
  const a = -v;
  if ((a & (a - 1n)) !== 0n) return null;
  return Number(a);
}

/** The target of a jump, or null when the instruction is not one. */
function jumpTarget(mnemonic, ops) {
  if (!/^(jmp|jmpq|j[a-z]{1,3})$/.test(mnemonic)) return null;
  const m = /^([0-9a-f]+)\b/.exec(ops);
  return m ? Number.parseInt(m[1], 16) : null;
}

/**
 * How far below its entry rsp the subject function can take rsp, from the
 * disassembly of the binary that was run.
 *
 * @param {string} disasm  `objdump -d --no-show-raw-insn <exe>` output
 * @param {string} symbol  the subject function
 * @returns {{parsed: boolean, subjectBytes: number|null, pushBytes: number|null,
 *            subBytes: number|null, alignSlackBytes: number|null, form: string|null,
 *            insnCount: number, why: string|null}}
 */
export function parseFrame(disasm, symbol) {
  const block = functionBlock(disasm, symbol);
  if (!block) return unparsed('symbol-not-in-the-disassembly');

  let pushBytes = 0, subBytes = 0, alignSlack = 0, insnCount = 0;
  const forms = new Set();
  // Only CUMULATIVE decrements are collected for the loop check below. A `push`
  // or a `sub $imm,%rsp` executed twice takes rsp twice as deep, so counting the
  // instruction once does not bound it. An `and $-N,%rsp` and an rbp-relative
  // restore are idempotent -- they set rsp rather than lower it -- so repeating
  // them changes nothing and they are exempt. Treating them as cumulative made
  // gcc-13's ordinary epilogue (`lea -0x18(%rbp),%rsp`, reached by a backward
  // `jmp` from the error path) look like an allocation in a loop.
  const cumulativeAt = [];
  const backJumps = [];

  for (const line of block) {
    const ins = insnOf(line);
    if (!ins) continue;
    insnCount++;
    const { addr, mnemonic, ops } = ins;

    const jt = jumpTarget(mnemonic, ops);
    if (jt !== null && jt <= addr) backJumps.push({ from: addr, to: jt });

    if (/^push(q|l|w)?$/.test(mnemonic)) {
      pushBytes += 8; forms.add('push'); cumulativeAt.push(addr); continue;
    }
    if (/^pop(q|l|w)?$/.test(mnemonic) || mnemonic === 'leave') continue;  // rsp rises; ignored
    if (mnemonic === 'enter') return unparsed('enter-allocates-a-frame-this-parser-does-not-model');

    if (!/,\s*%rsp$/.test(ops)) continue;        // does not write rsp
    if (READ_ONLY.has(mnemonic)) continue;       // names rsp, writes something else

    const src = ops.slice(0, ops.lastIndexOf(',')).trim();
    if (/^(sub|subq|subl)$/.test(mnemonic)) {
      const v = imm(src);
      if (v === null) return unparsed(`unbounded-rsp-write: ${mnemonic} ${src},%rsp`);
      if (v > 0n) { subBytes += Number(v); forms.add('sub'); cumulativeAt.push(addr); }
      continue;
    }
    if (/^(add|addq|addl)$/.test(mnemonic)) {
      const v = imm(src);
      if (v === null) return unparsed(`unbounded-rsp-write: ${mnemonic} ${src},%rsp`);
      if (v < 0n) { subBytes += Number(-v); forms.add('add'); cumulativeAt.push(addr); }
      continue;
    }
    if (/^(and|andq|andl)$/.test(mnemonic)) {
      const a = alignOfMask(imm(src));
      if (a === null) return unparsed(`unbounded-rsp-write: ${mnemonic} ${src},%rsp`);
      // Realignment moves rsp down by anything from 0 to align-1 bytes, and which
      // it is depends on the caller. The worst case is the only safe count.
      alignSlack += a - 1; forms.add('and');
      continue;
    }
    if (mnemonic === 'mov' && src === '%rbp') continue;                 // frame-pointer restore
    if (mnemonic === 'lea' && /^-?(0x[0-9a-fA-F]+|\d+)\(%rbp\)$/.test(src)) {
      // Also a frame-pointer restore in every build seen here, but it is counted
      // rather than waved through: over-counting only costs a wider window.
      const m = /^(-?)(0x[0-9a-fA-F]+|\d+)\(/.exec(src);
      if (m && m[1] === '-') { subBytes += Number(BigInt(m[2])); forms.add('lea-rbp'); }
      continue;
    }
    return unparsed(`unbounded-rsp-write: ${mnemonic} ${src},%rsp`);
  }

  for (const j of backJumps) {
    if (cumulativeAt.some((a) => a >= j.to && a <= j.from)) {
      return unparsed('stack-decrement-inside-a-loop');
    }
  }

  const order = ['push', 'sub', 'add', 'and', 'lea-rbp'];
  return {
    parsed: true,
    subjectBytes: pushBytes + subBytes + alignSlack,
    pushBytes,
    subBytes,
    alignSlackBytes: alignSlack,
    form: order.filter((f) => forms.has(f)).join('+') || 'no-frame',
    insnCount,
    why: null,
  };
}

/**
 * The smallest `--below` that covers the subject frame, or null when there is no
 * parsed frame to require anything of.
 */
export function requiredBelow(frame, margin = FRAME_MARGIN_BYTES) {
  if (!frame || frame.parsed !== true || !Number.isInteger(frame.subjectBytes)) return null;
  const m = Number.isInteger(margin) ? margin : FRAME_MARGIN_BYTES;
  return frame.subjectBytes + m;
}
