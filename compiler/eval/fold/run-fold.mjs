#!/usr/bin/env node
// eval/fold — do three functions that mean different things become one?
//
// WHAT IT MEASURES
//
// `subjects.c` holds three functions a reader would not confuse and one that
// must stay distinct. This runner compiles that file at a given optimisation
// level, disassembles the object, collects each function's bytes, and asks
// whether the three subjects are byte-identical.
//
// WHY THE BYTES AND NOT THE DISASSEMBLY TEXT
//
// Comparing mnemonics would let a register-allocation difference read as
// agreement, and comparing whole-file output would let the symbol names decide
// it. The comparison here is over the encoded bytes of each function body,
// keyed by symbol, which is the only form in which "the same code" is a fact
// about the artefact rather than about how it was printed.
//
// THE NEGATIVE CONTROL DECIDES WHETHER THE RUN COUNTS
//
// `reads_second_field` differs from the three only in which field it reads. If
// it comes back identical to them, the extraction matched something other than
// code and the run exits non-zero without writing anything. The same for a
// subject whose byte string is empty, or a symbol missing from the
// disassembly: the failure this lane exists to rule out is a comparison of two
// empty strings reporting agreement.
//
//   node run-fold.mjs                  -O0 and -O2, both compilers
//   node run-fold.mjs --write-data     also refresh data/
//   node run-fold.mjs --cc clang-18    one compiler
//
// Exit 0 when every configuration was measured, 3 when a control failed, 4 when
// a compiler or objdump is absent. No configuration is skipped silently.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const LANE = dirname(fileURLToPath(import.meta.url));
const SUBJECTS = join(LANE, 'subjects.c');
const DATA = join(LANE, 'data');

export const SUBJECT_SYMBOLS = ['is_authorized', 'feature_enabled', 'meaningless_probe'];
export const CONTROL_SYMBOL = 'reads_second_field';

// -O0 IS THE RESULT, not a warm-up. It was added expecting the three to stay
// distinct there, which would have made the fold a thing optimisation does.
// They are identical at -O0 too, on both compilers. The three are the same
// computation as written, and -O2 only shortens the code they share — so a
// sentence of the form "compiled at -O2 they came out identical" is true but
// invites the wrong cause. Keep this level in every run; it is the only thing
// in the lane that can say what -O2 did and did not do.
const LEVELS = ['-O0', '-O2'];

// No -fcf-protection flag either way: the distribution's default is what an
// ordinary build gets, and it decides the byte count. Ubuntu's compilers enable
// it, which prepends `endbr64` — four bytes — to every function here. A run that
// turned it off would report a different length for the same finding, and the
// length is the part people quote.
const FLAGS = ['-std=gnu11', '-c'];

// Trailing alignment padding sits inside the address range objdump prints for a
// function, and it is not the function. Counting it makes the length an artefact
// of the next symbol's alignment: measured, it added 7 bytes under clang and 6
// under gcc at -O2, which is half again the code itself. Both counts are kept —
// `byteCount` excludes the padding, `byteCountWithPadding` is what a naive read
// of objdump would give — because the gap between them is exactly the mistake
// this field exists to stop somebody making later.
const PADDING_MNEMONIC = /^(nop|nopl|nopw|xchg\s+%ax,%ax|data16|cs\s+nop)/;

function die(code, message) {
  process.stderr.write(`run-fold: ${message}\n`);
  process.exit(code);
}

function run(cmd, args, cwd) {
  return execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function versionOf(cc) {
  try {
    return run(cc, ['--version']).split('\n')[0].trim();
  } catch (error) {
    die(
      4,
      `${cc} is not runnable here (${error?.message ?? error}). This lane needs the compiler\n` +
        '  itself; there is nothing to fall back to.',
    );
  }
  return '';
}

/**
 * symbol -> lowercase hex byte string, parsed out of `objdump -d`.
 *
 * objdump prints one function per `<name>:` header and then lines whose second
 * tab-separated column is the raw encoding. Both compilers are read by the same
 * reader on purpose: a per-vendor parser is a place for a per-vendor mistake to
 * hide.
 */
export function bytesBySymbol(text) {
  const collected = new Map();
  let current = null;
  for (const line of text.split('\n')) {
    const header = /^[0-9a-f]+\s+<([^>]+)>:\s*$/.exec(line);
    if (header) {
      current = header[1];
      collected.set(current, []);
      continue;
    }
    if (!current) continue;
    const cols = line.split('\t');
    if (cols.length < 2) continue;
    const hex = cols[1].trim();
    if (!/^([0-9a-f]{2}\s*)+$/.test(hex)) continue;
    collected.get(current).push({
      bytes: hex.split(/\s+/).filter(Boolean),
      mnemonic: (cols[2] ?? '').trim(),
    });
  }

  const out = new Map();
  for (const [name, insns] of collected) {
    // Trim trailing padding, not padding anywhere: a nop in the middle of a
    // function is code the compiler chose to emit and is part of what is being
    // compared.
    let end = insns.length;
    while (end > 0 && PADDING_MNEMONIC.test(insns[end - 1].mnemonic)) end -= 1;
    const flat = (list) => list.flatMap((i) => i.bytes).join(' ');
    out.set(name, { bytes: flat(insns.slice(0, end)), withPadding: flat(insns) });
  }
  return out;
}

function main() {
  const argv = process.argv.slice(2);
  const writeData = argv.includes('--write-data');
  const ccArgIndex = argv.indexOf('--cc');
  const compilers = ccArgIndex >= 0 ? [argv[ccArgIndex + 1]] : ['clang-18', 'gcc-13'];

  const rows = [];
  const lines = [];

  for (const cc of compilers) {
    const version = versionOf(cc);
    for (const opt of LEVELS) {
      const work = mkdtempSync(join(tmpdir(), 'vg-fold-'));
      try {
        const obj = join(work, 'subjects.o');
        run(cc, [...FLAGS, opt, SUBJECTS, '-o', obj], work);
        const bytes = bytesBySymbol(run('objdump', ['-d', obj], work));

        const missing = [...SUBJECT_SYMBOLS, CONTROL_SYMBOL].filter((s) => !bytes.get(s)?.bytes);
        if (missing.length) {
          die(
            3,
            `${cc} ${opt}: no bytes for ${missing.join(', ')}. Either the symbols were renamed\n` +
              "  in subjects.c or the disassembly reader stopped matching this objdump's output.\n" +
              '  Reporting agreement over a missing symbol is the one result this lane must never\n' +
              '  produce.',
          );
        }

        const subjectBytes = SUBJECT_SYMBOLS.map((s) => bytes.get(s).bytes);
        const identical = subjectBytes.every((b) => b === subjectBytes[0]);
        const control = bytes.get(CONTROL_SYMBOL).bytes;

        if (identical && control === subjectBytes[0]) {
          die(
            3,
            `${cc} ${opt}: the negative control carries the same bytes as the three subjects.\n` +
              `  ${CONTROL_SYMBOL} reads a different field and cannot legitimately fold with them,\n` +
              '  so this comparison is matching something other than the code.',
          );
        }

        const countOf = (s) => s.split(' ').filter(Boolean).length;
        const perSubject = SUBJECT_SYMBOLS.map((s, i) => [s, countOf(subjectBytes[i])]);

        rows.push({
          cc,
          ccVersion: version,
          opt,
          arch: process.arch === 'x64' ? 'x86-64' : process.arch,
          subjects: SUBJECT_SYMBOLS,
          identical,
          byteCount: identical ? countOf(subjectBytes[0]) : null,
          byteCountWithPadding: identical
            ? countOf(bytes.get(SUBJECT_SYMBOLS[0]).withPadding)
            : null,
          bytes: identical ? subjectBytes[0] : null,
          perSubjectByteCount: perSubject,
          controlSymbol: CONTROL_SYMBOL,
          controlDiffers: control !== subjectBytes[0],
          controlByteCount: countOf(control),
        });

        lines.push(
          `${cc.padEnd(9)} ${opt.padEnd(4)} ` +
            (identical
              ? `IDENTICAL  ${countOf(subjectBytes[0])} bytes  ${subjectBytes[0]}`
              : `DISTINCT   ${perSubject.map(([s, n]) => `${s}=${n}`).join(' ')}`) +
            `  control ${control !== subjectBytes[0] ? 'differs' : 'SAME'}`,
        );
      } finally {
        rmSync(work, { recursive: true, force: true });
      }
    }
  }

  const text =
    'eval/fold - three functions that mean different things, and whether they become one\n' +
    '\n' +
    `subjects: ${SUBJECT_SYMBOLS.join(', ')}\n` +
    `negative control: ${CONTROL_SYMBOL} (reads the second field; must differ)\n` +
    `flags: ${FLAGS.join(' ')} <level>\n` +
    '\n' +
    `${lines.join('\n')}\n`;

  process.stdout.write(text);

  if (writeData) {
    mkdirSync(DATA, { recursive: true });
    writeFileSync(join(DATA, 'fold-rows.json'), `${JSON.stringify(rows, null, 2)}\n`, 'utf8');
    writeFileSync(join(DATA, 'fold-results.txt'), text, 'utf8');
    process.stdout.write('\nwrote data/fold-rows.json and data/fold-results.txt\n');
  }
}

if (process.argv[1] && process.argv[1].endsWith('run-fold.mjs')) main();
