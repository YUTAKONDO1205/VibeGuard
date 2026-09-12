#!/usr/bin/env node
/**
 * Which memset spelling does each rung emit, and can this lane's detector see
 * the fortified one at all?
 *
 *   node compiler/eval/version-ladder/tools/fortify-spelling-probe.mjs [--ccs a,b] [--opts -O1,-O2]
 *
 * The README reports that across all 495 cells the observed spellings were
 * `memset` and `none`, and that `__memset_chk` never appeared. A negative
 * observation is only worth reading if the instrument could have seen the thing,
 * so the README also says the fortified spelling IS emitted for a wipe whose
 * length is not compile-time known. That second claim was first recorded with a
 * command that cannot have produced the output beside it -- `cc -S file.c |
 * grep` writes the listing to a FILE and pipes an empty stream -- so the record
 * was unreproducible even though the fact held. This tool is the record instead:
 * it runs, it prints what it saw, and anyone can re-run it.
 *
 * Two probes, one difference:
 *
 *   const    the shape every subject of this lane has: a fixed-size buffer
 *            wiped for `sizeof buf` bytes. Both sizes are known, so glibc's
 *            fortifying wrapper folds away and the call is plain `memset`.
 *   runtime  the same wipe with a length the compiler cannot fold (an extern),
 *            against the same 32-byte object. This is where `_FORTIFY_SOURCE`
 *            has something to check, and the call becomes `__memset_chk`.
 *
 * Both carry an `asm volatile ("" ::: "memory")` after the wipe so that the
 * question stays "which spelling" and never becomes "was it removed".
 *
 * Nothing here is a verdict and nothing here feeds one: the spellings come from
 * CONTROL_EFFECT.symbols through the runner's own `spellingIn`, which is
 * metadata (interfaces.md section 4 forbids deciding an effect by searching a
 * listing for a symbol name). The compiler flags are the lane's FLAGS, imported,
 * so this probe cannot drift from the measurement it explains.
 */
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { FLAGS, CONTROL_EFFECT, compile } from '../../ai-generated/lib/ablation-cell.mjs';
import { spellingIn, allRungs } from '../run-version-ladder.mjs';
import { ALL_OPTS } from '../lib/ladder.mjs';

const run = promisify(execFile);

const PROBES = {
  const: `#include <string.h>
void vgp_use(const unsigned char *p, unsigned long n);
void vgp_const(void) {
  unsigned char secret[32];
  vgp_use(secret, sizeof secret);
  memset(secret, 0, sizeof secret);
  __asm__ __volatile__("" ::: "memory");
}
`,
  runtime: `#include <string.h>
extern unsigned long vgp_len;
void vgp_use(const unsigned char *p, unsigned long n);
void vgp_runtime(void) {
  unsigned char secret[32];
  vgp_use(secret, vgp_len);
  memset(secret, 0, vgp_len);
  __asm__ __volatile__("" ::: "memory");
}
`,
};

function parse(argv) {
  const o = { ccs: null, opts: ['-O0', '-O1', '-O2'] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--ccs') o.ccs = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    else if (argv[i] === '--opts') o.opts = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    else { process.stderr.write(`unknown argument ${argv[i]}\n`); process.exit(4); }
  }
  const bad = o.opts.find((x) => !ALL_OPTS.includes(x));
  if (bad) { process.stderr.write(`--opts: ${bad} is not one of ${ALL_OPTS.join(', ')}\n`); process.exit(4); }
  return o;
}

const args = parse(process.argv.slice(2));
const dir = mkdtempSync(join(tmpdir(), 'vg-fortify-probe-'));
try {
  const src = {};
  for (const [name, text] of Object.entries(PROBES)) {
    src[name] = join(dir, `${name}.c`);
    writeFileSync(src[name], text, 'utf8');
  }
  process.stdout.write(`declared effect symbols: ${CONTROL_EFFECT.symbols.join(', ')}\n`);
  process.stdout.write(`flags: ${FLAGS.join(' ')}\n\n`);
  process.stdout.write(`  ${'rung'.padEnd(9)} ${'level'.padEnd(5)} ${'const size'.padEnd(14)} runtime length\n`);
  for (const cc of args.ccs ?? allRungs()) {
    try { await run(cc, ['--version'], { timeout: 30000 }); } catch { process.stdout.write(`  ${cc.padEnd(9)} -(not obtained)\n`); continue; }
    for (const opt of args.opts) {
      const seen = {};
      for (const name of Object.keys(PROBES)) {
        const asm = await compile(cc, [opt], src[name], join(dir, `${name}.${cc}${opt}.s`));
        seen[name] = asm === null ? 'DID-NOT-COMPILE' : spellingIn(asm);
      }
      process.stdout.write(`  ${cc.padEnd(9)} ${opt.padEnd(5)} ${seen.const.padEnd(14)} ${seen.runtime}\n`);
    }
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
