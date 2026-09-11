#!/usr/bin/env node
/**
 * Reads the -S listings of a WipePinGcc fixture-loop lab with the repository's
 * assembly oracle, and prints what it saw as JSON. check-gcc-fixture-loop.py
 * runs this; it decides nothing itself about whether a cell is right.
 *
 *   node asm-presence.mjs --lab DIR --subject handle_request --control wipe_kept
 *
 * The oracle is compiler/eval/second-vendor/lib/asm-oracle.mjs, imported and
 * not copied -- the same file the find step's verdict code is built on -- and
 * the effect is ablation-cell.mjs's CONTROL_EFFECT (memset and __memset_chk
 * calls, and inline zero stores), imported from there for the same reason.
 *
 * One fallback, labelled and counted separately, as ablation-cell.mjs's
 * controlPresent labels its own: observeEffect does not know `rep stos`, which
 * is the form gcc-13 chooses for a 32-byte zero fill at -Os. Without it the
 * fixture's control reads ABSENT at -Os with and without the plugin, and the
 * pinned wipe reads ABSENT although it is in the listing. A reading that came
 * from the fallback says `via: "rep-stos-fallback"`; nothing is folded in
 * silently.
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const ORACLE_PATH = resolve(HERE, '..', '..', '..', 'eval', 'second-vendor', 'lib', 'asm-oracle.mjs');
export const CELL_PATH = resolve(HERE, '..', '..', '..', 'eval', 'ai-generated', 'lib', 'ablation-cell.mjs');

const oracle = await import(pathToFileURL(ORACLE_PATH).href);
const cell = await import(pathToFileURL(CELL_PATH).href);

export const EFFECT = cell.CONTROL_EFFECT;

/**
 * `xorl %eax, %eax` followed later in the body by `rep stos*`: a zero fill in
 * the form gcc uses at -Os. The same two-line recognition as ablation-cell.mjs's
 * controlPresent fallback, applied to any function rather than only to the
 * appended control.
 */
export function repStosZeroFill(asmText, fn) {
  const body = oracle.extractFunctionBody(asmText, fn);
  if (!body) return false;
  let zeroed = false;
  for (const raw of body.lines) {
    const l = raw.replace(/#.*$/, '');
    if (/^\s*xorl?\s+%(e?ax),\s*%\1\s*$/.test(l)) zeroed = true;
    if (zeroed && /^\s*rep\s+stos[bwlq]?\s*$/.test(l)) return true;
  }
  return false;
}

/**
 * The oracle's verdict on `fn`, and where it came from.
 *
 * @returns {{verdict: 'PRESENT'|'ABSENT'|'NOT_OBSERVED', via: string|null, evidence: number, reason: string|null}}
 */
export function readEffect(asmText, fn) {
  const v = oracle.observeEffect(asmText, fn, EFFECT);
  if (v.verdict === 'PRESENT') return { verdict: 'PRESENT', via: 'oracle', evidence: v.evidence.length, reason: null };
  if (v.verdict === 'NOT_OBSERVED') return { verdict: 'NOT_OBSERVED', via: null, evidence: 0, reason: v.reason };
  if (repStosZeroFill(asmText, fn)) return { verdict: 'PRESENT', via: 'rep-stos-fallback', evidence: 1, reason: null };
  return { verdict: 'ABSENT', via: 'oracle', evidence: 0, reason: null };
}

/** Every <lab>/asm/<cell>.s, read for the subject and the control. */
export function readLab(lab, subject, control) {
  const dir = join(lab, 'asm');
  const cells = {};
  for (const f of readdirSync(dir).filter((x) => x.endsWith('.s')).sort()) {
    const text = readFileSync(join(dir, f), 'utf8');
    cells[f.slice(0, -2)] = {
      sha256: createHash('sha256').update(text).digest('hex'),
      subject: readEffect(text, subject),
      control: readEffect(text, control),
    };
  }
  return cells;
}

function main(argv) {
  const args = { lab: null, subject: null, control: null };
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i].replace(/^--/, '');
    if (!(k in args) || i + 1 >= argv.length) {
      process.stderr.write('usage: asm-presence.mjs --lab DIR --subject FN --control FN\n');
      return 3;
    }
    args[k] = argv[i + 1];
  }
  if (!args.lab || !args.subject || !args.control || !existsSync(join(args.lab, 'asm'))) {
    process.stderr.write('usage: asm-presence.mjs --lab DIR --subject FN --control FN (and DIR/asm must exist)\n');
    return 3;
  }
  process.stdout.write(JSON.stringify({ oracle: 'second-vendor/lib/asm-oracle.mjs', effect: EFFECT,
    cells: readLab(args.lab, args.subject, args.control) }) + '\n');
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = main(process.argv.slice(2));
}
