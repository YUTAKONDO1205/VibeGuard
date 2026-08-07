#!/usr/bin/env node
// artefact-controls — check the measured table with THIS tree's ELF reader.
//
// WHY A SECOND READER
//
// `artefact-ground-truth.md` is asserted in two places by two independently
// written pieces of code:
//
//   packages/artifact-integrity/tools/verify-real-fixtures.mjs   its own reader
//   compiler/elf-verifier/artefact-controls.mjs (this file)      ./lib/elf.mjs
//
// The two do not share a line: `packages/**` and `compiler/**` do not reference
// each other in either direction, and this component does not spend that. The
// duplication is therefore not an accident to be tidied away — it is the only
// cross-check available, and two readers agreeing on twenty-three real binaries
// is stronger evidence than one reader agreeing with itself.
//
// Three of the six decisions here are not re-implemented at all: `decidePie`,
// `decideRelroFull` and `decideNx` already exist in `./lib/elf.mjs` and are
// called. What this file adds is the stack-protector, fortify, build-id and W+X
// half that the tree did not have.
//
//   node compiler/elf-verifier/artefact-controls.mjs --dir <matrix/bin>
//
// COUNTING CONTRACT: prints `inputs=N checked=N skipped=S` and exits non-zero
// when N is 0 unless `--allow-empty`.
//
// SKIP IS NOT PASS: a fixture the table names and the directory does not hold
// is a failure. `VG_ART_ALLOW_MISSING_FIXTURES=1` downgrades it to a skip, and
// then every skipped fixture is listed by name.

import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

import {
  readElf, decidePie, decideRelroFull, decideNx, undefinedSymbols,
  neededLibraries, dynTag, dynTags, ET, PT, SHF, DT, R_X86_64,
} from './lib/elf.mjs';
import { EXIT_OK, EXIT_TOOL_FAILED, EXIT_FINDINGS, EXIT_INCOMPLETE } from '../driver/lib/exit.mjs';

/**
 * artefact-ground-truth.md section 1, as data.
 *
 * `stack` is PT_GNU_STACK.p_flags; `relro` is whether PT_GNU_RELRO exists;
 * `flags`/`flags1` are DT_FLAGS/DT_FLAGS_1 or null; `sp` is whether
 * __stack_chk_fail is imported or JUMP_SLOT-relocated; `chk` is the sorted list
 * of __*_chk JUMP_SLOT targets; `wx` is the sections with SHF_WRITE and
 * SHF_EXECINSTR; `dbg` is the number of .debug_* sections.
 */
const TABLE = {
  'sp-on':             { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: true,  chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'sp-off':            { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'pie-on':            { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'pie-off':           { type: ET.EXEC, stack: 6, relro: true,  interp: true,  flags: null, flags1: null,      sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'relro-full':        { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'relro-part':        { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: null, flags1: 0x8000000, sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'relro-none':        { type: ET.DYN,  stack: 6, relro: false, interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'nx-on':             { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'nx-off':            { type: ET.DYN,  stack: 7, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'fortify-on':        { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: ['__strcpy_chk'], buildId: true,  wx: [],        dbg: 0 },
  'fortify-off':       { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'buildid-on':        { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'buildid-off':       { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: [],               buildId: false, wx: [],        dbg: 0 },
  'dbg-on':            { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: [],               buildId: true,  wx: [],        dbg: 6 },
  'dbg-off':           { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'rpath':             { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: true,  chk: ['__strcpy_chk'], buildId: true,  wx: [],        dbg: 0, runpath: 1 },
  'hardened':          { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: true,  chk: ['__strcpy_chk'], buildId: true,  wx: [],        dbg: 0 },
  'hardened-stripped': { type: ET.DYN,  stack: 6, relro: true,  interp: true,  flags: 0x8,  flags1: 0x8000001, sp: true,  chk: ['__strcpy_chk'], buildId: true,  wx: [],        dbg: 0 },
  'unhardened':        { type: ET.EXEC, stack: 7, relro: false, interp: true,  flags: null, flags1: null,      sp: false, chk: [],               buildId: false, wx: [],        dbg: 6 },
  'static-hardened':   { type: ET.EXEC, stack: 6, relro: true,  interp: false, flags: null, flags1: null,      sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'static-plain':      { type: ET.EXEC, stack: 6, relro: true,  interp: false, flags: null, flags1: null,      sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'libshared.so':      { type: ET.DYN,  stack: 6, relro: true,  interp: false, flags: null, flags1: null,      sp: false, chk: [],               buildId: true,  wx: [],        dbg: 0 },
  'wx-on':             { type: ET.DYN,  stack: 6, relro: false, interp: true,  flags: 0x8,  flags1: 0x8000001, sp: false, chk: ['__printf_chk'], buildId: true,  wx: ['.vgwx'], dbg: 0 },
};

/** The verdicts the three in-tree deciders must return, per fixture. */
const VERDICTS = {
  'sp-on':             { pie: true,  nx: true,  relroFull: true  },
  'sp-off':            { pie: true,  nx: true,  relroFull: true  },
  'pie-on':            { pie: true,  nx: true,  relroFull: true  },
  'pie-off':           { pie: false, nx: true,  relroFull: false },
  'relro-full':        { pie: true,  nx: true,  relroFull: true  },
  'relro-part':        { pie: true,  nx: true,  relroFull: false },
  'relro-none':        { pie: true,  nx: true,  relroFull: false },
  'nx-on':             { pie: true,  nx: true,  relroFull: true  },
  'nx-off':            { pie: true,  nx: false, relroFull: true  },
  'fortify-on':        { pie: true,  nx: true,  relroFull: true  },
  'fortify-off':       { pie: true,  nx: true,  relroFull: true  },
  'buildid-on':        { pie: true,  nx: true,  relroFull: true  },
  'buildid-off':       { pie: true,  nx: true,  relroFull: true  },
  'dbg-on':            { pie: true,  nx: true,  relroFull: true  },
  'dbg-off':           { pie: true,  nx: true,  relroFull: true  },
  'rpath':             { pie: true,  nx: true,  relroFull: true  },
  'hardened':          { pie: true,  nx: true,  relroFull: true  },
  'hardened-stripped': { pie: true,  nx: true,  relroFull: true  },
  'unhardened':        { pie: false, nx: false, relroFull: false },
  // `decideRelroFull` in ./lib/elf.mjs requires eager binding unconditionally,
  // so a static image reads false there. That is the tree's existing behaviour
  // and this file records it rather than quietly correcting it; the artefact
  // verifier states the static case separately.
  'static-hardened':   { pie: false, nx: true,  relroFull: false },
  'static-plain':      { pie: false, nx: true,  relroFull: false },
  'libshared.so':      { pie: false, nx: true,  relroFull: false },
  'wx-on':             { pie: true,  nx: true,  relroFull: false },
};

const CHK = /^__[A-Za-z0-9_]+_chk$/;
const PROTECTOR = new Set(['__stack_chk_fail', '__stack_chk_fail_local']);

function jumpSlotTargets(elf) {
  const out = new Set();
  for (const r of elf.relocations) {
    if (r.r_type !== R_X86_64.JUMP_SLOT || !r.symbolName) continue;
    out.add(r.symbolName.split('@')[0]);
  }
  return out;
}

function measure(elf) {
  const gs = elf.phdrs.find((p) => p.p_type === PT.GNU_STACK) ?? null;
  const relro = elf.phdrs.some((p) => p.p_type === PT.GNU_RELRO);
  const interp = elf.phdrs.some((p) => p.p_type === PT.INTERP);
  const fl = dynTag(elf, DT.FLAGS);
  const f1 = dynTag(elf, DT.FLAGS_1);
  const js = jumpSlotTargets(elf);
  const imports = new Set(undefinedSymbols(elf).map((s) => s.name));
  const sp = [...PROTECTOR].some((n) => js.has(n) || imports.has(n));
  const chk = [...js].filter((n) => CHK.test(n) && !PROTECTOR.has(n)).sort();
  const buildId = elf.sections.some((s) => s.name === '.note.gnu.build-id');
  const wx = elf.sections
    .filter((s) => (s.sh_flags & SHF.WRITE) && (s.sh_flags & SHF.EXECINSTR) && (s.sh_flags & SHF.ALLOC))
    .map((s) => s.name);
  const dbg = elf.sections.filter((s) => s.name && s.name.startsWith('.debug')).length;
  const runpath = dynTags(elf, DT.RUNPATH).length + dynTags(elf, DT.RPATH).length;
  return {
    type: elf.ehdr.e_type,
    stack: gs ? gs.p_flags : null,
    relro,
    interp,
    flags: fl ? Number(fl.value & 0xffffffffn) : null,
    flags1: f1 ? Number(f1.value & 0xffffffffn) : null,
    sp, chk, buildId, wx, dbg, runpath,
    needed: neededLibraries(elf),
  };
}

function eq(a, b) {
  if (Array.isArray(a) || Array.isArray(b)) return JSON.stringify(a) === JSON.stringify(b);
  return a === b;
}

function main(argv) {
  let dir = null;
  let allowEmpty = false;
  let verbose = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--dir') dir = argv[++i];
    else if (argv[i] === '--allow-empty') allowEmpty = true;
    else if (argv[i] === '--verbose') verbose = true;
    else if (argv[i] === '-h' || argv[i] === '--help') {
      process.stdout.write('usage: node artefact-controls.mjs --dir <matrix/bin> [--verbose] [--allow-empty]\n' +
        'Build the matrix with: bash artefact-fixtures.sh <workdir>\n');
      return EXIT_OK;
    } else {
      process.stderr.write(`artefact-controls: unknown option ${argv[i]}\n`);
      return EXIT_TOOL_FAILED;
    }
  }
  if (!dir) {
    process.stderr.write('artefact-controls: --dir is required\n');
    return EXIT_TOOL_FAILED;
  }

  const root = resolve(dir);
  const have = existsSync(root) ? new Set(readdirSync(root)) : new Set();
  const names = Object.keys(TABLE);
  const missing = names.filter((n) => !have.has(n));
  const found = names.filter((n) => have.has(n));
  const allowMissing = process.env.VG_ART_ALLOW_MISSING_FIXTURES === '1';

  const skipped = [];
  const failures = [];
  let checked = 0;
  let comparisons = 0;

  for (const name of found) {
    const elf = readElf(join(root, name));
    if (!elf.supported) {
      failures.push(`${name}: ${elf.reason}`);
      continue;
    }
    checked += 1;
    const got = measure(elf);
    const want = TABLE[name];
    for (const key of Object.keys(want)) {
      comparisons += 1;
      if (!eq(got[key], want[key])) {
        failures.push(`${name}.${key}: measured ${JSON.stringify(got[key])}, table says ${JSON.stringify(want[key])}`);
      }
    }
    const v = VERDICTS[name];
    const pie = decidePie(elf).value;
    const nx = decideNx(elf).value;
    const relroFull = decideRelroFull(elf).value;
    comparisons += 3;
    if (pie !== v.pie) failures.push(`${name}: lib/elf.mjs decidePie -> ${pie}, table says ${v.pie}`);
    if (nx !== v.nx) failures.push(`${name}: lib/elf.mjs decideNx -> ${nx}, table says ${v.nx}`);
    if (relroFull !== v.relroFull) failures.push(`${name}: lib/elf.mjs decideRelroFull -> ${relroFull}, table says ${v.relroFull}`);

    if (verbose) {
      process.stdout.write(`  ${name.padEnd(20)} e_type=${got.type} stack=${got.stack} relro=${got.relro} ` +
        `sp=${got.sp} chk=[${got.chk}] wx=[${got.wx}] dbg=${got.dbg} | pie=${pie} nx=${nx} relroFull=${relroFull}\n`);
    }
  }

  for (const n of missing) {
    if (allowMissing) skipped.push([n, 'not present in --dir (VG_ART_ALLOW_MISSING_FIXTURES=1)']);
    else failures.push(`${n}: the table names this fixture and --dir does not hold it. ` +
      'Build it with artefact-fixtures.sh, or set VG_ART_ALLOW_MISSING_FIXTURES=1 to downgrade to a listed skip.');
  }

  const inputs = found.length + missing.length;
  process.stdout.write(`\ninputs=${inputs} checked=${checked} skipped=${skipped.length}\n`);
  process.stdout.write(`comparisons=${comparisons} failures=${failures.length}\n`);
  if (skipped.length > 0) {
    process.stdout.write('skipped fixtures, by name:\n');
    for (const [n, why] of skipped) process.stdout.write(`  ${n} — ${why}\n`);
    process.stdout.write('  (a skip is not agreement)\n');
  }
  for (const f of failures) process.stdout.write(`  FAIL ${f}\n`);

  if (inputs === 0 && !allowEmpty) {
    process.stderr.write('artefact-controls: nothing was checked. An empty run is not a pass.\n');
    return EXIT_INCOMPLETE;
  }
  if (checked === 0 && !allowEmpty) {
    process.stderr.write('artefact-controls: no fixture was read. An empty run is not a pass.\n');
    return EXIT_INCOMPLETE;
  }
  return failures.length > 0 ? EXIT_FINDINGS : EXIT_OK;
}

process.exitCode = main(process.argv.slice(2));

export { TABLE, VERDICTS, measure };
