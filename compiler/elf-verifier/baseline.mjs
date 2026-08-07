#!/usr/bin/env node
// Toolchain baseline builder.
//
// Compiles a near-empty translation unit with a given flag set and link form,
// and records everything the toolchain put in the result *without being asked
// by the source*. That set is the deduction the origin classifier is allowed to
// make, and it is keyed on (toolchain digest, flag set, link form) so that a
// deduction taken from one configuration is never applied to another.
//
//   node baseline.mjs --build --out <dir> --form exec-pie -- -O0
//   node baseline.mjs --list --out <dir>
//
// Everything after `--` is the flag set. The output directory must be outside
// the repository; --out defaults to ~/vg-lab/introduction-analysis/baseline.

import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { basename, join } from 'node:path';
import { homedir } from 'node:os';
import { readElf, definedSymbols, undefinedSymbols, readInitArrays, neededLibraries, bindName, typeName, decidePie, decideRelroFull, decideNx, SHF } from './lib/elf.mjs';
import { toolchainIdentity, normaliseFlags, baselineKey, linkForm, keyPathParts } from './lib/toolchain.mjs';
import { seal } from './lib/canonical.mjs';
import { BASELINE_TU } from './controls.mjs';

export const DEFAULT_BASELINE_DIR = join(homedir(), 'vg-lab', 'introduction-analysis', 'baseline');

function nowContext() {
  const sde = process.env.SOURCE_DATE_EPOCH ? Number(process.env.SOURCE_DATE_EPOCH) : null;
  return {
    generatedAt: sde !== null ? new Date(sde * 1000).toISOString() : new Date().toISOString(),
    timeSource: sde !== null ? 'SOURCE_DATE_EPOCH' : 'wall-clock',
    sourceDateEpoch: sde,
    host: 'redacted-by-policy',
  };
}

/**
 * Build one baseline.
 *
 * `form` is what the caller intends; the form actually recorded is read back
 * out of the produced artefact's header, and a disagreement is an error rather
 * than a preference — a baseline filed under the wrong link form is worse than
 * a missing one, because it will be found and used.
 */
export function buildBaseline({ flags, form, outDir = DEFAULT_BASELINE_DIR, cxx = 'clang++-18', workDir }) {
  const work = workDir ?? join(homedir(), 'vg-build', 'elf-verifier', 'baseline-work');
  mkdirSync(work, { recursive: true });
  const src = join(work, 'baseline_tu.cc');
  writeFileSync(src, BASELINE_TU, 'utf8');

  const norm = normaliseFlags(flags);
  const tc = toolchainIdentity(cxx);

  const linkArgsByForm = {
    object: ['-c'],
    'exec-pie': ['-pie', '-fPIE'],
    'exec-nopie-dynamic': ['-no-pie', '-fno-pie'],
    'exec-static': ['-static'],
    shared: ['-shared', '-fPIC'],
  };
  if (!(form in linkArgsByForm)) throw new Error(`unknown link form: ${form}`);
  const ext = form === 'object' ? '.o' : form === 'shared' ? '.so' : '.out';
  const outFile = join(work, `baseline_${form}${ext}`);
  const argv = [...norm, ...linkArgsByForm[form], src, '-o', outFile];
  execFileSync(cxx, argv, { stdio: ['ignore', 'pipe', 'pipe'] });

  const elf = readElf(outFile);
  if (!elf.supported) throw new Error(`baseline artefact is not readable as ELF64 LSB: ${elf.reason}`);
  const observed = linkForm(elf);
  if (observed.form !== form) {
    throw new Error(
      `asked for link form '${form}' but the artefact is '${observed.form}'. ` +
        `Filing this under '${form}' would make every later deduction wrong.`,
    );
  }

  const key = baselineKey({ toolchainDigest: tc.digest, flags: norm, form });

  const record = {
    recordType: 'introduction-baseline',
    schemaVersion: 1,
    key: { toolchainDigest: key.toolchainDigest, flagsDigest: key.flagsDigest, form: key.form, id: key.id },
    flags: norm,
    toolchain: { digest: tc.digest, clang: '18.1.3', packages: tc.entries, unresolved: tc.unresolved },
    linkFormDecidedBy: observed.decidedBy,
    artifactProperties: [decidePie(elf), decideNx(elf), decideRelroFull(elf)].map((p) => ({
      property: p.property,
      value: p.value ? 1 : 0,
      reader: p.reader,
      decidedBy: p.decidedBy.map((d) => ({ ...d, observed: typeof d.observed === 'boolean' ? (d.observed ? 1 : 0) : d.observed })),
    })),
    defined: definedSymbols(elf)
      .map((s) => ({ name: s.name, bind: bindName(s.bind), type: typeName(s.type) }))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)),
    undefined: undefinedSymbols(elf).map((s) => s.name).sort(),
    sections: elf.sections
      .filter((s) => s.index !== 0)
      .map((s) => ({
        name: s.name,
        type: s.sh_type,
        executable: (s.sh_flags & SHF.EXECINSTR) !== 0 ? 1 : 0,
        writable: (s.sh_flags & SHF.WRITE) !== 0 ? 1 : 0,
        alloc: (s.sh_flags & SHF.ALLOC) !== 0 ? 1 : 0,
      }))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)),
    initArrays: readInitArrays(elf).map((e) => ({ array: e.array, slot: e.slot, target: e.target })),
    needed: neededLibraries(elf).sort(),
    counts: {
      defined: definedSymbols(elf).length,
      undefined: undefinedSymbols(elf).length,
      sections: elf.sections.length - 1,
      initEntries: readInitArrays(elf).length,
    },
    context: nowContext(),
  };

  const sealed = seal(record);
  const parts = keyPathParts(key);
  const dir = join(outDir, parts[0], parts[1]);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${parts[2]}.json`);
  writeFileSync(path, `${JSON.stringify(sealed, null, 2)}\n`, 'utf8');
  return { path, record: sealed, key, artifact: outFile };
}

/**
 * Find the baseline for exactly this key.
 *
 * There is deliberately no nearest-match, no "same toolchain, different flags"
 * fallback and no ignore-the-link-form option. Every one of those is a way of
 * deducting a measurement that was never taken, which is the failure this whole
 * component exists to prevent; the only two answers are the right baseline and
 * none.
 */
export function findBaseline(key, outDir = DEFAULT_BASELINE_DIR) {
  const parts = keyPathParts(key);
  const path = join(outDir, parts[0], parts[1], `${parts[2]}.json`);
  if (!existsSync(path)) {
    const near = [];
    const tcDir = join(outDir, parts[0]);
    if (existsSync(tcDir)) {
      for (const form of readdirSync(tcDir)) {
        const d = join(tcDir, form);
        try {
          for (const f of readdirSync(d)) {
            const r = JSON.parse(readFileSync(join(d, f), 'utf8'));
            near.push({ form, flags: r.flags, flagsDigest: r.key.flagsDigest });
          }
        } catch { /* a directory that is not a baseline is not a baseline */ }
      }
    }
    return { state: 'key-mismatch', baseline: null, path, available: near };
  }
  return { state: 'matched', baseline: JSON.parse(readFileSync(path, 'utf8')), path, available: [] };
}

// ---- CLI -------------------------------------------------------------------

function main(argv) {
  const dashdash = argv.indexOf('--');
  const opts = dashdash === -1 ? argv : argv.slice(0, dashdash);
  const flags = dashdash === -1 ? [] : argv.slice(dashdash + 1);
  const get = (n, d) => {
    const i = opts.indexOf(n);
    return i === -1 ? d : opts[i + 1];
  };
  const outDir = get('--out', DEFAULT_BASELINE_DIR);

  if (opts.includes('--list')) {
    if (!existsSync(outDir)) {
      console.log(`no baselines under ${outDir}`);
      return 0;
    }
    for (const tc of readdirSync(outDir)) {
      for (const form of readdirSync(join(outDir, tc))) {
        for (const f of readdirSync(join(outDir, tc, form))) {
          const r = JSON.parse(readFileSync(join(outDir, tc, form, f), 'utf8'));
          console.log(
            `${tc}  ${form.padEnd(20)}  ${r.key.flagsDigest.slice(0, 16)}  flags=[${r.flags.join(' ')}]  ` +
              `defined=${r.counts.defined} undef=${r.counts.undefined} sections=${r.counts.sections} init=${r.counts.initEntries}`,
          );
        }
      }
    }
    return 0;
  }

  if (opts.includes('--build')) {
    const form = get('--form', 'exec-pie');
    const r = buildBaseline({ flags, form, outDir, cxx: get('--cxx', 'clang++-18') });
    console.log(`baseline ${form} flags=[${r.key.flags.join(' ')}]`);
    console.log(`  key.id            ${r.key.id}`);
    console.log(`  toolchain.digest  ${r.key.toolchainDigest}`);
    console.log(`  flagsDigest       ${r.key.flagsDigest}`);
    console.log(`  evidenceDigest    ${r.record.evidenceDigest}`);
    console.log(`  defined=${r.record.counts.defined} undef=${r.record.counts.undefined} sections=${r.record.counts.sections} init=${r.record.counts.initEntries}`);
    console.log(`  ${r.path}`);
    return 0;
  }

  console.error('usage: node baseline.mjs (--build --form <form> [--out <dir>] -- <flags…> | --list [--out <dir>])');
  console.error('forms: object exec-pie exec-nopie-dynamic exec-static shared');
  return 2;
}

if (process.argv[1] && basename(process.argv[1]) === 'baseline.mjs') {
  process.exit(main(process.argv.slice(2)));
}
