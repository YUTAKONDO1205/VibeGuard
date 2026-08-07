#!/usr/bin/env node
// Origin classifier and finding reporter for VG-INTRO-001..004.
//
//   node classify.mjs --artifact <file> --source <a.cc> [--source <b.cc>]
//                     [--baseline-dir <dir>] [--on-key-mismatch fail|unresolved]
//                     [--allow-lib libstdc++.so.6 ...] [--json <out.json>]
//                     -- <the flags the artefact was built with>
//
// Exit codes are compiler/schema/interfaces.md section 7:
//   0  nothing found, and nothing went unlooked-at
//   2  findings at or above the failure threshold
//   3  a check could not be completed — any Unresolved item, or a baseline key
//      that does not match. Never conflated with 0.
//   4  the artefact could not be read as an ELF64 LSB image

import { writeFileSync, existsSync } from 'node:fs';
import { basename, relative } from 'node:path';
import { readElf } from './lib/elf.mjs';
import { toolchainIdentity, normaliseFlags, baselineKey, linkForm } from './lib/toolchain.mjs';
import { buildSourceUniverse } from './lib/source-universe.mjs';
import { buildLibraryIndex } from './lib/libraries.mjs';
import { classifyArtifact, findingsFor, summarise } from './lib/origins.mjs';
import { findBaseline, DEFAULT_BASELINE_DIR } from './baseline.mjs';
import { seal } from './lib/canonical.mjs';

export function classify({
  artifact,
  sources = [],
  compileFlags = [],
  baselineDir = DEFAULT_BASELINE_DIR,
  onKeyMismatch = 'fail',
  allowedLibs = null,
  cxx = 'clang++-18',
}) {
  const elf = readElf(artifact);
  if (!elf.supported) {
    return { ok: false, reason: elf.reason, exitCode: 4 };
  }

  const form = linkForm(elf);
  const norm = normaliseFlags(compileFlags);
  const tc = toolchainIdentity(cxx);
  const key = baselineKey({ toolchainDigest: tc.digest, flags: norm, form: form.form });
  const found = findBaseline(key, baselineDir);

  const keyMismatch = found.state !== 'matched';
  const baseline = keyMismatch ? null : found.baseline;

  const source = buildSourceUniverse({ sources, compileFlags: norm.filter((f) => !/^-(pie|no-pie|static|shared|Wl,)/.test(f)), cxx });
  const libs = buildLibraryIndex(elf, { allowed: allowedLibs });

  const { items, needed } = classifyArtifact({
    elf,
    baseline,
    baselineState: found.state,
    source,
    libs,
    flags: norm,
  });

  const findings = findingsFor(items, basename(artifact));
  const summary = summarise(items);

  const record = seal({
    recordType: 'introduction-analysis',
    schemaVersion: 1,
    artifact: basename(artifact),
    key: { toolchainDigest: key.toolchainDigest, flagsDigest: key.flagsDigest, form: key.form, id: key.id },
    flags: norm,
    toolchain: { digest: tc.digest, clang: '18.1.3', packages: tc.entries },
    baseline: {
      state: found.state,
      // Relative to the baseline root: an absolute path must not reach a record.
      path: found.state === 'matched' ? relative(baselineDir, found.path).split('\\').join('/') : null,
      keyId: baseline ? baseline.key.id : null,
      evidenceDigest: baseline ? baseline.evidenceDigest : null,
      availableForThisToolchain: found.available.map((a) => ({ form: a.form, flags: a.flags, flagsDigest: a.flagsDigest })),
      onKeyMismatch,
    },
    linkFormDecidedBy: form.decidedBy.map((d) => ({ ...d, observed: typeof d.observed === 'boolean' ? (d.observed ? 1 : 0) : d.observed })),
    sourceUniverse: {
      available: source.available ? 1 : 0,
      sources: [...source.sourceBasenames].sort(),
      identifierCount: source.identifierCount,
      failures: source.failures,
    },
    libraries: { available: libs.available ? 1 : 0, needed: needed.sort(), resolved: libs.resolved, missing: libs.missing },
    summary: {
      total: summary.total,
      Explained: summary.byVerdict.Explained,
      Unexplained: summary.byVerdict.Unexplained,
      Unresolved: summary.byVerdict.Unresolved,
      byOrigin: summary.byOrigin,
      byKind: summary.byKind,
    },
    items: items
      .map((i) => ({
        kind: i.kind,
        name: i.name,
        verdict: i.verdict,
        origin: i.origin,
        rule: i.rule,
        bind: i.bind ?? null,
        symbolType: i.symbolType ?? null,
        section: i.section ?? null,
        array: i.array ?? null,
        slot: i.slot ?? null,
        target: i.target ?? null,
        executable: i.executable ?? null,
        evidence: i.evidence ?? null,
        unavailableRules: i.unavailableRules ?? null,
      }))
      .sort((a, b) => (a.kind + a.name < b.kind + b.name ? -1 : 1)),
    findings,
    context: {
      generatedAt: process.env.SOURCE_DATE_EPOCH
        ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000).toISOString()
        : new Date().toISOString(),
      timeSource: process.env.SOURCE_DATE_EPOCH ? 'SOURCE_DATE_EPOCH' : 'wall-clock',
      sourceDateEpoch: process.env.SOURCE_DATE_EPOCH ? Number(process.env.SOURCE_DATE_EPOCH) : null,
      host: 'redacted-by-policy',
    },
  });

  // A key mismatch under the default policy is a refusal, not a downgrade: the
  // classifier will not reach for a baseline taken under a different
  // configuration, and says so instead of quietly explaining less.
  let exitCode = 0;
  if (keyMismatch && onKeyMismatch === 'fail') exitCode = 3;
  else if (findings.length > 0) exitCode = 2;
  else if (summary.byVerdict.Unresolved > 0) exitCode = 3;

  return { ok: true, record, items, findings, summary, exitCode, keyMismatch, found, key };
}

// ---- CLI -------------------------------------------------------------------

function main(argv) {
  const dashdash = argv.indexOf('--');
  const opts = dashdash === -1 ? argv : argv.slice(0, dashdash);
  const compileFlags = dashdash === -1 ? [] : argv.slice(dashdash + 1);
  const get = (n, d) => {
    const i = opts.indexOf(n);
    return i === -1 ? d : opts[i + 1];
  };
  const many = (n) => opts.map((v, i) => (v === n ? opts[i + 1] : null)).filter(Boolean);

  const artifact = get('--artifact', null);
  if (!artifact || !existsSync(artifact)) {
    console.error('usage: node classify.mjs --artifact <file> [--source <src>]… [--baseline-dir <dir>]');
    console.error('       [--on-key-mismatch fail|unresolved] [--allow-lib <soname>]… [--json <out>] -- <flags…>');
    return 2;
  }
  const allow = many('--allow-lib');
  const r = classify({
    artifact,
    sources: many('--source'),
    compileFlags,
    baselineDir: get('--baseline-dir', DEFAULT_BASELINE_DIR),
    onKeyMismatch: get('--on-key-mismatch', 'fail'),
    allowedLibs: allow.length ? allow : null,
    cxx: get('--cxx', 'clang++-18'),
  });

  if (!r.ok) {
    console.error(`cannot read ${artifact}: ${r.reason}`);
    return r.exitCode;
  }

  const jsonOut = get('--json', null);
  if (jsonOut) writeFileSync(jsonOut, `${JSON.stringify(r.record, null, 2)}\n`, 'utf8');

  const s = r.summary.byVerdict;
  console.log(`artifact          ${basename(artifact)}  (${r.record.key.form})`);
  console.log(`baseline          ${r.record.baseline.state}${r.record.baseline.path ? `  ${r.record.baseline.path}` : ''}`);
  if (r.keyMismatch) {
    console.log(`  no baseline for key ${r.key.id.slice(0, 16)} — flags=[${r.key.flags.join(' ')}] form=${r.key.form}`);
    for (const a of r.record.baseline.availableForThisToolchain) {
      console.log(`  have instead: form=${a.form} flags=[${a.flags.join(' ')}]`);
    }
    console.log(`  on-key-mismatch=${r.record.baseline.onKeyMismatch}: ${r.record.baseline.onKeyMismatch === 'fail' ? 'refusing to deduct; exit 3' : 'continuing with the baseline rule marked unavailable'}`);
  }
  console.log(`items             ${r.summary.total}  Explained=${s.Explained}  Unexplained=${s.Unexplained}  Unresolved=${s.Unresolved}`);
  console.log(`origins           ${Object.entries(r.summary.byOrigin).map(([k, v]) => `${k}=${v}`).join('  ')}`);
  for (const i of r.items) {
    if (i.verdict === 'Unexplained') console.log(`  UNEXPLAINED  ${i.kind.padEnd(18)} ${i.name}`);
  }
  const unres = r.items.filter((i) => i.verdict === 'Unresolved');
  if (unres.length) {
    console.log(`unresolved        ${unres.length}`);
    for (const i of unres.slice(0, 12)) {
      console.log(`  UNRESOLVED   ${i.kind.padEnd(18)} ${i.name}   [${(i.unavailableRules ?? []).map((u) => u.rule).join(', ')}]`);
    }
    if (unres.length > 12) console.log(`  … and ${unres.length - 12} more (see --json)`);
  }
  for (const f of r.findings) console.log(`  ${f.id}  ${f.severity.padEnd(8)} ${f.detail}`);
  console.log(`exit              ${r.exitCode}`);
  return r.exitCode;
}

if (process.argv[1] && basename(process.argv[1]) === 'classify.mjs') {
  process.exit(main(process.argv.slice(2)));
}
