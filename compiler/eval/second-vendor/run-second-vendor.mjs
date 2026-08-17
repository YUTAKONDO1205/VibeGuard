#!/usr/bin/env node
/**
 * Second-vendor configuration envelope.
 *
 * Widens #V7 SCE by exactly one axis: a second compiler vendor (gcc-13) measured
 * with the same instrument as clang-18. It does not widen the machine axis, and
 * it does not claim pass-level attribution for gcc. Both of those are recorded
 * as UNSUPPORTED in the output rather than left to the reader's imagination.
 *
 * Usage:
 *   node run-second-vendor.mjs --fixtures <dir> --work <dir> --out <dir>
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { observeEffect, classifyCell } from './lib/asm-oracle.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i += 2) out[argv[i].replace(/^--/, '')] = argv[i + 1];
  return out;
}

function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/** Run a command and capture everything, including the failure. rc is data, not a verdict. */
function run(cmd, args, opts = {}) {
  try {
    const stdout = execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts });
    return { rc: 0, stdout, stderr: '' };
  } catch (e) {
    return {
      rc: typeof e.status === 'number' ? e.status : null,
      signal: e.signal ?? null,
      stdout: e.stdout ? String(e.stdout) : '',
      stderr: e.stderr ? String(e.stderr) : String(e.message),
    };
  }
}

function toolchainIdentity() {
  const id = {};
  for (const [key, cmd, args] of [
    ['clang-18', 'clang-18', ['--version']],
    ['gcc-13', 'gcc-13', ['--version']],
    ['as', 'as', ['--version']],
    ['ld', 'ld', ['--version']],
  ]) {
    const r = run(cmd, args);
    id[key] = r.rc === 0 ? r.stdout.split('\n')[0].trim() : { unresolved: r.stderr.trim().slice(0, 200) };
  }
  const host = run('uname', ['-a']);
  id.host = host.rc === 0 ? host.stdout.trim() : { unresolved: 'uname failed' };
  id.hostname = (run('hostname', []).stdout || '').trim() || null;
  return id;
}

/**
 * Compile one cell to assembly, then to an object, then link and run it.
 *
 * The link+run step is not decoration. rc=0 from a compiler driver has been
 * observed in this project to accompany an empty output directory, so every
 * artifact this function claims to have produced is stat()ed before it is
 * reported as produced.
 */
function buildCell(driver, opt, extraFlags, commonFlags, fixtureDir, cellWork) {
  fs.mkdirSync(cellWork, { recursive: true });
  const asmPath = path.join(cellWork, 'target.s');
  const objPath = path.join(cellWork, 'target.o');
  const opaquePath = path.join(cellWork, 'opaque.o');
  const mainPath = path.join(cellWork, 'main.o');
  const binPath = path.join(cellWork, 'a.out');

  const base = [opt, ...commonFlags, ...extraFlags];

  const artifacts = {};
  const steps = {};

  steps.asm = run(driver, [...base, '-S', '-o', asmPath, path.join(fixtureDir, 'target.c')]);
  artifacts.asm = statArtifact(asmPath);
  if (!artifacts.asm.exists) {
    return { steps, artifacts, asmText: null, produced: false };
  }
  const asmText = fs.readFileSync(asmPath, 'utf8');
  artifacts.asm.sha256 = sha256(asmText);

  steps.obj = run(driver, [...base, '-c', '-o', objPath, path.join(fixtureDir, 'target.c')]);
  artifacts.obj = statArtifact(objPath);
  if (artifacts.obj.exists) artifacts.obj.sha256 = sha256(fs.readFileSync(objPath));

  // opaque.c and main.c are compiled at -O0 without the mitigation on purpose:
  // they are scaffolding, and varying them would add a second uncontrolled axis.
  steps.opaque = run(driver, ['-O0', ...commonFlags, '-c', '-o', opaquePath, path.join(fixtureDir, 'opaque.c')]);
  steps.main = run(driver, ['-O0', ...commonFlags, ...extraFlags, '-c', '-o', mainPath, path.join(fixtureDir, 'main.c')]);
  artifacts.opaque = statArtifact(opaquePath);
  artifacts.main = statArtifact(mainPath);

  if (artifacts.obj.exists && artifacts.opaque.exists && artifacts.main.exists) {
    steps.link = run(driver, ['-o', binPath, objPath, opaquePath, mainPath]);
    artifacts.bin = statArtifact(binPath);
    if (artifacts.bin.exists) {
      artifacts.bin.sha256 = sha256(fs.readFileSync(binPath));
      const exec = run(binPath, []);
      steps.exec = { rc: exec.rc, signal: exec.signal ?? null, stderrHead: (exec.stderr || '').split('\n')[0] || '' };
    }
  }

  return { steps, artifacts, asmText, produced: true };
}

function statArtifact(p) {
  try {
    const st = fs.statSync(p);
    return { path: p, exists: true, size: st.size };
  } catch {
    return { path: p, exists: false, size: 0 };
  }
}

function main() {
  const args = parseArgs(process.argv);
  const fixturesRoot = args.fixtures || '$LAB/fixtures';
  const workRoot = args.work || '$LAB/_work-wave2/second-vendor';
  const outRoot = args.out || '$LAB/_results-wave2/second-vendor';

  const spec = JSON.parse(fs.readFileSync(path.join(HERE, 'spec.json'), 'utf8'));

  fs.rmSync(workRoot, { recursive: true, force: true });
  fs.mkdirSync(workRoot, { recursive: true });
  fs.mkdirSync(outRoot, { recursive: true });

  const results = {
    schemaVersion: 'second-vendor-envelope-v0',
    generatedAt: new Date().toISOString(),
    generator: 'compiler/eval/second-vendor/run-second-vendor.mjs',
    scopeStatement: spec.scopeStatement,
    limitations: spec.limitations,
    machineAxis: {
      status: 'UNSUPPORTED',
      machinesUsed: 1,
      identity: null,
      reason: spec.limitations.multiMachine.reason,
    },
    toolchain: toolchainIdentity(),
    vendors: spec.vendors,
    properties: [],
  };
  results.machineAxis.identity = results.toolchain.host;

  for (const prop of spec.properties) {
    const fixtureDir = path.join(fixturesRoot, prop.fixtureId);
    const propOut = {
      fixtureId: prop.fixtureId,
      propertyId: prop.propertyId,
      kind: prop.kind,
      targetFn: prop.targetFn,
      controlFn: prop.controlFn,
      referenceConfig: prop.referenceConfig,
      mitigation: prop.mitigation.name,
      note: prop.note ?? null,
      cells: [],
    };

    for (const vendor of spec.vendors) {
      for (const opt of spec.opts) {
        for (const mitOn of [false, true]) {
          const cellId = `${vendor.vendorId}__${opt.replace('-', '')}__mit-${mitOn ? 'on' : 'off'}`;
          const extraFlags = mitOn ? prop.mitigation.on : prop.mitigation.off;
          const cellWork = path.join(workRoot, prop.fixtureId, cellId);

          const built = buildCell(vendor.driver, opt, extraFlags, spec.commonFlags, fixtureDir, cellWork);

          let subject, control, cls;
          if (!built.asmText) {
            subject = { verdict: 'NOT_OBSERVED', evidence: [], reason: 'assembly not produced', bodyLineCount: null };
            control = { verdict: 'NOT_OBSERVED', evidence: [], reason: 'assembly not produced', bodyLineCount: null };
            cls = { state: 'NOT_OBSERVED', rationale: 'compiler produced no assembly for this cell' };
          } else {
            subject = observeEffect(built.asmText, prop.targetFn, prop.targetEffect);
            control = observeEffect(built.asmText, prop.controlFn, prop.controlEffect);
            cls = classifyCell(subject, control);
          }

          propOut.cells.push({
            cellId,
            vendor: vendor.vendorId,
            opt,
            mitigation: { name: prop.mitigation.name, on: mitOn },
            flags: [opt, ...spec.commonFlags, ...extraFlags],
            state: cls.state,
            rationale: cls.rationale,
            observedAt: 'asm',
            subject: { fn: prop.targetFn, verdict: subject.verdict, evidenceCount: subject.evidence.length, evidence: subject.evidence, reason: subject.reason },
            positiveControl: { fn: prop.controlFn, verdict: control.verdict, evidenceCount: control.evidence.length, evidence: control.evidence, reason: control.reason },
            attribution: {
              level: 'artifact',
              firstLossStage: null,
              firstLossPass: null,
              status: vendor.passPluginLoadable
                ? 'NOT_OBSERVED'
                : 'UNSUPPORTED',
              reason: vendor.passPluginLoadable
                ? spec.limitations.clangPassAttributionInThisRun.reason
                : spec.limitations.gccPassAttribution.reason,
            },
            build: {
              compilerRc: built.steps.asm ? built.steps.asm.rc : null,
              compilerStderrHead: built.steps.asm ? (built.steps.asm.stderr || '').split('\n')[0] : null,
              artifactsProduced: Object.fromEntries(
                Object.entries(built.artifacts).map(([k, v]) => [k, { exists: v.exists, size: v.size, sha256: v.sha256 ?? null }])
              ),
              linkRc: built.steps.link ? built.steps.link.rc : null,
              exec: built.steps.exec ?? null,
            },
          });
        }
      }
    }
    results.properties.push(propOut);
  }

  // ---- correspondence table: the actual deliverable of this lane ----
  results.correspondence = buildCorrespondence(results.properties);
  results.summary = summarise(results);

  const outPath = path.join(outRoot, 'second-vendor-envelope.json');
  fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
  console.log('WROTE ' + outPath);
  console.log(JSON.stringify(results.summary, null, 2));
  console.log('\n--- CORRESPONDENCE (clang-18 vs gcc-13) ---');
  for (const row of results.correspondence.rows) {
    console.log(
      [row.propertyId.padEnd(20), row.opt.padEnd(4), (row.mitigation ? 'mit-on ' : 'mit-off'),
       row.clang.padEnd(22), row.gcc.padEnd(22), row.category].join(' | ')
    );
  }
  console.log('\n--- CATEGORY TOTALS ---');
  console.log(JSON.stringify(results.correspondence.totals, null, 2));
}

function buildCorrespondence(properties) {
  const rows = [];
  const totals = {};
  for (const prop of properties) {
    const byKey = new Map();
    for (const c of prop.cells) byKey.set(`${c.vendor}|${c.opt}|${c.mitigation.on}`, c);
    for (const opt of ['-O0', '-O1', '-O2', '-O3']) {
      for (const mitOn of [false, true]) {
        const clang = byKey.get(`clang-18|${opt}|${mitOn}`);
        const gcc = byKey.get(`gcc-13|${opt}|${mitOn}`);
        const cs = clang ? clang.state : 'NOT_OBSERVED';
        const gs = gcc ? gcc.state : 'NOT_OBSERVED';
        const category = categorise(cs, gs);
        totals[category] = (totals[category] || 0) + 1;
        rows.push({
          propertyId: prop.propertyId,
          opt,
          mitigation: mitOn,
          mitigationName: prop.mitigation,
          clang: cs,
          gcc: gs,
          category,
        });
      }
    }
  }
  return {
    definitions: {
      'both-preserved': 'the property survived under both vendors in this configuration',
      'both-lost': 'the property was removed under both vendors in this configuration',
      'clang-preserved-gcc-lost': 'VENDOR-DEPENDENT. The configuration protects the property under clang and does not protect it under gcc.',
      'clang-lost-gcc-preserved': 'VENDOR-DEPENDENT, opposite direction.',
      indeterminate: 'at least one side was not in {PRESERVED, LOST}; the pair says nothing and is excluded from vendor-dependence counts',
    },
    rows,
    totals,
  };
}

function categorise(cs, gs) {
  const decided = (s) => s === 'PRESERVED' || s === 'LOST';
  if (!decided(cs) || !decided(gs)) return 'indeterminate';
  if (cs === 'PRESERVED' && gs === 'PRESERVED') return 'both-preserved';
  if (cs === 'LOST' && gs === 'LOST') return 'both-lost';
  if (cs === 'PRESERVED' && gs === 'LOST') return 'clang-preserved-gcc-lost';
  return 'clang-lost-gcc-preserved';
}

function summarise(results) {
  const byVendor = {};
  for (const prop of results.properties) {
    for (const c of prop.cells) {
      const v = (byVendor[c.vendor] ||= { total: 0, states: {}, controlBlind: 0 });
      v.total += 1;
      v.states[c.state] = (v.states[c.state] || 0) + 1;
      if (c.positiveControl.verdict !== 'PRESENT') v.controlBlind += 1;
    }
  }
  const totalCells = Object.values(byVendor).reduce((a, v) => a + v.total, 0);
  return {
    totalCells,
    byVendor,
    passLevelAttribution: {
      'clang-18': 'NOT_OBSERVED in this run (asm instrument used for symmetry)',
      'gcc-13': 'UNSUPPORTED (no LLVM pass plugin under gcc)',
    },
    machinesUsed: 1,
    machineAxis: 'UNSUPPORTED',
  };
}

main();
