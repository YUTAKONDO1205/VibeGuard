#!/usr/bin/env node
/**
 * Controls for the second-vendor oracle.
 *
 * A table of PRESERVED/LOST verdicts is worth nothing until someone has shown
 * that the instrument can produce BOTH verdicts and can also refuse to produce
 * either. This file runs four controls, per property, per vendor:
 *
 *   C1 POSITIVE   a WITNESS configuration is sought for this vendor+property:
 *                 the first configuration in which the unmodified fixture reads
 *                 PRESENT for both subject and control. The search starts at the
 *                 property's reference configuration.
 *                 -> a witness must exist. If none does, the oracle is stuck at
 *                    ABSENT for this vendor and every LOST in the main table is
 *                    noise.
 *
 *                 The reference configuration is defined against clang. It is
 *                 not automatically a witness under gcc: gcc-13 folds the
 *                 signed-overflow guard away at -O0, so signedovf's reference
 *                 config (-O0/mit-off) reads ABSENT under gcc before any
 *                 optimisation level was raised. That is a finding about gcc,
 *                 not a broken oracle, and it is recorded as
 *                 referenceConfigIsWitness:false rather than silently retried.
 *
 *   C2 NEGATIVE   the defence is deleted from the source (the anchor line is
 *                 replaced by a comment) and compiled at the WITNESS
 *                 configuration
 *                 -> subject must read ABSENT. This is the red demonstration:
 *                    it proves the oracle is not stuck at PRESENT. Without it,
 *                    "PRESERVED everywhere" is indistinguishable from a detector
 *                    that always says yes.
 *
 *                 It must run at the witness, not at the reference: mutating a
 *                 configuration that already read ABSENT would "pass" by
 *                 observing ABSENT->ABSENT, which demonstrates nothing.
 *
 *   C3 CONTROL-SURVIVES  in the C2 mutant, the positive control function must
 *                 STILL read PRESENT. This separates "the defence went away"
 *                 from "the whole listing went away".
 *
 *   C4 SILENT-FAILURE  the oracle is asked for a function that does not exist
 *                 -> must return NOT_OBSERVED, never ABSENT and never LOST.
 *                    This is the vocabulary guard: an unreadable subject and an
 *                    removed subject are different findings and must stay
 *                    different words.
 *
 * Exit code: 0 all controls passed, 1 at least one failed.
 * A failure here invalidates the main table; it does not get worked around.
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { observeEffect, classifyCell, extractFunctionBody } from './lib/asm-oracle.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i += 2) out[argv[i].replace(/^--/, '')] = argv[i + 1];
  return out;
}

function run(cmd, args) {
  try {
    return { rc: 0, stdout: execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }), stderr: '' };
  } catch (e) {
    return { rc: e.status ?? null, stdout: e.stdout ? String(e.stdout) : '', stderr: e.stderr ? String(e.stderr) : String(e.message) };
  }
}

/** Reference config string looks like "clang-18/-O0/mit-off". */
function parseReference(ref) {
  const [vendorId, opt, mit] = ref.split('/');
  return { vendorId, opt, mitOn: mit === 'mit-on' };
}

/**
 * Candidate configurations to try when looking for a PRESENT witness, reference
 * configuration first.
 *
 * Order after the reference is deliberate: same optimisation level with the
 * mitigation on, then ascending optimisation levels. The witness should differ
 * from the reference by as little as possible, so that C2 exercises the oracle
 * in a configuration close to the one the main table actually cares about.
 */
function candidateConfigs(ref, opts) {
  const seen = new Set();
  const out = [];
  const push = (opt, mitOn) => {
    const k = opt + '|' + mitOn;
    if (!seen.has(k)) { seen.add(k); out.push({ opt, mitOn }); }
  };
  push(ref.opt, ref.mitOn);
  push(ref.opt, !ref.mitOn);
  for (const opt of opts) { push(opt, ref.mitOn); push(opt, !ref.mitOn); }
  return out;
}

/**
 * Delete the defence by line number, not by text.
 *
 * erasure/target.c has the identical string `memset(secret, 0, sizeof secret);`
 * on line 13 (the subject) and line 23 (the control). A text substitution would
 * have removed both and made C3 vacuous. The anchor line number is the only
 * unambiguous handle.
 */
function mutateAnchorLine(srcText, lineNo) {
  const lines = srcText.split('\n');
  const idx = lineNo - 1;
  if (idx < 0 || idx >= lines.length) throw new Error('anchor line ' + lineNo + ' out of range');
  const original = lines[idx];
  lines[idx] = '    /* [C2 red demonstration] defence deleted at source: ' + original.trim().replace(/\*\//g, '* /') + ' */';
  return { text: lines.join('\n'), original: original.trim() };
}

function compileToAsm(driver, flags, srcPath, asmPath) {
  const r = run(driver, [...flags, '-S', '-o', asmPath, srcPath]);
  let exists = false, size = 0;
  try { const st = fs.statSync(asmPath); exists = true; size = st.size; } catch {}
  return { rc: r.rc, stderrHead: (r.stderr || '').split('\n')[0], exists, size };
}

function main() {
  const args = parseArgs(process.argv);
  const fixturesRoot = args.fixtures || '$LAB/fixtures';
  const workRoot = args.work || '$LAB/_work-wave2/second-vendor-controls';
  const outRoot = args.out || '$LAB/_results-wave2/second-vendor';

  const spec = JSON.parse(fs.readFileSync(path.join(HERE, 'spec.json'), 'utf8'));
  fs.rmSync(workRoot, { recursive: true, force: true });
  fs.mkdirSync(workRoot, { recursive: true });
  fs.mkdirSync(outRoot, { recursive: true });

  const report = {
    schemaVersion: 'second-vendor-controls-v0',
    generatedAt: new Date().toISOString(),
    generator: 'compiler/eval/second-vendor/run-controls.mjs',
    purpose:
      'Demonstrate that the asm oracle can report PRESENT, can report ABSENT, and refuses to report either when it cannot read the subject. Run under BOTH vendors, because an oracle validated on one vendor says nothing about the other.',
    controls: [],
  };

  let failures = 0;

  for (const prop of spec.properties) {
    const fixtureDir = path.join(fixturesRoot, prop.fixtureId);
    const srcPath = path.join(fixtureDir, 'target.c');
    const srcText = fs.readFileSync(srcPath, 'utf8');
    const ref = parseReference(prop.referenceConfig);

    // The reference configuration fixes opt and mitigation. Vendor is varied on
    // purpose: the reference names clang, but the negative control has to be
    // demonstrated for gcc too or the gcc half of the table is unvalidated.
    for (const vendor of spec.vendors) {
      const cellDir = path.join(workRoot, prop.fixtureId, vendor.vendorId);
      fs.mkdirSync(cellDir, { recursive: true });

      // ---- C1 positive: find a configuration where this vendor shows the effect ----
      const tried = [];
      let witness = null;
      for (const cand of candidateConfigs(ref, spec.opts)) {
        const flags = [cand.opt, ...spec.commonFlags, ...(cand.mitOn ? prop.mitigation.on : prop.mitigation.off)];
        const tag = `${cand.opt.replace('-', '')}-mit-${cand.mitOn ? 'on' : 'off'}`;
        const asmPath = path.join(cellDir, `clean.${tag}.s`);
        const build = compileToAsm(vendor.driver, flags, srcPath, asmPath);
        const asm = build.exists ? fs.readFileSync(asmPath, 'utf8') : '';
        const subj = observeEffect(asm, prop.targetFn, prop.targetEffect);
        const ctl = observeEffect(asm, prop.controlFn, prop.controlEffect);
        tried.push({ opt: cand.opt, mitOn: cand.mitOn, buildRc: build.rc, subject: subj.verdict, control: ctl.verdict });
        if (subj.verdict === 'PRESENT' && ctl.verdict === 'PRESENT') {
          witness = { ...cand, flags, asm, subject: subj, control: ctl, asmBytes: build.size, buildRc: build.rc };
          break;
        }
      }

      const c1Pass = witness !== null;
      const referenceConfigIsWitness =
        c1Pass && witness.opt === ref.opt && witness.mitOn === ref.mitOn;

      // ---- C2/C3 red demonstration, at the witness configuration ----
      const mutated = mutateAnchorLine(srcText, prop.sourceAnchor.line);
      const mutPath = path.join(cellDir, 'target.mutant.c');
      fs.writeFileSync(mutPath, mutated.text);

      let c2Subject = null, c2Control = null, c2Classified = null, mutBuild = null;
      let c2Pass = false, c3Pass = false;
      if (c1Pass) {
        const mutAsmPath = path.join(cellDir, 'mutant.s');
        mutBuild = compileToAsm(vendor.driver, witness.flags, mutPath, mutAsmPath);
        const mutAsm = mutBuild.exists ? fs.readFileSync(mutAsmPath, 'utf8') : '';
        c2Subject = observeEffect(mutAsm, prop.targetFn, prop.targetEffect);
        c2Control = observeEffect(mutAsm, prop.controlFn, prop.controlEffect);
        c2Classified = classifyCell(c2Subject, c2Control);
        c2Pass = c2Subject.verdict === 'ABSENT';
        c3Pass = c2Control.verdict === 'PRESENT';
      }

      // ---- C4 silent-failure guard ----
      const guardAsm = c1Pass ? witness.asm : '';
      const bogusFn = '__vgc_no_such_function_' + prop.fixtureId;
      const c4Subject = observeEffect(guardAsm, bogusFn, prop.targetEffect);
      const c4Classified = classifyCell(c4Subject, c1Pass ? witness.control : { verdict: 'NOT_OBSERVED' });
      const c4Pass = c4Subject.verdict === 'NOT_OBSERVED' && c4Classified.state === 'NOT_OBSERVED';

      const allPass = c1Pass && c2Pass && c3Pass && c4Pass;
      if (!allPass) failures += 1;

      report.controls.push({
        propertyId: prop.propertyId,
        vendor: vendor.vendorId,
        referenceConfig: prop.referenceConfig,
        referenceConfigIsWitness,
        referenceConfigNote: referenceConfigIsWitness
          ? null
          : 'The clang-derived reference configuration does not exhibit this property under ' + vendor.vendorId +
            '. This is a measurement about the vendor, not an oracle fault; the red demonstration was moved to the first configuration that does exhibit it.',
        witnessConfig: c1Pass ? { opt: witness.opt, mitigationOn: witness.mitOn, flags: witness.flags } : null,
        configsTried: tried,
        deletedSourceLine: { line: prop.sourceAnchor.line, text: mutated.original },
        C1_positive: {
          description: 'a configuration must exist in which the unmodified subject reads PRESENT',
          witnessFound: c1Pass,
          subjectVerdict: c1Pass ? witness.subject.verdict : 'ABSENT',
          controlVerdict: c1Pass ? witness.control.verdict : 'NOT_OBSERVED',
          subjectEvidence: c1Pass ? witness.subject.evidence : [],
          asmBytes: c1Pass ? witness.asmBytes : 0,
          buildRc: c1Pass ? witness.buildRc : null,
          pass: c1Pass,
        },
        C2_negative_red: {
          description: 'defence deleted at source, witness config: subject must flip PRESENT -> ABSENT',
          ranAt: c1Pass ? { opt: witness.opt, mitigationOn: witness.mitOn } : null,
          buildRc: mutBuild ? mutBuild.rc : null,
          asmBytes: mutBuild ? mutBuild.size : 0,
          subjectVerdict: c2Subject ? c2Subject.verdict : 'NOT_RUN',
          cellStateIfScored: c2Classified ? c2Classified.state : 'NOT_RUN',
          pass: c2Pass,
        },
        C3_control_survives_mutation: {
          description: 'in the mutant, the positive control must still be PRESENT',
          controlVerdict: c2Control ? c2Control.verdict : 'NOT_RUN',
          controlEvidence: c2Control ? c2Control.evidence : [],
          pass: c3Pass,
        },
        C4_silent_failure_guard: {
          description: 'unreadable subject must be NOT_OBSERVED, never ABSENT and never LOST',
          askedFor: bogusFn,
          subjectVerdict: c4Subject.verdict, cellState: c4Classified.state,
          reason: c4Subject.reason, pass: c4Pass,
        },
        pass: allPass,
      });
    }
  }

  report.summary = {
    totalControlBlocks: report.controls.length,
    failedBlocks: failures,
    referenceConfigNotWitness: report.controls
      .filter((c) => !c.referenceConfigIsWitness)
      .map((c) => ({ propertyId: c.propertyId, vendor: c.vendor, referenceConfig: c.referenceConfig, witnessUsed: c.witnessConfig })),
    verdict: failures === 0 ? 'ALL_CONTROLS_PASSED' : 'CONTROLS_FAILED',
    meaningOfFailure:
      'A failed block means the oracle could not be shown to distinguish present from absent in that vendor/property. The corresponding rows of the main table are not evidence and must be reported as VERIFICATION_INCOMPLETE.',
  };

  const outPath = path.join(outRoot, 'second-vendor-controls.json');
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
  console.log('WROTE ' + outPath);
  for (const c of report.controls) {
    const w = c.witnessConfig ? `${c.witnessConfig.opt}/mit-${c.witnessConfig.mitigationOn ? 'on' : 'off'}` : 'NONE';
    console.log(
      [c.pass ? 'PASS' : 'FAIL', c.propertyId.padEnd(20), c.vendor.padEnd(9),
       'witness=' + w.padEnd(12),
       (c.referenceConfigIsWitness ? 'ref=witness ' : 'ref!=witness'),
       'C1=' + c.C1_positive.subjectVerdict.padEnd(8),
       'C2=' + c.C2_negative_red.subjectVerdict.padEnd(8),
       'C3=' + c.C3_control_survives_mutation.controlVerdict.padEnd(8),
       'C4=' + c.C4_silent_failure_guard.subjectVerdict].join(' | ')
    );
  }
  console.log(JSON.stringify(report.summary, null, 2));
  process.exit(failures === 0 ? 0 : 1);
}

main();
