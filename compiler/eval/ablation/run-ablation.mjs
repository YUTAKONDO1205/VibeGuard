#!/usr/bin/env node
// the design plan section 24 — the A–I ablation, run rather than estimated.
//
//   node compiler/eval/ablation/run-ablation.mjs \
//        --lab $LAB \
//        --out $LAB/_results-wave2/ablation
//
// Options
//   --lab <dir>        the measurement workspace: fixtures/, scripts/lib/, _work/
//   --out <dir>        where the result JSON goes. Created; never an existing
//                      results directory of another run
//   --fixtures a,b     restrict to these fixture ids
//   --opts -O0,-O2     restrict to these optimisation levels
//   --compilers c,d    restrict to these compilers
//   --skip-tamper      do not run the component-F matrix
//
// Nothing here decides what a component is; that is configs.mjs. Nothing here
// decides what a loss is; that is oracle.mjs. This file walks cells, calls
// gates, and writes down what came back — including the words for "could not
// be run" and "does not answer this question", which are not the same word and
// are never merged.

import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { COMPONENTS, CONFIGURATIONS, combine } from './lib/configs.mjs';
import { GROUND_TRUTH, groundTruth, score, emptyTally, recall, falseAlarmRate } from './lib/oracle.mjs';
import {
  makeSourceGate, makeAstGate, makeIrPrePostGate, makePassTrackingGate,
  makeObjectLinkGate, makeEvidenceGate,
} from './lib/gates.mjs';
import { runTamperMatrix } from './lib/tamper.mjs';
import { runControls } from './lib/controls.mjs';

/* ---------------------------------------------------------------- args -- */

function parseArgs(argv) {
  const o = { fixtures: null, opts: null, compilers: null, skipTamper: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--lab') o.lab = argv[++i];
    else if (a === '--out') o.out = argv[++i];
    else if (a === '--fixtures') o.fixtures = argv[++i].split(',');
    else if (a === '--opts') o.opts = argv[++i].split(',');
    else if (a === '--compilers') o.compilers = argv[++i].split(',');
    else if (a === '--skip-tamper') o.skipTamper = true;
    else if (a === '--repo') o.repo = argv[++i];
    else if (a === '--observer') o.observer = argv[++i];
    else if (a === '--ast-plugin') o.astPlugin = argv[++i];
    else if (a === '--pubkey') o.pubkey = argv[++i];
    else if (a === '--cli') o.cli = argv[++i];
    else throw new Error(`unknown argument: ${a}`);
  }
  if (!o.lab) throw new Error('--lab is required: the measurement workspace holding fixtures/ and scripts/lib/');
  if (!o.out) throw new Error('--out is required');
  return o;
}

const args = parseArgs(process.argv.slice(2));
const HERE = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const REPO = args.repo || path.resolve(HERE, '..', '..', '..');
const LAB = path.resolve(args.lab);
const OUT = path.resolve(args.out);
const WORK = path.join(OUT, '_work');

const OBSERVER_SO = args.observer || path.join(process.env.HOME || '/root', 'vg-build', 'observer-mainverify', 'libPropertyObserver.so');
const AST_PLUGIN_SO = args.astPlugin || path.join(process.env.HOME || '/root', 'vg-build', 'clang-plugin', 'libIntentGate.so');
const CLI = args.cli || path.join(REPO, 'apps', 'cli', 'dist', 'index.js');
const LEXSCAN = path.join(REPO, 'compiler', 'clang-plugin', 'tools', 'lexscan.mjs');
const AST_RULES = path.join(REPO, 'compiler', 'clang-plugin', 'rules', 'default-rules.json');
const PUBKEY = args.pubkey || path.join(process.env.HOME || '/root', '.evidence-keys', 'evidence-ed25519.pub');
const VERIFIER = path.join(LAB, 'scripts', 'evidence-verify.mjs');

/* ------------------------------------------------- workspace libraries -- */
//
// The compile driver and the property predicate are imported from the
// measurement workspace rather than reimplemented. Reimplementing the predicate
// would mean this harness scored gates against a *different* question from the
// one the rest of the experiment asks, and the two sets of numbers could not be
// put in the same paragraph. The dependency is declared, not hidden: if the
// workspace is not there, the run stops here.

const libUrl = (f) => pathToFileURL(path.join(LAB, 'scripts', 'lib', f)).href;
let compileLib;
let predicateLib;
let runLib;
try {
  compileLib = await import(libUrl('compile.mjs'));
  predicateLib = await import(libUrl('predicates.mjs'));
  runLib = await import(libUrl('run.mjs'));
} catch (e) {
  console.error(
    `cannot load the measurement workspace libraries from ${path.join(LAB, 'scripts', 'lib')}: ${e.message}\n` +
    'This harness drives the existing components; it does not carry its own copy of the compile driver ' +
    'or the property predicate.',
  );
  process.exit(3);
}
const { buildCell, enumerateCells, referenceCell, ensureWork } = compileLib;
const { evaluate, PREDICATE_VERSION } = predicateLib;
const { run, toolchainProvenance } = runLib;

/* --------------------------------------------------------------- setup -- */

mkdirSync(OUT, { recursive: true });
mkdirSync(WORK, { recursive: true });
ensureWork();

const gates = {
  sourceGate: makeSourceGate({ run, cliPath: CLI }),
  astGate: makeAstGate({ run, lexscanPath: LEXSCAN, rulesPath: AST_RULES, pluginSo: AST_PLUGIN_SO, workRoot: WORK }),
  irPrePost: makeIrPrePostGate(),
  passTracking: makePassTrackingGate({ run, observerSo: OBSERVER_SO, workRoot: WORK }),
  objectLink: makeObjectLinkGate({ run }),
  evidenceVerifier: makeEvidenceGate(),
};

const LAYERS = { preprocess: 'text', ast: 'ast', 'ir-pre': 'ir', 'ir-post': 'ir', asm: 'asm' };

function loadFixtures() {
  const dir = path.join(LAB, 'fixtures');
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const mf = path.join(dir, name, 'manifest.json');
    if (!existsSync(mf)) continue;
    const manifest = JSON.parse(readFileSync(mf, 'utf8'));
    if (args.fixtures && !args.fixtures.includes(manifest.fixtureId)) continue;
    out.push({ dir: path.join(dir, name), manifest });
  }
  return out;
}

function selectedCells(manifest) {
  return enumerateCells(manifest).filter(
    (c) => (!args.opts || args.opts.includes(c.opt)) && (!args.compilers || args.compilers.includes(c.compiler)),
  );
}

/* ---------------------------------------------------------------- run --- */

const cells = [];
const coverage = { fixtures: [], artifactOnlyFixtures: [] };
// Contexts for the harness's own controls, one per property family. Chosen from
// cells where the pass observer succeeded, so the deliberate breakages are shown
// against a background that works. One per family because what a fictional
// symbol list does to the oracle depends on the family's extractor.
const controlContexts = new Map();

for (const { dir, manifest } of loadFixtures()) {
  const properties = manifest.properties || [];

  // An artifact-only fixture has no compiled property. Only the artefact-level
  // component has anything to say about it, and it is walked separately so that
  // its cells never enter a recall denominator built from property losses.
  if (properties.length === 0) {
    coverage.artifactOnlyFixtures.push(manifest.fixtureId);
    for (const cell of selectedCells(manifest)) {
      const built = buildCell(dir, manifest, cell);
      const exe = built.artifacts.executable ? path.resolve(LAB, built.artifacts.executable.path) : null;
      const e = gates.objectLink({ manifest, prop: {}, artifactPath: exe });
      cells.push({
        fixtureId: manifest.fixtureId,
        propertyId: null,
        propertyKind: 'artifact-markers',
        cellId: cell.cellId,
        compiler: cell.compiler,
        opt: cell.opt,
        mitigation: { name: cell.mitigationName, on: cell.mitigationOn },
        groundTruth: {
          state: 'NOT_APPLICABLE',
          reason:
            'this fixture declares artefact markers, not a compiled property. There is no assembly-layer ' +
            'oracle for it, so it is reported and never scored',
        },
        gates: { objectLink: e },
        configurations: {},
      });
      console.log(`${manifest.fixtureId.padEnd(12)} ${cell.cellId.padEnd(28)} artifact-only  E=${e.result}`);
    }
    continue;
  }

  coverage.fixtures.push(manifest.fixtureId);
  const ref = referenceCell(manifest);
  const refBuilt = buildCell(dir, manifest, ref);

  for (const prop of properties) {
    const baselineAsm = evaluate({ layer: 'asm', text: refBuilt.layers.asm, spec: prop });

    for (const cell of selectedCells(manifest)) {
      const built = buildCell(dir, manifest, cell);
      const readings = {};
      for (const [cp, layer] of Object.entries(LAYERS)) {
        readings[cp] = evaluate({ layer, text: built.layers[cp], spec: prop });
      }
      const truth = groundTruth(readings.asm, baselineAsm);
      const exe = built.artifacts.executable ? path.resolve(LAB, built.artifacts.executable.path) : null;

      const results = {
        sourceGate: gates.sourceGate({ fixtureDir: dir, prop }),
        astGate: gates.astGate({ fixtureDir: dir, manifest, cell, prop }),
        irPrePost: gates.irPrePost({ readings }),
        passTracking: gates.passTracking({ fixtureDir: dir, manifest, cell, prop }),
        objectLink: gates.objectLink({ manifest, prop, artifactPath: exe }),
        evidenceVerifier: gates.evidenceVerifier(),
      };

      if (!controlContexts.has(prop.family) && cell.compiler.startsWith('clang') && truth.state === GROUND_TRUTH.LOST && results.passTracking.result === 'DETECTED') {
        controlContexts.set(prop.family, { fixtureDir: dir, manifest, prop, cell, layers: built.layers });
      }

      const configurations = {};
      for (const [id, cfg] of Object.entries(CONFIGURATIONS)) {
        const members = {};
        for (const c of cfg.components) members[c] = results[c].result;
        const combined = combine(members);
        const explanations = cfg.components
          .map((c) => results[c].explanation)
          .filter(Boolean);
        configurations[id] = {
          result: combined,
          members,
          explainedBy: explanations.length ? explanations : null,
          score: score(combined, truth.state),
        };
      }

      cells.push({
        fixtureId: manifest.fixtureId,
        propertyId: prop.propertyId,
        propertyKind: prop.kind,
        family: prop.family,
        cellId: cell.cellId,
        compiler: cell.compiler,
        opt: cell.opt,
        mitigation: { name: cell.mitigationName, on: cell.mitigationOn },
        hypothesisFirstLossStage: prop.hypothesis ? prop.hypothesis.firstLossStage : null,
        checkpointVerdicts: Object.fromEntries(
          Object.entries(readings).map(([k, v]) => [k, { verdict: v.verdict, effect: v.effect ? v.effect.count : null, forms: v.effect ? v.effect.forms : null }]),
        ),
        groundTruth: truth,
        gates: results,
        configurations,
      });

      const line = Object.entries(CONFIGURATIONS)
        .map(([id]) => `${id}:${configurations[id].result[0] === 'D' && configurations[id].result === 'DETECTED' ? 'Y' : configurations[id].result === 'NOT_DETECTED' ? 'n' : configurations[id].result === 'UNSUPPORTED' ? 'u' : configurations[id].result === 'NOT_APPLICABLE' ? '-' : '?'}`)
        .join(' ');
      console.log(`${manifest.fixtureId.padEnd(12)} ${cell.cellId.padEnd(28)} ${truth.state.padEnd(22)} ${line}`);
    }
  }
}

/* -------------------------------------------------------------- tally --- */

const scored = cells.filter((c) => c.propertyId);
const perConfiguration = {};
for (const [id, cfg] of Object.entries(CONFIGURATIONS)) {
  const t = emptyTally();
  const outcomes = {};
  let explained = 0;
  for (const c of scored) {
    const r = c.configurations[id];
    t[r.score] += 1;
    outcomes[r.result] = (outcomes[r.result] || 0) + 1;
    if (c.groundTruth.state === GROUND_TRUTH.LOST && r.explainedBy) explained += 1;
  }
  perConfiguration[id] = {
    label: cfg.label,
    components: cfg.components,
    tally: t,
    recall: recall(t),
    falseAlarmRate: falseAlarmRate(t),
    outcomes,
    // "Explained" means a component named the pass. It is counted over the
    // losses that actually happened, not over the losses the configuration
    // detected, so a configuration that detects a loss and cannot say why is
    // visible as the difference between the two columns.
    lossesExplained: explained,
    lossesTotal: scored.filter((c) => c.groundTruth.state === GROUND_TRUTH.LOST).length,
  };
}

const perComponent = {};
for (const id of Object.keys(COMPONENTS)) {
  const t = emptyTally();
  const outcomes = {};
  const unsupportedReasons = new Set();
  for (const c of scored) {
    const g = c.gates[id];
    if (!g) continue;
    t[score(g.result, c.groundTruth.state)] += 1;
    outcomes[g.result] = (outcomes[g.result] || 0) + 1;
    if (g.result === 'UNSUPPORTED') unsupportedReasons.add(g.reason);
  }
  perComponent[id] = {
    ...COMPONENTS[id],
    tally: t,
    recall: recall(t),
    falseAlarmRate: falseAlarmRate(t),
    outcomes,
    unsupportedReasons: [...unsupportedReasons],
  };
}

/* ------------------------------------------------------- controls ------- */

let harnessControls = {
  status: 'UNSUPPORTED',
  reason: 'no clang cell in this selection produced a pass-level detection, so there is no working background to break',
  runs: [],
};
if (controlContexts.size) {
  const runs = [];
  for (const [family, ctx] of controlContexts) {
    runs.push({ family, ...runControls({ run, evaluate, observerSo: OBSERVER_SO, workRoot: path.join(WORK, `controls-${family}`), ...ctx }) });
  }
  harnessControls = {
    status: 'RAN',
    allHeld: runs.every((r) => r.allHeld),
    held: runs.reduce((n, r) => n + r.controls.filter((c) => c.held).length, 0),
    total: runs.reduce((n, r) => n + r.controls.length, 0),
    runs,
  };
}

/* ------------------------------------------------------- component F ---- */

let tamper = { status: 'NOT_OBSERVED', reason: '--skip-tamper was given' };
if (!args.skipTamper) {
  const bundleRoot = path.join(LAB, '_results', 'bundles');
  const bundles = existsSync(bundleRoot) ? readdirSync(bundleRoot).sort() : [];
  if (bundles.length < 2) {
    tamper = {
      status: 'UNSUPPORTED',
      reason: `fewer than two signed bundles under ${bundleRoot}; the substitution row needs a second one`,
      rows: [],
    };
  } else {
    const preferred = bundles.find((b) => b.startsWith('erasure__clang-18__O2')) || bundles[0];
    const donor = bundles.find((b) => b !== preferred);
    tamper = runTamperMatrix({
      run,
      verifier: VERIFIER,
      bundle: path.join(bundleRoot, preferred),
      donor: path.join(bundleRoot, donor),
      pubkey: PUBKEY,
      workDir: path.join(WORK, 'tamper'),
    });
    tamper.bundle = preferred;
    tamper.donorBundle = donor;
  }
}

/* ------------------------------------------------- attempted, not used -- */
//
// Recorded so that "elf-verifier was not what produced column E" is a fact in
// the output rather than something a reader has to infer from its absence.

const attempted = [];
{
  const linkWrapper = path.join(REPO, 'compiler', 'link-wrapper', 'vg-link.mjs');
  if (existsSync(linkWrapper)) {
    const r = run('node', [linkWrapper, '--help']);
    attempted.push({
      component: 'link-wrapper',
      invocation: 'node compiler/link-wrapper/vg-link.mjs --help',
      exitCode: r.status,
      used: false,
      reason:
        'vg-link.mjs wraps one link and compares it against a policy.link document. No such policy exists for ' +
        'these fixtures, and writing one here would have meant inventing the standard the component is measured ' +
        'against. Column E therefore does not include it',
    });
  }
  const classify = path.join(REPO, 'compiler', 'elf-verifier', 'classify.mjs');
  if (existsSync(classify)) {
    const r = run('node', [classify, '--help']);
    attempted.push({
      component: 'elf-verifier',
      invocation: 'node compiler/elf-verifier/classify.mjs --help',
      exitCode: r.status,
      used: false,
      reason:
        'classify.mjs refuses to answer without a baseline keyed by (toolchain digest, flag set, link form), ' +
        'and it has no nearest-match lookup by design. Forty such baselines were not built in this run, so its ' +
        'classifier did not run and column E is the object-level call check described in gates.mjs instead',
    });
  }
}

/* -------------------------------------------------------------- write --- */

const report = {
  schemaVersion: 'ablation-v0',
  source: 'the design plan section 24 (ablation A-I)',
  generatedAt: new Date().toISOString(),
  predicateVersion: PREDICATE_VERSION,
  lab: LAB,
  toolchain: toolchainProvenance(),
  binaries: {
    vibeguardCli: { path: CLI, present: existsSync(CLI) },
    astGatePlugin: { path: AST_PLUGIN_SO, present: existsSync(AST_PLUGIN_SO) },
    passObserver: { path: OBSERVER_SO, present: existsSync(OBSERVER_SO) },
    evidenceVerifier: { path: VERIFIER, present: existsSync(VERIFIER) },
  },
  components: COMPONENTS,
  configurations: CONFIGURATIONS,
  groundTruthOracle: {
    layer: 'asm',
    rule: 'effect ABSENT in the subject while the co-resident control still shows the effect in the same text',
    sharesImplementationWith: ['astGate (no)', 'irPrePost (yes: the same predicates.mjs, at a different layer)'],
  },
  coverage,
  cellCount: cells.length,
  scoredCellCount: scored.length,
  perComponent,
  perConfiguration,
  harnessControls,
  evidenceVerifierTamperMatrix: tamper,
  attemptedNotUsed: attempted,
  notMeasured: [
    'Configuration I is not the Beyond integrated system: no beyond/ directory exists in this repository, so I is the union of the five components that do exist and is labelled as such.',
    'Column E and the ground-truth oracle ask nearly the same question one layer apart — "is the effect still in the subject at the end" — so E\'s recall is close to tautological and is not evidence that an artefact check is the best detector. Its informative columns are the nine cells it refused (VERIFICATION_INCOMPLETE) and the zero passes it named.',
    'gcc-13 cells produce no AST, no IR and no pass observation; the three clang-only components are UNSUPPORTED there rather than missing.',
    'The AST gate ran only where its rule table has an entry. Coverage is reported in perComponent.astGate.outcomes; nothing was added to the rule table for this run.',
    'Column E is an object-level call-form check written in this harness. compiler/elf-verifier and compiler/link-wrapper were invoked but not used as the detector; see attemptedNotUsed.',
    'The tamper matrix measures whether the verifier refused to call a bundle clean. Whether it named the alteration correctly is recorded per row and is not aggregated.',
    'No timing, memory or build-slowdown figure is taken here.',
  ],
  cells,
};

const outFile = path.join(OUT, 'ablation.json');
writeFileSync(outFile, JSON.stringify(report, null, 2) + '\n');

const summaryLines = [];
summaryLines.push('configuration  label                       recall      falseAlarm  tp fn fp tn excl  explained/losses');
for (const [id, r] of Object.entries(perConfiguration)) {
  const t = r.tally;
  summaryLines.push(
    `${id.padEnd(14)} ${r.label.padEnd(27)} ` +
    `${(r.recall === null ? 'n/a' : r.recall.toFixed(3)).padEnd(11)} ` +
    `${(r.falseAlarmRate === null ? 'n/a' : r.falseAlarmRate.toFixed(3)).padEnd(11)} ` +
    `${String(t.tp).padStart(2)} ${String(t.fn).padStart(2)} ${String(t.fp).padStart(2)} ${String(t.tn).padStart(2)} ${String(t.excluded).padStart(4)}  ` +
    `${r.lossesExplained}/${r.lossesTotal}`,
  );
}
summaryLines.push('');
summaryLines.push(`harness controls: ${harnessControls.status}${harnessControls.status === 'RAN' ? ` (${harnessControls.held}/${harnessControls.total} held)` : ''}`);
for (const r of harnessControls.runs || []) {
  summaryLines.push(`  on ${r.fixtureId}/${r.cell} (family ${r.family})`);
  for (const c of r.controls) {
    summaryLines.push(`    ${(c.held ? 'held' : 'DID NOT HOLD').padEnd(12)} ${c.polarity.padEnd(8)} ${c.id}`);
  }
}
summaryLines.push('');
summaryLines.push(
  `evidence-verifier tamper matrix: ${tamper.status}` +
  (tamper.status === 'RAN' ? `  detected ${tamper.detected}/${tamper.ofMutations}, negative control ${tamper.negativeControl ? tamper.negativeControl.verdict : '?'}` : `  ${tamper.reason || ''}`),
);
const summary = summaryLines.join('\n');
writeFileSync(path.join(OUT, 'summary.txt'), summary + '\n');
console.log('\n' + summary);
console.log('\nwrote %s', outFile);
