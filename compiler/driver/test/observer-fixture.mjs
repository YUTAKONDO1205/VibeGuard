// A property observer, for the driver's fallback tests. Not a test file.
//
// This is a *fixture*, and the distinction matters. The real observer for
// `must-survive` is the C++ pass in compiler/llvm-pass/, which counts the effect
// at IR checkpoints inside the pipeline. This one is the smallest thing that can
// answer the driver's question honestly on the IR the driver hands it, so that
// the driver's own control flow — read policy.fallback, observe, recompile,
// observe again, decide — can be tested end to end against a real clang-18
// instead of against a mock that agrees with whatever it is asked.
//
// The counting rule is interfaces.md §4: count CALL SITES inside `define`
// bodies, never symbol names. A `declare` line mentions the callee and is not a
// call, and blaming the pass that finally sweeps an unused declaration is the
// classic way this measurement goes wrong.
//
// It reports a control effect alongside the property, and the driver refuses the
// whole reading if the control is not PRESENT — the fixture's `mode=control-broken`
// exists to prove that refusal is real and not decorative.
//
// Contract, as the driver invokes it:
//
//     observer --profile <-O0|-O1|…> --unit <source> --ir <path to textual IR>
//
// stdout: the subset of compiler/schema/observation.schema.json the driver reads.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const CALLSITE = (symbol) => new RegExp(
  `(?:^|\\s)(?:(?:tail|musttail|notail)\\s+)?(?:call|invoke)\\s[^;]*@${symbol.replace(/[.$]/g, '\\$&')}\\b`,
);
const DEFINE = /^define\b/;
const DECLARE = /^declare\b/;

/** Call sites to `symbol`, counted only inside a `define` body. */
export function countCallSites(irText, symbol) {
  const re = CALLSITE(symbol);
  let inBody = false;
  let sites = 0;
  let declares = 0;
  for (const raw of String(irText).split('\n')) {
    const line = raw.trim();
    if (DECLARE.test(line)) { declares += 1; continue; }
    if (DEFINE.test(line)) { inBody = true; continue; }
    if (line === '}') { inBody = false; continue; }
    if (!inBody) continue;
    if (re.test(line)) sites += 1;
  }
  return { sites, declares };
}

function arg(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null;
}

function main() {
  const argv = process.argv.slice(2);
  const mode = process.env.VG_TEST_OBSERVER_MODE ?? 'normal';
  if (mode === 'nonzero') { process.stderr.write('the fixture observer was told to fail\n'); process.exit(7); }
  // A real tool that fails says where it failed, and where is a path. The
  // driver has to keep that out of the record without losing the record.
  if (mode === 'stderr-path') {
    process.stderr.write('observer: cannot open /opt/vg/observer.cfg: No such file or directory\n');
    process.exit(5);
  }
  if (mode === 'malformed') { process.stdout.write('{"observationVersion":"observation-v0","properties":[{"id":"x"}]}\n'); return; }
  if (mode === 'not-json') { process.stdout.write('this is not a record\n'); return; }

  const irPath = arg(argv, '--ir');
  const profile = arg(argv, '--profile');
  const unit = arg(argv, '--unit');
  if (!irPath || !profile || !unit) {
    process.stderr.write(`fixture observer: expected --profile, --unit and --ir; got ${JSON.stringify(argv)}\n`);
    process.exit(2);
  }
  const ir = readFileSync(irPath, 'utf8');

  const effect = process.env.VG_TEST_OBSERVER_EFFECT ?? 'vg_authorize';
  const control = process.env.VG_TEST_OBSERVER_CONTROL ?? 'vg_control_sum';
  const id = process.env.VG_TEST_OBSERVER_PROPERTY ?? 'survive.authorization-check';

  const effectCount = countCallSites(ir, effect);
  const controlCount = countCallSites(ir, control);

  // PRESENT or LOST, from the count. Nothing here infers NOT_OBSERVED: the IR
  // was read, so the question was answered one way or the other.
  const finalState = effectCount.sites > 0 ? 'PRESENT' : 'LOST';
  const controlState = mode === 'control-broken' ? 'LOST'
    : controlCount.sites > 0 ? 'PRESENT' : 'LOST';

  process.stdout.write(`${JSON.stringify({
    observationVersion: 'observation-v0',
    profile,
    unit,
    properties: [{
      id,
      kind: 'must-survive',
      control: {
        unit: control,
        state: controlState,
        count: { callSites: controlCount.sites, oracle: 'call-site', naiveSymbolMatches: controlCount.sites + controlCount.declares },
      },
      historyComplete: mode !== 'incomplete-history',
      finalState,
      count: { callSites: effectCount.sites, oracle: 'call-site', naiveSymbolMatches: effectCount.sites + effectCount.declares },
    }],
  })}\n`);
}

// Run only when this file IS the entry point; imported by a test it is a
// library. Compared as resolved paths rather than by name, so that a test file
// that happens to end in the same basename cannot trigger it.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
