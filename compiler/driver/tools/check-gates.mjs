#!/usr/bin/env node
// Run the driver's two policy gates over a set of policies, without compiling
// anything.
//
//   node tools/check-gates.mjs <policy-or-directory>... [--allow-empty]
//                              [--catalogue <path>] [--mode c|cxx] [--quiet]
//
// Gate 1 — the toolchain pin covers the binary that would actually run.
// Gate 2 — every `policy.properties[]` entry exists in the catalogue, agrees
//          with it on kind, and has an implemented extractor at a checkpoint
//          the policy asked for.
//
// THE COUNTING CONTRACT
//
// The last line is always `inputs=N checked=N skipped=S`, and `inputs=0` is a
// FAILURE unless `--allow-empty` was passed. A scan that found nothing and
// said so cheerfully is the failure this repository keeps re-learning: pointed
// at the wrong directory, it reports a clean tree it never opened. `--quiet`
// silences the per-policy lines and never the counting line.
//
// A policy that cannot be read is a failure, not a skip. `skipped` is
// incremented only for a case an environment variable explicitly authorises,
// and every such case is listed by name before the counting line.

import { readdirSync, statSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';

import { loadPolicy, pinPath } from '../lib/policy.mjs';
import { CATALOGUE_PATH, CATALOGUE_RECORD_PATH, checkProperties, countingLine, loadCatalogue } from '../lib/properties.mjs';
import { loadPin, reconcileCompiler, resolveCompiler } from '../lib/toolchain.mjs';

const EXIT_OK = 0;
const EXIT_FINDINGS = 2;
const EXIT_INCOMPLETE = 3;
const EXIT_INTEGRITY = 4;

/** Names the caller has explicitly authorised skipping, via the environment. */
const AUTHORISED_SKIPS = new Set(
  String(process.env.VG_CHECK_GATES_SKIP ?? '').split(',').map((s) => s.trim()).filter(Boolean),
);

function parseArgs(argv) {
  const out = { paths: [], allowEmpty: false, catalogue: CATALOGUE_PATH, mode: 'c', quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--allow-empty') out.allowEmpty = true;
    else if (a === '--quiet') out.quiet = true;
    else if (a === '--catalogue') out.catalogue = argv[++i];
    else if (a === '--mode') out.mode = argv[++i];
    else if (a.startsWith('-')) throw new Error(`unknown argument ${a}`);
    else out.paths.push(a);
  }
  if (out.mode !== 'c' && out.mode !== 'cxx') throw new Error(`--mode must be c or cxx, got ${out.mode}`);
  return out;
}

/** Every `.vgpolicy.json` under `p`, or `p` itself when it is a file. */
function collectPolicies(p) {
  const abs = resolve(p);
  let st;
  try {
    st = statSync(abs);
  } catch (err) {
    throw new Error(`${p}: ${err.code ?? 'cannot stat'}`);
  }
  if (st.isFile()) return [abs];
  const found = [];
  const walk = (dir) => {
    for (const ent of readdirSync(dir, { withFileTypes: true })) {
      const child = join(dir, ent.name);
      if (ent.isDirectory()) walk(child);
      else if (ent.isFile() && ent.name === '.vgpolicy.json') found.push(child);
    }
  };
  walk(abs);
  return found;
}

function checkOne(policyFile, { catalogue, mode }) {
  const problems = [];
  const loaded = loadPolicy({ cwd: dirname(policyFile), policyPath: policyFile });
  if (!loaded.ok) {
    return { ok: false, severity: EXIT_INTEGRITY, problems: [`policy ${loaded.reason}: ${loaded.detail}`] };
  }
  const { policy } = loaded;

  // Gate 1.
  const pinFile = pinPath(policy, loaded.dir);
  let severity = EXIT_OK;
  if (pinFile === null) {
    problems.push('pin: not configured — nothing constrains which compiler runs');
    severity = Math.max(severity, EXIT_INCOMPLETE);
  } else {
    const pinLoad = loadPin(pinFile);
    if (!pinLoad.ok) {
      problems.push(`pin ${pinLoad.reason}: ${pinLoad.detail}`);
      severity = Math.max(severity, EXIT_INTEGRITY);
    } else {
      const compiler = resolveCompiler({ mode, pin: pinLoad.pin, override: null });
      const rec = reconcileCompiler({ pin: pinLoad.pin, compiler, cwd: loaded.dir });
      if (rec.status !== 'in-pin') {
        problems.push(`pin ${rec.status}: ${rec.detail}`);
        severity = Math.max(severity, EXIT_INTEGRITY);
      }
    }
  }

  // Gate 2.
  const props = checkProperties(policy.properties, catalogue);
  for (const f of props.findings) problems.push(`${f.id}: ${f.detail}`);
  if (!props.complete) severity = Math.max(severity, EXIT_INCOMPLETE);

  return { ok: problems.length === 0, severity, problems, properties: props };
}

function main(argv) {
  const args = parseArgs(argv);

  const catalogueLoad = loadCatalogue(args.catalogue);
  if (!catalogueLoad.ok) {
    process.stderr.write(`check-gates: ${CATALOGUE_RECORD_PATH} ${catalogueLoad.reason}: ${catalogueLoad.detail}\n`);
    process.stdout.write(`${countingLine({ inputs: 0, checked: 0, skipped: 0 })}\n`);
    return EXIT_INCOMPLETE;
  }

  const policies = [];
  for (const p of args.paths) policies.push(...collectPolicies(p));

  const inputs = policies.length;
  let checked = 0;
  let worst = EXIT_OK;
  const skippedNames = [];

  for (const policyFile of policies) {
    const label = basename(dirname(policyFile));
    if (AUTHORISED_SKIPS.has(label)) {
      skippedNames.push(label);
      continue;
    }
    const r = checkOne(policyFile, { catalogue: catalogueLoad.catalogue, mode: args.mode });
    checked += 1;
    worst = Math.max(worst, r.severity);
    if (!args.quiet) {
      const head = r.ok ? 'ok  ' : 'BAD ';
      process.stdout.write(`${head}${label}/.vgpolicy.json properties=${r.properties ? r.properties.verdict : 'n/a'}\n`);
      for (const problem of r.problems) process.stdout.write(`      ${problem}\n`);
    }
  }

  for (const name of skippedNames) {
    process.stdout.write(`skip ${name} — authorised by VG_CHECK_GATES_SKIP\n`);
  }
  process.stdout.write(`${countingLine({ inputs, checked, skipped: skippedNames.length })}\n`);

  if (inputs === 0) {
    if (args.allowEmpty) return EXIT_OK;
    process.stderr.write('check-gates: nothing was scanned. A scan of nothing is not a clean scan; '
      + 'pass --allow-empty if an empty input really is the expected case.\n');
    return EXIT_INCOMPLETE;
  }
  return worst;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (err) {
  process.stderr.write(`check-gates: ${err.message}\n`);
  process.exitCode = EXIT_FINDINGS;
}
