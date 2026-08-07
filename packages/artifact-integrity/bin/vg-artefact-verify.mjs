#!/usr/bin/env node
// Artefact security verifier — CLI.
//
//   node bin/vg-artefact-verify.mjs [options] <file|dir> ...
//
// THE COUNTING CONTRACT
//
// The run always prints `inputs=N checked=C skipped=S` and exits NON-ZERO when
// N is 0 unless `--allow-empty` was passed. An empty scan that reports success
// has happened three times in this repository; the guard is at the one place
// every path leaves through, `finish()` below, and `test/cli.test.mjs` runs the
// binary against an empty directory and asserts the exit code.
//
// SKIP IS NOT PASS
//
// A file that exists and cannot be read as ELF64 is INCOMPLETE (exit 3), not a
// skip. The only skip is a directory entry that does not look like an ELF at
// all when `--recursive` walked into it, and every skipped case is listed by
// name. There is no environment variable that turns a failure into a pass.

import { readdirSync, statSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyPath, exitCodeFor, EXIT_OK, EXIT_TOOL_FAILED, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_INTEGRITY } from '../src/verify.mjs';
import { STATE } from '../src/properties.mjs';

const USAGE = `vg-artefact-verify — verify a finished ELF against the artefact policy

  node bin/vg-artefact-verify.mjs [options] <file|dir> ...

Options
  --policy <file>        JSON with { require, forbidStrings, expectStrings,
                         allowedDynamicDependencies }. Same shape as
                         policy.artifact in compiler/schema/policy.schema.json.
  --require <a,b,c>      Override policy.require.
  --forbid <s>           Add a forbidden literal. Repeatable.
  --expect <s>           Add a control literal that MUST be found; if it is not,
                         the extractor is broken and the run is INCOMPLETE.
                         Repeatable.
  --allowed-lib <name>   Add an authorised DT_NEEDED. Repeatable; enables the
                         dependency check.
  --pin <sha256>         Compare the artefact digest. A mismatch is exit 4. No
                         VG-ART finding is emitted: that id is owned elsewhere.
  --fail-on <sev>        low|medium|high|critical. Default medium.
  --recursive            Walk directories.
  --allow-empty          Permit zero inputs (still prints the counts).
  --json <file>          Write the full record.
  --quiet                Counts and findings only.

Exit codes (compiler/schema/interfaces.md section 7)
  0 clean · 1 tool failed · 2 findings · 3 a check could not be completed · 4 digest/policy
`;

function parseArgs(argv) {
  const o = {
    inputs: [], policy: null, require: null, forbid: [], expect: [], allowedLibs: null,
    pin: null, failOn: 'medium', recursive: false, allowEmpty: false, json: null, quiet: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    switch (a) {
      case '-h': case '--help': o.help = true; break;
      case '--policy': o.policy = next(); break;
      case '--require': o.require = next().split(',').map((s) => s.trim()).filter(Boolean); break;
      case '--forbid': o.forbid.push(next()); break;
      case '--expect': o.expect.push(next()); break;
      case '--allowed-lib': (o.allowedLibs ??= []).push(next()); break;
      case '--pin': o.pin = next().toLowerCase(); break;
      case '--fail-on': o.failOn = next(); break;
      case '--recursive': o.recursive = true; break;
      case '--allow-empty': o.allowEmpty = true; break;
      case '--json': o.json = next(); break;
      case '--quiet': o.quiet = true; break;
      default:
        if (a.startsWith('-')) throw new Error(`unknown option ${a}`);
        o.inputs.push(a);
    }
  }
  return o;
}

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);

function looksElf(path) {
  try {
    const fd = readFileSync(path);
    return fd.length >= 4 && fd.subarray(0, 4).equals(ELF_MAGIC);
  } catch {
    return false;
  }
}

/** Expand the command line into the list of files that will be checked. */
function collect(opts) {
  const files = [];
  const skipped = [];
  const missing = [];
  for (const raw of opts.inputs) {
    const p = resolve(raw);
    let st;
    try {
      st = statSync(p);
    } catch {
      missing.push(raw);
      continue;
    }
    if (st.isDirectory()) {
      const walk = (dir) => {
        for (const e of readdirSync(dir, { withFileTypes: true })) {
          const child = join(dir, e.name);
          if (e.isDirectory()) {
            if (opts.recursive) walk(child);
            else skipped.push([child, 'directory (no --recursive)']);
          } else if (e.isFile()) {
            // A named file is always checked. A file merely *found* by walking
            // is skipped only when it carries no ELF magic — and it is listed.
            if (looksElf(child)) files.push(child);
            else skipped.push([child, 'no ELF magic']);
          }
        }
      };
      walk(p);
    } else {
      files.push(p);
    }
  }
  return { files, skipped, missing };
}

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`vg-artefact-verify: ${e.message}\n\n${USAGE}`);
    return EXIT_TOOL_FAILED;
  }
  if (opts.help) {
    process.stdout.write(USAGE);
    return EXIT_OK;
  }

  let policy = { require: [], forbidStrings: [], expectStrings: [], allowedDynamicDependencies: null };
  if (opts.policy) {
    let text;
    try {
      text = readFileSync(opts.policy, 'utf8');
    } catch (e) {
      process.stderr.write(`vg-artefact-verify: cannot read policy ${opts.policy}: ${e.message}\n`);
      return EXIT_INTEGRITY;
    }
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      process.stderr.write(`vg-artefact-verify: policy is not JSON: ${e.message}\n`);
      return EXIT_INTEGRITY;
    }
    const a = parsed.artifact ?? parsed;
    if (typeof a !== 'object' || a === null || Array.isArray(a)) {
      process.stderr.write('vg-artefact-verify: policy.artifact must be an object\n');
      return EXIT_INTEGRITY;
    }
    policy = {
      require: a.require ?? [],
      forbidStrings: a.forbidStrings ?? [],
      expectStrings: a.expectStrings ?? [],
      allowedDynamicDependencies: a.allowedDynamicDependencies ?? null,
    };
    if (!Array.isArray(policy.require) || !Array.isArray(policy.forbidStrings)) {
      process.stderr.write('vg-artefact-verify: policy.artifact.require and .forbidStrings must be arrays\n');
      return EXIT_INTEGRITY;
    }
  }
  if (opts.require) policy.require = opts.require;
  policy.forbidStrings = [...policy.forbidStrings, ...opts.forbid];
  policy.expectStrings = [...policy.expectStrings, ...opts.expect];
  if (opts.allowedLibs) policy.allowedDynamicDependencies = [...(policy.allowedDynamicDependencies ?? []), ...opts.allowedLibs];

  const { files, skipped, missing } = collect(opts);

  const results = [];
  let checked = 0;
  let worst = EXIT_OK;
  const bump = (code) => {
    // 4 > 2 > 3 > 1 > 0 in reporting weight: an integrity failure is the most
    // specific thing a run can conclude, and 3 must never be flattened to 0.
    const weight = { 0: 0, 1: 1, 3: 2, 2: 3, 4: 4 };
    if (weight[code] > weight[worst]) worst = code;
  };

  for (const raw of missing) {
    process.stderr.write(`  MISSING  ${raw} — named on the command line and not present\n`);
    bump(EXIT_INCOMPLETE);
    results.push({ path: raw, exit: EXIT_INCOMPLETE, incomplete: ['input does not exist'], findings: [] });
  }

  for (const f of files) {
    const r = verifyPath(f, policy);
    checked += 1;
    let code = exitCodeFor(r, opts.failOn);
    if (opts.pin && r.observation.sha256 && r.observation.sha256 !== opts.pin) {
      process.stdout.write(
        `  DIGEST   ${rel(f)}\n` +
        `           pinned   ${opts.pin}\n` +
        `           observed ${r.observation.sha256}\n` +
        '           (no VG-ART finding: the digest-mismatch id is owned by the evidence verifier)\n');
      code = EXIT_INTEGRITY;
    }
    bump(code);
    results.push({ path: f, exit: code, ...r });

    if (!opts.quiet) report(f, r, code);
    else for (const fi of r.findings) process.stdout.write(`  ${fi.severity.toUpperCase().padEnd(8)} ${fi.id}  ${rel(f)}  ${fi.title}\n`);
  }

  for (const [p, why] of skipped) process.stdout.write(`  SKIPPED  ${rel(p)} — ${why}\n`);

  return finish({ inputs: files.length + missing.length, checked, skipped, results, worst, opts });
}

function rel(p) {
  const r = relative(process.cwd(), p);
  return r && !r.startsWith('..' + sep) && r !== '..' ? r : p;
}

function report(f, r, code) {
  const o = r.observation;
  process.stdout.write(`\n${rel(f)}\n`);
  if (o.supported === false) {
    process.stdout.write(`  unreadable: ${o.reason}\n`);
    return;
  }
  process.stdout.write(`  sha256 ${o.sha256}\n`);
  process.stdout.write(`  form ${o.linkForm}  sections ${o.sections.length}  exec-sections ${o.executableSections.length}` +
    `  imports ${o.symbolCounts.undefined}  exports ${o.symbolCounts.exported}  needed ${o.dynamicDependencies.length}\n`);
  const p = o.properties;
  const cell = (n) => `${n}=${p[n].state}`;
  process.stdout.write('  ' + ['pie', 'nx', 'relro-full', 'stack-protector', 'fortify', 'build-id', 'no-writable-executable-section']
    .map(cell).join('  ') + '\n');
  if (p['relro-full'].level) process.stdout.write(`  relro level ${p['relro-full'].level}\n`);
  if (o.buildId) process.stdout.write(`  build-id ${o.buildId}\n`);
  if (o.initFunctions.length) {
    process.stdout.write(`  init functions ${o.initFunctions.length}: ` +
      o.initFunctions.map((e) => `${e.array}[${e.slot}]->${e.target ?? 'UNRESOLVED'}`).join(', ') + '\n');
  }
  if (o.debugSections.length) process.stdout.write(`  debug sections ${o.debugSections.join(', ')}\n`);
  for (const c of o.residueControls ?? []) {
    process.stdout.write(`  control ${JSON.stringify(c.needle)} ${c.found ? 'FOUND' : 'NOT FOUND — extractor is broken'}\n`);
  }
  for (const fi of r.findings) {
    process.stdout.write(`  ${fi.severity.toUpperCase().padEnd(8)} ${fi.id}  ${fi.title}\n           ${fi.detail}\n`);
  }
  for (const inc of r.incomplete) process.stdout.write(`  INCOMPLETE ${inc}\n`);
  process.stdout.write(`  exit ${code}\n`);
}

function finish({ inputs, checked, skipped, results, worst, opts }) {
  const findings = results.reduce((n, r) => n + (r.findings?.length ?? 0), 0);
  const incomplete = results.reduce((n, r) => n + (r.incomplete?.length ?? 0), 0);

  process.stdout.write(`\ninputs=${inputs} checked=${checked} skipped=${skipped.length}\n`);
  process.stdout.write(`findings=${findings} incomplete=${incomplete}\n`);
  if (skipped.length > 0) {
    process.stdout.write('skipped cases, by name:\n');
    for (const [p, why] of skipped) process.stdout.write(`  ${rel(p)} — ${why}\n`);
  }

  if (opts.json) {
    writeFileSync(opts.json, JSON.stringify({
      inputs, checked, skipped: skipped.map(([p, why]) => ({ path: rel(p), why })), results,
    }, null, 2) + '\n');
  }

  // THE GUARD. Every path out of this program passes here.
  if (inputs === 0 && !opts.allowEmpty) {
    process.stderr.write('vg-artefact-verify: nothing was checked. An empty scan is not a pass; ' +
      'pass --allow-empty if zero inputs is genuinely what you meant.\n');
    return EXIT_INCOMPLETE;
  }
  return worst;
}

// Run only when this file IS the program. Without the guard, importing `main`
// from a test would execute a scan with the test runner's own argv — which is
// zero inputs, and would set the runner's exit code to 3.
const invokedDirectly =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) process.exitCode = main(process.argv.slice(2));

export { main, parseArgs, collect, STATE };
