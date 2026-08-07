#!/usr/bin/env node
// intro-scan: compile a source file, subtract the toolchain baseline, and
// report what is left.
//
//   node cli/intro-scan.mjs <source>... [options]
//
//   --opt <level>          optimisation level to analyse at (default -O2)
//   --std <std>            language standard passed through
//   --cxx                  compile as C++ (inferred from the extension too)
//   --intro-policy <path>  see lib/policy.mjs for why this is its own file
//   --work <dir>           Linux-side scratch (default $HOME/vg-lab/...)
//   --json <path>          write the full classified element list
//   --allow-empty          an empty input set is the expected result
//   --quiet                only the counting line and the verdict
//
// WHAT IT DOES, IN ORDER. The order is the argument this component makes.
//
//   1. Ask the front end what it produced from this exact compilation, by
//      running it again with the optimisation pipeline disabled and the IR
//      dumped. That is the measured half of the baseline.
//   2. Compile the object the ordinary way.
//   3. Read the object: defined symbols, call-shaped relocations in executable
//      sections, .init_array slots, executable sections.
//   4. Subtract the baseline -- measured half and structural half.
//   5. Report only what neither half explains.
//
// Steps 1 and 4 are most of the work and produce no findings of their own.
// Skipping them is how a detector ends up reporting a hundred and forty-nine
// vtables, thunks and template instantiations on a file that is entirely
// normal, on every build, for ever.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

import { writeFileSync } from 'node:fs';
import { basename, extname } from 'node:path';

import { subtractBaseline, subtractionReport } from '../lib/baseline.mjs';
import { Tally } from '../lib/count.mjs';
import { normaliseElf, objectElements } from '../lib/elf.mjs';
import { EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_INTEGRITY, EXIT_OK, EXIT_TOOL_FAILED } from '../lib/exit.mjs';
import { buildFindings, failing } from '../lib/findings.mjs';
import { frontEndSetFromIr } from '../lib/irsyms.mjs';
import { emptyContext } from '../lib/origins.mjs';
import { dependencyExportMap, loadIntroPolicy, PolicyError } from '../lib/policy.mjs';
import { labDir, requireTool, runTool, toLinuxPath } from '../lib/toolchain.mjs';

function parseArgs(argv) {
  const opts = {
    sources: [], opt: '-O2', std: null, cxx: false, introPolicy: null,
    work: null, json: null, allowEmpty: false, quiet: false,
    cc: 'clang-18', cxxBin: 'clang++-18', readelf: 'llvm-readelf-18',
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--allow-empty') opts.allowEmpty = true;
    else if (a === '--quiet') opts.quiet = true;
    else if (a === '--cxx') opts.cxx = true;
    else if (a === '--opt') opts.opt = argv[++i];
    else if (a === '--std') opts.std = argv[++i];
    else if (a === '--intro-policy') opts.introPolicy = argv[++i];
    else if (a === '--work') opts.work = argv[++i];
    else if (a === '--json') opts.json = argv[++i];
    else if (a === '--cc') opts.cc = argv[++i];
    else if (a === '--cxx-bin') opts.cxxBin = argv[++i];
    else if (a === '--readelf') opts.readelf = argv[++i];
    else if (a.startsWith('--')) throw new Error(`unknown option ${a}`);
    else opts.sources.push(a);
  }
  return opts;
}

const CXX_EXT = new Set(['.cpp', '.cc', '.cxx', '.C', '.c++']);

/**
 * Analyse one translation unit.
 *
 * Every intermediate is written on the Linux side and read back over the pipe,
 * so nothing lands under compiler/ and no absolute path from this machine ends
 * up in a record.
 */
function analyseOne(source, opts, policy) {
  const isCxx = opts.cxx || CXX_EXT.has(extname(source));
  const compiler = isCxx ? opts.cxxBin : opts.cc;
  const stem = basename(source).replace(/[^A-Za-z0-9_.-]/g, '_');
  const work = opts.work ?? labDir();
  const src = toLinuxPath(source);
  const objPath = `${work}/${stem}.o`;
  const irPath = `${work}/${stem}.entry.ll`;

  const common = [opts.opt];
  if (opts.std) common.push(`-std=${opts.std}`);

  runTool('mkdir', ['-p', work]);

  // 1. the measured baseline: what the front end produced, before any pass ran.
  let frontEnd = null;
  let baselineNote = '';
  const ir = runTool(compiler, [
    ...common, '-Xclang', '-disable-llvm-passes', '-emit-llvm', '-S', src, '-o', irPath,
  ], { allowFail: true });
  if (ir.status === 0) {
    const text = runTool('cat', [irPath]).stdout;
    frontEnd = frontEndSetFromIr(text);
  } else {
    baselineNote = `the front-end dump failed (${ir.stderr.split('\n')[0]})`;
  }

  // 2. the object, compiled the ordinary way.
  const obj = runTool(compiler, [...common, '-c', src, '-o', objPath], { allowFail: true });
  if (obj.status !== 0) {
    return { source, toolFailed: true, stderr: obj.stderr };
  }

  // 3. read it.
  const elfJson = runTool(opts.readelf, [
    '--sections', '--symbols', '--relocations', '--elf-output-style=JSON', objPath,
  ]).stdout;
  const elf = normaliseElf(JSON.parse(elfJson));
  const elements = objectElements(elf, { objectName: basename(source) });

  // 4. subtract.
  const ctx = emptyContext({
    frontEnd: frontEnd ?? { functions: new Set(), globals: new Set(), aliases: new Set() },
    haveFrontEnd: frontEnd !== null,
    dependencyExports: dependencyExportMap(policy),
    haveDependencyExports: (policy.dependencies ?? []).length > 0,
    generatedSourceGlobs: policy.generatedSources ?? [],
    haveSourceAttribution: false,
  });
  const result = subtractBaseline(elements, ctx);

  // 5. report what is left.
  const { findings, incomplete } = buildFindings(result.classified, {
    policy, path: basename(source),
  });
  return { source, elf, result, findings, incomplete, baselineNote, isCxx, compiler };
}

export function main(argv, out = console) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    out.error(`intro-scan: ${e.message}`);
    return EXIT_INTEGRITY;
  }

  let policy;
  try {
    policy = loadIntroPolicy(opts.introPolicy);
  } catch (e) {
    if (e instanceof PolicyError) {
      out.error(`intro-scan: ${e.message}`);
      return EXIT_INTEGRITY;
    }
    throw e;
  }

  const tally = new Tally('intro-scan', { allowEmpty: opts.allowEmpty });
  tally.input(opts.sources.length);

  // The empty case is decided before any tool is touched, so that an empty run
  // cannot be turned green by a later step reporting nothing wrong.
  if (tally.emptyAndUnauthorised) {
    out.log(tally.render());
    out.error(tally.emptyReason());
    return EXIT_INCOMPLETE;
  }

  // Only when there is something to read. A missing tool is a failure and never
  // a skip -- but with zero inputs and `--allow-empty` there is nothing the tool
  // would have been used for, and reporting a tool failure there would say the
  // run went wrong when the caller asked for exactly this. The distinction is
  // narrow and worth being exact about: `--allow-empty` authorises an empty
  // input set, it does not authorise skipping a check that had an input.
  if (opts.sources.length > 0) {
    try {
      requireTool(opts.readelf);
    } catch (e) {
      out.log(tally.render());
      out.error(`intro-scan: ${e.message}`);
      return EXIT_TOOL_FAILED;
    }
  }

  const allFindings = [];
  const allIncomplete = [];
  let toolFailed = false;

  for (const source of opts.sources) {
    let r;
    try {
      r = analyseOne(source, opts, policy);
    } catch (e) {
      out.error(`intro-scan: ${source}: ${e.message}`);
      toolFailed = true;
      continue;
    }
    if (r.toolFailed) {
      out.error(r.stderr);
      toolFailed = true;
      continue;
    }
    tally.counted();
    if (!opts.quiet) {
      out.log(`\n--- ${basename(source)} (${r.compiler} ${opts.opt}) ---`);
      out.log(subtractionReport(r.result));
    }
    if (r.baselineNote) {
      out.error(`intro-scan: ${basename(source)}: ${r.baselineNote}; every element the `
        + 'structural rules do not explain is Unresolved, not Unexplained');
    }
    for (const f of r.findings) allFindings.push({ ...f, source: basename(source) });
    for (const i of r.incomplete) allIncomplete.push({ ...i, source: basename(source) });
    if (opts.json) {
      // Written on the caller's side of the mount on purpose: this is a report,
      // not a measurement intermediate.
      writeFileSync(opts.json, `${JSON.stringify(r.result.classified, null, 2)}\n`, 'utf8');
    }
  }

  out.log('');
  out.log(tally.render());

  for (const f of allFindings) {
    out.log(`${f.id} [${f.severity}] ${f.source}: ${f.detail}`);
  }
  for (const i of allIncomplete) {
    out.log(`INCOMPLETE ${i.source}: ${i.element} -- ${i.reason}`);
  }
  out.log(`findings=${allFindings.length} incomplete=${allIncomplete.length}`);

  if (toolFailed) return EXIT_TOOL_FAILED;
  const failed = failing(allFindings, policy);
  if (failed.length > 0) return tally.exitFor(EXIT_FINDINGS);
  if (allIncomplete.length > 0) return tally.exitFor(EXIT_INCOMPLETE);
  return tally.exitFor(EXIT_OK);
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('intro-scan.mjs')) {
  process.exit(main(process.argv.slice(2)));
}
