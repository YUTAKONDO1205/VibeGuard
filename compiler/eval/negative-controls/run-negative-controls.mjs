#!/usr/bin/env node
// Corpus-level Negative Controls for introduction detection (the design plan section 23.1).
//
//   node compiler/eval/negative-controls/run-negative-controls.mjs [options]
//
//   --only <id>[,<id>...]  run a subset (nc01, pc01, ...)
//   --results <dir>        where the JSON goes. Written through the
//                          distribution, never over the mount.
//   --no-write             do not write JSON at all
//   --crosscheck           additionally run the shipped cli/intro-scan.mjs on
//                          every case it can take, and compare
//   --quiet                one line per case
//
// WHAT THIS IS FOR. VG-INTRO-001..004 report elements that appeared in an object
// with no permitted origin. That is the detector with the highest false-positive
// exposure in the component, because *most* of what appears in an object has no
// line of source behind it: compiling one small C++ file produces around two
// hundred elements the source never names, and every one of them is normal
// compiler output.
//
// So the question this runner answers is not "does the detector fire" -- the
// positive controls answer that -- but "does it stay silent on seven separate
// kinds of ordinary compiler output, each isolated so that a failure names the
// kind that caused it". A detector that cannot do that is a machine for accusing
// the compiler of doing its job.
//
// THREE THINGS THIS RUNNER REFUSES TO CONFLATE, because each is a way a green
// result can be worthless:
//
//   1. Clean because nothing was found, vs clean because nothing was looked at.
//      Every case declares the structure it exists to exercise, as a predicate
//      over the elements actually read out of the object. If nc02's object holds
//      no `_ZTV`, the case FAILS with "the fixture no longer exercises its
//      structure" -- it does not pass quietly. This is the failure mode -O2
//      introduces for free: inline everything, and the fixture's subject
//      disappears while its verdict stays green.
//
//   2. Clean because the detector is right, vs clean because the detector is
//      dead. Positive controls are compiled with the *same compiler and the same
//      flags* as the negative controls they are paired with, in the same run. A
//      configuration in which the negative controls are clean and the paired
//      positive control is also clean is reported as NOT ESTABLISHED.
//
//   3. Explained, vs not decidable. `Unresolved` is not `Explained`. A case with
//      Unresolved elements does not pass, and every one of them is listed.
//
// WHY THIS DOES NOT SHELL OUT TO cli/intro-scan.mjs. It would be the obvious
// thing, and it nearly works: that CLI takes `--opt` and `--std` and nothing
// else, so there is no way to ask it for `-fsanitize=address`. Sanitizer
// instrumentation is precisely the negative control that matters most here,
// because it is the only one in this corpus that the *measured* half of the
// baseline cannot see -- AddressSanitizer is an LLVM pass, so it runs after the
// front-end dump is taken and everything it adds is, to the baseline, something
// that appeared out of nowhere. Rather than edit a shipped CLI to suit an
// experiment, this runner drives the same library modules that CLI drives, so
// the detector under test is the shipped one. The equivalence is checked rather
// than asserted: `--crosscheck` runs cli/intro-scan.mjs on every case that needs
// no extra flag and compares the counts.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

import { spawnSync } from 'node:child_process';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { subtractBaseline } from '../../pass-instrumentation/introduction/lib/baseline.mjs';
import { normaliseElf, objectElements } from '../../pass-instrumentation/introduction/lib/elf.mjs';
import { buildFindings, failing } from '../../pass-instrumentation/introduction/lib/findings.mjs';
import { frontEndSetFromIr } from '../../pass-instrumentation/introduction/lib/irsyms.mjs';
import { emptyContext } from '../../pass-instrumentation/introduction/lib/origins.mjs';
import { DEFAULT_INTRO_POLICY } from '../../pass-instrumentation/introduction/lib/policy.mjs';
import {
  labDir, requireTool, runTool, toLinuxPath,
} from '../../pass-instrumentation/introduction/lib/toolchain.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SUBJECTS = join(HERE, 'subjects');
const INTRO_SCAN = join(HERE, '..', '..', 'pass-instrumentation', 'introduction', 'cli', 'intro-scan.mjs');
const DEFAULT_RESULTS = '$LAB/_results-wave2/negative-controls';

// --- the matrix ------------------------------------------------------------
//
// `requires` is the anti-vacuity check: [label, regexp] pairs -- optionally
// [label, regexp, {opts}] -- tested against `kind:name` over every element read
// out of the object. A missing shape fails the case, because a fixture whose
// subject was optimised away is not a passing negative control, it is an unrun
// one.
//
// The optional third element restricts a requirement to the optimisation levels
// at which the structure survives. There are two such entries and each carries
// its measurement next to it. The bar for using one is that the *compiler*, not
// the detector, is demonstrably the reason the shape is absent -- established by
// looking at the front-end IR for the same compilation, which contains the shape
// in both cases below. It is not a way to make a failing case pass: a
// requirement is never dropped because the detector reported something.
//
// `expect`:
//   'clean'    Unexplained = 0, Unresolved = 0, findings = 0. Anything else is
//              a false positive and is reported as one.
//   'findings' at least one finding. Silence here means the detector is off.
//   'probe'    recorded, never scored. See pc03.

const CASES = [
  {
    id: 'nc01', kind: 'negative', structure: 'template instantiation',
    source: 'nc01_template_instantiation.cpp', lang: 'c++', std: 'c++17',
    opts: ['-O0', '-O2'], expect: 'clean',
    requires: [['a template instantiation', /^symbol:_Z[^:]*[A-Za-z0-9_]I[A-Za-z_0-9]/]],
  },
  {
    id: 'nc02', kind: 'negative', structure: 'vtable',
    source: 'nc02_vtable.cpp', lang: 'c++', std: 'c++17',
    opts: ['-O0', '-O2'], expect: 'clean',
    requires: [
      ['a virtual table', /^symbol:_ZTV/],
      ['a typeinfo object', /^symbol:_ZTI/],
      ['a typeinfo name', /^symbol:_ZTS/],
    ],
  },
  {
    id: 'nc03', kind: 'negative', structure: 'RTTI',
    source: 'nc03_rtti.cpp', lang: 'c++', std: 'c++17',
    opts: ['-O0', '-O2'], expect: 'clean',
    requires: [
      ['a call to __dynamic_cast', /^extcall:__dynamic_cast$/],
      ['a typeinfo object', /^symbol:_ZTI/],
    ],
  },
  {
    id: 'nc04', kind: 'negative', structure: 'lambda',
    source: 'nc04_lambda.cpp', lang: 'c++', std: 'c++17',
    opts: ['-O0', '-O2'], expect: 'clean',
    requires: [["a lambda's call operator", /^symbol:_Z.*(Ul.*E_|\$_\d)/]],
  },
  {
    id: 'nc05', kind: 'negative', structure: 'thunk',
    source: 'nc05_thunk.cpp', lang: 'c++', std: 'c++17',
    opts: ['-O0', '-O2'], expect: 'clean',
    requires: [
      ['a non-virtual thunk', /^symbol:_ZThn/],
      ['a covariant-return thunk', /^symbol:_ZTc/],
      // -O0 only, and the compiler is the reason. Measured: the front-end dump
      // for this compilation (`-Xclang -disable-llvm-passes -emit-llvm`)
      // contains `_ZTv` names at BOTH -O0 and -O2 -- 17 matching lines either
      // way -- and the -O2 object contains none, so the optimisation pipeline
      // discarded the linkonce_odr virtual thunks after the front end emitted
      // them. The fixture still produces the structure at -O2; the pipeline
      // removes it. Requiring it there would be requiring the compiler not to
      // optimise.
      ['a virtual thunk', /^symbol:_ZTv/, { opts: ['-O0'] }],
    ],
  },
  {
    id: 'nc06', kind: 'negative', structure: 'static initializer',
    source: 'nc06_static_initializer.cpp', lang: 'c++', std: 'c++17',
    opts: ['-O0', '-O2'], expect: 'clean',
    requires: [
      ['a translation-unit static-init entry', /^symbol:_GLOBAL__sub_I_/],
      // -O0 only, and the compiler is the reason: at -O2 clang inlines every
      // __cxx_global_var_init body into the single _GLOBAL__sub_I_ entry, so no
      // correct build at that level contains one. Measured on this fixture.
      ['a dynamic initialiser body', /^symbol:__cxx_global_var_init/, { opts: ['-O0'] }],
      ['a guard variable', /^symbol:_ZGV/],
      ['an .init_array slot', /^initialiser:/],
    ],
  },
  {
    id: 'nc07n', kind: 'negative', structure: 'the sanitizer subject, with no sanitizer',
    source: 'nc07_sanitizer.c', lang: 'c', std: null,
    opts: ['-O0', '-O2'], expect: 'clean',
    // The lane control for nc07/nc07u. Same source, no instrumentation: it
    // separates "the sanitizer pass introduced something the baseline cannot
    // explain" from "this source introduced it", which is a distinction the two
    // instrumented cases cannot make on their own.
    requires: [['the control function', /^symbol:nc07_control_sum$/]],
  },
  {
    id: 'nc07', kind: 'negative', structure: 'sanitizer instrumentation (ASan)',
    source: 'nc07_sanitizer.c', lang: 'c', std: null,
    opts: ['-O0', '-O2'], extra: ['-fsanitize=address', '-fno-omit-frame-pointer'],
    expect: 'clean',
    requires: [
      ["AddressSanitizer's module initialiser", /^symbol:asan\.module_ctor$/],
      ['a call into the AddressSanitizer runtime', /^extcall:__asan_/],
    ],
  },
  {
    id: 'nc07u', kind: 'negative', structure: 'sanitizer instrumentation (UBSan)',
    source: 'nc07_sanitizer.c', lang: 'c', std: null,
    opts: ['-O0', '-O2'], extra: ['-fsanitize=undefined'],
    expect: 'clean',
    requires: [['a call into the UndefinedBehaviorSanitizer runtime', /^extcall:__ubsan_/]],
  },

  // --- positive controls, one per configuration family ---------------------
  {
    id: 'pc01x', kind: 'positive', structure: 'unexplained injection, C++ configuration',
    source: 'pc01_unexplained_injection.c', lang: 'c++', std: 'c++17', extra: ['-x', 'c++'],
    opts: ['-O0', '-O2'], expect: 'findings',
    requires: [['the injected symbol', /^symbol:pc01_injected_thunk$/]],
  },
  {
    id: 'pc01', kind: 'positive', structure: 'unexplained injection, C configuration',
    source: 'pc01_unexplained_injection.c', lang: 'c', std: null,
    opts: ['-O0', '-O2'], expect: 'findings',
    requires: [['the injected symbol', /^symbol:pc01_injected_thunk$/]],
  },
  {
    id: 'pc01a', kind: 'positive', structure: 'unexplained injection under -fsanitize=address',
    source: 'pc01_unexplained_injection.c', lang: 'c', std: null,
    opts: ['-O0', '-O2'], extra: ['-fsanitize=address', '-fno-omit-frame-pointer'],
    expect: 'findings',
    requires: [['the injected symbol', /^symbol:pc01_injected_thunk$/]],
  },
  {
    id: 'pc01u', kind: 'positive', structure: 'unexplained injection under -fsanitize=undefined',
    source: 'pc01_unexplained_injection.c', lang: 'c', std: null,
    opts: ['-O0', '-O2'], extra: ['-fsanitize=undefined'],
    expect: 'findings',
    requires: [['the injected symbol', /^symbol:pc01_injected_thunk$/]],
  },
  {
    id: 'pc02', kind: 'positive', structure: 'injection into a respectable-looking section',
    source: 'pc02_respectable_section.c', lang: 'c', std: null,
    opts: ['-O0', '-O2'], expect: 'findings',
    requires: [
      ['the injected symbol', /^symbol:pc02_injected_worker$/],
      ['the laundered section', /^section:\.text\._ZN4pc026Widget6renderEv$/],
    ],
  },

  // --- evasion probes: recorded, never scored ------------------------------
  {
    id: 'pc03', kind: 'probe', structure: 'ABI-shaped name, calling out of the object',
    source: 'pc03_abi_shaped_name.c', lang: 'c', std: null,
    opts: ['-O0', '-O2'], expect: 'probe',
    requires: [['the laundered symbol', /^symbol:_ZTV12pc03_Laundry$/]],
  },
  {
    id: 'pc04', kind: 'probe', structure: 'ABI-shaped name, making no call at all',
    source: 'pc04_abi_shaped_silent.c', lang: 'c', std: null,
    opts: ['-O0', '-O2'], expect: 'probe',
    requires: [['the laundered symbol', /^symbol:_ZTV13pc04_Silencer$/]],
  },
];

// --- one measurement -------------------------------------------------------

/**
 * Compile, take the front-end baseline from the same compilation, read the
 * object, subtract, classify. This is `analyseOne` from cli/intro-scan.mjs with
 * one addition -- `extra` compiler flags -- which is the whole reason this file
 * exists rather than a shell loop around the CLI.
 */
function measure(caseDef, opt, { work, cc, cxx, readelf, policy }) {
  const compiler = caseDef.lang === 'c++' ? cxx : cc;
  const src = toLinuxPath(join(SUBJECTS, caseDef.source));
  const stem = `${caseDef.id}_${opt.replace(/[^A-Za-z0-9]/g, '')}`;
  const objPath = `${work}/${stem}.o`;
  const irPath = `${work}/${stem}.entry.ll`;

  const common = [opt];
  if (caseDef.std) common.push(`-std=${caseDef.std}`);
  for (const f of caseDef.extra ?? []) common.push(f);

  // 1. the measured half of the baseline: what the front end produced, before
  //    any pass ran. Note what this means for nc07: AddressSanitizer is a pass,
  //    so nothing it adds is in here and the structural rules carry it alone.
  let frontEnd = null;
  let baselineNote = '';
  const ir = runTool(compiler, [
    ...common, '-Xclang', '-disable-llvm-passes', '-emit-llvm', '-S', src, '-o', irPath,
  ], { allowFail: true });
  if (ir.status === 0) {
    frontEnd = frontEndSetFromIr(runTool('cat', [irPath]).stdout);
  } else {
    baselineNote = `the front-end dump failed (${(ir.stderr || '').split('\n')[0]})`;
  }

  // 2. the object, compiled the ordinary way.
  const obj = runTool(compiler, [...common, '-c', src, '-o', objPath], { allowFail: true });
  if (obj.status !== 0) {
    return { toolFailed: true, stderr: obj.stderr, argv: common };
  }

  // 3. rc=0 is not evidence that an object exists. Ask for it.
  if (runTool('test', ['-s', objPath], { allowFail: true }).status !== 0) {
    return {
      toolFailed: true, argv: common,
      stderr: `${compiler} exited 0 but left no non-empty ${objPath}`,
    };
  }

  const elfJson = runTool(readelf, [
    '--sections', '--symbols', '--relocations', '--elf-output-style=JSON', objPath,
  ]).stdout;
  const elf = normaliseElf(JSON.parse(elfJson));
  const elements = objectElements(elf, { objectName: basename(caseDef.source) });

  // 4. subtract.
  const ctx = emptyContext({
    frontEnd: frontEnd ?? { functions: new Set(), globals: new Set(), aliases: new Set() },
    haveFrontEnd: frontEnd !== null,
  });
  const result = subtractBaseline(elements, ctx);

  // 5. findings.
  const { findings, incomplete } = buildFindings(result.classified, {
    policy, path: basename(caseDef.source),
  });

  return {
    compiler,
    argv: common,
    objPath,
    baselineNote,
    frontEndNames: frontEnd
      ? frontEnd.functions.size + frontEnd.globals.size + frontEnd.aliases.size
      : null,
    elements: result.classified,
    verdicts: result.verdicts,
    byOrigin: result.byOrigin,
    findings,
    incomplete,
  };
}

function checkRequires(caseDef, opt, elements) {
  const keys = elements.map((e) => `${e.kind}:${e.name}`);
  return (caseDef.requires ?? []).map(([label, re, restrict]) => {
    const applies = !restrict?.opts || restrict.opts.includes(opt);
    const hits = keys.filter((k) => re.test(k));
    return {
      label, pattern: String(re), applies, matched: hits.length, sample: hits.slice(0, 3),
    };
  });
}

function scoreCase(caseDef, m, requires) {
  const problems = [];
  const missing = requires.filter((r) => r.applies && r.matched === 0);
  if (missing.length > 0) {
    problems.push(`the fixture no longer exercises ${missing.map((r) => r.label).join('; ')}`);
  }
  if (m.baselineNote) problems.push(m.baselineNote);

  if (caseDef.expect === 'clean') {
    if (m.verdicts.Unexplained > 0) {
      problems.push(`FALSE POSITIVE: ${m.verdicts.Unexplained} Unexplained element(s) on normal compiler output`);
    }
    if (m.verdicts.Unresolved > 0) {
      problems.push(`${m.verdicts.Unresolved} Unresolved element(s) -- not the same as explained`);
    }
    if (m.findings.length > 0) problems.push(`${m.findings.length} finding(s)`);
  } else if (caseDef.expect === 'findings' && m.findings.length === 0) {
    problems.push('POSITIVE CONTROL SILENT: no finding on an injection the detector is '
      + 'supposed to catch, so a clean negative control in this configuration is '
      + 'indistinguishable from a dead detector');
  }
  return { pass: problems.length === 0, problems };
}

// --- the equivalence check against the shipped CLI -------------------------

function crosscheckAgainstCli(caseDef, opt, m) {
  if ((caseDef.extra ?? []).length > 0) {
    return {
      ran: false,
      reason: 'the case carries extra compiler flags, which cli/intro-scan.mjs cannot take',
    };
  }
  const args = [INTRO_SCAN, join(SUBJECTS, caseDef.source), '--opt', opt, '--quiet'];
  if (caseDef.std) args.push('--std', caseDef.std);
  if (caseDef.lang === 'c++') args.push('--cxx');
  const r = spawnSync(process.execPath, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const stdout = r.stdout ?? '';
  const line = /findings=(\d+) incomplete=(\d+)/.exec(stdout);
  if (!line) {
    return {
      ran: true, agreed: false,
      reason: 'cli/intro-scan.mjs produced no counting line',
      stderr: (r.stderr ?? '').slice(0, 400),
    };
  }
  const introScan = { findings: Number(line[1]), incomplete: Number(line[2]) };
  const thisRunner = { findings: m.findings.length, incomplete: m.incomplete.length };
  return {
    ran: true,
    agreed: introScan.findings === thisRunner.findings
      && introScan.incomplete === thisRunner.incomplete,
    exit: r.status,
    introScan,
    thisRunner,
  };
}

// --- driving ---------------------------------------------------------------

function parseArgs(argv) {
  const o = {
    only: null, results: DEFAULT_RESULTS, write: true, quiet: false, crosscheck: false,
    cc: 'clang-18', cxx: 'clang++-18', readelf: 'llvm-readelf-18',
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--only') o.only = new Set(argv[++i].split(','));
    else if (a === '--results') o.results = argv[++i];
    else if (a === '--no-write') o.write = false;
    else if (a === '--quiet') o.quiet = true;
    else if (a === '--crosscheck') o.crosscheck = true;
    else throw new Error(`unknown option ${a}`);
  }
  return o;
}

/**
 * Write on the distribution's side of the mount.
 *
 * `tee`, not `sh -c 'cat > "$1"'`. The shell form loses its positional argument
 * crossing the wsl.exe boundary -- the redirection target arrives empty and the
 * write fails with "cannot create : Directory nonexistent", which reads like a
 * missing results directory and is not one. Measured; it cost a round here.
 * `tee` takes the path as an ordinary argument, so there is no shell and nothing
 * to lose.
 */
function writeLinuxFile(path, text) {
  const r = runTool('tee', [path], { input: text, allowFail: true });
  if (r.status !== 0) throw new Error(`could not write ${path}: ${r.stderr}`);
  const check = runTool('test', ['-s', path], { allowFail: true });
  if (check.status !== 0) throw new Error(`wrote ${path} but it is empty or absent`);
}

export function main(argv, out = console) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    out.error(`negative-controls: ${e.message}`);
    return 4;
  }

  const policy = { ...DEFAULT_INTRO_POLICY, source: '(built-in defaults)' };
  const selected = CASES.filter((c) => !opts.only || opts.only.has(c.id));

  // The empty case is decided before any tool is touched, so an empty run cannot
  // be turned green by a later step reporting nothing wrong.
  if (selected.length === 0) {
    out.log('negative-controls: inputs=0 checked=0 skipped=0');
    out.error('negative-controls: no case matched. This is exit 3 (INCOMPLETE), not exit 0.');
    return 3;
  }

  const banners = {
    cc: requireTool(opts.cc), cxx: requireTool(opts.cxx), readelf: requireTool(opts.readelf),
  };
  const work = `${labDir()}/negative-controls`;
  runTool('mkdir', ['-p', work]);
  if (opts.write) runTool('mkdir', ['-p', opts.results]);

  const record = {
    tool: 'compiler/eval/negative-controls/run-negative-controls.mjs',
    purpose: 'the design plan section 23.1 Negative Controls for VG-INTRO-001..004: normal compiler output '
      + 'must not be reported as an unexplained introduction.',
    generatedAt: new Date().toISOString(),
    toolchain: banners,
    policy: 'lib/policy.mjs built-in defaults (failOn=high, externalCalls.mode=baseline). '
      + 'No per-fixture exception list and no approved-symbol list: if a negative control '
      + 'fires, that is a false positive to report, not a threshold to move.',
    cases: [],
  };

  let inputs = 0;
  let checked = 0;
  let failures = 0;
  let toolFailures = 0;

  for (const caseDef of selected) {
    for (const opt of caseDef.opts) {
      inputs += 1;
      const label = `${caseDef.id} ${opt}`;
      let m;
      try {
        m = measure(caseDef, opt, { work, ...opts, policy });
      } catch (e) {
        out.error(`FAIL ${label}: ${e.message}`);
        toolFailures += 1;
        record.cases.push({ id: caseDef.id, opt, error: String(e.message) });
        continue;
      }
      if (m.toolFailed) {
        out.error(`FAIL ${label}: the compilation failed\n${m.stderr}`);
        toolFailures += 1;
        record.cases.push({ id: caseDef.id, opt, error: 'compilation failed', stderr: m.stderr });
        continue;
      }
      checked += 1;

      const requires = checkRequires(caseDef, opt, m.elements);
      const score = scoreCase(caseDef, m, requires);
      const cross = opts.crosscheck ? crosscheckAgainstCli(caseDef, opt, m) : null;
      if (cross && cross.ran && !cross.agreed) {
        score.problems.push(`this runner and cli/intro-scan.mjs disagree: ${JSON.stringify(cross)}`);
        score.pass = false;
      }
      if (!score.pass && caseDef.expect !== 'probe') failures += 1;

      const unexplained = m.elements.filter((e) => e.verdict === 'Unexplained')
        .map((e) => ({ kind: e.kind, name: e.name, where: e.where, rule: e.rule, reason: e.reason }));
      const unresolved = m.elements.filter((e) => e.verdict === 'Unresolved')
        .map((e) => ({ kind: e.kind, name: e.name, where: e.where, rule: e.rule, reason: e.reason }));

      record.cases.push({
        id: caseDef.id,
        kind: caseDef.kind,
        structure: caseDef.structure,
        source: caseDef.source,
        opt,
        compiler: m.compiler,
        compilerArgs: m.argv,
        expect: caseDef.expect,
        pass: score.pass,
        problems: score.problems,
        frontEndBaselineNames: m.frontEndNames,
        elementCount: m.elements.length,
        verdicts: m.verdicts,
        byOrigin: m.byOrigin,
        structuresPresent: requires,
        unexplained,
        unresolved,
        findings: m.findings.map((f) => ({ id: f.id, severity: f.severity, detail: f.detail })),
        failingUnderPolicy: failing(m.findings, policy).length,
        crosscheck: cross,
      });

      const mark = caseDef.expect === 'probe' ? 'note' : (score.pass ? 'ok  ' : 'FAIL');
      out.log(`${mark} ${label.padEnd(11)} ${caseDef.structure.padEnd(50)} `
        + `elements=${String(m.elements.length).padStart(4)} `
        + `Unexplained=${m.verdicts.Unexplained} Unresolved=${m.verdicts.Unresolved} `
        + `findings=${m.findings.length}`);
      if (!opts.quiet) {
        for (const r of requires) {
          out.log(`       exercises ${r.label}: ${r.matched} match(es)`
            + `${r.applies ? '' : ' [not required at this level]'}`
            + `${r.sample.length ? ` e.g. ${r.sample[0]}` : ''}`);
        }
        for (const u of unexplained) out.log(`       Unexplained ${u.kind}:${u.name} (${u.where})`);
        for (const u of unresolved) out.log(`       Unresolved  ${u.kind}:${u.name} -- ${u.rule}`);
        for (const f of m.findings) out.log(`       ${f.id} [${f.severity}] ${f.detail.split('.')[0]}`);
        if (cross) {
          out.log(`       crosscheck vs cli/intro-scan.mjs: ${cross.ran
            ? `${cross.agreed ? 'agreed' : 'DISAGREED'} ${JSON.stringify(cross.introScan ?? cross.reason)}`
            : `not run (${cross.reason})`}`);
        }
      }
      for (const p of score.problems) out.log(`       PROBLEM ${p}`);
    }
  }

  const negatives = record.cases.filter((c) => c.kind === 'negative');
  const positives = record.cases.filter((c) => c.kind === 'positive');
  const probes = record.cases.filter((c) => c.kind === 'probe');
  const negativesClean = negatives.filter((c) => c.pass).length;
  const positivesFired = positives.filter((c) => (c.findings ?? []).length > 0).length;

  out.log('');
  out.log(`negative-controls: inputs=${inputs} checked=${checked} skipped=0`);
  out.log(`negatives=${negatives.length} clean=${negativesClean} `
    + `positives=${positives.length} fired=${positivesFired} probes=${probes.length}`);

  let verdict;
  if (toolFailures > 0) {
    verdict = 'NOT ESTABLISHED -- a compilation or a tool failed, so part of the corpus was '
      + 'never measured.';
  } else if (positives.length > 0 && positivesFired < positives.length) {
    verdict = 'NOT ESTABLISHED -- a positive control was silent, so a clean negative control '
      + 'in that configuration is indistinguishable from a dead detector.';
  } else if (negatives.length > 0 && negativesClean === negatives.length && failures === 0) {
    verdict = 'the negative controls are clean and every paired positive control fired in the '
      + 'same run, with the same compiler and the same flags.';
  } else {
    verdict = 'at least one case did not meet its expectation; see the PROBLEM lines above.';
  }
  out.log(`VERDICT: ${verdict}`);

  record.summary = {
    inputs,
    checked,
    failures,
    toolFailures,
    negatives: negatives.length,
    negativesClean,
    positives: positives.length,
    positivesFired,
    probes: probes.length,
    verdict,
  };

  if (opts.write) {
    const stamp = record.generatedAt.replace(/[:.]/g, '-');
    const path = `${opts.results}/negative-controls-${stamp}.json`;
    const text = `${JSON.stringify(record, null, 2)}\n`;
    writeLinuxFile(path, text);
    writeLinuxFile(`${opts.results}/latest.json`, text);
    out.log(`written: ${path}`);
    out.log(`written: ${opts.results}/latest.json`);
  }

  if (toolFailures > 0) return 5;
  if (failures > 0) return 2;
  return 0;
}

if (process.argv[1]?.endsWith('run-negative-controls.mjs')) {
  process.exit(main(process.argv.slice(2)));
}
