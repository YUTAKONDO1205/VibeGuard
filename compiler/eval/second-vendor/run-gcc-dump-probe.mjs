#!/usr/bin/env node
/**
 * EXPLORATORY: gcc's own pass-dump channel.
 *
 * ---------------------------------------------------------------------------
 * READ THIS BEFORE QUOTING ANY NUMBER FROM THIS FILE
 *
 * This probe does NOT produce the same kind of result as the the compiler-side toolchain pass-plugin
 * observer, and its output must never be merged into the same column.
 *
 *   the compiler-side toolchain observer (clang only)  : an instrument WE control, injected into the
 *                                pipeline, cross-checked against the source and
 *                                object gates. Produces `firstLossPass`.
 *
 *   gcc dump channel (this)    : gcc describing its own behaviour to itself via
 *                                -fdump-tree-all. We did not instrument anything;
 *                                we are reading the compiler's self-report. There
 *                                is no independent confirmation that the dump
 *                                boundary is where the transformation actually
 *                                happened. Produces `firstAbsentDump`.
 *
 * Hence the deliberately different field name. "gcc's first-absent dump was
 * 042t.dse1" is a supportable sentence. "we identified the first-loss pass under
 * gcc" is NOT, and this file does not emit a field that would let anyone write it
 * by accident.
 *
 * gcc cannot load an LLVM -fpass-plugin, so the the compiler-side toolchain instrument remains
 * UNSUPPORTED for gcc. This probe does not change that; it only shows that a
 * weaker, unvalidated alternative channel exists and what it says.
 * ---------------------------------------------------------------------------
 *
 * Controls carried by this probe:
 *   P1 subject tracking  the effect must be PRESENT in at least one dump before
 *                        it goes absent, otherwise "first absent dump" is
 *                        meaningless and the result is absent-from-first-dump.
 *   P2 control tracking  the property's control function is tracked through the
 *                        same dumps, and must still be visible AT THE DUMP WHERE
 *                        THE SUBJECT FIRST GOES ABSENT. That is the moment the
 *                        determination is made, so that is where the probe has to
 *                        prove it was not simply blind.
 *
 *                        Scope matters here. An earlier version of this check
 *                        asked whether the control ever went absent anywhere in
 *                        the pipeline, and it failed all six erasure probes: gcc
 *                        lowers the surviving `__builtin_memset` in wipe_kept to
 *                        inline zero stores in the later RTL dumps, so the token
 *                        legitimately stops appearing long after the subject's
 *                        fate was already decided. Downstream lowering of a
 *                        control is not evidence that the probe misread anything.
 *                        It is still recorded, as controlAbsentInLaterDumps.
 *   P3 no-loss control   the probe is also run on a configuration the main table
 *                        scored PRESERVED. It must report NO first-absent dump.
 *                        Without this the probe could be a detector that always
 *                        finds a disappearance somewhere.
 *   P4 dump-count guard  zero dumps produced is NOT_OBSERVED, never "no loss".
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i += 2) out[argv[i].replace(/^--/, '')] = argv[i + 1];
  return out;
}

function run(cmd, args, cwd) {
  try {
    return { rc: 0, stdout: execFileSync(cmd, args, { encoding: 'utf8', cwd, stdio: ['ignore', 'pipe', 'pipe'] }), stderr: '' };
  } catch (e) {
    return { rc: e.status ?? null, stdout: '', stderr: e.stderr ? String(e.stderr) : String(e.message) };
  }
}

/** Tokens to look for in a GIMPLE/RTL dump for a given effect symbol set. */
function dumpTokens(symbols) {
  const t = new Set();
  for (const s of symbols) {
    t.add(s);
    t.add('__builtin_' + s);
  }
  return [...t];
}

/**
 * Slice one function out of a gcc dump.
 * gcc marks each function with `;; Function <name> (<asmname>, funcdef_no=...`.
 */
function extractDumpFunction(text, fnName) {
  const lines = text.split('\n');
  const header = /^;; Function\s+(\S+)\s/;
  let start = -1;
  for (let i = 0; i < lines.length; i++) {
    const m = header.exec(lines[i]);
    if (m && m[1] === fnName) { start = i; break; }
  }
  if (start === -1) return null;
  for (let j = start + 1; j < lines.length; j++) {
    if (header.test(lines[j])) return lines.slice(start, j).join('\n');
  }
  return lines.slice(start).join('\n');
}

function tokenPresent(region, tokens) {
  for (const tok of tokens) {
    // `\b` will not let `memset` match inside `__builtin_memset`, because `_` is
    // a word character. That is why the builtin spelling is listed separately.
    const re = new RegExp('\\b' + tok.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
    if (re.test(region)) return true;
  }
  return false;
}

/** Numeric-then-lexical ordering of gcc dump files: out.c.042t.dse1 -> 42. */
function dumpOrder(name) {
  const m = /\.(\d+)([tri])\./.exec(name);
  if (!m) return [Number.MAX_SAFE_INTEGER, name];
  const phase = { t: 0, r: 1, i: 2 }[m[2]] ?? 3;
  return [Number(m[1]) * 10 + phase, name];
}

/**
 * Compile with all dumps on and walk them in pass order.
 */
function probeConfig(driver, flags, fixtureDir, workDir, prop) {
  fs.rmSync(workDir, { recursive: true, force: true });
  fs.mkdirSync(workDir, { recursive: true });

  const compile = run(
    driver,
    [...flags, '-fdump-tree-all', '-fdump-rtl-all', '-S', '-o', 'out.s', path.join(fixtureDir, 'target.c')],
    workDir
  );

  const files = fs.existsSync(workDir)
    ? fs.readdirSync(workDir).filter((f) => /\.\d+[tri]\./.test(f))
    : [];
  files.sort((a, b) => {
    const [na, sa] = dumpOrder(a); const [nb, sb] = dumpOrder(b);
    return na - nb || sa.localeCompare(sb);
  });

  if (files.length === 0) {
    return {
      status: 'NOT_OBSERVED',
      reason: 'P4 dump-count guard: the compiler produced no dump files, so nothing was tracked. This is not evidence that the effect survived.',
      compileRc: compile.rc,
      compileStderrHead: (compile.stderr || '').split('\n')[0],
      dumpCount: 0,
      firstAbsentDump: null,
      lastPresentDump: null,
      timeline: [],
    };
  }

  const subjTokens = dumpTokens(prop.targetEffect.symbols);
  const ctlTokens = dumpTokens(prop.controlEffect.symbols);

  const timeline = [];
  let lastPresent = null, firstAbsent = null, everPresent = false;
  let controlEverPresent = false;
  let controlAtFirstAbsent = null;      // P2: the value that actually decides
  let controlAbsentInLaterDumps = null; // informational only

  for (const f of files) {
    let text;
    try { text = fs.readFileSync(path.join(workDir, f), 'utf8'); } catch { continue; }
    const subjRegion = extractDumpFunction(text, prop.targetFn);
    const ctlRegion = extractDumpFunction(text, prop.controlFn);
    if (subjRegion === null && ctlRegion === null) continue; // dump has no function bodies

    const subjPresent = subjRegion === null ? null : tokenPresent(subjRegion, subjTokens);
    const ctlPresent = ctlRegion === null ? null : tokenPresent(ctlRegion, ctlTokens);

    if (ctlPresent === true) controlEverPresent = true;

    if (subjPresent === true) { everPresent = true; lastPresent = f; }
    if (subjPresent === false && everPresent && firstAbsent === null) {
      firstAbsent = f;
      controlAtFirstAbsent = ctlPresent;
    }
    if (firstAbsent !== null && f !== firstAbsent && ctlPresent === false && controlAbsentInLaterDumps === null) {
      controlAbsentInLaterDumps = f;
    }

    timeline.push({ dump: f, subject: subjPresent, control: ctlPresent });
  }

  const passName = (f) => {
    const m = /\.(\d+[tri]\.[A-Za-z0-9_+-]+)$/.exec(f);
    return m ? m[1] : f;
  };

  let status, reason;
  if (!everPresent) {
    status = 'absent-from-first-dump';
    reason =
      'The effect was never present in any dump, so no disappearance could be located. Under this configuration the construct is gone before the first dump gcc emits (for example a preprocessor-level removal), which is a different finding from a pass removing it.';
  } else if (firstAbsent === null) {
    status = 'no-disappearance-observed';
    reason = 'The effect was present in the last dump that contains this function; the probe located no disappearance.';
  } else if (controlAtFirstAbsent !== true) {
    status = 'VERIFICATION_INCOMPLETE';
    reason =
      'P2 control tracking failed: at ' + passName(firstAbsent) + ', the dump where the subject first goes absent, the control function\'s effect was ' +
      (controlAtFirstAbsent === null ? 'not present in the dump at all' : 'also absent') +
      '. The probe cannot show it was still able to see this kind of effect at the moment it declared the subject gone, so the disappearance is not attributable to that dump.';
  } else {
    status = 'first-absent-dump-located';
    reason = 'The effect was present through ' + passName(lastPresent) + ' and absent from ' + passName(firstAbsent) + ' onward.';
  }

  return {
    status,
    reason,
    compileRc: compile.rc,
    compileStderrHead: (compile.stderr || '').split('\n')[0],
    dumpCount: files.length,
    dumpsContainingFunctions: timeline.length,
    lastPresentDump: lastPresent ? passName(lastPresent) : null,
    firstAbsentDump: firstAbsent ? passName(firstAbsent) : null,
    controlEverPresent,
    controlAtFirstAbsentDump: controlAtFirstAbsent,
    controlAbsentInLaterDumps: controlAbsentInLaterDumps ? passName(controlAbsentInLaterDumps) : null,
    controlAbsentInLaterDumpsNote:
      'Informational, not a fault. After the subject is gone, the compiler may lower the control\'s surviving call into a form that no longer spells the symbol (gcc turns the kept __builtin_memset into inline zero stores in the RTL dumps). This does not bear on the subject determination made earlier.',
    timeline,
  };
}

function main() {
  const args = parseArgs(process.argv);
  const fixturesRoot = args.fixtures || '$LAB/fixtures';
  const workRoot = args.work || '$LAB/_work-wave2/gcc-dump-probe';
  const outRoot = args.out || '$LAB/_results-wave2/second-vendor';
  const envPath = args.envelope || path.join(outRoot, 'second-vendor-envelope.json');

  const spec = JSON.parse(fs.readFileSync(path.join(HERE, 'spec.json'), 'utf8'));
  const env = JSON.parse(fs.readFileSync(envPath, 'utf8'));

  fs.rmSync(workRoot, { recursive: true, force: true });
  fs.mkdirSync(workRoot, { recursive: true });

  const report = {
    schemaVersion: 'gcc-dump-probe-v0',
    generatedAt: new Date().toISOString(),
    generator: 'compiler/eval/second-vendor/run-gcc-dump-probe.mjs',
    status: 'EXPLORATORY_UNVALIDATED',
    vocabularyWarning: {
      emits: 'firstAbsentDump',
      doesNotEmit: 'firstLossPass',
      why:
        'firstLossPass is produced by the the compiler-side toolchain pass-plugin observer, an instrument we control and cross-check. This probe reads gcc describing its own behaviour via -fdump-tree-all, with no independent confirmation. The two are different measurements and are given different field names so that neither can be quoted as the other.',
      vgcInstrumentUnderGcc: 'UNSUPPORTED - gcc cannot load an LLVM -fpass-plugin. This probe does not lift that limitation.',
      clangUnderThisProbe: 'NOT_APPLICABLE - clang has no -fdump-tree-all channel; its counterpart is the the compiler-side toolchain observer, measured elsewhere.',
    },
    probes: [],
  };

  for (const prop of spec.properties) {
    const fixtureDir = path.join(fixturesRoot, prop.fixtureId);
    const envProp = env.properties.find((p) => p.propertyId === prop.propertyId);
    if (!envProp) continue;

    // Probe every gcc cell the main table scored LOST, plus one PRESERVED gcc
    // cell as the P3 no-loss control.
    const gccCells = envProp.cells.filter((c) => c.vendor === 'gcc-13');
    const lost = gccCells.filter((c) => c.state === 'LOST');
    const preservedControl = gccCells.find((c) => c.state === 'PRESERVED');

    const targets = [
      ...lost.map((c) => ({ cell: c, role: 'subject-lost-cell' })),
      ...(preservedControl ? [{ cell: preservedControl, role: 'P3-no-loss-control' }] : []),
    ];

    for (const { cell, role } of targets) {
      const workDir = path.join(workRoot, prop.fixtureId, cell.cellId + '__' + role);
      const result = probeConfig('gcc-13', cell.flags, fixtureDir, workDir, prop);

      let controlVerdict = null;
      if (role === 'P3-no-loss-control') {
        const ok = result.status === 'no-disappearance-observed';
        controlVerdict = {
          expected: 'no-disappearance-observed',
          actual: result.status,
          pass: ok,
          meaning: ok
            ? 'The probe reported no disappearance in a cell the main table scored PRESERVED, so it is not a detector that always finds one.'
            : 'The probe reported a disappearance in a cell the main table scored PRESERVED. The probe and the asm oracle disagree and the probe output for this property must not be used.',
        };
      }

      report.probes.push({
        propertyId: prop.propertyId,
        cellId: cell.cellId,
        role,
        mainTableState: cell.state,
        flags: cell.flags,
        ...result,
        // keep the timeline out of the top-level summary; it is long
        timeline: undefined,
        timelineLength: result.timeline.length,
        p3Control: controlVerdict,
      });

      // full timeline lands in a sidecar so the summary stays readable
      const tlDir = path.join(outRoot, 'gcc-dump-timelines');
      fs.mkdirSync(tlDir, { recursive: true });
      fs.writeFileSync(
        path.join(tlDir, `${prop.fixtureId}.${cell.cellId}.${role}.json`),
        JSON.stringify({ propertyId: prop.propertyId, cellId: cell.cellId, role, timeline: result.timeline }, null, 2)
      );
    }
  }

  const p3 = report.probes.filter((p) => p.role === 'P3-no-loss-control');
  report.summary = {
    totalProbes: report.probes.length,
    byStatus: report.probes.reduce((a, p) => ((a[p.status] = (a[p.status] || 0) + 1), a), {}),
    p3Controls: { total: p3.length, passed: p3.filter((p) => p.p3Control && p.p3Control.pass).length },
    reminder: 'firstAbsentDump is gcc self-report. It is NOT firstLossPass and NOT a compiler-side pass-level attribution.',
  };

  const outPath = path.join(outRoot, 'gcc-dump-probe.json');
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
  console.log('WROTE ' + outPath);
  for (const p of report.probes) {
    console.log(
      [p.role === 'P3-no-loss-control' ? 'P3CTL' : 'probe',
       p.propertyId.padEnd(20), p.cellId.padEnd(26), ('main=' + p.mainTableState).padEnd(16),
       ('dumps=' + p.dumpCount).padEnd(11),
       p.status.padEnd(28),
       'lastPresent=' + String(p.lastPresentDump).padEnd(22),
       'firstAbsent=' + String(p.firstAbsentDump),
       p.p3Control ? (p.p3Control.pass ? '[P3 PASS]' : '[P3 FAIL]') : ''].join(' | ')
    );
  }
  console.log(JSON.stringify(report.summary, null, 2));
}

main();
