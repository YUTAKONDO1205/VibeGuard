#!/usr/bin/env node
// Lane CMP -- run the nine systems of the design plan section 23.2 over one fixture set.
//
// The rule that shapes this file: every arm sees the same input. Not the same
// kind of input, the same bytes, the same flags, the same cell. An arm that was
// given an easier fixture and scored better has not been compared with
// anything.
//
// Two arms do not run. They are still emitted, with different reason codes, and
// no arm is ranked against another -- see arms.mjs.
//
// Usage:
//   node run-comparison.mjs [--fixtures DIR] [--out DIR] [--repo DIR]
//                           [--observer SO] [--opt -O0,-O2] [--quick]
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

import { spawnSync } from 'node:child_process';
import {
  existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, statSync,
} from 'node:fs';
import { basename, join } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  ARMS, RUNNABLE_ARMS, UNSUPPORTED_ARMS, PROPERTY_STATES, ARM_STATUSES,
} from './arms.mjs';
import { parseObserverLog, roleVerdict, resolutionFor } from './lib/observer-log.mjs';
import { endpointCompare, functionBody } from './lib/ir-effect.mjs';

// ---------------------------------------------------------------------------
// configuration

function arg(name, dflt) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? dflt : process.argv[i + 1];
}
const FLAG = (name) => process.argv.includes(`--${name}`);

const FIXTURES = arg('fixtures', '$LAB/fixtures');
const OUT_DIR = arg('out', '$LAB/_results-wave2/comparison');
// Derived from this file's own location, never from the author's checkout path.
// A default like `/mnt/c/Users/<name>/...` is a disclosure of the identifier it
// contains, and writing one into a tracked file discloses it exactly as surely
// as leaking it any other way — see check-disclosure-shape.mjs HOME-DIRECTORY.
const REPO = arg('repo', fileURLToPath(new URL('../../..', import.meta.url)));
const OBSERVER_SO = arg('observer', '/root/vg-build/observer-mainverify/libPropertyObserver.so');
const WORK = arg('work', '$LAB/_work/cmp-run');
const CC = arg('cc', 'clang-18');
const OPT_LEVELS = arg('opt', FLAG('quick') ? '-O0,-O2' : '-O0,-O1,-O2,-O3').split(',');

const CLI = join(REPO, 'apps/cli/dist/index.js');
const CHECK_RES = join(REPO, 'compiler/pass-instrumentation/observer/tools/check-subject-resolution.mjs');

// ---------------------------------------------------------------------------
// shelling out. Never conflates "the tool said nothing" with "the tool did not
// run": every invocation records rc, stdout, stderr and whether it threw.

// spawnSync, not execFileSync: execFileSync only hands back stderr on the
// throwing path, so a process that exits 0 while writing a diagnostic loses it.
// That is precisely the observer's `refusing to install` case -- rc 0 and a
// message -- and discarding it would have hidden the one failure mode this
// harness is supposed to demonstrate.
function run(cmd, args, opts = {}) {
  const started = Date.now();
  const r = spawnSync(cmd, args, {
    encoding: 'utf8',
    timeout: opts.timeout ?? 120000,
    cwd: opts.cwd,
    env: { ...process.env, ...(opts.env || {}) },
    maxBuffer: 64 * 1024 * 1024,
  });
  return {
    ok: r.status === 0,
    rc: typeof r.status === 'number' ? r.status : null,
    signal: r.signal ?? null,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? (r.error ? String(r.error.message) : ''),
    spawnError: r.error ? String(r.error.message) : null,
    ms: Date.now() - started,
  };
}

/**
 * rc=0 is not evidence that anything happened. Every step that is supposed to
 * produce a file is asked whether the file is there and non-empty; a step that
 * exited clean and produced nothing is a failure with a good exit code, which
 * is the failure mode this experiment has already been bitten by.
 */
function produced(path) {
  try { return statSync(path).size > 0; } catch { return false; }
}

// ---------------------------------------------------------------------------
// fixtures and the config matrix

function loadFixtures() {
  return readdirSync(FIXTURES)
    .filter((d) => !d.startsWith('_'))
    .filter((d) => existsSync(join(FIXTURES, d, 'manifest.json')))
    .sort()
    .map((d) => ({
      dir: join(FIXTURES, d),
      manifest: JSON.parse(readFileSync(join(FIXTURES, d, 'manifest.json'), 'utf8')),
    }));
}

/**
 * Where a mitigation flag belongs.
 *
 * `-s` is a link-time strip; handing it to `-c` makes clang warn about an
 * unused argument and changes nothing, so it is applied at link only. Macro
 * and codegen flags apply to both phases. Getting this wrong would silently
 * turn the notappear mitigation axis into a no-op while still labelling the
 * cell "mit-on", i.e. would produce a fabricated comparison.
 */
function flagPhase(flag) {
  if (flag === '-s' || flag.startsWith('-Wl,')) return 'link';
  return 'both';
}

function cellsFor(fx) {
  const mit = fx.manifest.axes?.mitigation;
  const variants = mit ? [
    { mit: 'off', flags: mit.off ?? [] },
    { mit: 'on', flags: mit.on ?? [] },
  ] : [{ mit: 'off', flags: [] }];
  const out = [];
  for (const opt of OPT_LEVELS) {
    for (const v of variants) {
      out.push({
        fixtureId: fx.manifest.fixtureId,
        compiler: CC,
        opt,
        mit: v.mit,
        mitName: mit?.name ?? null,
        mitFlags: v.flags,
        compileFlags: [opt, ...v.flags.filter((f) => flagPhase(f) === 'both')],
        linkFlags: [opt, ...v.flags],
        key: `${fx.manifest.fixtureId}/${CC}/${opt}/mit-${v.mit}`,
        isReference: `${CC}/${opt}/mit-${v.mit}` === fx.manifest.referenceConfig,
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// arm 1 -- VibeGuard source scanner

function armVibeGuard(cell, cellDir) {
  const r = run('node', [CLI, cellDir, '--format', 'json', '--no-color'], { timeout: 180000 });
  let findings = null;
  let parseError = null;
  try {
    const start = r.stdout.indexOf('{');
    findings = JSON.parse(r.stdout.slice(start)).findings ?? [];
  } catch (e) { parseError = e.message; }
  if (findings === null) {
    return {
      armKey: 'vibeguard-source', ran: true, rc: r.rc,
      propertyVerdict: 'NOT_OBSERVED', attribution: 'NOT_OBSERVED',
      note: `could not parse CLI JSON: ${parseError}`,
      stderrHead: r.stderr.slice(0, 400),
    };
  }
  const anchors = (cell._properties ?? [])
    .map((p) => p.sourceAnchor).filter(Boolean);
  const anchorHits = anchors.map((a) => ({
    anchor: `${a.file}:${a.line}`,
    hit: findings.some((f) => basename(f.filePath) === basename(a.file)
      && Number(f.startLine) === Number(a.line)),
    rules: findings
      .filter((f) => basename(f.filePath) === basename(a.file) && Number(f.startLine) === Number(a.line))
      .map((f) => f.ruleId),
  }));
  return {
    armKey: 'vibeguard-source',
    ran: true, rc: r.rc,
    // It scanned source and reported source facts. It did not and cannot say
    // whether the construct survived the build, which is the cell's question.
    propertyVerdict: 'OUT_OF_SCOPE',
    attribution: 'NO_ATTRIBUTION_BY_DESIGN',
    findingCount: findings.length,
    findings: findings.map((f) => ({
      ruleId: f.ruleId, file: basename(f.filePath), line: f.startLine,
      severity: f.severity, confidence: f.confidence,
    })),
    anchorHits,
    // Fingerprint of the report, so config-invariance is measured across cells
    // rather than assumed from the fact that it is a source scanner.
    reportFingerprint: JSON.stringify(findings.map((f) => `${f.ruleId}@${basename(f.filePath)}:${f.startLine}`).sort()),
  };
}

// ---------------------------------------------------------------------------
// arm 2 -- Clang Static Analyzer

function armCSA(cell, cellDir) {
  const perTu = {};
  let total = 0;
  for (const src of ['target.c', 'opaque.c', 'main.c']) {
    const r = run(CC, ['--analyze', '-Xclang', '-analyzer-output=text',
      ...cell.compileFlags, src, '-o', '/dev/null'], { cwd: cellDir });
    const diags = (r.stdout + r.stderr).split('\n')
      .filter((l) => /:\d+:\d+: (warning|error|note):/.test(l))
      .filter((l) => !/note:/.test(l));
    perTu[src] = { rc: r.rc, diagnostics: diags };
    total += diags.length;
  }
  // scan-build is the driver around the same engine. Recorded so the arm is
  // not open to the objection that it was run in a weaker form than the plan
  // named.
  const sb = run('scan-build-18', ['-o', join(cellDir, 'scan-build-out'),
    CC, ...cell.linkFlags, 'target.c', 'opaque.c', 'main.c', '-o', 'app-sb'],
  { cwd: cellDir, timeout: 180000 });
  const sbLine = (sb.stdout + sb.stderr).split('\n')
    .find((l) => /bug[s]? found|No bugs found/.test(l)) ?? null;

  const anchors = (cell._properties ?? []).map((p) => p.sourceAnchor).filter(Boolean);
  const anchorHits = anchors.map((a) => ({
    anchor: `${a.file}:${a.line}`,
    hit: (perTu[a.file]?.diagnostics ?? []).some((d) => d.includes(`:${a.line}:`)),
  }));
  return {
    armKey: 'clang-static-analyzer', ran: true, rc: 0,
    propertyVerdict: 'OUT_OF_SCOPE',
    attribution: 'NO_ATTRIBUTION_BY_DESIGN',
    diagnosticCount: total,
    perTu,
    anchorHits,
    scanBuildHeadline: sbLine ? sbLine.trim() : null,
    scanBuildRc: sb.rc,
  };
}

// ---------------------------------------------------------------------------
// arm 3 -- clang warnings

function armWarnings(cell, cellDir) {
  const perTu = {};
  let total = 0;
  for (const src of ['target.c', 'opaque.c', 'main.c']) {
    const r = run(CC, [...cell.compileFlags, '-Wall', '-Wextra', '-c', src,
      '-o', join(cellDir, `${src}.warn.o`)], { cwd: cellDir });
    const warns = (r.stderr).split('\n').filter((l) => /: warning:/.test(l));
    perTu[src] = { rc: r.rc, warnings: warns };
    total += warns.length;
  }
  return {
    armKey: 'clang-warnings', ran: true, rc: 0,
    propertyVerdict: 'OUT_OF_SCOPE',
    attribution: 'NO_ATTRIBUTION_BY_DESIGN',
    warningCount: total,
    perTu,
  };
}

// ---------------------------------------------------------------------------
// arms 4 and 5 need the linked artifact

function link(cell, cellDir) {
  const bin = join(cellDir, 'app');
  const r = run(CC, [...cell.linkFlags, 'target.c', 'opaque.c', 'main.c', '-o', bin], { cwd: cellDir });
  return { bin, rc: r.rc, stderr: r.stderr.slice(0, 800), produced: produced(bin) };
}

function armStrings(cell, cellDir, linked) {
  if (!linked.produced) {
    return {
      armKey: 'strings-scan', ran: false,
      propertyVerdict: 'VERIFICATION_INCOMPLETE',
      attribution: 'NOT_OBSERVED',
      note: `no linked artifact to scan (link rc=${linked.rc})`,
    };
  }
  const r = run('strings', ['-a', linked.bin]);
  const text = r.stdout;
  const markers = cell._artifactMarkers;
  if (!markers) {
    return {
      armKey: 'strings-scan', ran: true, rc: r.rc,
      propertyVerdict: 'NO_MARKERS_DECLARED',
      attribution: 'NO_ATTRIBUTION_BY_DESIGN',
      totalStrings: text.split('\n').filter(Boolean).length,
      note:
        'This fixture declares no artifactMarkers. The arm ran and read the '
        + 'binary; the must-not-appear question simply has no referent here. '
        + 'That is not the same as scanning and finding nothing.',
    };
  }
  // Positive control first. If the string that is *supposed* to be in the
  // artifact cannot be found, then every absence this arm reports is
  // uninterpretable and the cell is incomplete rather than clean.
  const oc = markers.oracleControl;
  const controlFound = oc ? text.includes(oc.bytes) : null;
  const mustNot = (markers.mustNotAppear ?? []).map((m) => ({
    markerId: m.markerId, found: text.includes(m.bytes),
  }));
  if (oc && !controlFound) {
    return {
      armKey: 'strings-scan', ran: true, rc: r.rc,
      propertyVerdict: 'VERIFICATION_INCOMPLETE',
      attribution: 'NO_ATTRIBUTION_BY_DESIGN',
      controlMarker: { markerId: oc.markerId, found: false },
      mustNotAppear: mustNot,
      note:
        'The oracle-control marker is absent, so the scan cannot see strings '
        + 'in this artifact. Absent must-not-appear markers therefore mean '
        + 'nothing in this cell and are not reported as a pass.',
    };
  }
  const anyLeak = mustNot.some((m) => m.found);
  return {
    armKey: 'strings-scan', ran: true, rc: r.rc,
    // For a must-not-appear property, "the marker is present in the artifact"
    // IS the property being violated -- the effect the scan looks for is the
    // leak, so PRESENT here means the leak is present.
    propertyVerdict: anyLeak ? 'PRESENT' : 'LOST',
    propertyVerdictMeaning: anyLeak
      ? 'the must-not-appear bytes are in the shipped artifact'
      : 'the must-not-appear bytes are not in the artifact, and the oracle control proves the scan could have seen them',
    attribution: 'NO_ATTRIBUTION_BY_DESIGN',
    controlMarker: oc ? { markerId: oc.markerId, found: controlFound } : null,
    mustNotAppear: mustNot,
    totalStrings: text.split('\n').filter(Boolean).length,
  };
}

function armChecksec(cell, cellDir, linked) {
  if (!linked.produced) {
    return {
      armKey: 'checksec', ran: false,
      propertyVerdict: 'VERIFICATION_INCOMPLETE',
      attribution: 'NOT_OBSERVED',
      note: `no linked artifact to inspect (link rc=${linked.rc})`,
    };
  }
  const r = run('checksec', [`--file=${linked.bin}`, '--output=json']);
  let posture = null;
  try {
    const parsed = JSON.parse(r.stdout);
    posture = parsed[Object.keys(parsed)[0]];
  } catch { /* recorded as null below */ }
  return {
    armKey: 'checksec', ran: true, rc: r.rc,
    // It answered its own question completely. It was never asked this one.
    propertyVerdict: 'OUT_OF_SCOPE',
    attribution: 'NO_ATTRIBUTION_BY_DESIGN',
    hardening: posture,
    rawHead: posture ? null : r.stdout.slice(0, 400),
  };
}

// ---------------------------------------------------------------------------
// arm 7 -- pre/post IR endpoints

function armPrePost(cell, cellDir, prop) {
  if (!prop) {
    return {
      armKey: 'cc-prepost', ran: false,
      propertyVerdict: 'NO_PROPERTY_DECLARED',
      attribution: 'NOT_OBSERVED',
      note: 'this fixture declares no IR-level property (role=artifact-only)',
    };
  }
  const pre = join(cellDir, 'pre.ll');
  const post = join(cellDir, 'post.ll');
  const rPre = run(CC, [...cell.compileFlags, '-S', '-emit-llvm',
    '-Xclang', '-disable-llvm-passes', 'target.c', '-o', pre], { cwd: cellDir });
  const rPost = run(CC, [...cell.compileFlags, '-S', '-emit-llvm', 'target.c', '-o', post], { cwd: cellDir });
  if (!produced(pre) || !produced(post)) {
    return {
      armKey: 'cc-prepost', ran: false,
      propertyVerdict: 'VERIFICATION_INCOMPLETE',
      attribution: 'NOT_OBSERVED',
      note: `IR not produced (pre rc=${rPre.rc} present=${produced(pre)}, post rc=${rPost.rc} present=${produced(post)})`,
    };
  }
  const preText = readFileSync(pre, 'utf8');
  const postText = readFileSync(post, 'utf8');
  const syms = prop.effectSymbols ?? [];
  const subject = endpointCompare(preText, postText, prop.targetFn, syms);
  const control = endpointCompare(preText, postText, prop.oracleControlFn, syms);

  // The control is the positive control of this arm. If the effect that cannot
  // be removed has gone missing, the arm is blind in this cell and its verdict
  // about the subject is not evidence.
  const controlHeld = control.state === 'PRESENT';
  return {
    armKey: 'cc-prepost', ran: true, rc: 0,
    propertyVerdict: controlHeld ? subject.state : 'VERIFICATION_INCOMPLETE',
    attribution: controlHeld
      ? (subject.state === 'LOST' ? 'NO_ATTRIBUTION_BY_DESIGN' : subject.attribution)
      : 'NOT_OBSERVED',
    subject: { fn: prop.targetFn, ...subject },
    control: { fn: prop.oracleControlFn, ...control },
    controlHeld,
    controlNote: controlHeld ? null
      : 'positive control did not hold: the oracle control effect is not '
        + 'PRESENT after optimisation, so this cell cannot distinguish "the '
        + 'subject lost its defence" from "this arm cannot see the effect in '
        + 'the form the compiler chose".',
    effectSymbols: syms,
  };
}

// ---------------------------------------------------------------------------
// arm 8 -- pass-level tracking

function armPassLevel(cell, cellDir, prop) {
  if (!prop) {
    return {
      armKey: 'cc-passlevel', ran: false,
      propertyVerdict: 'NO_PROPERTY_DECLARED',
      attribution: 'NOT_OBSERVED',
      note: 'this fixture declares no IR-level property (role=artifact-only)',
    };
  }
  const log = join(cellDir, 'observer.tsv');
  const env = {
    OBS_TARGET_FN: prop.targetFn,
    OBS_CONTROL_FN: prop.oracleControlFn,
    OBS_EFFECT_SYMBOLS: (prop.effectSymbols ?? []).join(','),
    OBS_OUT: log,
    OBS_MODE: 'standard',
  };
  const r = run(CC, [...cell.compileFlags, '-c', 'target.c',
    '-o', join(cellDir, 'target-obs.o'), `-fpass-plugin=${OBSERVER_SO}`],
  { cwd: cellDir, env });

  // Silent-failure fence 1: refusing to install leaves rc=0 and no log.
  if (!produced(log)) {
    return {
      armKey: 'cc-passlevel', ran: false, rc: r.rc,
      propertyVerdict: 'NOT_OBSERVED', attribution: 'NOT_OBSERVED',
      note: 'no observer log was written. rc alone would have called this a success.',
      stderr: r.stderr.slice(0, 800),
    };
  }
  const text = readFileSync(log, 'utf8');
  const parsed = parseObserverLog(text);

  // Silent-failure fence 2: no EV records means the plugin loaded and observed
  // nothing. The observer's own README requires this to fail rather than pass
  // quietly.
  // Silent-failure fence 3: the configured names may not name anything.
  const chk = run('node', [CHECK_RES, '--json', log]);
  let resolution = null;
  try { resolution = JSON.parse(chk.stdout); } catch { /* left null */ }

  const subjRes = resolutionFor(parsed, 'subject');
  const ctrlRes = resolutionFor(parsed, 'control');
  const subject = roleVerdict(parsed, 'subject');
  const control = roleVerdict(parsed, 'control');

  const runObservedSubject = chk.rc === 0;
  const controlHeld = control.state === 'PRESENT';

  let verdict;
  let attribution;
  let note = null;
  if (parsed.evRecordCount === 0) {
    verdict = 'NOT_OBSERVED'; attribution = 'NOT_OBSERVED';
    note = 'the log has no EV records: the plugin installed but observed nothing.';
  } else if (!runObservedSubject) {
    verdict = 'NOT_OBSERVED'; attribution = 'NOT_OBSERVED';
    note = `check-subject-resolution exit ${chk.rc}: ${resolution?.reason ?? chk.stdout.slice(0, 300)}`;
  } else if (!controlHeld) {
    verdict = 'VERIFICATION_INCOMPLETE'; attribution = 'NOT_OBSERVED';
    note = 'the oracle control is not PRESENT, so the subject verdict in this cell is not evidence.';
  } else if (subject.state === 'NOT_OBSERVED') {
    // No SUMMARY row at all for the subject. Distinct from ABSENT below: there
    // the observer counted and saw nothing; here it never counted.
    verdict = 'NOT_OBSERVED';
    attribution = 'NOT_OBSERVED';
    note = 'the names resolved but no SUMMARY row was written for the subject.';
  } else if (subject.state === 'ABSENT') {
    // interfaces.md §3: ABSENT is "observed to be missing, at a point where the
    // property had not yet been established" -- the effect was never in the IR
    // at all. The names resolved and the control held, so this is not a
    // configuration error; it is the arm correctly reporting that whatever
    // removed the defence did so before the first IR boundary. Calling this
    // "no loss" would be false, and calling it LOST would attribute to the
    // pipeline something the pipeline never touched.
    verdict = 'ABSENT';
    attribution = 'LOSS_PRECEDES_WINDOW';
    note = 'the subject resolved and the control held, but the effect was '
      + 'never present at any IR boundary. Whatever removed it acted before '
      + 'the window this arm can see -- so this arm can establish that the '
      + 'defence is missing, and can establish that no pass is responsible, '
      + 'but cannot name the stage that removed it.';
  } else {
    verdict = subject.state;
    attribution = subject.attribution;
    if (subject.state === 'PRESENT' && subject.everPresent === '1'
        && Number(subject.lossEpisodes) > 0) {
      note = 'lost and reintroduced: two endpoints would have called this PRESENT and missed the episode.';
    }
  }

  // A subject that resolved, held the effect at the first boundary, and then
  // has count 0 with no SUMMARY row would be indistinguishable from a typo
  // without the record above. Both facts are kept.
  return {
    armKey: 'cc-passlevel', ran: true, rc: r.rc,
    propertyVerdict: verdict,
    attribution,
    note,
    firstLossPass: subject.firstLossPass ?? null,
    firstLossSeq: subject.firstLossSeq ?? null,
    firstLossPrevPass: subject.firstLossPrevPass ?? null,
    subject: { fn: prop.targetFn, state: subject.state, row: subject.row?._raw ?? null },
    control: { fn: prop.oracleControlFn, state: control.state, held: controlHeld },
    subjectResolution: subjRes.resolution,
    controlResolution: ctrlRes.resolution,
    checkSubjectResolutionRc: chk.rc,
    checkSubjectResolutionStatus: resolution?.status ?? null,
    passesSeen: parsed.stats[0]?.passesSeen ?? null,
    evRecords: parsed.evRecordCount,
    observerStderr: r.stderr ? r.stderr.slice(0, 600) : '',
  };
}

// ---------------------------------------------------------------------------
// unsupported arms -- emitted, never scored, reasons kept apart

function armUnsupported(armDef) {
  return {
    armKey: armDef.key, ran: false,
    propertyVerdict: 'UNSUPPORTED',
    attribution: 'UNSUPPORTED',
    unsupportedReason: armDef.unsupportedReason,
    unsupportedDetail: armDef.unsupportedDetail,
    // Deliberately no score, rank or comparison. For arm 6 the plan states the
    // relationship is complementary, and a rank would misstate it.
    relationship: armDef.relationship ?? null,
  };
}

// ---------------------------------------------------------------------------
// controls that are about the harness, not about a cell

// VG-SMELL-003 fires here on length and branch count. Its premise does not hold:
// the rule is about "a monolithic handler that validates, authorizes, mutates,
// and responds", and the risk it names is an authorization gap hidden in a long
// body. This is a measurement harness — it writes fixture sources, compiles
// them, and records what came back. There is no principal, no request and no
// authorization decision anywhere in it, so there is no gap of that kind to
// hide. Splitting it would move build steps away from the readings they produce,
// which is the property the lane is reviewed on.
// vibeguard:disable-next-line VG-SMELL-003
function harnessControls(fixtures) {
  const out = { positive: [], negative: [], red: [] };
  const dir = join(WORK, '_controls');
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const erasure = fixtures.find((f) => f.manifest.fixtureId === 'erasure');
  for (const f of ['target.c', 'opaque.c', 'main.c']) {
    writeFileSync(join(dir, f), readFileSync(join(erasure.dir, f)));
  }
  const prop = erasure.manifest.properties[0];
  const syms = prop.effectSymbols.join(',');
  const baseEnv = {
    OBS_TARGET_FN: prop.targetFn,
    OBS_CONTROL_FN: prop.oracleControlFn,
    OBS_EFFECT_SYMBOLS: syms,
    OBS_MODE: 'standard',
  };

  // --- positive control: fully configured observer on a cell where the loss
  // is known to happen. If this does not attribute, nothing else in arm 8 is
  // readable.
  {
    const log = join(dir, 'pos.tsv');
    const r = run(CC, ['-O2', '-c', 'target.c', '-o', join(dir, 'pos.o'),
      `-fpass-plugin=${OBSERVER_SO}`], { cwd: dir, env: { ...baseEnv, OBS_OUT: log } });
    const p = produced(log) ? parseObserverLog(readFileSync(log, 'utf8')) : null;
    const s = p ? roleVerdict(p, 'subject') : null;
    const chk = run('node', [CHECK_RES, log]);
    out.positive.push({
      id: 'observer-fully-configured',
      what: 'observer with every variable set, real names, erasure/-O2',
      expected: 'a log is written, SUBJECTRES resolved for both roles, subject LOST with a named pass, control PRESENT',
      rc: r.rc,
      logWritten: produced(log),
      subjectResolution: p ? resolutionFor(p, 'subject').resolution : null,
      controlResolution: p ? resolutionFor(p, 'control').resolution : null,
      subjectState: s?.state ?? null,
      firstLossPass: s?.firstLossPass ?? null,
      controlState: p ? roleVerdict(p, 'control').state : null,
      checkRc: chk.rc,
      passed: produced(log) && s?.state === 'LOST' && !!s?.firstLossPass && chk.rc === 0,
    });
  }

  // --- positive control for arm 7: at -O0 the effect must still be at both
  // endpoints. An endpoint comparator that reported LOST everywhere would look
  // impressive and be worthless.
  {
    const pre = join(dir, 'c-pre.ll');
    const post = join(dir, 'c-post.ll');
    run(CC, ['-O0', '-S', '-emit-llvm', '-Xclang', '-disable-llvm-passes', 'target.c', '-o', pre], { cwd: dir });
    run(CC, ['-O0', '-S', '-emit-llvm', 'target.c', '-o', post], { cwd: dir });
    const cmp = endpointCompare(readFileSync(pre, 'utf8'), readFileSync(post, 'utf8'),
      prop.targetFn, prop.effectSymbols);
    out.positive.push({
      id: 'prepost-effect-visible-at-O0',
      what: 'arm 7 endpoint comparison on erasure at -O0, where nothing should be removed',
      expected: 'PRESENT at both endpoints',
      state: cmp.state, preCount: cmp.preCount, postCount: cmp.postCount,
      passed: cmp.state === 'PRESENT' && cmp.preCount > 0 && cmp.postCount > 0,
    });
  }

  // --- negative control for arm 5: checksec must distinguish two artifacts
  // built with opposite hardening. If it reported the same for both, then "it
  // reported X" would carry no information.
  {
    const hard = join(dir, 'hard');
    const soft = join(dir, 'soft');
    run(CC, ['-O2', '-fstack-protector-all', '-Wl,-z,relro,-z,now', '-pie', '-fPIE',
      'target.c', 'opaque.c', 'main.c', '-o', hard], { cwd: dir });
    run(CC, ['-O2', '-fno-stack-protector', '-Wl,-z,norelro', '-no-pie',
      'target.c', 'opaque.c', 'main.c', '-o', soft], { cwd: dir });
    const readPosture = (b) => {
      const r = run('checksec', [`--file=${b}`, '--output=json']);
      try { const j = JSON.parse(r.stdout); return j[Object.keys(j)[0]]; } catch { return null; }
    };
    const h = readPosture(hard);
    const s = readPosture(soft);
    out.negative.push({
      id: 'checksec-discriminates',
      what: 'the same sources linked hardened and unhardened',
      expected: 'checksec reports different postures; identical output would mean its output is not information',
      hardened: h, unhardened: s,
      differs: JSON.stringify(h) !== JSON.stringify(s),
      passed: !!h && !!s && JSON.stringify(h) !== JSON.stringify(s),
    });
  }

  // --- red A: a missing variable. rc stays 0 and no log appears. This is the
  // failure an harness that only checks rc reports as a clean run.
  {
    const log = join(dir, 'red-a.tsv');
    rmSync(log, { force: true });
    const env = { ...baseEnv, OBS_OUT: log };
    delete env.OBS_CONTROL_FN;
    const r = run(CC, ['-O2', '-c', 'target.c', '-o', join(dir, 'red-a.o'),
      `-fpass-plugin=${OBSERVER_SO}`], { cwd: dir, env });
    out.red.push({
      id: 'red-missing-env-var',
      what: 'OBS_CONTROL_FN unset',
      expected: 'compiler exits 0, plugin refuses to install, NO log is written',
      rc: r.rc,
      stderr: r.stderr.trim(),
      logWritten: produced(log),
      demonstrates: 'rc=0 is not evidence of measurement. The fence that catches this is "was the log produced", not the exit code.',
      passed: r.rc === 0 && !produced(log) && /refusing to install/.test(r.stderr),
    });
  }

  // --- red B: a subject name that names nothing. A log IS written, the
  // control IS present, STATS counts hundreds of passes -- and none of it is
  // about the subject.
  {
    const log = join(dir, 'red-b.tsv');
    rmSync(log, { force: true });
    const r = run(CC, ['-O2', '-c', 'target.c', '-o', join(dir, 'red-b.o'),
      `-fpass-plugin=${OBSERVER_SO}`],
    { cwd: dir, env: { ...baseEnv, OBS_TARGET_FN: `${prop.targetFn}X`, OBS_OUT: log } });
    const p = produced(log) ? parseObserverLog(readFileSync(log, 'utf8')) : null;
    const chk = run('node', [CHECK_RES, log]);
    out.red.push({
      id: 'red-subject-name-resolves-to-nothing',
      what: `OBS_TARGET_FN=${prop.targetFn}X`,
      expected: 'compiler exits 0, a non-empty log IS written, the control is PRESENT, hundreds of passes are counted, and only SUBJECTRES + check-subject-resolution reveal that nothing observed the subject',
      rc: r.rc,
      logWritten: produced(log),
      passesSeen: p?.stats[0]?.passesSeen ?? null,
      controlState: p ? roleVerdict(p, 'control').state : null,
      subjectSummaryRowPresent: p ? !!p.summary.find((x) => x.role === 'subject') : null,
      subjectResolution: p ? resolutionFor(p, 'subject').resolution : null,
      checkRc: chk.rc,
      stderr: r.stderr.trim().slice(0, 400),
      demonstrates:
        'the absence of subject rows is the same shape as a subject erased '
        + 'before the first boundary. The co-resident control cannot separate '
        + 'them because the control is fine. Only SUBJECTRES can, and it is '
        + 'read as NOT_OBSERVED -- never as LOST.',
      passed: r.rc === 0 && produced(log) && chk.rc === 2
        && (p ? resolutionFor(p, 'subject').resolution === 'not-in-module' : false),
    });
  }

  // --- red C: the same trap in arm 7. An endpoint comparator that finds no
  // function and reports LOST would fabricate a finding out of a typo.
  {
    const pre = join(dir, 'c-pre.ll');
    const post = join(dir, 'c-post.ll');
    const cmp = endpointCompare(readFileSync(pre, 'utf8'), readFileSync(post, 'utf8'),
      `${prop.targetFn}X`, prop.effectSymbols);
    out.red.push({
      id: 'red-prepost-subject-name-resolves-to-nothing',
      what: `arm 7 asked for ${prop.targetFn}X`,
      expected: 'NOT_OBSERVED, never LOST',
      state: cmp.state, reason: cmp.reason,
      demonstrates: 'the weaker arm is fenced against the same lie as the stronger one; the difference between them is attribution, not honesty.',
      passed: cmp.state === 'NOT_OBSERVED',
    });
  }

  // --- red D: arm 4 asked for bytes that are not in the artifact, alongside
  // the oracle control that is. One without the other is not a measurement.
  {
    const notappear = fixtures.find((f) => f.manifest.fixtureId === 'notappear');
    const nd = join(dir, 'notappear');
    mkdirSync(nd, { recursive: true });
    for (const f of ['target.c', 'opaque.c', 'main.c']) {
      writeFileSync(join(nd, f), readFileSync(join(notappear.dir, f)));
    }
    const bin = join(nd, 'app');
    run(CC, ['-O0', 'target.c', 'opaque.c', 'main.c', '-o', bin], { cwd: nd });
    const text = run('strings', ['-a', bin]).stdout;
    const oc = notappear.manifest.artifactMarkers.oracleControl;
    const absurd = 'absent-marker-never-compiled-in-4f1b9c';
    out.red.push({
      id: 'red-strings-absence-needs-a-positive-control',
      what: 'search the same artifact for the oracle-control marker and for bytes that were never compiled in',
      expected: 'the control marker is found and the invented marker is not; if the control were also missing, every absence would be uninterpretable',
      controlMarkerFound: text.includes(oc.bytes),
      inventedMarkerFound: text.includes(absurd),
      demonstrates: 'a strings scan that finds nothing has two explanations, and only a found positive control removes one of them.',
      passed: text.includes(oc.bytes) && !text.includes(absurd),
    });
  }

  return out;
}

// ---------------------------------------------------------------------------
// main

// VG-SMELL-003, same reading as `harnessControls` above: a long CLI entry point
// that sequences a measurement run. No authorization decision is made here.
// vibeguard:disable-next-line VG-SMELL-003
function main() {
  const fixtures = loadFixtures();
  rmSync(WORK, { recursive: true, force: true });
  mkdirSync(WORK, { recursive: true });
  mkdirSync(OUT_DIR, { recursive: true });

  const cells = [];
  for (const fx of fixtures) {
    const props = fx.manifest.properties ?? [];
    const prop = props[0] ?? null;
    for (const cell of cellsFor(fx)) {
      cell._properties = props;
      cell._artifactMarkers = fx.manifest.artifactMarkers ?? null;
      const cellDir = join(WORK, cell.key.replace(/[/]/g, '__'));
      mkdirSync(cellDir, { recursive: true });
      for (const f of ['target.c', 'opaque.c', 'main.c']) {
        writeFileSync(join(cellDir, f), readFileSync(join(fx.dir, f)));
      }
      process.stderr.write(`cell ${cell.key}\n`);
      const linked = link(cell, cellDir);
      const arms = {
        'vibeguard-source': armVibeGuard(cell, cellDir),
        'clang-static-analyzer': armCSA(cell, cellDir),
        'clang-warnings': armWarnings(cell, cellDir),
        'strings-scan': armStrings(cell, cellDir, linked),
        checksec: armChecksec(cell, cellDir, linked),
        'cc-prepost': armPrePost(cell, cellDir, prop),
        'cc-passlevel': armPassLevel(cell, cellDir, prop),
      };
      for (const a of UNSUPPORTED_ARMS) arms[a.key] = armUnsupported(a);
      cells.push({
        key: cell.key,
        fixtureId: cell.fixtureId,
        title: fx.manifest.title,
        role: fx.manifest.role,
        compiler: cell.compiler, opt: cell.opt, mit: cell.mit,
        mitName: cell.mitName, mitFlags: cell.mitFlags,
        compileFlags: cell.compileFlags, linkFlags: cell.linkFlags,
        isReference: cell.isReference,
        hypothesisFirstLossStage: prop?.hypothesis?.firstLossStage ?? null,
        link: { rc: linked.rc, produced: linked.produced },
        arms,
      });
    }
  }

  // Config-invariance of arm 1, measured rather than assumed.
  const invariance = {};
  for (const fx of fixtures) {
    const id = fx.manifest.fixtureId;
    const prints = new Set(cells.filter((c) => c.fixtureId === id)
      .map((c) => c.arms['vibeguard-source'].reportFingerprint));
    invariance[id] = {
      cells: cells.filter((c) => c.fixtureId === id).length,
      distinctReports: prints.size,
      invariant: prints.size === 1,
    };
  }

  const controls = harnessControls(fixtures);

  const toolVersions = {};
  for (const [name, args] of [
    [CC, ['--version']], ['clang-tidy-18', ['--version']], ['checksec', ['--version']],
    ['strings', ['--version']], ['node', ['--version']], ['scan-build-18', ['-h']],
  ]) {
    const r = run(name, args, { timeout: 20000 });
    toolVersions[name] = r.ok || r.stdout
      ? (r.stdout || r.stderr).split('\n').slice(0, 2).join(' ').trim()
      : `NOT RUNNABLE (${r.stderr.slice(0, 80)})`;
  }
  const aliveTv = run('sh', ['-c', 'command -v alive-tv || true']);
  toolVersions['alive-tv'] = aliveTv.stdout.trim() || 'MISSING';

  const report = {
    schemaVersion: 'comparison-v1',
    lane: 'CMP',
    planSection: 'the design plan section 23.2 -- nine systems',
    generatedAt: new Date().toISOString(),
    generator: 'compiler/eval/comparison/run-comparison.mjs',
    inputDiscipline:
      'Every arm in a cell was given the same fixture sources, the same '
      + 'optimisation level and the same mitigation flags. No arm was run on '
      + 'inputs another arm did not see.',
    noRanking:
      'No arm is scored against another. Arms 1-5 answer different questions '
      + 'from arms 7-8, arm 6 is complementary by the plan\'s own statement, '
      + 'and arm 9 does not exist. A column of verdicts is a map of scope, not '
      + 'a league table.',
    host: {
      fixtures: FIXTURES, repo: REPO, observer: OBSERVER_SO, work: WORK,
      compiler: CC, optLevels: OPT_LEVELS, toolVersions,
    },
    vocabulary: {
      propertyStates: PROPERTY_STATES,
      propertyStatesSource: 'compiler/schema/interfaces.md §3, not extended here',
      armStatuses: ARM_STATUSES,
      rule:
        'A cell\'s `propertyVerdict` holds either a property state or an arm '
        + 'status, never a blend of the two. NOT_OBSERVED is never written '
        + 'where LOST is meant, ABSENT is never written where LOST is meant, '
        + 'and UNSUPPORTED is never written where either is meant.',
    },
    arms: ARMS,
    cellCount: cells.length,
    cells,
    armOneConfigInvariance: invariance,
    controls,
  };

  const outFile = join(OUT_DIR, 'comparison.json');
  writeFileSync(outFile, `${JSON.stringify(report, null, 2)}\n`);
  process.stderr.write(`\nwrote ${outFile}\n`);
  return report;
}

main();
