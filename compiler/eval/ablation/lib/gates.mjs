// One function per component of the design plan section 24. Each takes a cell and returns
//
//   { result, reason, explanation, evidence }
//
// where `result` is from GATE_RESULTS, `explanation` is the pass name when the
// component can name one and null otherwise, and `evidence` is whatever the
// component actually produced — a command line, a log path, a verdict record.
//
// Every gate here is a *driver*. None of them reimplements a check: the
// analyser, the AST plugin, the observer plugin and the verifier are run as
// subprocesses and their own output is parsed. The two exceptions are stated
// where they occur (gateObjectLink), and they exist because the component in
// question needs infrastructure this run did not build.

import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';

/* ------------------------------------------------------------------ */
/* A — Source Gate                                                     */
/* ------------------------------------------------------------------ */

/**
 * Runs the shipped analyser once per fixture directory and caches the result.
 *
 * The Source Gate reads source. It cannot see an optimisation level, so its
 * answer is the same for all eight cells of a fixture. That is not a defect to
 * work around; it is the measurement, and the per-cell scoring is what turns it
 * into a number.
 */
export function makeSourceGate({ run, cliPath }) {
  const cache = new Map();

  function scanFixture(fixtureDir) {
    if (cache.has(fixtureDir)) return cache.get(fixtureDir);
    const r = run('node', [cliPath, '.', '--format', 'json'], { cwd: fixtureDir });
    let parsed = null;
    let parseError = null;
    try {
      parsed = JSON.parse(r.stdout);
    } catch (e) {
      parseError = String(e && e.message);
    }
    const out = { status: r.status, parsed, parseError, argv: ['node', '<vibeguard-cli>', '.', '--format', 'json'] };
    cache.set(fixtureDir, out);
    return out;
  }

  return function gateSource({ fixtureDir, prop }) {
    const scan = scanFixture(fixtureDir);
    if (!scan.parsed) {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason: `the analyser produced no parseable JSON (exit ${scan.status}): ${scan.parseError}`,
        explanation: null,
        evidence: { argv: scan.argv },
      };
    }
    const anchor = prop.sourceAnchor;
    if (!anchor) {
      return {
        result: 'UNSUPPORTED',
        reason: 'this property declares no sourceAnchor, so there is no location to score a source finding against',
        explanation: null,
        evidence: { argv: scan.argv },
      };
    }
    const findings = scan.parsed.findings || [];
    const atAnchor = findings.filter((f) => f.filePath === anchor.file && f.startLine === anchor.line);
    const elsewhere = findings.filter((f) => !(f.filePath === anchor.file && f.startLine === anchor.line));

    if (atAnchor.length === 0) {
      return {
        result: 'NOT_DETECTED',
        reason:
          `no finding was reported at ${anchor.file}:${anchor.line}; the analyser reported ` +
          `${findings.length} finding(s) elsewhere in this fixture`,
        explanation: null,
        evidence: { argv: scan.argv, findingsTotal: findings.length, rulesElsewhere: elsewhere.map((f) => f.ruleId) },
      };
    }
    return {
      result: 'DETECTED',
      reason: `${atAnchor.map((f) => f.ruleId).join(', ')} fired at ${anchor.file}:${anchor.line}`,
      // The Source Gate names a rule, never a pass. Recording the rule id in the
      // explanation slot would make the pass-attribution column read as though
      // five components could answer a question only one of them can.
      explanation: null,
      evidence: {
        argv: scan.argv,
        rulesAtAnchor: atAnchor.map((f) => f.ruleId),
        findingsTotal: findings.length,
        findingsNotAtAnchor: elsewhere.length,
        // Configuration-blind by construction: the same verdict is returned for
        // every optimisation level and every mitigation flag of this fixture.
        configurationSensitive: false,
      },
    };
  };
}

/* ------------------------------------------------------------------ */
/* B — AST Gate                                                        */
/* ------------------------------------------------------------------ */

/**
 * IntentGate cannot run standalone: it classifies findings it is handed. §24
 * calls this configuration "AST Gate only", so it is driven from the component's
 * own naive lexical scanner (`clang-plugin/tools/lexscan.mjs`) rather than from
 * the Source Gate, which would make B a silent A+B.
 *
 * The consequence is a coverage limit rather than a result: lexscan and
 * `rules/default-rules.json` between them target `system`/`popen`, the exec
 * family, `gets`, the str* family, `memset` and `explicit_bzero`. A fixture
 * whose effect is none of those is UNSUPPORTED here, and that is reported as a
 * coverage number in its own right.
 */
export function makeAstGate({ run, lexscanPath, rulesPath, pluginSo, workRoot }) {
  return function gateAst({ fixtureDir, manifest, cell, prop }) {
    if (!existsSync(pluginSo)) {
      return {
        result: 'UNSUPPORTED',
        reason: `the AST gate plugin is not built at ${pluginSo}`,
        explanation: null,
        evidence: {},
      };
    }
    if (!cell.compiler.startsWith('clang')) {
      return {
        result: 'UNSUPPORTED',
        reason: 'IntentGate is a clang plugin; it cannot be loaded into another compiler',
        explanation: null,
        evidence: {},
      };
    }
    const out = path.join(workRoot, 'ast', manifest.fixtureId, cell.cellId);
    rmSync(out, { recursive: true, force: true });
    mkdirSync(out, { recursive: true });

    const src = manifest.sources.target;
    const findingsPath = path.join(out, 'findings.json');
    const lex = run('node', [lexscanPath, src, '--root', '.'], { cwd: fixtureDir });
    if (lex.status !== 0) {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason: `lexscan exited ${lex.status}`,
        explanation: null,
        evidence: { stderr: lex.stderr.slice(0, 400) },
      };
    }
    writeFileSync(findingsPath, lex.stdout);
    const lexFindings = JSON.parse(lex.stdout).findings || [];

    const anchor = prop.sourceAnchor;
    const anchored = lexFindings.filter((f) => f.where.path === anchor.file && f.where.line === anchor.line);
    if (anchored.length === 0) {
      return {
        result: 'UNSUPPORTED',
        reason:
          `no rule in the AST gate's table targets the effect of ${prop.propertyId}: the lexical front ` +
          `produced ${lexFindings.length} finding(s) in ${src} and none at ${anchor.file}:${anchor.line}`,
        explanation: null,
        evidence: { lexFindings: lexFindings.map((f) => `${f.id}@${f.where.line}`) },
      };
    }

    const recordPath = path.join(out, 'record.json');
    const objPath = path.join(out, 'target.o');
    const argv = [
      ...cell.flags,
      `-fplugin=${pluginSo}`,
      '-Xclang', '-add-plugin', '-Xclang', 'intent-gate',
      '-Xclang', '-plugin-arg-intent-gate', '-Xclang', `findings=${findingsPath}`,
      '-Xclang', '-plugin-arg-intent-gate', '-Xclang', `rules=${rulesPath}`,
      '-Xclang', '-plugin-arg-intent-gate', '-Xclang', `root=${fixtureDir}`,
      '-Xclang', '-plugin-arg-intent-gate', '-Xclang', `out=${recordPath}`,
      '-Xclang', '-plugin-arg-intent-gate', '-Xclang', 'quiet',
      '-c', src, '-o', objPath,
    ];
    const r = run(cell.compiler, argv, { cwd: fixtureDir });
    if (!existsSync(recordPath)) {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason: `the gate wrote no record (compiler exited ${r.status})`,
        explanation: null,
        evidence: { stderr: r.stderr.slice(0, 600) },
      };
    }
    const record = JSON.parse(readFileSync(recordPath, 'utf8'));
    // IntentGate keys a verdict by the lexical location it was handed.
    const lineOf = (v) => (v.lexical ? v.lexical.line : v.where ? v.where.line : v.line);
    const verdicts = (record.verdicts || record.findings || []).filter((v) => lineOf(v) === anchor.line);

    // What the AST gate can and cannot say about a must-survive property.
    //
    // A `Rejected / no-lexeme` at the anchor means the token is not there in
    // this configuration — a `-DNDEBUG` that removed an assert, an `#ifdef` that
    // excluded the call. That IS the loss, seen at the earliest layer that can
    // see it, and it is scored as a detection.
    //
    // A `Confirmed` means the call is spelled there. For a must-survive property
    // that is confirmation the requirement is real, not evidence about whether
    // it survived — the AST is the same at -O0 and at -O3. Scored NOT_DETECTED.
    if (verdicts.length === 0) {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason: `the record carries no verdict for ${anchor.file}:${anchor.line}`,
        explanation: null,
        evidence: { recordKeys: Object.keys(record) },
      };
    }
    const v = verdicts[0];
    const verdict = v.verdict;
    const reason = v.reason;
    const gone = verdict === 'Rejected' && (reason === 'no-lexeme' || reason === 'file-not-in-translation-unit');
    // The Derived Requirement is the gate's actual product: a property id, a
    // kind and a scope that a later stage can be asked about. Recorded because
    // §24 asks what each component contributed, and for this one the answer is
    // "a requirement", not "a detection".
    const derived = (record.requirements || []).filter((rq) => rq.origin && rq.origin.line === anchor.line);
    return {
      result: gone ? 'DETECTED' : 'NOT_DETECTED',
      reason: gone
        ? `the AST reports ${verdict}/${reason} at the anchor: the effect is not spelled there in this configuration`
        : `the AST reports ${verdict}/${reason} at the anchor; the AST is not changed by the optimiser, so this ` +
          'component cannot report a loss that happens after it',
      explanation: null,
      evidence: {
        verdict,
        astReason: reason,
        derivedRequirements: derived.map((rq) => ({ kind: rq.kind, scope: rq.scope, oracle: rq.oracle })),
        record: path.relative(workRoot, recordPath),
      },
    };
  };
}

/* ------------------------------------------------------------------ */
/* C — Pre/Post IR comparison                                          */
/* ------------------------------------------------------------------ */

/**
 * The two IR checkpoints, read through the same predicate the rest of the
 * experiment uses. A detection is PRESENT at ir-pre and ABSENT at ir-post — the
 * transition, not the end state, because an effect that was already gone before
 * the optimiser ran is not something a pre/post comparison found.
 */
export function makeIrPrePostGate() {
  return function gateIrPrePost({ readings }) {
    const pre = readings['ir-pre'];
    const post = readings['ir-post'];
    if (!pre || !post) {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason: 'one of the two IR checkpoints was not captured',
        explanation: null,
        evidence: {},
      };
    }
    if (pre.verdict === 'INVALID_CONTROL' || post.verdict === 'INVALID_CONTROL') {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason: (pre.verdict === 'INVALID_CONTROL' ? pre.reason : post.reason) || 'the control was not readable in the IR',
        explanation: null,
        evidence: { irPre: pre.verdict, irPost: post.verdict },
      };
    }
    if (pre.verdict === 'UNOBSERVED' || post.verdict === 'UNOBSERVED') {
      return {
        result: 'UNSUPPORTED',
        reason: 'this compiler does not expose LLVM IR, so there is no pre/post comparison to make',
        explanation: null,
        evidence: { irPre: pre.verdict, irPost: post.verdict },
      };
    }
    if (pre.verdict === 'PRESENT' && post.verdict === 'ABSENT') {
      return {
        result: 'DETECTED',
        reason: 'the effect is in the IR before the optimiser and gone after it',
        // A pre/post comparison brackets the loss between two checkpoints. It
        // cannot name a pass, and saying "the optimiser" is not naming one.
        explanation: null,
        evidence: {
          irPre: pre.verdict,
          irPost: post.verdict,
          effectPre: pre.effect ? pre.effect.count : null,
          effectPost: post.effect ? post.effect.count : null,
        },
      };
    }
    if (pre.verdict === 'ABSENT' || pre.verdict === 'NOT_APPLICABLE') {
      return {
        result: 'NOT_DETECTED',
        reason:
          `the effect was already ${pre.verdict} at ir-pre, so nothing happened between the two ` +
          'checkpoints for this comparison to see; the loss is upstream of the optimiser',
        explanation: null,
        evidence: { irPre: pre.verdict, irPost: post.verdict },
      };
    }
    return {
      result: 'NOT_DETECTED',
      reason: `ir-pre ${pre.verdict} -> ir-post ${post.verdict}: no pre/post transition`,
      explanation: null,
      evidence: {
        irPre: pre.verdict,
        irPost: post.verdict,
        effectPre: pre.effect ? pre.effect.count : null,
        effectPost: post.effect ? post.effect.count : null,
      },
    };
  };
}

/* ------------------------------------------------------------------ */
/* D — Pass-Level Tracking                                             */
/* ------------------------------------------------------------------ */

const SUMMARY_FIELDS = [
  '_type', 'unit', 'lineage', 'role', 'clone', 'firstLossSeq', 'firstLossPass',
  'firstLossPrevPass', 'firstLossPrevAfterPass', 'firstLossFnIdx', 'finalState',
  'everPresent', 'everLost', 'everReintroduced', 'lossEpisodes', 'fate', 'fateSeq',
  'fatePass', 'histLen',
];

export function parseObserverLog(text) {
  const out = { handshake: null, subjectRes: [], summary: [], hist: [], stats: null, roles: new Map() };
  for (const line of text.split('\n')) {
    if (!line) continue;
    const f = line.split('\t');
    switch (f[0]) {
      case 'HANDSHAKE':
        out.handshake = { schema: f[1], moduleId: f[2], target: f[3], control: f[4], mode: f[6] };
        break;
      case 'SUBJECTRES':
        out.subjectRes.push({ seq: Number(f[1]), moduleId: f[2], role: f[3], name: f[4], resolution: f[5] });
        break;
      case 'EV':
        out.roles.set(f[5], f[7]);
        break;
      case 'HIST':
        out.hist.push({ unit: f[1], idx: Number(f[2]), seq: Number(f[3]), phase: f[4], pass: f[5], count: Number(f[6]), state: f[7] });
        break;
      case 'SUMMARY': {
        const rec = {};
        SUMMARY_FIELDS.forEach((k, i) => { rec[k] = f[i]; });
        out.summary.push(rec);
        break;
      }
      case 'STATS':
        out.stats = { passesSeen: Number(f[1]), evRecords: Number(f[2]), unitsTracked: Number(f[3]), lineages: Number(f[4]), skipped: Number(f[5]), mode: f[6] };
        break;
      default:
        // Unknown record types are ignored, per the observer's own reader rule.
        break;
    }
  }
  return out;
}

export function makePassTrackingGate({ run, observerSo, workRoot }) {
  return function gatePassTracking({ fixtureDir, manifest, cell, prop }) {
    if (!existsSync(observerSo)) {
      return { result: 'UNSUPPORTED', reason: `the observer is not built at ${observerSo}`, explanation: null, evidence: {} };
    }
    if (!cell.compiler.startsWith('clang')) {
      return {
        result: 'UNSUPPORTED',
        reason: 'PropertyObserver is an LLVM pass-instrumentation plugin; it cannot be loaded into another compiler',
        explanation: null,
        evidence: {},
      };
    }
    const out = path.join(workRoot, 'observer', manifest.fixtureId, cell.cellId);
    rmSync(out, { recursive: true, force: true });
    mkdirSync(out, { recursive: true });
    const logPath = path.join(out, 'obs.tsv');

    const env = {
      OBS_TARGET_FN: prop.targetFn,
      OBS_CONTROL_FN: prop.oracleControlFn,
      OBS_EFFECT_SYMBOLS: (prop.effectSymbols || []).join(','),
      OBS_OUT: logPath,
      OBS_MODE: 'standard',
      OBS_REQUIRE_LIVE_BRANCH: prop.family === 'guardedCheck' ? '1' : '0',
    };
    const r = run(
      cell.compiler,
      [...cell.flags, '-c', manifest.sources.target, '-o', path.join(out, 'target.o'), `-fpass-plugin=${observerSo}`],
      { cwd: fixtureDir, env },
    );

    // rc 0 is not evidence the observer ran. `refusing to install` also exits 0,
    // and so does a plugin that loaded against a subject that is not there.
    if (!existsSync(logPath)) {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason:
          `no log was written (compiler exit ${r.status}). An observer that declines to install exits 0 ` +
          'and writes nothing, so a missing log is never read as "nothing was lost"',
        explanation: null,
        evidence: { stderr: r.stderr.slice(0, 400) },
      };
    }
    const log = parseObserverLog(readFileSync(logPath, 'utf8'));
    if (!log.handshake) {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason: 'the log carries no HANDSHAKE, so the plugin never announced itself',
        explanation: null,
        evidence: { logPath: path.relative(workRoot, logPath), stderr: r.stderr.slice(0, 400) },
      };
    }
    const subjRes = log.subjectRes.filter((s) => s.role === 'subject');
    const ctrlRes = log.subjectRes.filter((s) => s.role === 'control');
    const subjResolved = subjRes.some((s) => s.resolution === 'resolved');
    const ctrlResolved = ctrlRes.some((s) => s.resolution === 'resolved');
    if (!subjResolved || !ctrlResolved) {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason:
          `SUBJECTRES: subject=${subjRes.map((s) => s.resolution).join('/') || 'not-scanned'}, ` +
          `control=${ctrlRes.map((s) => s.resolution).join('/') || 'not-scanned'}. A run in which a name ` +
          'resolved nowhere cannot be read as an observation of that name',
        explanation: null,
        evidence: { subjectRes: subjRes, controlRes: ctrlRes, stats: log.stats },
      };
    }

    const subjectSummary = log.summary.find((s) => s.role === 'subject');
    const controlSummary = log.summary.find((s) => s.role === 'control');
    if (!subjectSummary) {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason: 'the log resolved the subject but wrote no SUMMARY row for it',
        explanation: null,
        evidence: { stats: log.stats },
      };
    }
    // The oracle again: a control that lost its own effect means the observer
    // could not see this form of the effect, not that the subject lost it.
    if (controlSummary && controlSummary.everLost === '1') {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason:
          `the control '${prop.oracleControlFn}' also went LOST (at ${controlSummary.firstLossPass}), so the ` +
          'observer is blind to this form of the effect and the subject reading means nothing',
        explanation: null,
        evidence: { controlSummary, stats: log.stats },
      };
    }

    const lost = subjectSummary.everLost === '1';
    const finalState = subjectSummary.finalState;
    if (!lost) {
      return {
        result: 'NOT_DETECTED',
        reason: `the subject's state never left ${finalState} across ${log.stats ? log.stats.passesSeen : '?'} pass invocations`,
        explanation: null,
        evidence: { finalState, stats: log.stats, fate: subjectSummary.fate },
      };
    }
    return {
      result: 'DETECTED',
      reason: `the subject went PRESENT -> LOST at ${subjectSummary.firstLossPass} (observation ${subjectSummary.firstLossSeq})`,
      explanation: subjectSummary.firstLossPass,
      evidence: {
        firstLossPass: subjectSummary.firstLossPass,
        firstLossSeq: Number(subjectSummary.firstLossSeq),
        previousAfterPass: subjectSummary.firstLossPrevAfterPass,
        finalState,
        everReintroduced: subjectSummary.everReintroduced === '1',
        lossEpisodes: Number(subjectSummary.lossEpisodes),
        unitFate: subjectSummary.fate,
        stats: log.stats,
        logPath: path.relative(workRoot, logPath),
      },
    };
  };
}

/* ------------------------------------------------------------------ */
/* E — Object/Link Integrity                                           */
/* ------------------------------------------------------------------ */

/**
 * Two honest notes before the code.
 *
 * `compiler/elf-verifier` answers "which permitted origin put this symbol in the
 * artefact", and it refuses to answer at all without a baseline keyed by
 * (toolchain digest, flag set, link form). Building forty such baselines was not
 * done in this run, so elf-verifier's classifier is not what runs below; its
 * status is recorded separately by the driver as an attempted invocation.
 *
 * What runs below is the object-level half of the same question, implemented
 * here: disassemble the linked executable and ask whether the subject function
 * still calls the effect, with the fixture's control function required to still
 * call it in the same binary. That is a call-form-only oracle. Above -O0 a wipe
 * is frequently rendered as inline zeroing and no call exists in either
 * function; the control requirement turns that into VERIFICATION_INCOMPLETE
 * rather than into a false detection, which is the whole reason it is there.
 */
export function makeObjectLinkGate({ run }) {
  function disassemble(binary, fn) {
    const r = run('objdump', ['-d', `--disassemble=${fn}`, binary]);
    return r.status === 0 ? r.stdout : null;
  }
  const callTo = (text, symbols) => {
    if (!text) return null;
    let n = 0;
    for (const line of text.split('\n')) {
      if (!/\b(call|callq|bl|blx|jmp)\b/.test(line)) continue;
      for (const s of symbols) {
        // objdump prints `call <memset@plt>` / `call <explicit_bzero>`
        if (new RegExp(`<${s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(@plt)?[+>]`).test(line)) { n++; break; }
      }
    }
    return n;
  };

  return function gateObjectLink({ manifest, prop, artifactPath }) {
    if (!artifactPath || !existsSync(artifactPath)) {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason: 'no linked executable was produced for this cell, so there is no artefact to check',
        explanation: null,
        evidence: {},
      };
    }
    // must-not-appear properties are the case this component is actually for.
    if (manifest.artifactMarkers) {
      const bytes = readFileSync(artifactPath);
      const has = (s) => bytes.includes(Buffer.from(s, 'utf8'));
      const control = manifest.artifactMarkers.oracleControl;
      if (control && !has(control.bytes)) {
        return {
          result: 'VERIFICATION_INCOMPLETE',
          reason: `the control marker '${control.markerId}' is not in the artefact, so a missing marker proves nothing`,
          explanation: null,
          evidence: {},
        };
      }
      const present = (manifest.artifactMarkers.mustNotAppear || []).filter((m) => has(m.bytes));
      return {
        result: present.length ? 'DETECTED' : 'NOT_DETECTED',
        reason: present.length
          ? `${present.map((m) => m.markerId).join(', ')} present in the linked executable`
          : 'no must-not-appear marker is in the linked executable',
        explanation: null,
        evidence: { markersPresent: present.map((m) => m.markerId), controlMarkerPresent: true },
      };
    }

    const subjectText = disassemble(artifactPath, prop.targetFn);
    const controlText = disassemble(artifactPath, prop.oracleControlFn);
    const symbols = prop.effectSymbols || [];
    const subjectCalls = callTo(subjectText, symbols);
    const controlCalls = callTo(controlText, symbols);

    if (controlText === null || controlCalls === 0) {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason:
          `the control '${prop.oracleControlFn}' shows no call to any of [${symbols.join(', ')}] in the linked ` +
          'executable. This oracle reads call sites only; when the compiler renders the effect inline there is ' +
          'nothing for it to see, and an absent call in the subject would then mean nothing',
        explanation: null,
        evidence: { controlDisassembled: controlText !== null, subjectCalls, controlCalls },
      };
    }
    if (subjectText === null) {
      return {
        result: 'VERIFICATION_INCOMPLETE',
        reason: `the subject '${prop.targetFn}' could not be disassembled out of the artefact`,
        explanation: null,
        evidence: { controlCalls },
      };
    }
    return {
      result: subjectCalls === 0 ? 'DETECTED' : 'NOT_DETECTED',
      reason:
        subjectCalls === 0
          ? `the subject calls none of [${symbols.join(', ')}] in the linked executable while the control calls ${controlCalls}`
          : `the subject still calls the effect ${subjectCalls} time(s) in the linked executable`,
      explanation: null,
      evidence: { subjectCalls, controlCalls, oracle: 'call-form-only' },
    };
  };
}

/* ------------------------------------------------------------------ */
/* F — Evidence Verifier                                               */
/* ------------------------------------------------------------------ */

/**
 * The verifier does not look at a property. It looks at a record of a run and
 * asks whether that record is the one its signer sealed. Asking it to detect a
 * deleted memset is a category error, and the honest word for that is
 * NOT_APPLICABLE — not a miss.
 *
 * Its real measurement is the tamper matrix in tamper.mjs, which is scored
 * separately and is not part of any recall number here.
 */
export function makeEvidenceGate() {
  return function gateEvidence() {
    return {
      result: 'NOT_APPLICABLE',
      reason:
        'the Evidence Verifier checks a record against its seal. It has no view of a compiled property, so it ' +
        'can neither detect nor miss a property loss. Its detections are recorded in the tamper matrix instead',
      explanation: null,
      evidence: {},
    };
  };
}
