// The driver proper: policy, normalisation, pin, flags, plugins, compile,
// evidence, exit code — in that order, because each step's failure mode is only
// safe if the steps before it have already succeeded.
//
// The plugin integrity check is a static import of the module compiler/schema/
// interfaces.md assigns to that component. It is not a lookup, not optional and
// not wrapped in a try/catch here: if it is missing the driver cannot claim to
// have checked plugins, and bin/vgcc.mjs turns the resolution failure into exit
// 3 rather than letting the build proceed unchecked.
import { checkPlugins } from '../plugin-integrity/integrity.mjs';

import { existsSync, mkdirSync, statSync } from 'node:fs';
import { resolve } from 'node:path';

import { splitDriverArgs, expandResponseFiles, normalise } from './cmdline.mjs';
import { loadEvidenceModule } from './evidence-binding.mjs';
import { EXIT_OK, EXIT_TOOL_FAILED, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_INTEGRITY } from './exit.mjs';
import { CFG, atOrAboveThreshold, isWellFormedFinding, makeFinding, normaliseFinding } from './findings.mjs';
import { checkFlags } from './flags.mjs';
import { parsePipeline, runObservation, runShipping } from './invoke.mjs';
import { relativiseToken, toRecordPath } from './paths.mjs';
import {
  evidenceOutDir, failOnIncomplete, loadPolicy, pinPath, requireDigestMatch, sourceDateEpoch,
} from './policy.mjs';
import { buildContext, buildRecord, writeRecord } from './record.mjs';
import { loadPin, pinnedSet, resolveCompiler, sha256File, verifyPin } from './toolchain.mjs';

const OBSERVATION_PIPELINE_FLAGS = ['-mllvm', '-print-pipeline-passes'];

function say(stderr, msg) { stderr.write(`vgcc: ${msg}\n`); }

/**
 * @param {{argv: string[], cwd: string, driverName: 'vgcc'|'vg++', mode: 'c'|'cxx',
 *          env: object, stdout: NodeJS.WritableStream, stderr: NodeJS.WritableStream}} io
 * @returns {Promise<number>} the process exit code
 */
export async function run({ argv, cwd, driverName, mode, env = process.env, stdout = process.stdout, stderr = process.stderr }) {
  const { own, compilerArgv, errors: argErrors } = splitDriverArgs(argv);
  for (const e of argErrors) say(stderr, e);
  if (argErrors.length > 0) return EXIT_INTEGRITY;

  // ---- 1. Policy. Nothing else runs until this succeeds. -------------------
  const loaded = loadPolicy({ cwd, policyPath: own.policy });
  if (!loaded.ok) {
    say(stderr, `policy ${loaded.reason}: ${loaded.detail}`);
    say(stderr, 'no evidence written — a record of a build checked against an unreadable policy would be a record of nothing.');
    return EXIT_INTEGRITY;
  }
  const { policy } = loaded;
  const root = loaded.dir; // record paths are relative to the policy's directory
  const outDir = evidenceOutDir(policy, root);

  // ---- 2. Normalise the command line. --------------------------------------
  const expansion = expandResponseFiles(compilerArgv, { cwd });
  const normalised = normalise(expansion.argv, { mode });

  const driverFindings = [];
  for (const note of expansion.notes) {
    driverFindings.push(makeFinding({
      id: CFG.RESPONSE_FILE_UNREADABLE,
      severity: 'high',
      title: 'A response file on the command line could not be expanded',
      detail: `${note.kind}: ${note.file} (${note.detail}). The tokens inside it were never matched against the policy.`,
      where: { kind: 'invocation', path: null, unit: null, pass: null },
    }));
  }
  let normalisationComplete = expansion.notes.length === 0 && normalised.unpairedXclang.length === 0;

  if (own.printNormalised) {
    stderr.write(`${JSON.stringify(recordInvocation({ normalised, expansion, cwd, root, driverName }), null, 2)}\n`);
  }

  // ---- 3. Toolchain pin. ----------------------------------------------------
  const pinFile = pinPath(policy, root);
  let pin = null;
  let pinVerification = { status: 'not-configured', packages: [], mismatches: [], reportedClang: null };
  let pinLoadError = null;

  if (pinFile) {
    const pinLoad = loadPin(pinFile);
    if (!pinLoad.ok) {
      pinLoadError = pinLoad;
    } else {
      pin = pinLoad.pin;
    }
  }

  const compiler = resolveCompiler({ mode, pin, override: own.clang });

  if (pin) {
    pinVerification = verifyPin(pin, { ccPath: compiler.path });
  }

  let integrityFailure = false;
  if (pinFile && pinLoadError) {
    driverFindings.push(makeFinding({
      id: CFG.PIN_UNREADABLE,
      severity: 'critical',
      title: 'The toolchain pin the policy names could not be read',
      detail: `${pinLoadError.reason}: ${pinLoadError.detail}`,
      where: { kind: 'invocation', path: null, unit: null, pass: null },
    }));
    if (requireDigestMatch(policy)) integrityFailure = true;
  } else if (pinVerification.status === 'mismatch') {
    for (const m of pinVerification.mismatches) {
      driverFindings.push(makeFinding({
        id: CFG.DIGEST_MISMATCH,
        severity: 'critical',
        title: 'An installed toolchain component does not match the pin',
        detail: `${m.name}: ${m.kind} — pin says ${m.expected}, installed is ${m.actual ?? '(could not be read)'}.`,
        where: { kind: 'invocation', path: null, unit: null, pass: null },
      }));
    }
    if (requireDigestMatch(policy)) integrityFailure = true;
  }

  // ---- 4. Flags. ------------------------------------------------------------
  const flagResult = checkFlags(normalised, policy, env);
  driverFindings.push(...flagResult.findings);

  // ---- 5. Plugin integrity (peer component). -------------------------------
  const labDir = outDir ? resolve(outDir, 'work', 'plugin-integrity') : null;
  if (labDir) mkdirSync(labDir, { recursive: true });

  let plugin = { findings: [], pipeline: null, pipelineAvailable: null, complete: false };
  let pluginError = null;
  if (integrityFailure) {
    // Nothing else runs after an integrity failure (interfaces.md §7). Saying
    // the plugin check is incomplete is the accurate thing to record; claiming
    // it passed would be the inaccurate one.
    pluginError = 'not attempted: toolchain integrity failed first';
  } else {
    try {
      // `argv[0]` is the compiler: the component's own contract, and it needs
      // one — it runs a shadow invocation of its own to capture the pipeline.
      // Passing the bare argument list would silently drop argv[1] from the
      // plugin scan, because the callee slices the compiler off the front.
      const raw = await checkPlugins({
        policy,
        argv: [compiler.path, ...expansion.argv],
        env,
        labDir,
      });
      plugin = {
        findings: Array.isArray(raw?.findings) ? raw.findings : [],
        ...readPipeline(raw?.pipeline),
        complete: raw?.complete === true,
      };
    } catch (err) {
      pluginError = err?.message ?? String(err);
    }
  }

  if (pluginError) {
    driverFindings.push(makeFinding({
      id: CFG.PLUGIN_CHECK_UNAVAILABLE,
      severity: 'high',
      title: 'The plugin integrity check did not complete',
      detail: pluginError,
      where: { kind: 'invocation', path: null, unit: null, pass: null },
    }));
  }

  const peerFindings = [];
  let malformedPeerFindings = 0;
  for (const f of plugin.findings) {
    if (isWellFormedFinding(f)) peerFindings.push(normaliseFinding(f));
    else malformedPeerFindings += 1;
  }
  if (malformedPeerFindings > 0) {
    normalisationComplete = false;
    driverFindings.push(makeFinding({
      id: CFG.PLUGIN_CHECK_UNAVAILABLE,
      severity: 'high',
      title: 'The plugin integrity check returned findings the driver could not record',
      detail: `${malformedPeerFindings} finding(s) did not match the shape in interfaces.md §2 and were dropped rather than reshaped.`,
      where: { kind: 'invocation', path: null, unit: null, pass: null },
    }));
  }

  const findings = [...driverFindings, ...peerFindings];
  const complete = plugin.complete && normalisationComplete && flagResult.complete !== false;
  const overThreshold = atOrAboveThreshold(findings, policy.failOn);

  // ---- 6. Decide whether to compile at all. --------------------------------
  //
  // Precedence, first match wins:
  //   4  integrity  — the pin does not match, or the policy is malformed
  //   2  findings   — at or above failOn; the build is not attempted, so a
  //                   forbidden configuration produces no object file to ship
  //   1  tool       — clang failed; its diagnostics already went to the caller
  //   3  incomplete — the build succeeded but a check could not be made, and
  //                   the policy says that is fatal
  //   3  evidence   — the record could not be written, so nothing was proved
  //   0  clean
  //
  // Two orderings here were got wrong first and are worth stating.
  //
  // 2 outranks 3: a named violation is more actionable than an unfinished
  // check, both are non-zero, and the incompleteness is in the record either
  // way. What must never happen is 3 collapsing to 0, and it cannot — the 0
  // branch is reached only when `complete` is true.
  //
  // 1 outranks 3, which is why the incompleteness test is *after* the build
  // and not before it. A source file that does not compile cannot have its
  // pass pipeline captured, so the plugin check reports `complete: false` for
  // every syntax error. Testing incompleteness first made every compile error
  // exit 3 with the compiler never run and its diagnostics never printed —
  // the driver answering "I could not check this" to a question whose real
  // answer was "line 1 does not parse".
  let exitCode = null;
  let reason = null;
  if (integrityFailure) { exitCode = EXIT_INTEGRITY; reason = 'toolchain-or-policy-integrity'; }
  else if (overThreshold.length > 0) { exitCode = EXIT_FINDINGS; reason = 'findings-at-threshold'; }

  // ---- 7. Build. ------------------------------------------------------------
  let shipping = null;
  let observation = null;
  let artifacts = [];
  const timings = {};

  if (exitCode === null) {
    const res = runShipping({ compiler: compiler.path, argv: compilerArgv, cwd, env });
    timings.shippingMs = res.durationMs;
    shipping = { attempted: true, exitCode: res.exitCode, signal: res.signal, spawnError: res.spawnError };
    if (!res.ok) {
      if (res.spawnError) say(stderr, `could not run ${compiler.path}: ${res.spawnError}`);
      exitCode = EXIT_TOOL_FAILED;
      reason = 'tool-failed';
    } else {
      artifacts = digestArtifacts(normalised.expectedArtifacts, cwd, root);

      // Anything added for observation runs separately and writes elsewhere;
      // the artefact the caller keeps is the one from the run above.
      if (own.observePipeline && labDir) {
        const obs = runObservation({
          compiler: compiler.path,
          argv: compilerArgv,
          cwd,
          scratchDir: resolve(labDir, '..', 'driver-observation'),
          extraFlags: OBSERVATION_PIPELINE_FLAGS,
          label: 'pipeline',
          env,
        });
        timings.observationMs = obs.durationMs;
        const parsed = obs.ok ? parsePipeline(obs.stdout + obs.stderr) : null;
        // Recorded under `build.observation` and nowhere else. It is *not*
        // folded into `checks.pluginIntegrity.pipeline*`: that field says what
        // the plugin integrity component observed, and quietly substituting a
        // different run's answer would make the record claim a provenance the
        // observation does not have.
        observation = {
          attempted: true,
          exitCode: obs.exitCode,
          extraFlags: obs.extraFlags,
          outputDiscarded: true,
          pipelineLength: parsed ? parsed.length : null,
        };
      }

      // The build succeeded. Only now is "a check could not be completed" the
      // most useful thing left to say about it.
      if (!complete && failOnIncomplete(policy)) {
        exitCode = EXIT_INCOMPLETE;
        reason = 'checks-incomplete';
      }
    }
  } else {
    shipping = { attempted: false, exitCode: null, signal: null, spawnError: null };
  }

  // ---- 8. Evidence. ---------------------------------------------------------
  const context = buildContext({ sourceDateEpoch: sourceDateEpoch(policy) });
  context.timings = timings;
  context.compiler = { invokedAs: compiler.path.split(/[\\/]/).pop(), resolvedFrom: compiler.source };

  const record = buildRecord({
    driverName,
    mode,
    policy: {
      policyVersion: policy.policyVersion,
      failOn: policy.failOn,
      sha256: loaded.sha256,
      path: toRecordPath(loaded.path, root),
      failOnIncomplete: failOnIncomplete(policy),
      requireDigestMatch: requireDigestMatch(policy),
    },
    invocation: recordInvocation({ normalised, expansion, cwd, root, driverName }),
    toolchain: {
      clang: pinVerification.reportedClang ?? (pin?.clang ?? null),
      digest: null, // filled below, once the canonicaliser is available
      packages: pinVerification.packages,
      pinConfigured: pinFile !== null,
      pinStatus: pinLoadError ? `unreadable:${pinLoadError.reason}` : pinVerification.status,
    },
    checks: {
      flags: flagResult.detail,
      pluginIntegrity: {
        complete: plugin.complete,
        findingCount: peerFindings.length,
        malformedFindings: malformedPeerFindings,
        // null, not false: "the component was not reached" is not "the pipeline
        // was not available", and collapsing the two is how a record starts
        // asserting something nobody observed.
        pipelineAvailable: plugin.pipelineAvailable,
        pipelineConstrained: Array.isArray(policy.toolchain?.allowedPassPipeline),
        pipelineLength: plugin.pipeline ? plugin.pipeline.length : null,
      },
      responseFiles: {
        expanded: expansion.expanded.length,
        unresolved: expansion.notes.length,
      },
      toolchainPin: {
        mismatchCount: pinVerification.mismatches.length,
        mismatches: pinVerification.mismatches,
        status: pinLoadError ? `unreadable:${pinLoadError.reason}` : pinVerification.status,
      },
    },
    build: { artifacts, observation, shipping },
    findings,
    exitCode: exitCode ?? EXIT_OK,
    exitReason: reason ?? 'clean',
    context,
  });

  // `toolchain.digest` is the digest of the pinned set, computed with the same
  // canonicaliser the record itself is digested with — not a second one.
  if (pin) {
    try {
      const { evidenceDigest } = await loadEvidenceModule();
      record.toolchain.digest = evidenceDigest(pinnedSet(pin, pinVerification));
    } catch { /* reported by writeRecord below */ }
  }

  if (!outDir) {
    say(stderr, 'policy has no evidence.out, so there is nowhere to record what was checked');
    return exitCode ?? EXIT_INCOMPLETE;
  }

  const written = await writeRecord({ record, outDir });
  if (!written.ok) {
    say(stderr, `evidence not written (${written.reason}):`);
    stderr.write(`${written.detail}\n`);
    return exitCode ?? EXIT_INCOMPLETE;
  }
  if (own.verbose) say(stderr, `evidence ${written.relPath} (${written.digest})`);

  return exitCode ?? EXIT_OK;
}

/**
 * The pipeline the plugin component reports. interfaces.md fixes the finding
 * shape but not this one, so both spellings in circulation are accepted: a bare
 * list of pass names, and the richer `{available, passes, reason}` the component
 * actually returns. Anything else is "no pipeline observed" — which is
 * different from "an empty pipeline", and is recorded as such.
 */
function readPipeline(pipeline) {
  if (Array.isArray(pipeline)) return { pipeline, pipelineAvailable: true };
  if (pipeline && typeof pipeline === 'object') {
    const available = pipeline.available === true;
    return {
      pipeline: available && Array.isArray(pipeline.passes) ? pipeline.passes : null,
      pipelineAvailable: available,
    };
  }
  return { pipeline: null, pipelineAvailable: false };
}

function recordInvocation({ normalised, expansion, cwd, root, driverName }) {
  return {
    action: normalised.action,
    argv: normalised.argv.map((t) => relativiseToken(t, root)),
    cwd: toRecordPath(cwd, root),
    driver: driverName,
    linkInputs: normalised.linkInputs.map((p) => toRecordPath(resolve(cwd, p), root)),
    optLevels: normalised.optLevels,
    output: normalised.output === null ? null : toRecordPath(resolve(cwd, normalised.output), root),
    plugins: {
      frontend: normalised.plugins.frontend.map(baseName),
      legacyLoad: normalised.plugins.legacyLoad.map(baseName),
      pass: normalised.plugins.pass.map(baseName),
    },
    responseFilesExpanded: expansion.expanded.length,
    sources: normalised.sources.map((p) => (p === '-' ? '-' : toRecordPath(resolve(cwd, p), root))),
    unpairedXclang: normalised.unpairedXclang.length,
  };
}

function baseName(p) { return String(p).split(/[\\/]/).pop(); }

function digestArtifacts(expected, cwd, root) {
  const out = [];
  for (const rel of expected) {
    const abs = resolve(cwd, rel);
    if (!existsSync(abs)) continue;
    let bytes = 0;
    try { bytes = statSync(abs).size; } catch { continue; }
    out.push({ bytes, path: toRecordPath(abs, root), sha256: sha256File(abs) });
  }
  return out;
}
