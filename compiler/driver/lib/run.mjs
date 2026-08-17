// The driver proper: policy, normalisation, pin, flags, plugins, compile,
// evidence, exit code —in that order, because each step's failure mode is only
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
import { evaluateFallback, readFallbackPolicy } from './fallback.mjs';
import { CFG, atOrAboveThreshold, isWellFormedFinding, makeFinding, normaliseFinding } from './findings.mjs';
import { checkFlags } from './flags.mjs';
import { parsePipeline, runObservation, runShipping } from './invoke.mjs';
import { relativiseToken, toRecordPath } from './paths.mjs';
import {
  evidenceOutDir, failOnIncomplete, loadPolicy, pinPath, requireDigestMatch, sourceDateEpoch,
} from './policy.mjs';
import {
  CATALOGUE_PATH, CATALOGUE_RECORD_PATH, catalogueUnreadableFinding, checkProperties, countingLine,
  loadCatalogue,
} from './properties.mjs';
import { buildContext, buildRecord, writeRecord } from './record.mjs';
import {
  loadPin, pinnedSet, reconcileCompiler, resolveCompiler, sha256File, verifyPin,
} from './toolchain.mjs';

const OBSERVATION_PIPELINE_FLAGS = ['-mllvm', '-print-pipeline-passes'];

function say(stderr, msg) { stderr.write(`vgcc: ${msg}\n`); }

/**
 * @param {{argv: string[], cwd: string, driverName: 'vgcc'|'vg++', mode: 'c'|'cxx',
 *          env: object, stdout: NodeJS.WritableStream, stderr: NodeJS.WritableStream}} io
 * @returns {Promise<number>} the process exit code
 */
export async function run({
  argv, cwd, driverName, mode, env = process.env, stdout = process.stdout, stderr = process.stderr,
  cataloguePath = CATALOGUE_PATH,
}) {
  const { own, compilerArgv, errors: argErrors } = splitDriverArgs(argv);
  for (const e of argErrors) say(stderr, e);
  if (argErrors.length > 0) return EXIT_INTEGRITY;

  // ---- 1. Policy. Nothing else runs until this succeeds. -------------------
  const loaded = loadPolicy({ cwd, policyPath: own.policy });
  if (!loaded.ok) {
    say(stderr, `policy ${loaded.reason}: ${loaded.detail}`);
    say(stderr, 'no evidence written —a record of a build checked against an unreadable policy would be a record of nothing.');
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
  let pinVerification = {
    status: 'not-configured', packages: [], mismatches: [], unobserved: [], versions: [], reportedClang: null,
  };
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

  // Reconcile before verifying, so that the version probe inside `verifyPin`
  // and the shipping build below both spawn the *same* file the reconciliation
  // judged. Spawning the string and reconciling a lookup of the string are two
  // resolutions of one name and a PATH change between them is a hole.
  const reconciliation = reconcileCompiler({ pin, compiler, cwd, env });
  // The located path, not the realpath: clang branches on its own argv[0], so
  // following the symlink here would put `vg++` into C mode. See toolchain.mjs.
  const compilerPath = reconciliation.locatedPath ?? compiler.path;

  if (pin) {
    pinVerification = verifyPin(pin, { ccPath: compilerPath });
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
      const isVersion = m.kind === 'package-version';
      driverFindings.push(makeFinding({
        id: isVersion ? CFG.PACKAGE_VERSION_MISMATCH : CFG.DIGEST_MISMATCH,
        severity: 'critical',
        title: isVersion
          ? 'An installed package is a different version from the one the pin records'
          : 'An installed toolchain component does not match the pin',
        detail: `${m.name}: ${m.kind} —pin says ${m.expected}, installed is ${m.actual ?? '(could not be read)'}.`,
        where: { kind: 'invocation', path: null, unit: null, pass: null },
      }));
    }
    if (requireDigestMatch(policy)) integrityFailure = true;
  }

  // A pinned version nobody could observe is not a pinned version that matched.
  // It is exit 3 (via `complete` below) rather than exit 4: nothing disagreed,
  // the check simply did not happen, and those are different claims.
  for (const u of pinVerification.unobserved) {
    driverFindings.push(makeFinding({
      id: CFG.PACKAGE_VERSION_UNOBSERVED,
      severity: 'high',
      title: 'The pin states a package version this machine could not observe',
      detail: `${u.name}: the pin says ${u.expected}, and the version could not be read back (${u.method}). `
        + 'The pin was written from a package database; verifying it needs one.',
      where: { kind: 'invocation', path: null, unit: null, pass: null },
    }));
  }
  const pinVersionsComplete = pinVerification.unobserved.length === 0;

  // The executed binary against the pinned set. This is a separate question
  // from `requireDigestMatch`, and is not gated on it: that switch downgrades
  // "the pinned files are not the pinned bytes" to a finding, and was never a
  // decision to let the driver run a compiler the pin has never seen.
  if (pin && reconciliation.status !== 'in-pin') {
    driverFindings.push(makeFinding({
      id: CFG.COMPILER_OUTSIDE_PIN,
      severity: 'critical',
      title: 'The compiler the driver would execute is not in the pinned set',
      detail: `${reconciliation.detail}. Every digest in the pin can be correct and this still be true; `
        + 'the pin covers files, and this is about which file runs.',
      where: { kind: 'invocation', path: null, unit: null, pass: null },
    }));
    integrityFailure = true;
  }

  // Leaving the pin on the command line is recorded as leaving the pin. The
  // confession also goes into `toolchain.compiler` below, which is inside the
  // digested part of the record —`context` is removed as a whole subtree
  // before digesting (compiler/evidence/canon.mjs rule 1), so a confession
  // written there would not be covered by `evidenceDigest` at all.
  if (reconciliation.overriddenByFlag) {
    driverFindings.push(makeFinding({
      id: CFG.PIN_OVERRIDDEN,
      severity: pin ? 'high' : 'medium',
      title: '--vg-clang replaced the compiler the pin names',
      detail: pin
        ? `the pin names a driver for this mode and --vg-clang overrode it with ${reconciliation.invokedAs}; `
          + `reconciliation against the pinned set says ${reconciliation.status}`
        : `--vg-clang selected ${reconciliation.invokedAs} and no pin is configured, so nothing constrains it`,
      where: { kind: 'invocation', path: null, unit: null, pass: null },
    }));
  }

  // ---- 4. Flags. ------------------------------------------------------------
  const flagResult = checkFlags(normalised, policy, env);
  driverFindings.push(...flagResult.findings);

  // ---- 4b. Declared properties against the catalogue. ----------------------
  //
  // `policy.properties[]` had no consumer at all: a policy could require five
  // security properties, none of which anything in this tree can observe, and
  // the build exited 0. policy.schema.json already fixes the answer —"A
  // property with no reachable checkpoint is exit 3, not a pass" —so what was
  // missing was the code, not the decision.
  const catalogueLoad = loadCatalogue(cataloguePath);
  let properties;
  let catalogueStatus;
  if (catalogueLoad.ok) {
    catalogueStatus = {
      path: CATALOGUE_RECORD_PATH,
      schemaVersion: catalogueLoad.catalogue.schemaVersion,
      sha256: catalogueLoad.catalogue.sha256,
      entryCount: catalogueLoad.catalogue.entryCount,
      status: 'loaded',
    };
    properties = checkProperties(policy.properties, catalogueLoad.catalogue);
  } else {
    catalogueStatus = {
      path: CATALOGUE_RECORD_PATH,
      schemaVersion: null,
      sha256: null,
      entryCount: 0,
      status: `unreadable:${catalogueLoad.reason}`,
    };
    // Not "there were no properties to check". The question could not be put.
    const requested = Array.isArray(policy.properties) ? policy.properties.length : 0;
    properties = {
      configured: Array.isArray(policy.properties),
      requested,
      checked: 0,
      skipped: requested,
      usable: 0,
      unanswerable: requested,
      complete: false,
      verdict: 'catalogue-unreadable',
      claim: 'the catalogue could not be read, so no property was cross-checked and none is claimed to hold',
      entries: [],
      findings: [catalogueUnreadableFinding(catalogueLoad)],
    };
  }
  driverFindings.push(...properties.findings);
  const propertiesLine = countingLine(properties);
  if (own.verbose) say(stderr, `properties ${propertiesLine} usable=${properties.usable} verdict=${properties.verdict}`);
  if (!properties.complete) say(stderr, `properties ${propertiesLine} —${properties.claim}`);

  // ---- 5. Plugin integrity (peer component). -------------------------------
  const labDir = outDir ? resolve(outDir, 'work', 'plugin-integrity') : null;
  if (labDir) mkdirSync(labDir, { recursive: true });

  // Declared here rather than beside the build because §5b writes into it too.
  // Everything in it is a duration, and durations live in `context`, which is
  // removed before the record is digested.
  const timings = {};

  let plugin = { findings: [], pipeline: null, pipelineAvailable: null, complete: false };
  let pluginError = null;
  if (integrityFailure) {
    // Nothing else runs after an integrity failure (interfaces.md §7). Saying
    // the plugin check is incomplete is the accurate thing to record; claiming
    // it passed would be the inaccurate one.
    pluginError = 'not attempted: toolchain integrity failed first';
  } else if (!properties.complete) {
    pluginError = 'not attempted: the policy declares a property that has no reachable checkpoint';
  } else {
    try {
      // `argv[0]` is the compiler: the component's own contract, and it needs
      // one —it runs a shadow invocation of its own to capture the pipeline.
      // Passing the bare argument list would silently drop argv[1] from the
      // plugin scan, because the callee slices the compiler off the front.
      const raw = await checkPlugins({
        policy,
        argv: [compilerPath, ...expansion.argv],
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

  // ---- 5b. Security-preserving fallback (policy.fallback; opt-in). ---------
  //
  // Entered only when the policy carries a `fallback` block. A policy that does
  // not mention it never reaches this code and gets no `checks.fallback` key, so
  // its record is what it was before this step existed — the opt-in cannot move
  // the default path by a single byte.
  //
  // It sits here, after the plugin check and before the exit decision, for two
  // reasons. It spawns the compiler, so it must not run before the checks that
  // decide whether this toolchain may be spawned at all. And it produces
  // findings that the threshold then judges, so it must run before §6.
  const fallbackPolicy = readFallbackPolicy(policy);
  let fallbackResult = null;
  if (fallbackPolicy.configured) {
    fallbackResult = evaluateFallback({
      policy,
      normalised,
      compilerArgv,
      compiler: compilerPath,
      cwd,
      root,
      workDir: outDir ? resolve(outDir, 'work', 'driver-fallback') : null,
      observer: own.observer,
      // The ladder frontier measured for this invocation, resolved against the
      // working directory rather than the fixture root: the policy names the
      // sidecar, the invocation carries the reading, and `--vg-observer` already
      // draws that line the same way. Passed unconditionally and read only when
      // the policy names a sidecar — without this the guard has two reachable
      // states, off and refuse-everything, because nothing could ever supply the
      // half of the comparison that is taken per build.
      exposureFrontier: own.exposureFrontier,
      env,
      blocked: integrityFailure ? 'toolchain-or-policy-integrity'
        : !properties.complete ? 'policy-properties-unanswerable'
          : atOrAboveThreshold([...driverFindings, ...peerFindings], policy.failOn).length > 0
            ? 'findings-at-threshold'
            : null,
    });
    driverFindings.push(...fallbackResult.findings);
    Object.assign(timings, fallbackResult.timings);
    if (own.verbose || fallbackResult.record.status !== 'disabled') {
      say(stderr, `fallback ${fallbackResult.record.status}/${fallbackResult.record.verdict} —${fallbackResult.record.claim}`);
    }
  }

  const findings = [...driverFindings, ...peerFindings];
  const complete = plugin.complete && normalisationComplete && flagResult.complete !== false
    && properties.complete && pinVersionsComplete && (fallbackResult ? fallbackResult.complete : true);
  const overThreshold = atOrAboveThreshold(findings, policy.failOn);

  // ---- 6. Decide whether to compile at all. --------------------------------
  //
  // Precedence, first match wins:
  //   4  integrity  —the pin does not match, the compiler is not in the pinned
  //                   set, or the policy is malformed
  //   3  properties —the policy declares a property with no reachable
  //                   checkpoint
  //   2  findings   —at or above failOn; the build is not attempted, so a
  //                   forbidden configuration produces no object file to ship
  //   1  tool       —clang failed; its diagnostics already went to the caller
  //   3  incomplete —the build succeeded but a check could not be made, and
  //                   the policy says that is fatal
  //   3  evidence   —the record could not be written, so nothing was proved
  //   0  clean
  //
  // The properties slot sits ABOVE findings, which is the one place this list
  // departs from "2 outranks 3". policy.schema.json writes the code down for
  // that condition —"A property with no reachable checkpoint is exit 3, not a
  // pass" —so letting a policy's own `failOn` re-map it to 2 would make the
  // schema's sentence false, and the code would depend on a threshold that has
  // nothing to do with it. It is also a different kind of statement: a finding
  // says the build did something; this says a question the policy asked was
  // never put. The build is not attempted, for the same fail-closed reason a
  // finding at threshold does not produce an object file.
  //
  // Two other orderings here were got wrong first and are worth stating.
  //
  // 2 outranks 3: a named violation is more actionable than an unfinished
  // check, both are non-zero, and the incompleteness is in the record either
  // way. What must never happen is 3 collapsing to 0, and it cannot —the 0
  // branch is reached only when `complete` is true.
  //
  // 1 outranks 3, which is why the incompleteness test is *after* the build
  // and not before it. A source file that does not compile cannot have its
  // pass pipeline captured, so the plugin check reports `complete: false` for
  // every syntax error. Testing incompleteness first made every compile error
  // exit 3 with the compiler never run and its diagnostics never printed —  // the driver answering "I could not check this" to a question whose real
  // answer was "line 1 does not parse".
  let exitCode = null;
  let reason = null;
  if (integrityFailure) { exitCode = EXIT_INTEGRITY; reason = 'toolchain-or-policy-integrity'; }
  else if (!properties.complete) { exitCode = EXIT_INCOMPLETE; reason = 'policy-properties-unanswerable'; }
  else if (overThreshold.length > 0) { exitCode = EXIT_FINDINGS; reason = 'findings-at-threshold'; }

  // ---- 7. Build. ------------------------------------------------------------
  let shipping = null;
  let observation = null;
  let artifacts = [];

  if (exitCode === null) {
    const res = runShipping({ compiler: compilerPath, argv: compilerArgv, cwd, env });
    timings.shippingMs = res.durationMs;
    shipping = { attempted: true, exitCode: res.exitCode, signal: res.signal, spawnError: res.spawnError };
    if (!res.ok) {
      if (res.spawnError) say(stderr, `could not run ${compilerPath}: ${res.spawnError}`);
      exitCode = EXIT_TOOL_FAILED;
      reason = 'tool-failed';
    } else {
      artifacts = digestArtifacts(normalised.expectedArtifacts, cwd, root);

      // Anything added for observation runs separately and writes elsewhere;
      // the artefact the caller keeps is the one from the run above.
      if (own.observePipeline && labDir) {
        const obs = runObservation({
          compiler: compilerPath,
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
  // Which compiler ran used to be recorded HERE, and that was the bug. `context`
  // is removed as a whole subtree before digesting (interfaces.md §5 rule 1,
  // compiler/evidence/canon.mjs), so `resolvedFrom: "flag"` —the record of a
  // build that left the pin —was outside `evidenceDigest` and two records, one
  // pinned and one overridden, digested identically. It now lives in
  // `toolchain.compiler`, which is digested.

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
      // Inside the digest, deliberately. See the note next to `context` above.
      compiler: {
        inPinSet: reconciliation.inPinSet,
        invokedAs: reconciliation.invokedAs,
        located: reconciliation.located,
        overriddenByFlag: reconciliation.overriddenByFlag,
        pinnedAs: reconciliation.pinnedAs,
        reconciliation: reconciliation.status,
        resolvedFrom: reconciliation.resolvedFrom,
      },
      digest: null, // filled below, once the canonicaliser is available
      packages: pinVerification.packages,
      pinConfigured: pinFile !== null,
      pinStatus: pinLoadError ? `unreadable:${pinLoadError.reason}` : pinVerification.status,
    },
    checks: {
      // Spread, not a `fallback: null`. A policy with no `fallback` block must
      // produce the record it produced before this feature existed, and a key
      // holding null is still a key: it changes the canonical text and therefore
      // the digest of every build in the world that never asked for this.
      ...(fallbackResult ? { fallback: fallbackResult.record } : {}),
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
      properties: {
        catalogue: catalogueStatus,
        // "the policy never raised the question" and "the policy raised it and
        // listed nothing" are two different facts, so they are two fields. An
        // empty list is legal and says requested=0 in as many words; neither
        // state is ever rendered as "all requirements met".
        claim: properties.claim,
        complete: properties.complete,
        configured: properties.configured,
        counts: { checked: properties.checked, inputs: properties.requested, skipped: properties.skipped },
        entries: properties.entries,
        requested: properties.requested,
        unanswerable: properties.unanswerable,
        usable: properties.usable,
        verdict: properties.verdict,
      },
      responseFiles: {
        expanded: expansion.expanded.length,
        unresolved: expansion.notes.length,
      },
      toolchainPin: {
        compilerReconciliation: reconciliation.status,
        compilerInPinSet: reconciliation.inPinSet,
        mismatchCount: pinVerification.mismatches.length,
        mismatches: pinVerification.mismatches,
        status: pinLoadError ? `unreadable:${pinLoadError.reason}` : pinVerification.status,
        unobserved: pinVerification.unobserved,
        unobservedCount: pinVerification.unobserved.length,
        versions: pinVerification.versions,
      },
    },
    build: { artifacts, observation, shipping },
    findings,
    exitCode: exitCode ?? EXIT_OK,
    exitReason: reason ?? 'clean',
    context,
  });

  // `toolchain.digest` is the digest of the pinned set, computed with the same
  // canonicaliser the record itself is digested with —not a second one.
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
 * actually returns. Anything else is "no pipeline observed" —which is
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
