#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import { ENGINE_VERSION, loadConfig, scanPath } from '@vibeguard/analyzer-core';
import {
  compareConfidence,
  compareSeverity,
  emptySummary,
  summarize,
  type ProtectionClaim,
  type Severity,
} from '@vibeguard/findings-schema';
import { toSarif } from '@vibeguard/sarif-adapter';
import { parseArgs, HELP_TEXT } from './args.js';
import { formatHuman, formatMarkdown } from './format.js';
import { diffScopePrefix, gitRepoRootOf, scanDiff } from './diff.js';
import { runFix } from './fix.js';
import { claimsFromLedger, recordFixerClaims } from './fix-ledger.js';
import { readDeclaredPackages } from './declared-packages.js';

// Tool version: the released CLI artifact version. Read from package.json at
// runtime so it always matches the published package and never drifts. This is
// distinct from ENGINE_VERSION (the detection-engine semantics version), which
// advances only when detection behavior changes.
const VERSION = (
  JSON.parse(
    readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
  ) as { version: string }
).version;

/**
 * The repository-root-relative prefix for `target`, or `''` when there is none.
 *
 * Only SARIF needs this. `filePath` on a finding is relative to the scan target
 * — the basis `--fix`, the config `suppress[].paths` globs and the human
 * formatter all read — but GitHub code scanning resolves
 * `artifactLocation.uri` from the repository root. For a scan of the repo root
 * the two coincide, which is why this went unnoticed; for a scan of a
 * subdirectory every emitted URI named a path that does not exist.
 *
 * Returns `''` outside a work tree, so a scan of a plain directory still
 * produces the URIs it always did.
 */
async function sarifUriPrefix(target: string): Promise<string> {
  const root = await gitRepoRootOf(target);
  return root ? diffScopePrefix(root, target) : '';
}

/**
 * Is the scan target a single file rather than a directory?
 *
 * Both the fix path and the ledger need it, and it has to answer the same way
 * for both: the ledger's `filePath` entries are relative to the root the fixer
 * resolved its edits against, so a disagreement here would write a ledger under
 * one root and look for it under another.
 */
function targetIsFileOf(target: string): boolean {
  try {
    return statSync(target).isFile();
  } catch {
    // A missing target has already failed the scan; `--diff` defaults to '.'.
    return false;
  }
}

const FAIL_LEVEL: Record<string, Severity | null> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  never: null,
};

async function main(): Promise<number> {
  const parsed = parseArgs(process.argv.slice(2));
  if ('help' in parsed) {
    process.stdout.write(HELP_TEXT);
    return 0;
  }
  if ('version' in parsed) {
    process.stdout.write(`vibeguard ${VERSION} (engine ${ENGINE_VERSION})\n`);
    return 0;
  }
  if ('error' in parsed) {
    process.stderr.write(`error: ${parsed.error}\n`);
    process.stderr.write(HELP_TEXT);
    return 2;
  }
  const args = parsed;

  // ── Declared-package veto (§17z-b) ───────────────────────────────────────
  //
  // ALWAYS ON, with no flag to disable it, and that is not an oversight.
  // `--include-design-smells` is default-off because it ADDS a class of finding
  // and costs a second pass over the tree; this is the opposite on both counts.
  // It removes findings whose PREMISE has been disproven — VG-AISC-001 says "a
  // generator invented this package name", and a lockfile entry is the record
  // of a registry having resolved it — so an opt-out would recover nothing
  // except findings that are known-wrong. It also costs one directory read,
  // whether or not anything is found.
  //
  // What it deliberately does NOT claim is that a declared package is SAFE; see
  // `declared-veto.ts` for the residual slopsquat case (a name that was
  // hallucinated, registered by an attacker, and then actually installed is in
  // the lockfile like any other). Nothing here is a substitute for a rule that
  // judges real packages.
  //
  // Read BEFORE the scan and reported on stderr, so the ordering a user sees is
  // "here is the evidence I used" then "here is what it removed", and so stdout
  // stays byte-identical to what the chosen format produced.
  const declared = await readDeclaredPackages(args.target);
  for (const w of declared.warnings) {
    process.stderr.write(`warning: ${w}\n`);
  }
  // A veto deletes findings, and this codebase does not allow a mechanism to
  // delete findings in silence. The count comes back through an analyzer
  // callback rather than a `ScanResponse` field only because this change is
  // budgeted one additive schema field; see `AnalyzerOptions.
  // onDeclaredPackageVeto`. Aggregated to one line: a project that legitimately
  // depends on twelve near-miss-looking packages should not get twelve notes.
  let vetoed = 0;
  const onDeclaredPackageVeto = (): void => {
    vetoed += 1;
  };

  let scan;
  try {
    if (args.diff) {
      scan = await scanDiff({
        cwd: args.target,
        range: args.diff,
        mode: args.mode,
        includeRemediation: !args.noRemediation,
        ignore: args.ignore,
        // Passed on BOTH paths. It used to reach `scanPath` only, so
        // `--known-only` was accepted and ignored whenever `--diff` was given —
        // a flag that changes what gets scanned, doing nothing, without saying so.
        knownLanguagesOnly: args.knownLanguagesOnly,
        config: args.noConfig ? false : args.config,
        // `ScanDiffOptions extends AnalyzerOptions`, so the declared set rides
        // in as the Analyzer-level default and reaches the requests `scanDiff`
        // builds internally. That is why the analyzer accepts an instance-level
        // default at all: without it the diff channel — the CI path, where a
        // hallucinated-dependency false positive is most expensive — could not
        // be given the evidence without rewriting a module this change does not
        // own.
        declaredPackages: declared.packages,
        declaredPackageSource: declared.sources.map((x) => x.file).join(', ') || undefined,
        onDeclaredPackageVeto,
      });
    } else {
      scan = await scanPath(args.target, {
        mode: args.mode,
        includeRemediation: !args.noRemediation,
        ignore: args.ignore,
        knownLanguagesOnly: args.knownLanguagesOnly,
        config: args.noConfig ? false : args.config,
        declaredPackages: declared.packages,
        declaredPackageSource: declared.sources.map((x) => x.file).join(', ') || undefined,
        onDeclaredPackageVeto,
      });
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`error: ${message}\n`);
    return 2;
  }

  if (vetoed > 0) {
    const from = declared.sources.map((s) => s.file).join(', ');
    // Phrased as what was OBSERVED, not what it proves. The lockfile is read as
    // written; nothing here contacts a registry, and nothing checks `resolved`
    // or `integrity`. A hand-written entry naming a package that was never
    // published is indistinguishable from a real one at this layer — so the old
    // wording ("This says the package EXISTS") asserted a fact the tool had not
    // established, the same over-claim `match-limit` used to make.
    process.stderr.write(
      `note: ${vetoed} supply-chain finding(s) not reported — ${from} declares the package, ` +
        'so the name is not treated as invented. That is a statement about the lockfile, ' +
        'not evidence that the package exists or is safe; the entry is read as written and ' +
        'is not verified against a registry.\n',
    );
  }

  // ── Cross-file design smells (opt-in) ────────────────────────────────────
  //
  // DYNAMIC import, inside the flag check, and that placement is the point.
  // `@vibeguard/analysis-graph` is the cross-file brain, and the phase's
  // absolute constraint is that it stays out of the browser and editor channels
  // so those keep the "zero dependency, light, four channels agree" properties.
  // The CLI is one of its two sanctioned consumers (the GitHub Action is the
  // other), but importing it at module top level would still be wrong here:
  //  - it would be loaded and evaluated on every invocation, including the
  //    `--help` that most first runs are, to support a flag almost nobody passes;
  //  - it would make a broken or missing optional package break the ordinary
  //    scan, turning an opt-in extra into a hard dependency of the core path.
  // Loading it only when asked keeps the failure contained: the `catch` below
  // reports that the cross-file pass did not run and lets the per-file findings
  // through, because a partial report is worth more than no report.
  //
  // The boundary itself is NOT maintained by this comment. See
  // `scripts/check-packaging-invariants.mjs`, which asserts three ways that this
  // package reaches neither extension bundle.
  if (args.includeDesignSmells) {
    if (args.diff) {
      // A diff scan sees only added lines, and cross-file analysis is a claim
      // about whole files in relation to each other. Running it over a
      // reconstructed partial tree would produce findings that cite line numbers
      // from a file the user never wrote in that shape — and, worse, would make
      // the same code report differently on a branch than on main, which is the
      // reproducibility property §5.4 exists to protect.
      process.stderr.write(
        'note: --include-design-smells is ignored with --diff; cross-file analysis needs whole files\n',
      );
    } else {
      try {
        const { analyzeProject, applyConfigSuppression, mergeCrossFileFindings } = await import(
          '@vibeguard/analysis-graph'
        );
        const crossFile = await analyzeProject(args.target, { ignore: args.ignore });
        // The config `suppress` channel has to be applied HERE rather than left
        // to the merge, because the core scan applied it inside `scanPath` and a
        // finding that arrives afterwards has never been offered to it. Without
        // this, `suppress` silently does nothing for design smells — and since
        // they are emitted at `high` under the default `--fail-on high`, the only
        // remaining escape would be dropping the flag entirely.
        // Same discovery rules as the core scan: `--no-config` skips entirely,
        // `--config` names a file, otherwise auto-discover in the scan target.
        // Loading it a second time here (the core path already did) rather than
        // threading it out of `scanPath` keeps the optional package's entry
        // point free of a parameter that only exists because of an internal
        // sharing decision — and the file is small enough that a second read is
        // not worth an API change.
        const loaded = args.noConfig
          ? undefined
          : await loadConfig(
              statSync(args.target).isFile() ? dirname(resolve(args.target)) : resolve(args.target),
              args.config,
            ).catch(() => undefined);
        const suppressed = applyConfigSuppression(crossFile, loaded?.config);
        scan = mergeCrossFileFindings(scan, suppressed);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        process.stderr.write(
          `warning: cross-file design-smell analysis did not run (${message}). ` +
            'Per-file findings below are complete; design smells are ABSENT, not clean.\n',
        );
      }
    }
  }

  // ── H3 multi-tool ensemble (opt-in) ──────────────────────────────────────
  //
  // Dynamically imported for the same reasons as `analysis-graph` above, and
  // guarded by the same packaging invariants — `@vibeguard/external-adapters` is
  // CLI/Action-only and must never reach the browser or editor bundles.
  //
  // ★ THIS BLOCK NEVER RUNS A TOOL. It reads a report the user already has. The
  // temptation to shell out to Semgrep is exactly the temptation to give a
  // zero-egress product a subprocess that downloads rule packs and phones home,
  // and it is refused here rather than argued about later.
  //
  // What it must never do is stay quiet. `--ensemble` with nothing supplied is a
  // legitimate invocation and gets a spoken degradation, because a user who
  // asked for a cross-check and silently received none would reasonably read the
  // clean result as corroboration by tools that never looked.
  // ── Protection claims, and the cross-examination of them ────────────────
  //
  // GENERATION IS UNCONDITIONAL. A claim is what a rule said about a protection
  // it found, and it is true whether or not anybody asked for a build to be
  // checked. Putting generation behind `--after-build` meant the third state
  // never reached a user who had not already suspected the problem — the ledger
  // did not exist unless you asked it to prove itself. So every scan now carries
  // the claims, born NOT_OBSERVED, and `--after-build` adds the only thing it
  // can add: an observation at another layer.
  //
  // Dynamic import for the same reason `@vibeguard/analysis-graph` is: these
  // read files off disk and must never reach an extension bundle.
  //
  // The whole channel is observability. It does not touch `summary`, `findings`
  // or the exit code — same posture as `degradations` and `suppressions`, and
  // for a sharper reason than either. A `LOST` rests on a witness token matched
  // against minified text; the day that gates a build is the day somebody adds
  // `--no-after-build` to CI and stops reading any of it.
  try {
    // Claim construction and claim adjudication come from different packages
    // on purpose: the first is a pure function of a finding and is bundled into
    // the extensions, the second reads the build output off disk and must never
    // reach them.
    const { claimsFromFindings, illegalClaimTransition } = await import('@vibeguard/findings-schema');
    const { crossExamine } = await import('@vibeguard/artifact-integrity/cross-examine');
    const claims = claimsFromFindings(scan.findings);

    // ── AND THE CLAIMS WHOSE FINDING NO LONGER EXISTS ──────────────────────
    //
    // A fixer's claim cannot be rebuilt from a finding, because fixing the
    // finding is what removed it. It is read back from the ledger the fixer
    // wrote instead. `claimsFromLedger` re-checks each entry against the source
    // before handing it over, so an edit that was reverted comes back expired
    // rather than as a claim about a line nobody can find any more.
    //
    // These are UNTRUSTED input in a way nothing else here is — see the header
    // of `fix-ledger.ts`. They arrive NOT_OBSERVED like every other claim, and
    // `claimantLayer` is hard-coded rather than read from the file, so a ledger
    // cannot promote itself to a layer that would let it settle itself.
    let ledgerNote: string | undefined;
    let expiredClaims: ProtectionClaim[] = [];
    try {
      const fromLedger = await claimsFromLedger(args.target, targetIsFileOf(args.target));
      ledgerNote = fromLedger.note;
      expiredClaims = fromLedger.expired;
      claims.push(...fromLedger.claims);
    } catch (err) {
      ledgerNote = `the fix ledger could not be read (${(err as Error).message})`;
    }
    if (ledgerNote) process.stderr.write(`note: ${ledgerNote}\n`);
    if (claims.length || expiredClaims.length) {
      scan.protectionClaims = [...claims, ...expiredClaims];
    }

    if (args.afterBuild) {
      const { observeBundleDir } = await import('@vibeguard/artifact-integrity/bundle');
      // Runs whether or not there are claims. "We read your build output and
      // found nothing to check" and "we never opened it" are different facts,
      // and the second one used to be reported as the first — silently, because
      // the observation was inside `if (claims.length)`.
      const observation = await observeBundleDir(args.afterBuild);
      scan.afterBuild = {
        directory: args.afterBuild,
        artefactsRead: observation.records.length,
        artefactsMeasured: observation.measured,
        skipped: observation.skipped.length,
      };
      for (const s of observation.skipped) {
        process.stderr.write(`note: --after-build skipped ${s.path}: ${s.reason}
`);
      }
      if (!observation.records.length) {
        process.stderr.write(
          `note: --after-build found no readable JavaScript under ${args.afterBuild}; every claim stays NOT_OBSERVED
`,
        );
      }
      if (claims.length) {
        // ★ NO SPECIAL CASE FOR `--fix --after-build`, AND THAT IS DELIBERATE.
        //
        // The obvious worry is that this run is about to write edits the
        // observed build cannot contain, so a fixer claim would read LOST for a
        // protection the build never had a chance to ship. Two things already
        // prevent it, and adding a third would only cost correct answers.
        //
        // The ordering: the ledger was read above, BEFORE the fix block runs,
        // so nothing this run inserts is in `claims` at all. And jurisdiction:
        // a claim is only settled by an artefact whose `sourcesContent` carries
        // its probe, and a fixer claim's probe IS the inserted line — a build
        // made before the edit does not contain it, so the claim comes back
        // NOT_OBSERVED rather than LOST. That is the honest answer, produced by
        // a mechanism that is already load-bearing rather than by a flag check
        // bolted on beside it.
        //
        // What IS worth saying is the ordering itself, because a user combining
        // the two flags reasonably expects this run to check the repair.
        scan.protectionClaims = [
          ...crossExamine(claims, observation, illegalClaimTransition),
          ...expiredClaims,
        ];
        if (args.fix && !args.dryRun) {
          process.stderr.write(
            'note: --fix and --after-build together read a build made before this run wrote ' +
              'anything, so the edits below are not in it. Rebuild, then scan again to settle them.\n',
          );
        }
      }
    }
  } catch (err) {
    // The ledger SURVIVES the failure. Previously the catch wrote one line to
    // stderr and left `protectionClaims` unset, so the JSON a machine reads was
    // indistinguishable from a scan that had no claims at all — the observer
    // failing looked exactly like nothing to observe.
    process.stderr.write(
      `note: protection claims could not be cross-examined (${(err as Error).message}). ` +
        'Any claim below is NOT_OBSERVED: it was not checked against the shipped bytes.\n',
    );
  }

  if (args.ensemble) {
    try {
      const { mergeEnsemble, notSupplied, parseSemgrepReport, parseCodeqlSarifReport, unreadableReport } =
        await import('@vibeguard/external-adapters');

      const readSide = <T,>(
        path: string | undefined,
        parse: (text: string, options: { reportPath: string }) => T,
      ) => {
        if (!path) return notSupplied<T>();
        try {
          return {
            kind: 'report' as const,
            report: parse(readFileSync(path, 'utf8'), { reportPath: path }),
          };
        } catch (err) {
          return unreadableReport<T>(path, err instanceof Error ? err.message : String(err));
        }
      };

      const result = mergeEnsemble({
        vibeguard: {
          kind: 'report',
          report: { findings: scan.findings, engineVersion: scan.engineVersions?.core ?? null },
        },
        semgrep: readSide(args.semgrepReport, parseSemgrepReport),
        codeql: readSide(args.codeqlReport, parseCodeqlSarifReport),
      });

      // `degradedNotice` is not advisory. `EnsembleResult` states that the CLI
      // MUST print it, because a run that quietly drops to one tool is the exact
      // failure this package exists to prevent.
      if (result.degradedNotice) process.stderr.write(`ensemble: ${result.degradedNotice}\n`);
      if (!result.agreementComputable) {
        process.stderr.write(
          `ensemble: agreement NOT COMPUTED — ${result.agreementNotComputableReason ?? 'fewer than two tools participated'}\n`,
        );
      } else {
        const byLabel = Object.entries(result.byAgreement)
          .map(([label, n]) => `${label}=${n}`)
          .join(' ');
        process.stderr.write(
          `ensemble: ${result.participatingTools.join(' + ')} · ${result.merged.length} merged findings · ${byLabel}\n`,
        );
      }
      // The standing caveat, printed every time rather than once in a README —
      // what an ensemble cannot see is a property of the result, not a footnote.
      process.stderr.write(`ensemble: ${result.unobservable}\n`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // Same posture as the cross-file catch: an absent cross-check is reported
      // as absent, never folded into the result as agreement.
      process.stderr.write(
        `warning: ensemble cross-check did not run (${message}). ` +
          'Findings below are VibeGuard-only and were NOT corroborated.\n',
      );
    }
  }

  // Confidence threshold, applied once here so every output format and the
  // --fail-on check below see the same finding set: a finding below the
  // threshold is absent from the report and from the exit-code decision alike.
  // Deliberately not pushed into the analyzer: the engine keeps reporting
  // everything, and only this reporting layer narrows it.
  if (args.minConfidence) {
    const min = args.minConfidence;
    const kept = scan.findings.filter((f) => compareConfidence(f.confidence, min) <= 0);
    const hidden = scan.findings.length - kept.length;
    if (hidden > 0) {
      // stderr, so stdout stays byte-identical to what the format produced.
      process.stderr.write(`note: ${hidden} finding(s) below --min-confidence ${min} hidden\n`);
    }
    scan = { ...scan, findings: kept, summary: kept.length ? summarize(kept) : emptySummary() };
  }

  // Fix mode (--fix / --dry-run) replaces the normal findings report with a fix
  // plan. It operates on the post-filter finding set, so --min-confidence also
  // narrows what gets fixed. --dry-run previews without writing; bare --fix
  // writes.
  //
  // FIX MODE MUST NOT WEAKEN THE GATE. It used to return a hardcoded 0, so
  // adding --fix to a red CI command turned it green — even for a finding whose
  // rule has no fixer at all, and even for --dry-run, which by definition
  // changes nothing. The gate is therefore evaluated on the SAME finding set the
  // non-fix path would have gated on, and the worse of the two codes is
  // returned.
  //
  // Deliberately NOT "gate on what survived the fix": `--fix` reporting a fix as
  // applied is not evidence that the finding is gone. A fixer can edit a token
  // other than the reported one and leave the defect in place (B4/A2), and the
  // detector can go quiet for a reason unrelated to the repair (B4/A1). Both
  // would produce a green gate over live code. The post-fix verdict comes from
  // re-running the scan on the written tree — an observation, not a claim by the
  // thing that did the writing.
  if (args.fix || args.dryRun) {
    // Shared with the ledger read above, deliberately: see `targetIsFileOf`.
    // Two copies of this could disagree, and a ledger written under one root
    // and read under another is a ledger that silently never settles anything.
    const targetIsFile = targetIsFileOf(args.target);
    const write = args.fix && !args.dryRun;
    let fixResult;
    try {
      fixResult = await runFix(scan.findings, { target: args.target, targetIsFile }, write);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`error: ${message}\n`);
      return 2;
    }
    process.stdout.write(fixResult.output);
    // The fixer is a claimant, not a witness. It knows exactly what it wrote,
    // which makes its witness token certainly correct and makes it the most
    // tempting claimant to believe. "I replaced a console.assert with a throw"
    // is a statement about the SOURCE, and the subject of this ledger is that
    // the source is not what ships. So the edits are NOT_OBSERVED.
    //
    // ★ TWO SENTENCES HAVE STOOD HERE, AND BOTH WERE ABOUT THE SAME GAP.
    //
    // The first said "Re-scan with --after-build <dist> to settle them", which
    // was false: fixing the finding deletes the only thing a later scan could
    // rebuild the claim from, so the claim did not survive to be settled. The
    // second said so plainly — the claims are not tracked past this run — which
    // was true, and was the right thing to print while it was true.
    //
    // It is no longer true. `fix-ledger.ts` writes the inserted line down, the
    // next scan reads it back, and an artefact observation settles it. What has
    // NOT changed is that the settling cannot happen in this run: the build
    // output on disk right now was made before this edit, so nothing in it
    // could carry the line just written. The user has to rebuild, and this says
    // so rather than implying the check already happened.
    if (fixResult.claims.length) {
      let recorded: Awaited<ReturnType<typeof recordFixerClaims>> | null = null;
      if (write) {
        try {
          recorded = await recordFixerClaims(args.target, targetIsFile, fixResult.claims);
        } catch (err) {
          // The ledger failing must not fail the fix. What it must not do is
          // fail quietly: without this line the user would believe a claim was
          // recorded that was not, and would read the next scan's silence about
          // it as the protection having been checked.
          process.stderr.write(
            `note: the inserted protection(s) could not be recorded (${(err as Error).message}); ` +
              'nothing will check whether they survive your build.\n',
          );
        }
      }
      process.stdout.write(
        `\n${fixResult.claims.length} protection(s) ${write ? 'were inserted' : 'would be inserted'} ` +
          'and are NOT_OBSERVED: a fixer cannot vouch for its own edit surviving your build.\n' +
          (recorded
            ? `Recorded in ${relative(process.cwd(), recorded.path) || recorded.path} (${recorded.total} entr(y/ies)` +
              `${recorded.evicted ? `, ${recorded.evicted} oldest dropped` : ''}).\n` +
              'Rebuild, then re-scan with --after-build <your dist directory> to settle them.\n'
            : write
              ? 'They are NOT recorded, so nothing will check whether they survive your build.\n'
              : 'A dry run records nothing: there is no edit yet for a build to keep or drop.\n'),
      );
    }
    const fixGate = FAIL_LEVEL[args.failOn];
    if (fixGate && scan.findings.some((f) => compareSeverity(f.severity, fixGate) <= 0)) {
      process.stderr.write(
        `note: --fail-on ${args.failOn} still applies in fix mode; re-scan to get the post-fix verdict\n`,
      );
      return Math.max(fixResult.code, 1);
    }
    return fixResult.code;
  }

  const useColor = !args.noColor && Boolean(process.stdout.isTTY) && !args.outFile;
  let output: string;
  if (args.format === 'json') {
    output = JSON.stringify(scan, null, 2);
  } else if (args.format === 'sarif') {
    // SARIF URIs are resolved from the REPOSITORY ROOT by GitHub code scanning,
    // while a finding's `filePath` is relative to the scan target. For a scan of
    // the repo root those coincide; for `vibeguard packages/api` they do not,
    // and every alert pointed at a path that does not exist. The prefix closes
    // that gap in the SARIF output alone, leaving `filePath` — which `--fix`,
    // the config globs and the human formatter all read — on its own basis.
    // ── AI provenance (#29b), collected only for SARIF ─────────────────────
    //
    // SARIF is the format that travels: it is what the Action uploads to code
    // scanning, so it is the one place a provenance observation has a consumer.
    // Attaching it to the human or JSON output would be noise on a path nobody
    // aggregates.
    //
    // Dynamic import of the `/node` subpath, matching how the cross-file pass is
    // loaded, because that module reads git history through `child_process` and
    // the package root must stay browser-safe. `check-packaging-invariants.mjs`
    // now fails the build if any light-side package imports this subpath.
    //
    // ★ WHAT THIS IS NOT: it is not a risk score and it must never be read as
    // one. AI-authorship markers are SELF-REPORTED and most AI-assisted commits
    // carry none, so the marker set is unusable as a denominator. It records
    // what was declared, by whom, in which channel — an observation, and the
    // field names are chosen so it cannot be mistaken for a verdict. A failure
    // here must never take a scan down: the report is worth more than the
    // annotation.
    let provenance;
    try {
      const { readAiProvenance } = await import('@vibeguard/sarif-adapter/node');
      provenance = await readAiProvenance({
        cwd: statSync(args.target).isFile() ? dirname(resolve(args.target)) : resolve(args.target),
      });
    } catch {
      provenance = undefined;
    }
    output = JSON.stringify(
      toSarif(scan, {
        toolVersion: VERSION,
        uriPrefix: await sarifUriPrefix(args.target),
        // Conditional spread: an absent key and a key holding `undefined` are
        // the same in JSON and different to a consumer enumerating them, which
        // is the discipline the whole adapter follows.
        ...(provenance ? { provenance } : {}),
      }),
      null,
      2,
    );
  } else if (args.format === 'markdown') {
    output = formatMarkdown(scan);
  } else {
    output = formatHuman(scan, useColor);
  }

  if (args.outFile) {
    await writeFile(args.outFile, output, 'utf8');
  } else {
    process.stdout.write(output);
    if (!output.endsWith('\n')) process.stdout.write('\n');
  }

  const failThreshold = FAIL_LEVEL[args.failOn];
  if (failThreshold) {
    const offender = scan.findings.find((f) => compareSeverity(f.severity, failThreshold) <= 0);
    if (offender) return 1;
  }
  return 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    process.exit(2);
  },
);
