#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { ENGINE_VERSION, loadConfig, scanPath } from '@vibeguard/analyzer-core';
import {
  compareConfidence,
  compareSeverity,
  emptySummary,
  summarize,
  type Severity,
} from '@vibeguard/findings-schema';
import { toSarif } from '@vibeguard/sarif-adapter';
import { parseArgs, HELP_TEXT } from './args.js';
import { formatHuman, formatMarkdown } from './format.js';
import { scanDiff } from './diff.js';
import { runFix } from './fix.js';
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
        config: args.noConfig ? false : args.config,
        // `ScanDiffOptions extends AnalyzerOptions`, so the declared set rides
        // in as the Analyzer-level default and reaches the requests `scanDiff`
        // builds internally. That is why the analyzer accepts an instance-level
        // default at all: without it the diff channel — the CI path, where a
        // hallucinated-dependency false positive is most expensive — could not
        // be given the evidence without rewriting a module this change does not
        // own.
        declaredPackages: declared.packages,
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
    process.stderr.write(
      `note: ${vetoed} supply-chain finding(s) not reported — the package is resolved in ${from}, ` +
        'so the name is not a hallucination. This says the package EXISTS, not that it is safe.\n',
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
  // writes. Fixing is not a gate, so this never returns the --fail-on exit code.
  if (args.fix || args.dryRun) {
    let targetIsFile = false;
    try {
      targetIsFile = statSync(args.target).isFile();
    } catch {
      // --diff defaults the target to '.', a directory; a missing target would
      // already have failed the scan above. Either way, treat as not-a-file.
    }
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
    return fixResult.code;
  }

  const useColor = !args.noColor && Boolean(process.stdout.isTTY) && !args.outFile;
  let output: string;
  if (args.format === 'json') {
    output = JSON.stringify(scan, null, 2);
  } else if (args.format === 'sarif') {
    output = JSON.stringify(toSarif(scan, { toolVersion: VERSION }), null, 2);
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
