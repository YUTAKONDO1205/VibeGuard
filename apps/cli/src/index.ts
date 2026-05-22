#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { ENGINE_VERSION, scanPath } from '@vibeguard/analyzer-core';
import { compareSeverity, type Severity } from '@vibeguard/findings-schema';
import { toSarif } from '@vibeguard/sarif-adapter';
import { parseArgs, HELP_TEXT } from './args.js';
import { formatHuman, formatMarkdown } from './format.js';
import { scanDiff } from './diff.js';

const VERSION = '0.1.0';

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
      });
    } else {
      scan = await scanPath(args.target, {
        mode: args.mode,
        includeRemediation: !args.noRemediation,
        ignore: args.ignore,
        knownLanguagesOnly: args.knownLanguagesOnly,
        config: args.noConfig ? false : args.config,
      });
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`error: ${message}\n`);
    return 2;
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
