#!/usr/bin/env node
// artefact-require — the consumer for `policy.artifact` on the compiler side.
//
//   node artefact-require.mjs --artifact <path> --policy <policy.json>
//   node artefact-require.mjs --artifact <path> --require pie,nx,relro-full \
//                             --forbid AKIA... --expect always-present-marker
//
// `compiler/schema/policy.schema.json` accepts `artifact.require`,
// `artifact.forbidStrings` and `artifact.allowedDynamicDependencies`, and
// `compiler/schema/properties.json` records that nothing in `compiler/` reads
// them. This reads the first two.
//
// EXPECT IS REQUIRED WHEN ANYTHING IS FORBIDDEN. A policy that forbids byte
// sequences and names no sequence that must be present gets exit 3, not exit 0.
// `artifact.expectStrings` is not in the schema today; it is accepted here from
// the policy file and from `--expect`, and the shape is reported rather than
// added to the schema, which is what interfaces.md asks a component to do when
// it needs a key the schema does not have.
//
// COUNTING CONTRACT: prints `required=N supported=N unsupported=N findings=N
// incomplete=N`. A run that examined nothing is exit 3.
//
// Exit codes: `../driver/lib/exit.mjs` (interfaces.md section 7).
//   0 everything asked for was checked and nothing found
//   2 findings at or above failOn
//   3 a check could not be completed — including a broken byte scan
//   4 the policy is malformed

import { readFileSync, writeFileSync } from 'node:fs';

import { readElf } from './lib/elf.mjs';
import {
  applyArtifactPolicy, exitCodeFor, ALL_REQUIREMENTS, UNSUPPORTED_REQUIREMENTS,
} from './lib/artifact-policy.mjs';
import { EXIT_OK, EXIT_TOOL_FAILED, EXIT_INCOMPLETE, EXIT_INTEGRITY } from '../driver/lib/exit.mjs';

const USAGE = `usage: node artefact-require.mjs --artifact <path> [options]

  --artifact <path>   the finished image to read (required)
  --policy <file>     a policy file; artifact.require / .forbidStrings /
                      .expectStrings and failOn are read from it
  --require <a,b,c>   requirement names, comma separated (repeatable)
  --forbid <string>   a byte sequence that must not be present (repeatable)
  --expect <string>   a byte sequence that MUST be present (repeatable).
                      Required whenever --forbid is used: without it a scan
                      that read nothing is indistinguishable from a clean one.
  --fail-on <sev>     low | medium | high | critical (default medium)
  --json <path>       write the full record here
  --quiet             findings only

names: ${ALL_REQUIREMENTS.join(', ')}
not decided here (each is exit 3 when required): ${Object.keys(UNSUPPORTED_REQUIREMENTS).join(', ')}
`;

function main(argv) {
  let artifact = null;
  let policyPath = null;
  let failOn = null;
  let jsonOut = null;
  let quiet = false;
  const require_ = [];
  const forbid = [];
  const expect = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--artifact') artifact = argv[++i];
    else if (a === '--policy') policyPath = argv[++i];
    else if (a === '--require') require_.push(...String(argv[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean));
    else if (a === '--forbid') forbid.push(argv[++i]);
    else if (a === '--expect') expect.push(argv[++i]);
    else if (a === '--fail-on') failOn = argv[++i];
    else if (a === '--json') jsonOut = argv[++i];
    else if (a === '--quiet') quiet = true;
    else if (a === '-h' || a === '--help') {
      process.stdout.write(USAGE);
      return EXIT_OK;
    } else {
      process.stderr.write(`artefact-require: unknown option ${a}\n${USAGE}`);
      return EXIT_TOOL_FAILED;
    }
  }

  if (!artifact) {
    process.stderr.write(`artefact-require: --artifact is required\n${USAGE}`);
    return EXIT_TOOL_FAILED;
  }

  let policy = { require: [], forbidStrings: [], expectStrings: [] };
  if (policyPath) {
    let raw;
    try {
      raw = JSON.parse(readFileSync(policyPath, 'utf8'));
    } catch (e) {
      process.stderr.write(`artefact-require: cannot read policy ${policyPath}: ${e.message}\n`);
      return EXIT_INTEGRITY;
    }
    const art = raw.artifact ?? {};
    if (art.require !== undefined && !Array.isArray(art.require)) {
      process.stderr.write('artefact-require: artifact.require must be an array\n');
      return EXIT_INTEGRITY;
    }
    if (art.forbidStrings !== undefined && !Array.isArray(art.forbidStrings)) {
      process.stderr.write('artefact-require: artifact.forbidStrings must be an array\n');
      return EXIT_INTEGRITY;
    }
    // expectStrings is checked with the same force as the two above, and for a
    // sharper reason. The other two spread into a list of things to look for; a
    // scalar there would merely search for single characters. A scalar HERE is
    // worse, because the controls are what make a clean scan mean anything: a
    // 38-character control string spreads into 38 one-character controls, every
    // one of which is present in any artefact, so every control is "found", the
    // scan reports CLEAN and the process exits 0 -- on precisely the artefact
    // the control existed to catch. That is the silent exit 0 this component was
    // written to make impossible, arriving through the one key it cannot afford
    // to leave unshaped. policy.schema.json does not carry `expectStrings`, so
    // there is no upstream validator to fall back on; this is the check.
    if (art.expectStrings !== undefined && !Array.isArray(art.expectStrings)) {
      process.stderr.write('artefact-require: artifact.expectStrings must be an array. ' +
        'A scalar string would spread into one control per character, and a scan whose ' +
        'controls are all single characters can never be BROKEN.\n');
      return EXIT_INTEGRITY;
    }
    policy = {
      require: art.require ?? [],
      forbidStrings: art.forbidStrings ?? [],
      expectStrings: art.expectStrings ?? [],
    };
    if (!failOn && typeof raw.failOn === 'string') failOn = raw.failOn;
  }

  policy.require = [...policy.require, ...require_];
  policy.forbidStrings = [...policy.forbidStrings, ...forbid];
  policy.expectStrings = [...policy.expectStrings, ...expect];

  const elf = readElf(artifact);
  if (!elf.supported) {
    // Unreadable is never clean. This is the `4` case in interfaces.md only when
    // a digest fails; an image this reader does not cover is `3`.
    process.stdout.write(`artifact=${artifact}\nunreadable: ${elf.reason}\n`);
    process.stderr.write('artefact-require: the artefact could not be read as ELF64 LSB. ' +
      'That is "could not look", not "nothing found".\n');
    return EXIT_INCOMPLETE;
  }

  const result = applyArtifactPolicy(elf, policy);
  const code = exitCodeFor(result, failOn ?? 'medium');

  const supported = policy.require.filter((n) => !Object.prototype.hasOwnProperty.call(UNSUPPORTED_REQUIREMENTS, n));
  if (!quiet) {
    const o = result.observation;
    process.stdout.write(`artifact=${artifact}\n`);
    process.stdout.write(`linkForm=${o.linkForm} e_type=${o.eType} dynamic=${o.dynamicallyLinked}\n`);
    process.stdout.write(`pie=${o.properties.pie.state} nx=${o.properties.nx.state} ` +
      `relro=${o.properties['relro-full'].level} ` +
      `wx=${o.properties['no-writable-executable-section'].hits.length}\n`);
    if (result.scan) {
      process.stdout.write(`scan=${result.scan.verdict} controls=${result.scan.controlsChecked} ` +
        `hits=${result.scan.hits.length} unverified=${result.scan.unverifiedHits} ` +
        `bytes=${result.scan.bytesScanned}\n`);
    } else {
      process.stdout.write('scan=NOT_REQUESTED (no forbidStrings and no expectStrings)\n');
    }
  }
  process.stdout.write(`required=${policy.require.length} supported=${supported.length} ` +
    `unsupported=${result.unsupported.length} findings=${result.findings.length} ` +
    `incomplete=${result.incomplete.length}\n`);

  for (const f of result.findings) {
    process.stdout.write(`  ${f.severity.toUpperCase().padEnd(8)} ${f.id}  ${f.title}\n      ${f.detail}\n`);
  }
  for (const why of result.incomplete) {
    process.stdout.write(`  INCOMPLETE  ${why}\n`);
  }

  if (jsonOut) {
    writeFileSync(jsonOut, JSON.stringify({ ...result, exitCode: code }, jsonReplacer, 2));
  }
  return code;
}

function jsonReplacer(_k, v) {
  return typeof v === 'bigint' ? v.toString() : v;
}

process.exitCode = main(process.argv.slice(2));
