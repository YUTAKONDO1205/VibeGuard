#!/usr/bin/env node
// run-artefact-policy — apply one policy file to the set of artefacts a build
// produced, by running `./artefact-require.mjs` over each of them.
//
//   node run-artefact-policy.mjs --policy <file> --dir <build-output-dir>
//   node run-artefact-policy.mjs --policy <file> --artifact a.out --artifact lib.so
//
// ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
//
// `./artefact-require.mjs` is the only reader of `policy.artifact` on this side
// of the tree, and it reads ONE image. A build writes many. Until something
// walked the set, the policy key had a reader and no caller, which is the same
// position `compiler/schema/properties.json` described before the reader
// existed: the policy file says the build is checked and nothing looks.
//
// ── WHAT THIS FILE DOES NOT DO ──────────────────────────────────────────────
//
// It decides nothing. It does not parse the policy — `artefact-require.mjs`
// does, including the `expectStrings`-must-be-an-array guard, which is the one
// piece of validation a second parser here would be most likely to drop and
// most expensive to drop. It does not compute a severity, or map findings to an
// exit code: each child does that for its own image with `exitCodeFor`, and the
// aggregate below is a precedence over the numbers the children already
// returned. The only judgement added is WHICH FILES ARE ARTEFACTS, and that is
// in `./lib/artefact-set.mjs` with its reasoning written out there.
//
// Every child is a real process. The record it writes with `--json` is read
// back and its `exitCode` field is compared with the process's actual exit
// status; a disagreement is reported as incomplete rather than resolved in
// favour of either, because the two disagreeing is evidence that one of them is
// not what it appears to be.
//
// ── EXIT CODES ──────────────────────────────────────────────────────────────
//
// The shared set, `../driver/lib/exit.mjs` (interfaces.md §7) — deliberately
// NOT `./run-controls.mjs`'s 0/1. That file predates the shared set and does
// not import it, and its `1` means "a case disagreed", which in the shared set
// is `2` and in `1` is "the underlying tool failed, its diagnostics passed
// through unchanged". A caller branching on the number would go looking for
// compiler diagnostics that do not exist. `1` is kept here for what
// `artefact-require.mjs` already uses it for: this runner was invoked wrongly.
//
//   0  every selected artefact was inspected and nothing was found
//   1  the runner was called wrongly (unknown option, no policy, nothing to check)
//   2  findings at or above the policy's threshold, on at least one artefact
//   3  a check could not be completed — including "no artefact was inspected"
//   4  the policy is malformed or unreadable. Nothing else runs.
//
// Aggregating: findings outrank incompleteness (2 beats 3), which is
// `exitCodeFor`'s own rule applied one level up, and 3 is never collapsed into
// 0. An integrity failure from any child aborts the run immediately, because
// interfaces.md says nothing else runs after one.
//
// ── AN EMPTY RUN IS NOT A PASS, AND THERE IS NO FLAG TO MAKE IT ONE ─────────
//
// The 23-row fixture matrix is git-ignored and absent from a clean checkout, so
// the common way to run this file is with nothing to run it on. That case is
// exit 3 with the reason named. `./artefact-controls.mjs` has `--allow-empty`
// and this deliberately does not: there, the run asserts a fixed table and an
// authorised skip of a named row is a meaningful thing to record. Here the
// question is "did the build satisfy the policy", and for a build nothing was
// read from there is no caller for whom the answer is yes.
//
// ── COUNTING CONTRACT ───────────────────────────────────────────────────────
//
// Prints `artefacts=N inspected=N skipped=N findings=N incomplete=N` and lists
// every skipped path with the reason it was skipped.
//
// ── A LIMIT THIS RUNNER INHERITS AND DOES NOT FIX ───────────────────────────
//
// The byte scan under it has been shown to report a hit, and to refuse to
// report anything when its control string is missing. It has never been shown
// to report CLEAN with a live control and a forbidden string configured, for a
// fixture reason recorded in `compiler/schema/properties.json` under
// `_notAnExtractor.artifactByteScan`: every image in the matrix that carries
// the control string also carries the forbidden one. Running the scan over more
// images does not change that; only a fixture holding the control and not the
// secret would.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { collectArtefacts } from './lib/artefact-set.mjs';
import {
  EXIT_OK, EXIT_TOOL_FAILED, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_INTEGRITY,
} from '../driver/lib/exit.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REQUIRE_CLI = join(HERE, 'artefact-require.mjs');

const USAGE = `usage: node run-artefact-policy.mjs --policy <file> [--dir <d>] [--artifact <p>]

  --policy <file>     required. The policy whose artifact.require /
                      .forbidStrings / .expectStrings / failOn apply. It is
                      handed to artefact-require.mjs unread; this file does not
                      parse it.
  --dir <d>           inspect every file directly inside <d> whose e_ident says
                      ELF64 LSB (repeatable, NOT recursive). Every other file is
                      listed by name with the reason it was passed over.
  --artifact <p>      inspect this exact path (repeatable). Not filtered: a
                      named path that is not an ELF is exit 3 from the checker,
                      not a skip. A named path that is absent is exit 3 here.
  --fail-on <sev>     low | medium | high | critical. Forwarded unchanged.
  --json <path>       write the aggregate record here
  --verbose           print each finding, not only the per-artefact counts
  --quiet             the counting line and failures only

At least one --dir or --artifact is required. There is no --allow-empty: a run
that inspected nothing is exit 3.
`;

/**
 * Precedence when several artefacts return different codes.
 *
 * Higher wins. This is `exitCodeFor`'s rule one level up — a finding is a thing
 * that was seen, so 2 outranks 3 — plus the two codes that end a run: 1 means
 * this runner was called wrongly and 4 means nothing else may run.
 */
const RANK = { 0: 0, 3: 1, 2: 2, 1: 3, 4: 4 };

function worse(a, b) {
  return (RANK[b] ?? 0) > (RANK[a] ?? 0) ? b : a;
}

function main(argv) {
  let policyPath = null;
  let failOn = null;
  let jsonOut = null;
  let verbose = false;
  let quiet = false;
  const dirs = [];
  const named = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--policy') policyPath = argv[++i];
    else if (a === '--dir') dirs.push(argv[++i]);
    else if (a === '--artifact') named.push(argv[++i]);
    else if (a === '--fail-on') failOn = argv[++i];
    else if (a === '--json') jsonOut = argv[++i];
    else if (a === '--verbose') verbose = true;
    else if (a === '--quiet') quiet = true;
    else if (a === '-h' || a === '--help') {
      process.stdout.write(USAGE);
      return EXIT_OK;
    } else {
      process.stderr.write(`run-artefact-policy: unknown option ${a}\n${USAGE}`);
      return EXIT_TOOL_FAILED;
    }
  }

  if (!policyPath) {
    process.stderr.write(`run-artefact-policy: --policy is required\n${USAGE}`);
    return EXIT_TOOL_FAILED;
  }
  if (dirs.length === 0 && named.length === 0) {
    process.stderr.write('run-artefact-policy: nothing to check. Give --dir or --artifact.\n' +
      'This is a usage error rather than an empty run: the run was never told where to look.\n');
    return EXIT_TOOL_FAILED;
  }
  // interfaces.md §7: an unreadable policy is 4, and it is 4 before anything
  // else happens rather than once per artefact. Presence only — the shape is
  // artefact-require.mjs's to judge, and it judges it on the first child.
  if (!existsSync(policyPath)) {
    process.stderr.write(`run-artefact-policy: policy not found: ${policyPath}\n`);
    return EXIT_INTEGRITY;
  }

  const { selected, skipped, problems } = collectArtefacts({ dirs, artifacts: named });

  const out = (s) => { if (!quiet) process.stdout.write(s); };
  out(`policy=${resolve(policyPath)}\n`);
  out(`looked in: ${dirs.length} director${dirs.length === 1 ? 'y' : 'ies'}, ` +
    `${named.length} named artefact${named.length === 1 ? '' : 's'}\n\n`);

  const tmp = mkdtempSync(join(tmpdir(), 'vg-artefact-policy-'));
  const records = [];
  const incomplete = [...problems];
  let findingCount = 0;
  let aggregate = EXIT_OK;
  let aborted = null;

  try {
    for (const item of selected) {
      const recPath = join(tmp, `${records.length}.json`);
      const args = ['--artifact', item.path, '--policy', policyPath, '--json', recPath, '--quiet'];
      if (failOn) args.push('--fail-on', failOn);
      const child = spawnSync(process.execPath, [REQUIRE_CLI, ...args], { encoding: 'utf8' });

      const label = basename(item.path);
      if (child.error) {
        incomplete.push(`${label}: could not run artefact-require.mjs: ${child.error.message}`);
        aggregate = worse(aggregate, EXIT_INCOMPLETE);
        records.push({ path: item.path, source: item.source, exitCode: null, ran: false, inspected: false });
        continue;
      }
      const code = child.status;

      if (code === EXIT_INTEGRITY) {
        // interfaces.md §7: "Nothing else runs."
        aborted = `${label}: the policy was refused as malformed. ` +
          `${(child.stderr || child.stdout || '').trim()}`;
        aggregate = EXIT_INTEGRITY;
        // `inspected: false` — exit 4 is a verdict about the POLICY, not about
        // this image. Counting it as inspected would say one artefact was
        // checked when none was.
        records.push({ path: item.path, source: item.source, exitCode: code, ran: true, inspected: false });
        break;
      }

      let rec = null;
      if (existsSync(recPath)) {
        try {
          rec = JSON.parse(readFileSync(recPath, 'utf8'));
        } catch (e) {
          incomplete.push(`${label}: artefact-require.mjs exited ${code} and its --json record does not parse: ${e.message}`);
          aggregate = worse(aggregate, EXIT_INCOMPLETE);
        }
      }

      if (!rec) {
        // The checker writes no record when it never got as far as a verdict —
        // an image it cannot read is the measured case. The exit code is still
        // the answer, and it is not 0.
        const why = (child.stdout || '').split('\n').find((l) => l.startsWith('unreadable:')) ??
          (child.stderr || '').trim().split('\n')[0] ?? 'no record written';
        incomplete.push(`${label}: no record from artefact-require.mjs (exit ${code}) — ${why}`);
        aggregate = worse(aggregate, code === EXIT_OK ? EXIT_INCOMPLETE : code);
        // Counted as inspected: the checker did reach a verdict about this
        // image — "I cannot read it" — and that verdict is exit 3, not exit 0.
        records.push({ path: item.path, source: item.source, exitCode: code, ran: true, inspected: true });
        continue;
      }

      // The child computed its own exit code from its own record. If the two
      // disagree, one of them is not describing this run.
      if (rec.exitCode !== code) {
        incomplete.push(`${label}: artefact-require.mjs exited ${code} and recorded exitCode=${rec.exitCode}. ` +
          'A record that does not describe the process that wrote it is not evidence.');
        aggregate = worse(aggregate, EXIT_INCOMPLETE);
      }

      const ids = (rec.findings ?? []).map((f) => f.id);
      findingCount += ids.length;
      for (const why of rec.incomplete ?? []) incomplete.push(`${label}: ${why}`);
      aggregate = worse(aggregate, code);

      const o = rec.observation ?? {};
      const props = o.properties ?? {};
      records.push({
        path: item.path,
        source: item.source,
        exitCode: code,
        ran: true,
        inspected: true,
        linkForm: o.linkForm ?? null,
        properties: {
          pie: props.pie?.state ?? null,
          nx: props.nx?.state ?? null,
          relro: props['relro-full']?.level ?? null,
          writableExecutable: props['no-writable-executable-section']?.hits?.length ?? null,
        },
        scan: rec.scan
          ? {
            verdict: rec.scan.verdict,
            controlsChecked: rec.scan.controlsChecked,
            hits: rec.scan.hits.length,
            unverifiedHits: rec.scan.unverifiedHits,
            bytesScanned: rec.scan.bytesScanned,
          }
          : null,
        findings: ids,
        incomplete: rec.incomplete ?? [],
        unsupported: (rec.unsupported ?? []).map((u) => u.property),
      });

      const verdict = code === EXIT_OK ? 'OK' : code === EXIT_FINDINGS ? 'FINDINGS' : 'INCOMPLETE';
      out(`  ${verdict.padEnd(10)} ${label.padEnd(20)} exit=${code} ` +
        `findings=${ids.length} incomplete=${(rec.incomplete ?? []).length}` +
        (rec.scan ? ` scan=${rec.scan.verdict}` : '') +
        (ids.length ? `  ${[...new Set(ids)].sort().join(',')}` : '') + '\n');
      if (verbose) {
        for (const f of rec.findings ?? []) {
          out(`             ${f.severity.toUpperCase().padEnd(8)} ${f.id}  ${f.detail}\n`);
        }
      }
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }

  // ── the counting contract ─────────────────────────────────────────────────
  //
  //   artefacts  every file the runner looked at: selected plus passed over.
  //   inspected  those artefact-require.mjs returned a verdict ABOUT THE IMAGE
  //              for. "I cannot read this" is such a verdict and counts; the
  //              exit-4 abort is a verdict about the policy and does not.
  //   skipped    files the e_ident filter passed over, each named below.
  const inspected = records.filter((r) => r.inspected).length;
  const artefacts = selected.length + skipped.length;

  if (inspected === 0 && !aborted) {
    incomplete.push('no artefact was inspected. A policy run that read nothing is not a clean build — ' +
      'the images may be absent, git-ignored, or filtered out as not ELF64 LSB (each is listed above).');
    aggregate = worse(aggregate, EXIT_INCOMPLETE);
  }
  if (incomplete.length > 0) aggregate = worse(aggregate, EXIT_INCOMPLETE);

  process.stdout.write(`\nartefacts=${artefacts} inspected=${inspected} skipped=${skipped.length} ` +
    `findings=${findingCount} incomplete=${incomplete.length}\n`);

  if (skipped.length > 0) {
    process.stdout.write('passed over, by name (each was looked at and is not an ELF64 LSB image):\n');
    for (const s of skipped) process.stdout.write(`  ${s.path} — ${s.why}\n`);
    process.stdout.write('  (a skip is not a pass)\n');
  }
  for (const why of incomplete) process.stdout.write(`  INCOMPLETE  ${why}\n`);
  if (aborted) {
    process.stdout.write(`  INTEGRITY   ${aborted}\n`);
    process.stdout.write('  the run stopped there: interfaces.md §7 says nothing else runs after a policy failure.\n');
  }

  if (jsonOut) {
    writeFileSync(jsonOut, `${JSON.stringify({
      recordType: 'artefact-policy-run',
      schemaVersion: 1,
      policy: resolve(policyPath),
      failOn: failOn ?? null,
      counts: { artefacts, inspected, skipped: skipped.length, findings: findingCount, incomplete: incomplete.length },
      artefacts: records,
      skipped,
      incomplete,
      aborted,
      exitCode: aggregate,
      context: {
        generatedAt: new Date().toISOString(),
        timeSource: 'wall-clock',
        sourceDateEpoch: null,
        host: 'redacted-by-policy',
      },
    }, null, 2)}\n`);
  }

  return aggregate;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exitCode = main(process.argv.slice(2));
}

export { main, RANK, worse };
