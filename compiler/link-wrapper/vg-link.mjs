#!/usr/bin/env node
// vg-link — run one link, and be able to say afterwards what went into it.
//
//   vg-link.mjs link  --policy <p> [--root <dir>] [--record <f>] -- <link command>
//   vg-link.mjs recheck <record.json | dir> --root <dir>
//
// WHAT `link` DOES, IN ORDER, AND WHY THE ORDER IS THE DESIGN
//
//   1. Read the link command line. If it names the map — `-Wl,-Map=`, `-Wl,-M`,
//      `--print-map`, any of them — REFUSE, exit 4, before the linker runs. The
//      map has to be the wrapper's observation of the link. A caller who can
//      name it can supply it, and then this program reports on a link that
//      never happened, with all the authority of a check that did.
//   2. Pick a map path the caller has never seen: a fresh random name under a
//      wrapper-owned directory. Assert it does not already exist.
//   3. Run the link with `-Wl,-Map=<that>` and `-Wl,-t` appended, capturing
//      stdout and stderr SEPARATELY. lld writes the input trace to stdout; a
//      wrapper that reads the linker's output off stderr, as one would for
//      diagnostics, records an empty input list and then finds nothing wrong
//      with it.
//   4. Verify the map is the one from step 2 and that this run wrote it.
//   5. Observe: inputs, archive members, shared libraries, linker script,
//      options, entry point, sections, symbol resolution, `.init_array`.
//   6. Compare with `policy.link`. Write the record. Print the count. Exit.
//
// `recheck` answers the other question — is the artefact still the one the link
// produced — by re-hashing it and comparing with the digest the record sealed.
//
// COUNTING. Both subcommands print `inputs=N checked=N skipped=S` and exit
// non-zero when N is 0 unless `--allow-empty` was passed. A scan that examined
// nothing and reported success has happened in this repository more than once;
// the shape of that failure is a zero that looks like a pass.

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { hostname } from 'node:os';

import { EXIT_OK, EXIT_TOOL_FAILED, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_INTEGRITY, EXIT_NAMES } from './lib/exit.mjs';
import { buildObservation, PRODUCED_BY_WRAPPER } from './lib/observe.mjs';
import { readLinkPolicy } from './lib/policy-link.mjs';
import { verdict, recheckArtifact } from './lib/verdict.mjs';
import { seal, sha256Hex } from './lib/canonical.mjs';
import { findAbsolutePaths, scrubText } from './lib/hygiene.mjs';
import { normalisePath } from './lib/refs.mjs';
import { parseLinkCommand, screenLinkCommand } from './lib/cmdline.mjs';
import { LINK, makeFinding, atOrAboveThreshold } from './lib/findings.mjs';

const USAGE = `vg-link — link-integrity wrapper (VG-LINK-0NN)

  vg-link.mjs link  --policy <policy.json> [--root <dir>] [--record <out.json>]
                    [--work <dir>] [--allow-empty] -- <link command>
  vg-link.mjs recheck <record.json | directory> --root <dir> [--allow-empty]

There is deliberately no flag that accepts a map file. See the header comment.`;

// ── argument handling ────────────────────────────────────────────────────────

function splitArgv(argv) {
  const at = argv.indexOf('--');
  return at < 0 ? { own: argv, link: [] } : { own: argv.slice(0, at), link: argv.slice(at + 1) };
}

function takeOptions(own, known) {
  const opts = {};
  const positional = [];
  for (let i = 0; i < own.length; i += 1) {
    const a = own[i];
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const eq = a.indexOf('=');
    const name = eq < 0 ? a.slice(2) : a.slice(2, eq);
    if (!Object.prototype.hasOwnProperty.call(known, name)) {
      // An unknown flag is refused rather than ignored. `--map=theirs.txt`
      // must not quietly become a run with a wrapper-made map and a caller who
      // believes otherwise.
      return { error: `unknown option --${name}. Known: ${Object.keys(known).map((k) => `--${k}`).join(', ')}` };
    }
    if (known[name] === 'boolean') opts[name] = true;
    else if (eq >= 0) opts[name] = a.slice(eq + 1);
    else {
      opts[name] = own[i + 1];
      i += 1;
    }
  }
  return { opts, positional };
}

function fail(code, lines) {
  for (const l of [].concat(lines)) console.error(l);
  return code;
}

function countLine(counts) {
  return `inputs=${counts.inputs} checked=${counts.checked} skipped=${counts.skipped}`;
}

function report({ counts, skipped, findings, incomplete, exitCode, allowEmpty }) {
  for (const f of findings ?? []) {
    console.log(`${f.id}  ${f.severity.padEnd(8)} ${f.title}`);
    console.log(`          ${f.detail}`);
  }
  for (const i of incomplete ?? []) {
    console.log(`NOT_OBSERVED  ${i.what}: ${i.why}`);
  }
  // Every skipped case by name. A number on its own tells a reader that
  // something was not checked without telling them what, which is the same
  // amount of information as not printing it.
  for (const s of skipped ?? []) console.log(`skipped       ${s}`);
  console.log('');
  console.log(countLine(counts));
  if (counts.inputs === 0) {
    console.log(allowEmpty
      ? 'inputs=0 accepted because --allow-empty was passed'
      : 'inputs=0 and --allow-empty was not passed: nothing was examined, so nothing is being reported clean');
  }
  console.log(`exit ${exitCode} (${EXIT_NAMES[exitCode]})`);
}

// ── link ─────────────────────────────────────────────────────────────────────

const LINK_OPTS = { policy: 'string', root: 'string', record: 'string', work: 'string', 'allow-empty': 'boolean', help: 'boolean' };

function cmdLink(own, linkArgv) {
  const taken = takeOptions(own, LINK_OPTS);
  if (taken.error) return fail(EXIT_INTEGRITY, [taken.error, '', USAGE]);
  const { opts } = taken;
  if (opts.help) return fail(EXIT_OK, USAGE);
  if (!opts.policy) return fail(EXIT_INTEGRITY, ['--policy is required: without one there is nothing to compare the link against', '', USAGE]);
  if (linkArgv.length === 0) return fail(EXIT_INTEGRITY, ['no link command given after `--`', '', USAGE]);

  const root = normalisePath(resolve(opts.root ?? process.cwd()));
  const allowEmpty = opts['allow-empty'] === true;

  // ---- policy, first: a malformed one stops everything (interfaces.md §7) ----
  let policyBytes;
  try {
    policyBytes = readFileSync(resolve(opts.policy));
  } catch (err) {
    return fail(EXIT_INTEGRITY, [`the policy could not be read: ${err.message}`]);
  }
  let policyJson;
  try {
    policyJson = JSON.parse(policyBytes.toString('utf8'));
  } catch (err) {
    return fail(EXIT_INTEGRITY, [`the policy is not JSON: ${err.message}`]);
  }
  const policyResult = readLinkPolicy(policyJson);
  if (!policyResult.ok) return fail(EXIT_INTEGRITY, [`the policy is malformed: ${policyResult.detail}`]);

  // ---- refuse a caller-controlled map BEFORE running anything ---------------
  const parsed = parseLinkCommand(linkArgv);
  const screen = screenLinkCommand(parsed);
  if (screen.refusals.length > 0) {
    const findings = screen.refusals.map((r) => makeFinding({
      id: LINK.MAP_NOT_PRODUCED_HERE,
      detail: `the link command line carries ${JSON.stringify(r.what)}: ${r.why}`,
      where: { kind: 'invocation', path: null },
    }));
    report({ counts: { inputs: 0, checked: 0, skipped: 0 }, skipped: [], findings, incomplete: [{ what: 'observation', why: 'the link was not run: the command line names the map' }], exitCode: EXIT_INTEGRITY, allowEmpty });
    return EXIT_INTEGRITY;
  }

  // ---- a map path the caller has never seen ---------------------------------
  const nonce = randomBytes(8).toString('hex');
  const workDir = resolve(opts.work ?? join(root, '.vg-link'));
  const runDir = join(workDir, nonce);
  mkdirSync(runDir, { recursive: true });
  const mapPath = join(runDir, 'map.txt');
  const existedBefore = existsSync(mapPath);
  if (existedBefore) {
    return fail(EXIT_INTEGRITY, [`${mapPath} already exists; the wrapper will not reuse a map path it did not just create`]);
  }

  const startedAt = Date.now();
  const extra = parsed.direct ? [`-Map=${mapPath}`, '-t'] : [`-Wl,-Map=${mapPath}`, '-Wl,-t'];
  const child = spawnSync(linkArgv[0], [...linkArgv.slice(1), ...extra], {
    cwd: root,
    encoding: 'buffer',
    maxBuffer: 256 * 1024 * 1024,
  });

  if (child.error) {
    return fail(EXIT_TOOL_FAILED, [`could not run ${linkArgv[0]}: ${child.error.message}`]);
  }
  const stderrText = child.stderr ? child.stderr.toString('utf8') : '';
  const stdoutText = child.stdout ? child.stdout.toString('utf8') : '';
  if (stderrText) process.stderr.write(stderrText); // diagnostics pass through unchanged
  if (child.status !== 0) {
    return fail(EXIT_TOOL_FAILED, [`the link failed with status ${child.status}; nothing was checked`]);
  }

  // ---- is this the map we asked for, written by this run? -------------------
  let mapText = null;
  let writtenByThisRun = false;
  try {
    const st = statSync(mapPath);
    // 2s of slack: a filesystem's mtime granularity is not the wrapper's business.
    writtenByThisRun = st.mtimeMs + 2000 >= startedAt;
    mapText = readFileSync(mapPath, 'utf8');
  } catch (err) {
    return fail(EXIT_INCOMPLETE, [
      `the linker did not write the map at the path the wrapper chose (${err.message}).`,
      'Without a map produced here there is no observation of this link, and exit 0 would be a claim about nothing.',
    ]);
  }
  if (!writtenByThisRun) {
    return fail(EXIT_INTEGRITY, ['the map at the wrapper-chosen path predates this run']);
  }

  // ---- observe ---------------------------------------------------------------
  const outputRel = parsed.output ?? 'a.out';
  const artifactAbs = isAbsolute(outputRel) ? outputRel : join(root, outputRel);
  let artifactBytes = null;
  try {
    artifactBytes = readFileSync(artifactAbs);
  } catch { /* recorded as a problem by buildObservation */ }

  const observation = buildObservation({
    linkRoot: root,
    argv: linkArgv,
    mapText,
    mapProvenance: { producedBy: PRODUCED_BY_WRAPPER, existedBefore: false, writtenByThisRun: true, nonce },
    traceText: stdoutText,
    artifactPath: artifactAbs,
    artifactBytes,
  });
  observation.command.options = observation.command.options.map((o) => scrubText(o, root));
  observation.problems = observation.problems.map((p) => ({ ...p, why: scrubText(p.why, root), ...(p.text ? { text: scrubText(p.text, root) } : {}) }));

  const v = verdict({ observation, policyResult, options: { allowEmpty } });

  // ---- record ----------------------------------------------------------------
  const epoch = /^\d+$/.test(process.env.SOURCE_DATE_EPOCH ?? '') ? Number.parseInt(process.env.SOURCE_DATE_EPOCH, 10) : null;
  const record = {
    recordVersion: 'link-v0',
    component: 'link-wrapper',
    context: {
      generatedAt: new Date(epoch === null ? Date.now() : epoch * 1000).toISOString(),
      timeSource: epoch === null ? 'wall-clock' : 'SOURCE_DATE_EPOCH',
      sourceDateEpoch: epoch,
      host: hostname(),
    },
    policy: { sha256: sha256Hex(policyBytes), failOn: policyResult.failOn, constrained: policyResult.constrained },
    observation,
    verdict: {
      exitCode: v.exitCode,
      findings: v.findings,
      incomplete: v.incomplete,
      decisions: v.decisions,
      counts: v.counts,
      skipped: v.skipped,
    },
  };

  const offenders = findAbsolutePaths(record, { skipTopLevelKeys: ['context'] });
  if (offenders.length > 0) {
    console.error('the record would have carried an absolute path, so it was not written:');
    for (const o of offenders) console.error(`  ${o.where} (${o.in}, ${o.kind}): ${JSON.stringify(o.value)}`);
    return EXIT_INCOMPLETE;
  }

  const sealed = seal(record);
  const recordPath = resolve(opts.record ?? join(runDir, 'link-record.json'));
  mkdirSync(dirname(recordPath), { recursive: true });
  writeFileSync(recordPath, `${JSON.stringify(sealed, null, 2)}\n`, 'utf8');

  report({ counts: v.counts, skipped: v.skipped, findings: v.findings, incomplete: v.incomplete, exitCode: v.exitCode, allowEmpty });
  console.log(`record        ${basename(recordPath)} (evidenceDigest ${sealed.evidenceDigest.slice(0, 16)}…)`);
  return v.exitCode;
}

// ── recheck ──────────────────────────────────────────────────────────────────

const RECHECK_OPTS = { root: 'string', 'allow-empty': 'boolean', help: 'boolean' };

function collectRecords(target) {
  const st = statSync(target);
  if (st.isFile()) return [target];
  return readdirSync(target)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => join(target, f));
}

function cmdRecheck(own) {
  const taken = takeOptions(own, RECHECK_OPTS);
  if (taken.error) return fail(EXIT_INTEGRITY, [taken.error, '', USAGE]);
  const { opts, positional } = taken;
  if (opts.help) return fail(EXIT_OK, USAGE);
  if (positional.length !== 1) return fail(EXIT_INTEGRITY, ['recheck takes exactly one record file or directory', '', USAGE]);
  if (!opts.root) return fail(EXIT_INTEGRITY, ['--root is required: records carry paths relative to the link root, and without it there is nothing to resolve them against']);

  const root = normalisePath(resolve(opts.root));
  const allowEmpty = opts['allow-empty'] === true;
  const target = resolve(positional[0]);

  let files;
  try {
    files = collectRecords(target);
  } catch (err) {
    return fail(EXIT_INCOMPLETE, [`${err.message}`, 'nothing was examined']);
  }

  const findings = [];
  const incomplete = [];
  const skipped = [];
  let checked = 0;

  for (const f of files) {
    const label = basename(f);
    let record;
    try {
      record = JSON.parse(readFileSync(f, 'utf8'));
    } catch (err) {
      incomplete.push({ what: label, why: `not readable as JSON: ${err.message}` });
      skipped.push(label);
      continue;
    }
    if (record.recordVersion !== 'link-v0') {
      incomplete.push({ what: label, why: `recordVersion is ${JSON.stringify(record.recordVersion ?? null)}, not "link-v0"` });
      skipped.push(label);
      continue;
    }
    const want = record.observation?.artifact ?? null;
    if (!want || typeof want.path !== 'string') {
      incomplete.push({ what: label, why: 'the record names no artefact' });
      skipped.push(label);
      continue;
    }
    const abs = join(root, want.path);
    let now = null;
    try {
      const bytes = readFileSync(abs);
      now = { sha256: sha256Hex(bytes), size: bytes.length };
    } catch { now = null; }

    const r = recheckArtifact(record, now);
    checked += 1;
    if (r.finding) findings.push(r.finding);
    if (r.incomplete) incomplete.push({ what: label, why: r.incomplete.why });
  }

  const counts = { inputs: files.length, checked, skipped: skipped.length };

  if (files.length === 0 && !allowEmpty) {
    console.log('NOT_OBSERVED  records: no link records were found, so no artefact was compared with anything');
    report({ counts, skipped, findings, incomplete, exitCode: EXIT_INCOMPLETE, allowEmpty });
    return EXIT_INCOMPLETE;
  }

  const failOn = 'high';
  const firing = atOrAboveThreshold(findings, failOn);
  let exitCode = EXIT_OK;
  if (firing.length > 0) exitCode = EXIT_FINDINGS;
  else if (incomplete.length > 0) exitCode = EXIT_INCOMPLETE;

  report({ counts, skipped, findings, incomplete, exitCode, allowEmpty });
  return exitCode;
}

// ── main ─────────────────────────────────────────────────────────────────────

function main(argv) {
  const { own, link } = splitArgv(argv);
  const sub = own[0];
  if (sub === undefined || sub === '--help' || sub === '-h') return fail(sub === undefined ? EXIT_INTEGRITY : EXIT_OK, USAGE);
  if (sub === 'link') return cmdLink(own.slice(1), link);
  if (sub === 'recheck') return cmdRecheck(own.slice(1));
  return fail(EXIT_INTEGRITY, [`unknown subcommand ${JSON.stringify(sub)}`, '', USAGE]);
}

process.exit(main(process.argv.slice(2)));
