/**
 * Tests for the run-level subject-resolution verdict.
 *
 * The log fragments below are transcribed from real runs of the plugin against
 * `clang-18 -O2` (recorded under `_sanity/pc4` on the measurement host), then
 * trimmed to the records each case is about. Test data is inline rather than in
 * a directory beside this file: a path segment named `fixtures` under compiler/
 * is a committable measurement input and scripts/check-packaging-invariants.mjs
 * fails the build on one.
 *
 * The cases that matter most are the two that must NOT fail: a translation unit
 * that legitimately does not hold the subject, and a `.summary.tsv` side file
 * that carries no record at all. A checker that reported those as broken would
 * be turned off within a week, and then the failure it exists to catch would be
 * back with a green tick over it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  RESOLUTIONS, STATUS, aggregateResolution, exitCodeFor,
  formatResolutionReport, parseResolutionRecords,
} from '../lib/subject-resolution.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '..', 'tools', 'check-subject-resolution.mjs');

const SRC = '/tmp/target.c';
const TUA = '/tmp/tuA.c';
const TUB = '/tmp/tuB.c';

const handshake = (target) =>
  `HANDSHAKE\tobs-log-v1\t${SRC}\t${target}\twipe_kept\tmemset\tstandard\t0`;
const res = (mod, role, name, resolution) =>
  `SUBJECTRES\t1\t${mod}\t${role}\t${name}\t${resolution}`;

/** A healthy single-TU log: both names resolved, the subject lost at DSEPass. */
const HEALTHY = [
  handshake('handle_request'),
  res(SRC, 'subject', 'handle_request', RESOLUTIONS.RESOLVED),
  res(SRC, 'control', 'wipe_kept', RESOLUTIONS.RESOLVED),
  'UNIT\t1\tAnnotation2MetadataPass\thandle_request\thandle_request\tBORN',
  'EV\t172\tafter\tDSEPass\tfunction\thandle_request\thandle_request\tsubject\t0\tLOST\t1',
  'SUMMARY\thandle_request\thandle_request\tsubject\t0\t172\tDSEPass\tDSEPass\tMemCpyOptPass\t44\tLOST\t1\t1\t0\t1\tLIVE\t-\t-\t2',
  'STATS\t650\t3\t2\t2\t0\tstandard',
].join('\n') + '\n';

/** The misspelt subject: control PRESENT, subject absent, rc 0, log non-empty. */
const TYPO = [
  handshake('handle_requestX'),
  res(SRC, 'subject', 'handle_requestX', RESOLUTIONS.NOT_IN_MODULE),
  res(SRC, 'control', 'wipe_kept', RESOLUTIONS.RESOLVED),
  'UNIT\t1\tAnnotation2MetadataPass\twipe_kept\twipe_kept\tBORN',
  'EV\t1\tbefore\tAnnotation2MetadataPass\tmodule\twipe_kept\twipe_kept\tcontrol\t1\tPRESENT\t1',
  'SUMMARY\twipe_kept\twipe_kept\tcontrol\t0\t-\t-\t-\t-\t-1\tPRESENT\t1\t0\t0\t0\tLIVE\t-\t-\t1',
  'STATS\t650\t1\t1\t1\t0\tstandard',
].join('\n') + '\n';

const MULTI_A = [
  handshake('handle_request').replace(SRC, TUA),
  res(TUA, 'subject', 'handle_request', RESOLUTIONS.RESOLVED),
  res(TUA, 'control', 'wipe_kept', RESOLUTIONS.RESOLVED),
  'STATS\t454\t3\t2\t2\t0\tstandard',
].join('\n') + '\n';

const MULTI_B = [
  handshake('handle_request').replace(SRC, TUB),
  res(TUB, 'subject', 'handle_request', RESOLUTIONS.NOT_IN_MODULE),
  res(TUB, 'control', 'wipe_kept', RESOLUTIONS.NOT_IN_MODULE),
  'STATS\t294\t0\t0\t0\t0\tstandard',
].join('\n') + '\n';

// --- parsing -----------------------------------------------------------------

test('parse picks the record out and leaves every other type alone', () => {
  const p = parseResolutionRecords(HEALTHY, 'healthy.tsv');
  assert.equal(p.records.length, 2);
  assert.equal(p.hasRecord, true);
  assert.equal(p.nonEmptyLines, 7);
  assert.deepEqual(p.records[0], {
    source: 'healthy.tsv', seq: 1, moduleId: SRC, role: 'subject',
    name: 'handle_request', resolution: 'resolved',
  });
});

test('a record type from a newer plugin is ignored, not rejected', () => {
  const p = parseResolutionRecords(HEALTHY + 'FUTURETHING\t1\twhatever\n');
  assert.equal(p.records.length, 2);
  assert.equal(aggregateResolution([{ text: HEALTHY + 'FUTURETHING\t1\twhatever\n' }]).ok, true);
});

test('CRLF line endings do not smuggle a carriage return into the word', () => {
  const p = parseResolutionRecords(HEALTHY.replace(/\n/g, '\r\n'));
  assert.equal(p.records[0].resolution, RESOLUTIONS.RESOLVED);
});

// --- the green case ----------------------------------------------------------

test('a healthy single-TU log passes, and says how many modules resolved', () => {
  const v = aggregateResolution([{ source: 'healthy.tsv', text: HEALTHY }]);
  assert.equal(v.ok, true);
  assert.equal(v.status, STATUS.OK);
  assert.equal(v.modulesSeen, 1);
  assert.deepEqual(v.roles.subject.resolvedIn, [SRC]);
  assert.equal(exitCodeFor(v), 0);
});

// --- the red case ------------------------------------------------------------

test('the misspelt subject fails, and the failure names the string that was configured', () => {
  const v = aggregateResolution([{ source: 'typo.tsv', text: TYPO }]);
  assert.equal(v.ok, false);
  assert.equal(v.status, STATUS.UNRESOLVED);
  assert.match(v.reason, /handle_requestX/);
  assert.equal(exitCodeFor(v), 2);
  // The control is fine, which is exactly why the pre-existing invariant --
  // "a co-resident control held, so the run was sound" -- cannot see this.
  assert.equal(v.roles.control.ok, true);
});

test('the report distinguishes the two roles rather than reporting one verdict', () => {
  const text = formatResolutionReport(aggregateResolution([{ text: TYPO }]));
  assert.match(text, /^FAIL/);
  assert.match(text, /subject *: handle_requestX/);
  assert.match(text, /control *: wipe_kept/);
});

// --- multi-TU: the false positive this design exists to avoid -----------------

test('two TUs, subject defined in one of them: the run passes', () => {
  const v = aggregateResolution([
    { source: 'tuA.tsv', text: MULTI_A },
    { source: 'tuB.tsv', text: MULTI_B },
  ]);
  assert.equal(v.ok, true);
  assert.equal(v.modulesSeen, 2);
  assert.equal(v.roles.subject.counts[RESOLUTIONS.NOT_IN_MODULE], 1);
  assert.equal(v.roles.subject.counts[RESOLUTIONS.RESOLVED], 1);
});

test('the tuB log ON ITS OWN fails -- which is why the verdict is over the run', () => {
  const alone = aggregateResolution([{ source: 'tuB.tsv', text: MULTI_B }]);
  assert.equal(alone.ok, false);
  assert.equal(alone.status, STATUS.UNRESOLVED);
});

test('two TUs and a misspelt subject: no module resolves it, so the run fails', () => {
  const badTU = (mod) => [
    handshake('handle_requestX').replace(SRC, mod),
    res(mod, 'subject', 'handle_requestX', RESOLUTIONS.NOT_IN_MODULE),
    res(mod, 'control', 'wipe_kept', RESOLUTIONS.RESOLVED),
  ].join('\n');
  const v = aggregateResolution([
    { source: 'tuA.tsv', text: badTU(TUA) },
    { source: 'tuB.tsv', text: badTU(TUB) },
  ]);
  assert.equal(v.ok, false);
  assert.equal(v.status, STATUS.UNRESOLVED);
  assert.equal(v.roles.subject.counts[RESOLUTIONS.NOT_IN_MODULE], 2);
});

// --- the cases that must not be read as "fine" -------------------------------

test('a log with no SUBJECTRES record is unjudgeable, not passing', () => {
  const old = HEALTHY.split('\n').filter((l) => !l.startsWith('SUBJECTRES')).join('\n');
  const v = aggregateResolution([{ source: 'old.tsv', text: old }]);
  assert.equal(v.ok, false);
  assert.equal(v.status, STATUS.NO_RECORD);
  assert.equal(v.judged, false);
  assert.equal(exitCodeFor(v), 3);
});

test('no logs at all is unjudgeable, not passing', () => {
  const v = aggregateResolution([]);
  assert.equal(v.ok, false);
  assert.equal(v.status, STATUS.NO_LOGS);
  assert.equal(exitCodeFor(v), 3);
});

test('not-scanned reports that nobody asked, and is not a report of absence', () => {
  const v = aggregateResolution([{
    text: [handshake('handle_request'),
      'SUBJECTRES\t0\t-\tsubject\thandle_request\tnot-scanned',
      'SUBJECTRES\t0\t-\tcontrol\twipe_kept\tnot-scanned'].join('\n'),
  }]);
  assert.equal(v.ok, false);
  assert.equal(v.status, STATUS.NOT_SCANNED);
  assert.equal(v.judged, false);
  assert.match(v.reason, /never determined/);
  assert.equal(exitCodeFor(v), 3);
  assert.equal(v.modulesSeen, 0, 'the placeholder module id must not be counted as a module');
});

test('declaration-only is its own answer, not folded into not-in-module', () => {
  const v = aggregateResolution([{
    text: [handshake('handle_request'),
      res(SRC, 'subject', 'handle_request', RESOLUTIONS.DECLARATION_ONLY),
      res(SRC, 'control', 'wipe_kept', RESOLUTIONS.RESOLVED)].join('\n'),
  }]);
  assert.equal(v.status, STATUS.DECLARATION_ONLY);
  assert.match(v.reason, /never a body to count anything in/);
  assert.equal(exitCodeFor(v), 2);
});

test('a resolution word this checker does not know is refused, not assumed benign', () => {
  const v = aggregateResolution([{
    text: [handshake('handle_request'),
      res(SRC, 'subject', 'handle_request', 'probably-fine'),
      res(SRC, 'control', 'wipe_kept', RESOLUTIONS.RESOLVED)].join('\n'),
  }]);
  assert.equal(v.status, STATUS.UNKNOWN_WORD);
  assert.match(v.reason, /'probably-fine'/);
  assert.equal(exitCodeFor(v), 2);
});

test('logs that disagree about the configured name are not one run', () => {
  const v = aggregateResolution([
    { source: 'a.tsv', text: MULTI_A },
    { source: 'b.tsv', text: MULTI_B.replace(/handle_request/g, 'handle_reqest') },
  ]);
  assert.equal(v.status, STATUS.INCONSISTENT_NAME);
  assert.equal(exitCodeFor(v), 2);
});

test('a control that resolves nowhere fails even when the subject is fine', () => {
  const v = aggregateResolution([{
    text: [handshake('handle_request'),
      res(SRC, 'subject', 'handle_request', RESOLUTIONS.RESOLVED),
      res(SRC, 'control', 'wipe_keptX', RESOLUTIONS.NOT_IN_MODULE)].join('\n'),
  }]);
  assert.equal(v.ok, false);
  assert.match(v.reason, /wipe_keptX/);
  assert.equal(v.roles.subject.ok, true);
});

test('--role=subject judges only the subject', () => {
  const logs = [{
    text: [handshake('handle_request'),
      res(SRC, 'subject', 'handle_request', RESOLUTIONS.RESOLVED),
      res(SRC, 'control', 'wipe_keptX', RESOLUTIONS.NOT_IN_MODULE)].join('\n'),
  }];
  assert.equal(aggregateResolution(logs, { roles: ['subject'] }).ok, true);
  assert.equal(aggregateResolution(logs).ok, false);
});

// --- the CLI -----------------------------------------------------------------

function runCli(files, args = []) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args, ...files], { encoding: 'utf8' });
    return { code: 0, stdout };
  } catch (err) {
    return { code: err.status, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

const write = (name, text) => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-subjectres-'));
  const p = join(dir, name);
  writeFileSync(p, text);
  return p;
};

test('CLI exits 0 on a healthy log', () => {
  const r = runCli([write('healthy.tsv', HEALTHY)]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /^PASS/);
});

test('CLI exits 2 on the misspelt subject', () => {
  const r = runCli([write('typo.tsv', TYPO)]);
  assert.equal(r.code, 2);
  assert.match(r.stdout, /handle_requestX/);
});

test('CLI exits 0 over the two-TU run and 2 over tuB alone', () => {
  const a = write('tuA.tsv', MULTI_A);
  const b = write('tuB.tsv', MULTI_B);
  assert.equal(runCli([a, b]).code, 0);
  assert.equal(runCli([b]).code, 2);
});

test('CLI exits 3 on a file it cannot read, rather than skipping it', () => {
  const r = runCli([join(tmpdir(), 'vg-subjectres-no-such-file.tsv')]);
  assert.equal(r.code, 3);
  assert.match(r.stderr, /cannot read/);
});

test('CLI --json emits a parseable verdict with its schema version', () => {
  const r = runCli([write('typo.tsv', TYPO)], ['--json']);
  assert.equal(r.code, 2);
  const j = JSON.parse(r.stdout);
  assert.equal(j.schemaVersion, 'subject-resolution-v1');
  assert.equal(j.status, STATUS.UNRESOLVED);
  assert.equal(j.ok, false);
});
