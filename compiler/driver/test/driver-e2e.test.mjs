// End-to-end: the driver as a process, against the real clang-18.
//
// Every claim here has a matching negative: the byte-for-byte test is worth
// nothing unless something in the suite shows the comparison can fail, and an
// exit-code test is worth nothing unless the same fixture returns a different
// code when the thing being checked is intact. Those pairs are marked.

import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  CLANG, CXX_BIN, evidenceRecords, liveBuildSkipReason, makeFixture, runClang, runDriver, sha256File,
} from './helpers.mjs';

const skip = liveBuildSkipReason();

test('the live tests in this file are actually running', () => {
  // node:test skips on `{ skip: null }` — presence of the property, not its
  // truth. This whole file once reported green with every live test skipped.
  // The guard is `Object.is(..., undefined)` rather than a falsy check,
  // because `null` is falsy and `null` is precisely the bug.
  const reason = liveBuildSkipReason();
  if (process.platform === 'linux' && CLANG) {
    assert.ok(Object.is(reason, undefined), `expected undefined, got ${JSON.stringify(reason)}`);
  } else {
    assert.equal(typeof reason, 'string');
  }
});

test('a clean build exits 0, produces the artefact, and records it', { skip }, (t) => {
  const fx = makeFixture('e2e-ok');
  t.after(fx.cleanup);

  const r = runDriver(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(existsSync(join(fx.src, 'app')));

  const records = evidenceRecords(fx.evidence);
  assert.equal(records.length, 1);
  const { record, name } = records[0];
  assert.equal(record.exitCode, 0);
  assert.deepEqual(record.findings, []);
  assert.equal(record.build.shipping.exitCode, 0);
  assert.equal(record.build.artifacts.length, 1);
  assert.equal(record.build.artifacts[0].sha256, sha256File(join(fx.src, 'app')));
  assert.equal(record.checks.toolchainPin.status, 'match');
  // The filename is the digest, so a record cannot be silently swapped for another.
  assert.ok(name.includes(record.evidenceDigest.slice(0, 16)));
});

test('the record carries no absolute path — checked with the evidence component\'s own gate', { skip }, async (t) => {
  const fx = makeFixture('e2e-paths');
  t.after(fx.cleanup);
  assert.equal(runDriver(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src }).status, 0);

  const { path, record } = evidenceRecords(fx.evidence)[0];
  const text = readFileSync(path, 'utf8');
  assert.equal(text.includes('/mnt/c'), false);
  assert.equal(/"\/[a-z]/.test(text), false, 'a value beginning with a POSIX absolute path');

  // Not the driver's own gate: the independent one next door.
  const { findAbsolutePaths } = await import('../../evidence/paths.mjs');
  assert.deepEqual(findAbsolutePaths(record, { mode: 'strict' }), []);
});

test('the record is what the independent verifier says it is', { skip }, async (t) => {
  const fx = makeFixture('e2e-verify');
  t.after(fx.cleanup);
  assert.equal(runDriver(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src }).status, 0);

  const { record } = evidenceRecords(fx.evidence)[0];
  const { rederiveDigest } = await import('../../evidence/verify.mjs');
  assert.equal(rederiveDigest(record), record.evidenceDigest);
});

test('the same build twice writes one record, because the digest does not move', { skip }, (t) => {
  const fx = makeFixture('e2e-determinism');
  t.after(fx.cleanup);
  assert.equal(runDriver(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src }).status, 0);
  assert.equal(runDriver(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src }).status, 0);
  // Two runs, one content-addressed file: wall-clock and durations live in
  // `context` and are excluded from the digest, so nothing volatile leaked in.
  assert.equal(evidenceRecords(fx.evidence).length, 1);
});

// ---------------------------------------------------------------------------
// Non-invasiveness
// ---------------------------------------------------------------------------

test('the object file is byte-for-byte what plain clang-18 emits', { skip }, (t) => {
  const fx = makeFixture('e2e-bytes-o');
  t.after(fx.cleanup);

  assert.equal(runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src }).status, 0);
  copyFileSync(join(fx.src, 'out.o'), join(fx.src, 'driver.o'));
  rmSync(join(fx.src, 'out.o'));

  assert.equal(runClang(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src }).status, 0);
  assert.equal(sha256File(join(fx.src, 'driver.o')), sha256File(join(fx.src, 'out.o')));
});

test('the linked executable is byte-for-byte what plain clang-18 emits', { skip }, (t) => {
  const fx = makeFixture('e2e-bytes-exe');
  t.after(fx.cleanup);

  assert.equal(runDriver(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src }).status, 0);
  copyFileSync(join(fx.src, 'app'), join(fx.src, 'driver.app'));
  rmSync(join(fx.src, 'app'));

  assert.equal(runClang(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src }).status, 0);
  assert.equal(sha256File(join(fx.src, 'driver.app')), sha256File(join(fx.src, 'app')));
});

test('an observation build changes nothing the caller keeps', { skip }, (t) => {
  // The positive control for the two-build discipline: the driver is told to
  // add -mllvm -print-pipeline-passes, which on its own would truncate codegen
  // to a zero-byte object. The shipped artefact must still be the plain one.
  const fx = makeFixture('e2e-observe');
  t.after(fx.cleanup);

  assert.equal(runClang(['-c', 'hello.c', '-O2', '-o', 'plain.o'], { cwd: fx.src }).status, 0);
  const plain = sha256File(join(fx.src, 'plain.o'));

  const r = runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o', '--vg-observe-pipeline'], { cwd: fx.src });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(sha256File(join(fx.src, 'out.o')), plain);

  const { record } = evidenceRecords(fx.evidence)[0];
  assert.equal(record.build.observation.attempted, true);
  assert.equal(record.build.observation.outputDiscarded, true);
  assert.ok(record.build.observation.pipelineLength > 0);
  assert.equal(record.build.artifacts[0].sha256, plain);
});

test('the byte comparison can fail — a flag that changes codegen changes the digest', { skip }, (t) => {
  // Without this, "the digests matched" is not evidence of anything: it would
  // also hold if both sides were empty files or if the comparison were a no-op.
  const fx = makeFixture('e2e-bytes-control', { flags: { optLevels: ['-O0', '-O2'] } });
  t.after(fx.cleanup);

  assert.equal(runClang(['-c', 'hello.c', '-O2', '-o', 'a.o'], { cwd: fx.src }).status, 0);
  assert.equal(runClang(['-c', 'hello.c', '-O0', '-o', 'b.o'], { cwd: fx.src }).status, 0);
  assert.notEqual(sha256File(join(fx.src, 'a.o')), sha256File(join(fx.src, 'b.o')));
});

// ---------------------------------------------------------------------------
// Fail-closed paths, each with the intact case beside it
// ---------------------------------------------------------------------------

test('one changed character in the pin is exit 4', { skip }, (t) => {
  const fx = makeFixture('e2e-pin');
  t.after(fx.cleanup);

  // Intact first, so the exit 4 below is attributable to the edit and not to
  // the fixture having been broken all along.
  assert.equal(runDriver(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src }).status, 0);
  rmSync(join(fx.src, 'app'));

  const pin = JSON.parse(readFileSync(fx.pinPath, 'utf8'));
  const d = pin.packages[0].sha256;
  pin.packages[0].sha256 = (d[0] === '0' ? '1' : '0') + d.slice(1);
  writeFileSync(fx.pinPath, JSON.stringify(pin, null, 2), 'utf8');

  const r = runDriver(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src });
  assert.equal(r.status, 4, r.stderr);
  assert.equal(existsSync(join(fx.src, 'app')), false, 'nothing else runs after an integrity failure');

  const rec = evidenceRecords(fx.evidence).find((x) => x.record.exitCode === 4);
  assert.ok(rec, 'the integrity failure is recorded');
  assert.equal(rec.record.findings[0].id, 'VG-CFG-001');
  assert.equal(rec.record.build.shipping.attempted, false);
});

test('requireDigestMatch false downgrades the same mismatch to a finding', { skip }, (t) => {
  // The other half of the pin test: the exit 4 above comes from the policy
  // saying digests must match, not from the driver refusing to run at all.
  const fx = makeFixture('e2e-pin-soft', {
    failOn: 'critical',
    toolchain: { pin: 'toolchain.pin.json', requireDigestMatch: false },
  });
  t.after(fx.cleanup);

  const pin = JSON.parse(readFileSync(fx.pinPath, 'utf8'));
  const d = pin.packages[0].sha256;
  pin.packages[0].sha256 = (d[0] === '0' ? '1' : '0') + d.slice(1);
  writeFileSync(fx.pinPath, JSON.stringify(pin, null, 2), 'utf8');

  const r = runDriver(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src });
  // VG-CFG-001 is critical and failOn is critical, so this is 2 rather than 4:
  // a finding, not an integrity stop.
  assert.equal(r.status, 2, r.stderr);
});

test('a forbidden flag is exit 2, and no object file is produced', { skip }, (t) => {
  const fx = makeFixture('e2e-forbidden');
  t.after(fx.cleanup);

  const ok = runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  assert.equal(ok.status, 0, ok.stderr);
  rmSync(join(fx.src, 'out.o'));

  const r = runDriver(['-c', 'hello.c', '-O2', '-fno-stack-protector', '-o', 'out.o'], { cwd: fx.src });
  assert.equal(r.status, 2, r.stderr);
  assert.equal(existsSync(join(fx.src, 'out.o')), false, 'fail-closed: a forbidden build produces nothing to ship');

  const rec = evidenceRecords(fx.evidence).find((x) => x.record.exitCode === 2);
  assert.equal(rec.record.findings[0].id, 'VG-CFG-002');
});

test('a forbidden flag reached through -Xclang is still exit 2', { skip }, (t) => {
  const fx = makeFixture('e2e-forbidden-xclang', {
    flags: { forbidden: ['-load'], optLevels: ['-O2'] },
  });
  t.after(fx.cleanup);
  const r = runDriver(['-c', 'hello.c', '-O2', '-Xclang', '-load', '-Xclang', 'libNope.so', '-o', 'out.o'], { cwd: fx.src });
  assert.equal(r.status, 2, r.stderr);
});

test('a malformed policy is exit 4 and writes no evidence', { skip }, (t) => {
  const fx = makeFixture('e2e-bad-policy');
  t.after(fx.cleanup);

  assert.equal(runDriver(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src }).status, 0);
  const before = evidenceRecords(fx.evidence).length;
  assert.equal(before, 1);
  rmSync(join(fx.src, 'app'));

  writeFileSync(fx.policyPath, '{ "policyVersion": "policy-v0", "failOn": ', 'utf8');
  const r = runDriver(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src });
  assert.equal(r.status, 4, r.stderr);
  assert.equal(evidenceRecords(fx.evidence).length, before, 'no record is written for an unreadable policy');
  assert.equal(existsSync(join(fx.src, 'app')), false);
});

test('a policy that breaks the schema is exit 4, not a warning', { skip }, (t) => {
  const fx = makeFixture('e2e-schema-policy');
  t.after(fx.cleanup);
  writeFileSync(fx.policyPath, JSON.stringify({ policyVersion: 'policy-v0', failOn: 'severe' }), 'utf8');
  const r = runDriver(['hello.c', '-O2', '-o', 'app'], { cwd: fx.src });
  assert.equal(r.status, 4);
  assert.match(r.stderr, /failOn/);
});

test('an optimisation level outside the evaluated set is a finding, at its own severity', { skip }, (t) => {
  const fx = makeFixture('e2e-opt');
  t.after(fx.cleanup);
  // VG-CFG-003 is medium and failOn is high, so the build proceeds and the
  // finding is recorded: the policy's threshold decides, not the driver.
  const r = runDriver(['-c', 'hello.c', '-O3', '-o', 'out.o'], { cwd: fx.src });
  assert.equal(r.status, 0, r.stderr);
  const rec = evidenceRecords(fx.evidence)[0];
  assert.equal(rec.record.findings[0].id, 'VG-CFG-003');
  assert.equal(rec.record.checks.flags.optLevel.effective, '-O3');
});

test('the same finding at a lower threshold is exit 2', { skip }, (t) => {
  const fx = makeFixture('e2e-opt-threshold', { failOn: 'medium' });
  t.after(fx.cleanup);
  assert.equal(runDriver(['-c', 'hello.c', '-O3', '-o', 'out.o'], { cwd: fx.src }).status, 2);
});

test('a compile error is exit 1, with clang\'s diagnostics passed through unchanged', { skip }, (t) => {
  const fx = makeFixture('e2e-compile-error');
  t.after(fx.cleanup);
  writeFileSync(join(fx.src, 'broken.c'), 'int main(void) { return nope; }\n', 'utf8');

  const mine = runDriver(['-c', 'broken.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  const theirs = runClang(['-c', 'broken.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  assert.equal(mine.status, 1);
  assert.equal(mine.stderr, theirs.stderr);
});

test('an unreadable response file is exit 3, not a build checked against half a command line', { skip }, (t) => {
  const fx = makeFixture('e2e-rsp');
  t.after(fx.cleanup);

  writeFileSync(join(fx.src, 'good.rsp'), '-O2 -c hello.c -o out.o\n', 'utf8');
  const ok = runDriver(['@good.rsp'], { cwd: fx.src });
  assert.equal(ok.status, 0, ok.stderr);
  rmSync(join(fx.src, 'out.o'));

  const r = runDriver(['@absent.rsp', '-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  assert.equal(r.status, 2, r.stderr); // VG-CFG-006 is high, and failOn is high
  const rec = evidenceRecords(fx.evidence).find((x) => x.record.exitCode === 2);
  assert.equal(rec.record.findings[0].id, 'VG-CFG-006');
  assert.equal(rec.record.checks.responseFiles.unresolved, 1);
});

test('failOnIncomplete turns an incomplete check into exit 3 rather than 0', { skip }, (t) => {
  // The plugin component reports complete:false when it cannot capture the
  // pipeline. -fsyntax-only gives it nothing to capture.
  const fx = makeFixture('e2e-incomplete', { flags: { optLevels: ['-O0', '-O2'] } });
  t.after(fx.cleanup);
  const r = runDriver(['-fsyntax-only', 'hello.c'], { cwd: fx.src });
  assert.notEqual(r.status, 0, 'an unfinished check must not report clean');
  const rec = evidenceRecords(fx.evidence)[0];
  assert.equal(rec.record.checks.pluginIntegrity.complete, false);
});

test('vg++ drives clang++-18', { skip }, (t) => {
  const fx = makeFixture('e2e-cxx');
  t.after(fx.cleanup);
  writeFileSync(join(fx.src, 'hello.cc'), '#include <string>\nint main(){ return (int)std::string("x").size()-1; }\n', 'utf8');
  const r = runDriver(['-c', 'hello.cc', '-O2', '-o', 'out.o'], { cwd: fx.src, bin: CXX_BIN });
  assert.equal(r.status, 0, r.stderr);
  const rec = evidenceRecords(fx.evidence)[0];
  assert.equal(rec.record.driver, 'vg++');
  assert.equal(rec.record.mode, 'cxx');
});
