// The live suite: a real compiler, a real linker, a real artefact.
//
// SKIP IS NOT PASS.
//
// A suite that skips itself when the toolchain is absent reports the same green
// tick as one that ran. So when no usable toolchain is found, every case here
// FAILS — unless `VG_LINK_ALLOW_SKIP` is set, which is a person saying "I know
// this machine has no clang". Even then each skipped case is printed BY NAME,
// because a count of skipped tests tells a reader that something did not run
// without telling them what.
//
// Set `VG_LINK_SCRATCH` to put the build somewhere other than the system
// temporary directory.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { EXIT_OK, EXIT_FINDINGS, EXIT_INTEGRITY } from '../lib/exit.mjs';
import { CLI } from './helpers.mjs';

const ALLOW_SKIP_VAR = 'VG_LINK_ALLOW_SKIP';
const SCRATCH_VAR = 'VG_LINK_SCRATCH';
const allowSkip = Boolean(process.env[ALLOW_SKIP_VAR]);

// ── finding a toolchain ──────────────────────────────────────────────────────

function works(cc) {
  const probe = spawnSync(cc, ['--version'], { encoding: 'utf8' });
  return probe.status === 0;
}

function findCompiler() {
  for (const cc of ['clang-18', 'clang', 'cc', 'gcc']) if (works(cc)) return cc;
  return null;
}

const CC = findCompiler();

const skippedByName = [];
function needToolchain(t, caseName) {
  if (CC) return false;
  if (allowSkip) {
    skippedByName.push(caseName);
    console.log(`SKIPPED (authorised by ${ALLOW_SKIP_VAR})  ${caseName}`);
    t.skip(`no C compiler with a working --version; skip authorised by ${ALLOW_SKIP_VAR}`);
    return true;
  }
  assert.fail(
    `${caseName}: no usable C compiler was found (tried clang-18, clang, cc, gcc). ` +
    `This case FAILS rather than skipping, because a skipped live test is indistinguishable ` +
    `from a passing one in a summary. Set ${ALLOW_SKIP_VAR}=1 to authorise the skip; every ` +
    `skipped case is then listed by name in the output.`,
  );
  return true;
}

// ── the fixture, built once ──────────────────────────────────────────────────

const SOURCES = {
  // CONTROL — the zeroing cannot be optimised away: the buffer escapes into
  // another translation unit. A run in which the control is flagged, or in
  // which its symbol vanishes, is a broken measurement rather than a finding.
  'main.c': `#include <string.h>
extern int helper(int);
extern void opaque(char *p);
volatile int sink;
int control_fn(int n) { char b[16]; memset(b, 0, sizeof b); opaque(b); return n; }
int target_fn(int n) { char b[16]; memset(b, 0, sizeof b); return n; }
__attribute__((constructor)) static void ctor_main(void) { sink = 1; }
int main(void) { return helper(control_fn(3)) + target_fn(1); }
`,
  'helper.c': `volatile int hsink;
void opaque(char *p) { hsink = p[0]; }
int helper(int x) { return x * 2; }
`,
  // The unapproved input. A constructor, so it also reaches .init_array.
  'rogue.c': `volatile int rogue_sink;
__attribute__((constructor)) static void ctor_rogue(void) { rogue_sink = 1; }
int rogue_fn(int x) { return x + 1; }
`,
};

const POLICY = {
  policyVersion: 'policy-v0',
  failOn: 'high',
  link: {
    allowedObjects: ['main.o', 'helper.o', 'system:**/*.o', 'system:**/crt*.o'],
    allowedLibraries: ['system:**/*.so*'],
    allowedLinkers: ['lld', 'bfd', 'gold'],
    forbidLinkerScripts: true,
  },
};

let LAB = null;
let usesLld = false;

function prepare() {
  if (LAB) return LAB;
  const base = process.env[SCRATCH_VAR] ?? tmpdir();
  mkdirSync(base, { recursive: true });
  LAB = mkdtempSync(join(base, 'live-'));
  for (const [name, text] of Object.entries(SOURCES)) writeFileSync(join(LAB, name), text, 'utf8');
  for (const name of Object.keys(SOURCES)) {
    const o = name.replace(/\.c$/, '.o');
    const r = spawnSync(CC, ['-c', '-O2', name, '-o', o], { cwd: LAB, encoding: 'utf8' });
    assert.equal(r.status, 0, `compiling ${name} failed: ${r.stderr}`);
  }
  usesLld = spawnSync(CC, ['-fuse-ld=lld', '-xc', '-', '-o', join(LAB, 'probe.bin')], { cwd: LAB, input: 'int main(void){return 0;}', encoding: 'utf8' }).status === 0;
  writeFileSync(join(LAB, 'policy.json'), JSON.stringify(POLICY, null, 2), 'utf8');
  return LAB;
}

function link(args, extraEnv = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: LAB, encoding: 'utf8', env: { ...process.env, ...extraEnv } });
}

function ldFlag() {
  return usesLld ? ['-fuse-ld=lld'] : [];
}

// ── the cases ────────────────────────────────────────────────────────────────

test('live: the wrapper produces the map itself and the caller never names it', (t) => {
  if (needToolchain(t, 'the wrapper produces the map itself')) return;
  prepare();
  const record = join(LAB, 'neg-record.json');
  const r = link(['link', '--policy', 'policy.json', '--root', LAB, '--record', record, '--',
    CC, ...ldFlag(), 'main.o', 'helper.o', '-o', 'neg.bin']);
  assert.equal(r.status, EXIT_OK, `${r.stdout}\n${r.stderr}`);

  const work = join(LAB, '.vg-link');
  const runs = readdirSync(work);
  assert.equal(runs.length >= 1, true, 'the wrapper made its own working directory');
  assert.ok(runs.every((d) => /^[0-9a-f]{16}$/.test(d)), `map directories are unguessable: ${runs.join(', ')}`);
  assert.ok(existsSync(join(work, runs[0], 'map.txt')), 'the map is where the wrapper put it');

  const rec = JSON.parse(readFileSync(record, 'utf8'));
  assert.equal(rec.observation.provenance.map.producedBy, 'wrapper');
  assert.equal(rec.observation.provenance.map.existedBefore, false);
  assert.equal(rec.observation.provenance.map.writtenByThisRun, true);
});

test('live NEGATIVE: an approved link is clean, and the control is present', (t) => {
  if (needToolchain(t, 'an approved link is clean')) return;
  prepare();
  const record = join(LAB, 'neg2-record.json');
  const r = link(['link', '--policy', 'policy.json', '--root', LAB, '--record', record, '--',
    CC, ...ldFlag(), 'main.o', 'helper.o', '-o', 'neg2.bin']);
  assert.equal(r.status, EXIT_OK, `${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /^inputs=\d+ checked=\d+ skipped=\d+$/m);

  const rec = JSON.parse(readFileSync(record, 'utf8'));
  assert.deepEqual(rec.verdict.findings, []);
  assert.ok(rec.verdict.counts.inputs > 0, 'a clean verdict over zero inputs would be a lie about an empty set');

  // CONTROL: main.o is authorised here and must stay authorised in the positive
  // run below. If it ever comes out unauthorised the matcher is broken.
  const control = rec.verdict.decisions.find((d) => d.ref === 'main.o');
  assert.equal(control.allowed, true);
  assert.ok(rec.observation.symbols.some((s) => s.name === 'control_fn' && s.input === 'main.o'),
    'the control function survived to the link and is attributed to the object that defines it');
});

test('live POSITIVE: an unapproved object linked in is detected', (t) => {
  if (needToolchain(t, 'an unapproved object linked in is detected')) return;
  prepare();
  const record = join(LAB, 'pos-record.json');
  const r = link(['link', '--policy', 'policy.json', '--root', LAB, '--record', record, '--',
    CC, ...ldFlag(), 'main.o', 'helper.o', 'rogue.o', '-o', 'pos.bin']);
  assert.equal(r.status, EXIT_FINDINGS, `${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /VG-LINK-001/);
  assert.match(r.stdout, /rogue\.o/);

  const rec = JSON.parse(readFileSync(record, 'utf8'));
  const control = rec.verdict.decisions.find((d) => d.ref === 'main.o');
  assert.equal(control.allowed, true, 'the control moved: this run says nothing about rogue.o');

  if (usesLld) {
    // .init_array attribution needs a map, and only lld writes one here.
    assert.match(r.stdout, /VG-LINK-009/);
  }
});

test('live: a post-link modification of the artefact is detected', (t) => {
  if (needToolchain(t, 'a post-link modification of the artefact is detected')) return;
  prepare();
  const records = join(LAB, 'records');
  mkdirSync(records, { recursive: true });
  const record = join(records, 'mod-record.json');
  const built = link(['link', '--policy', 'policy.json', '--root', LAB, '--record', record, '--',
    CC, ...ldFlag(), 'main.o', 'helper.o', '-o', 'mod.bin']);
  assert.equal(built.status, EXIT_OK, `${built.stdout}\n${built.stderr}`);

  // NEGATIVE: untouched.
  const before = spawnSync(process.execPath, [CLI, 'recheck', records, '--root', LAB], { cwd: LAB, encoding: 'utf8' });
  assert.equal(before.status, EXIT_OK, `${before.stdout}\n${before.stderr}`);
  assert.equal(/VG-LINK-006/.test(before.stdout), false);

  // POSITIVE: one byte appended after the link.
  appendFileSync(join(LAB, 'mod.bin'), '\0');
  const after = spawnSync(process.execPath, [CLI, 'recheck', records, '--root', LAB], { cwd: LAB, encoding: 'utf8' });
  assert.equal(after.status, EXIT_FINDINGS, `${after.stdout}\n${after.stderr}`);
  assert.match(after.stdout, /VG-LINK-006/);
  assert.match(after.stdout, /inputs=1 checked=1 skipped=0/);
});

test('live: a link command that names the map is refused and the linker never runs', (t) => {
  if (needToolchain(t, 'a link command that names the map is refused')) return;
  prepare();
  const r = link(['link', '--policy', 'policy.json', '--root', LAB, '--',
    CC, ...ldFlag(), 'main.o', 'helper.o', '-Wl,-Map=theirs.txt', '-o', 'never.bin']);
  assert.equal(r.status, EXIT_INTEGRITY, `${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /VG-LINK-007/);
  assert.equal(existsSync(join(LAB, 'theirs.txt')), false, 'the caller-named map was never written');
  assert.equal(existsSync(join(LAB, 'never.bin')), false, 'the link did not happen');
});

test('live: the record carries no absolute path', (t) => {
  if (needToolchain(t, 'the record carries no absolute path')) return;
  prepare();
  const record = join(LAB, 'hyg-record.json');
  const r = link(['link', '--policy', 'policy.json', '--root', LAB, '--record', record, '--',
    CC, ...ldFlag(), 'main.o', 'helper.o', '-o', 'hyg.bin']);
  assert.equal(r.status, EXIT_OK, `${r.stdout}\n${r.stderr}`);
  const rec = JSON.parse(readFileSync(record, 'utf8'));
  delete rec.context; // context is recorded, never digested, and may name the host
  const text = JSON.stringify(rec);
  assert.equal(/"\/[A-Za-z]/.test(text), false, 'an absolute path reached the record');
  assert.equal(/[A-Za-z]:[\\/]/.test(text), false, 'a drive-lettered path reached the record');
});

test('the skip roster is reported, so a green tick cannot hide an empty run', () => {
  if (CC) {
    assert.deepEqual(skippedByName, [], 'a toolchain was found, so nothing should have been skipped');
    console.log(`live suite ran against ${CC}${usesLld ? ' with lld' : ' with the default linker'}`);
    return;
  }
  assert.ok(allowSkip, `no toolchain and ${ALLOW_SKIP_VAR} unset: the cases above have already failed`);
  console.log(`live suite SKIPPED, authorised by ${ALLOW_SKIP_VAR}. Cases not run (${skippedByName.length}):`);
  for (const name of skippedByName) console.log(`  - ${name}`);
  assert.ok(skippedByName.length > 0, 'the skip roster is empty, which means the roster is not being filled');
});
