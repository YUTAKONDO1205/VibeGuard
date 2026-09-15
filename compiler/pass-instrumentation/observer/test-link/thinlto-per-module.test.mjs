// The observer under a link with more than one module.
//
// WHY THIS DIRECTORY EXISTS AT ALL. `../test/` is 22 pure-JS cases over
// `lib/subject-resolution.mjs`; it never loads the .so and it never links, so
// on 2026-09-14, when the plugin stopped keeping a process-global tracker and
// started opening one log per `PassBuilder`, nothing in the observer's own
// suite could have caught a regression of it. The defect that change fixed --
// N ThinLTO backends racing over one OBS_OUT, leaving a file with several
// modules' records spliced together, NUL bytes and lines torn mid-field -- is
// invisible to every test that compiles one translation unit, because a
// compile creates exactly one tracker and so does a full-LTO link. Only
// ThinLTO makes more than one.
//
// WHY IT IS NOT IN `../test/`. That glob is run by `run_suite observer` in
// ci.yml's `native-toolchain` job, which installs clang and no linker. A test
// that needs lld dropped in there turns that job red. The precedent for
// lld-needing suites is `compiler/fingerprint` and `compiler/link-wrapper`,
// which ci.yml runs in `native-plugins` for exactly this reason; this
// directory is named by a step in that job beside them. Moving these files
// into `../test/` without moving the ci.yml step would run them on a machine
// with no linker.
//
// SKIP IS NOT PASS: without clang-18, an lld, and a built plugin these cases
// FAIL. VG_OBS_LINK_ALLOW_SKIP=1 authorises the skip and names the case. The
// plugin is not built here -- it is taken from OBS_PLUGIN, defaulting to the
// same path `scripts/noninvasive.mjs` defaults to, so a run by hand after the
// cmake line in the README needs no environment at all.
//
// WHAT THIS FILE DOES NOT CLAIM. It says nothing about non-invasiveness: that
// is `scripts/noninvasive.mjs`, whose NI-09..NI-11 cover the same ThinLTO
// path, and duplicating a byte-identity assertion here would give two places
// to update and one of them would rot.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import test from 'node:test';

const SKIP_ENV = 'VG_OBS_LINK_ALLOW_SKIP';
const PLUGIN = process.env.OBS_PLUGIN
  || join(homedir(), 'vg-build', 'pass-observer', 'libPropertyObserver.so');

const TARGET_FN = 'handle_request';
const CONTROL_FN = 'wipe_kept';
const EFFECT_SYMBOLS = 'llvm.memset,memset,explicit_bzero,bzero,__memset_chk';

// A subject in each module, which is the point of the fixture: `a.c` holds the
// configured target (a wipe that is the last use of the buffer, so the
// optimiser may delete it) and `b.c` holds the configured control (the same
// wipe, read afterwards, so it cannot be deleted). Neither module is a
// bystander, so neither backend's log can be empty for the boring reason.
const SOURCES = {
  'a.c': `#include <string.h>
void fill_bytes(unsigned char *out, unsigned long n);   /* b.c */
void sink_bytes(const unsigned char *p, unsigned long n); /* b.c */
void wipe_kept(void);                                    /* b.c */

/* Subject: the wipe is the last use, so it is a dead store. */
void handle_request(void) {
    unsigned char secret[32];
    fill_bytes(secret, sizeof secret);
    sink_bytes(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
}

int main(void) { handle_request(); wipe_kept(); return 0; }
`,
  'b.c': `#include <string.h>
volatile unsigned char observable_sink;

void fill_bytes(unsigned char *out, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) out[i] = (unsigned char)(i * 7u + 1u);
}

void sink_bytes(const unsigned char *p, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) observable_sink ^= p[i];
}

/* Control: the wipe is read afterwards, so it survives every level. */
void wipe_kept(void) {
    unsigned char secret[32];
    fill_bytes(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
    sink_bytes(secret, sizeof secret);
}
`,
};

// The arity half of "is this line torn", copied from History.cpp's writers
// rather than imported: this suite is the observer's own and must not depend on
// a lane under compiler/eval. A legal record type in field 0 is not enough --
// that is precisely what a tear mid-line leaves behind -- so the field count is
// checked too. WHAT THIS SILENTLY BREAKS IF A RECORD GROWS A FIELD: every row
// of that type becomes a torn line and this suite goes red, so the table has to
// move in the same change as History.cpp. That is the loud direction, and it is
// the one worth having.
const RECORD_ARITY = Object.freeze({
  HANDSHAKE: 8, SUBJECTRES: 6, PASS: 6, EV: 11, UNIT: 6, SNAP: 6, SKIP: 4,
  SUMMARY: 19, HIST: 8, STATS: 7,
});

function probe(tool, arg) {
  const r = spawnSync(tool, [arg], { encoding: 'utf8' });
  return r.status === 0 ? (r.stdout || '').trim() : null;
}

let missingNote = null;
let linker = null;
function missing() {
  if (missingNote !== null) return missingNote;
  const m = [];
  if (probe('clang-18', '--version') === null) m.push('clang-18');
  // `--ld-path` with a resolved path, not `-fuse-ld=lld`: the lld-18 package
  // installs `ld.lld-18` and the unversioned `ld.lld` is an alternative that
  // may not be set up. Asking for `lld` on such a machine fails at the link and
  // reads like a plugin fault.
  for (const cand of ['ld.lld-18', 'ld.lld']) {
    const where = spawnSync('which', [cand], { encoding: 'utf8' });
    if (where.status === 0 && where.stdout.trim()) { linker = where.stdout.trim().split('\n')[0]; break; }
  }
  if (linker === null) m.push('ld.lld-18 or ld.lld');
  if (!existsSync(PLUGIN)) m.push(`${PLUGIN} (build it, or set OBS_PLUGIN)`);
  missingNote = m.join(', ');
  return missingNote;
}

function gate(caseName) {
  if (missing() === '') return undefined;
  if (process.env[SKIP_ENV] !== '1') return undefined;
  // eslint-disable-next-line no-console
  console.log(`SKIPPED CASE: ${caseName} -- ${missing()} (authorised by ${SKIP_ENV}=1)`);
  return `${caseName}: ${missing()}`;
}

function requireToolchain(caseName) {
  if (missing() === '') return;
  assert.fail(
    `${caseName}: ${missing()}. This is a failure, not a skip. Set `
    + `${SKIP_ENV}=1 to authorise skipping it.`,
  );
}

function run(cmd, args, env = {}) {
  const r = spawnSync(cmd, args, {
    encoding: 'utf8', env: { ...process.env, ...env }, maxBuffer: 32 * 1024 * 1024,
  });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

/** A log, read the way a reader has to read it: bytes first, records second. */
function readLog(logPath) {
  const bytes = readFileSync(logPath);
  let nulBytes = 0;
  for (const b of bytes) if (b === 0) nulBytes++;
  const torn = [];
  const moduleIds = new Set();
  let handshakes = 0;
  let evRecords = 0;
  for (const raw of bytes.toString('utf8').split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (line === '') continue;
    const f = line.split('\t');
    if (!Object.hasOwn(RECORD_ARITY, f[0]) || f.length !== RECORD_ARITY[f[0]]) {
      torn.push(line.slice(0, 120));
      continue;
    }
    if (f[0] === 'HANDSHAKE') { handshakes++; moduleIds.add(f[2]); }
    // `-` is what the writer puts there when no module was ever walked, so it
    // is the absence of a module id and not a second one.
    if (f[0] === 'SUBJECTRES' && f[2] !== '-') moduleIds.add(f[2]);
    if (f[0] === 'EV') evRecords++;
  }
  return { bytes: bytes.length, nulBytes, torn, handshakes, evRecords, moduleIds: [...moduleIds] };
}

let measured = null;

/** Compile, link twice, read once; every case below reads the same run. */
function measure() {
  if (measured) return measured;
  const lab = mkdtempSync(join(tmpdir(), 'vg-obs-thinlto-'));
  const failures = [];
  const cc = (args, env) => {
    const r = run('clang-18', args, env);
    if (r.status !== 0) failures.push(`clang-18 ${args.join(' ')}\n${r.stderr.slice(0, 2000)}`);
    return r;
  };

  for (const [name, text] of Object.entries(SOURCES)) writeFileSync(join(lab, name), text);
  const objects = Object.keys(SOURCES).map((name) => {
    const obj = join(lab, name.replace(/\.c$/, '.o'));
    cc(['-O2', '-flto=thin', '-c', join(lab, name), '-o', obj]);
    return obj;
  });

  // lld's own enumeration of the bitcode modules it took, produced WITHOUT the
  // plugin. This is where the expected backend count comes from: reading it out
  // of the manifest the plugin wrote and then checking the manifest against
  // itself would assert nothing. `--save-temps` writes `<output>.resolution.txt`,
  // in which a line with no `-r=` prefix is one input module; the run is put in
  // its own directory because that flag writes several files beside the output.
  const stDir = join(lab, 'save-temps');
  mkdirSync(stDir, { recursive: true });
  const stOut = join(stDir, 'app');
  cc(['-O2', '-flto=thin', `--ld-path=${linker}`, ...objects, '-o', stOut, '-Wl,--save-temps']);
  const resolution = existsSync(`${stOut}.resolution.txt`)
    ? readFileSync(`${stOut}.resolution.txt`, 'utf8').split('\n')
        .filter((l) => l !== '' && !l.startsWith('-r='))
    : [];

  const obsOut = join(lab, 'obs.tsv');
  const link = cc(['-O2', '-flto=thin', `--ld-path=${linker}`, ...objects,
    '-o', join(lab, 'app.observed'), `-Wl,--load-pass-plugin=${PLUGIN}`], {
    OBS_TARGET_FN: TARGET_FN,
    OBS_CONTROL_FN: CONTROL_FN,
    OBS_EFFECT_SYMBOLS: EFFECT_SYMBOLS,
    OBS_OUT: obsOut,
    OBS_MODE: 'standard',
  });

  // Every file the observer left behind, found by looking rather than by
  // predicting: the suffix is sanitised from the module id and falls back to
  // `module-<index>` past 128 characters, so a test that rebuilt the names
  // would be asserting its own arithmetic.
  const stem = basename(obsOut);
  const produced = readdirSync(lab)
    .filter((f) => f === stem || f.startsWith(`${stem}.`))
    .map((f) => join(lab, f));
  const logs = produced.filter((f) => f.endsWith('.tsv') && !f.endsWith('.summary.tsv'));

  const manifestPath = `${obsOut}.modules`;
  const manifestRaw = existsSync(manifestPath) ? readFileSync(manifestPath, 'utf8') : null;
  const manifest = (manifestRaw ?? '').split('\n').filter((l) => l !== '')
    .map((l) => { const f = l.split('\t'); return { fields: f.length, moduleId: f[0], logPath: f[1] }; });

  measured = {
    lab, failures, linkStatus: link.status, linkStderr: link.stderr,
    objects, obsOut, manifestPath, manifestRaw, manifest,
    produced, logs, backendModules: resolution,
    read: Object.fromEntries(logs.map((p) => [p, readLog(p)])),
  };
  return measured;
}

test.after(() => { if (measured) rmSync(measured.lab, { recursive: true, force: true }); });

test('the ThinLTO link runs, with the plugin loaded into its backends', {
  skip: gate('link'),
}, () => {
  requireToolchain('link');
  const m = measure();
  assert.deepEqual(m.failures, [], m.failures.join('\n'));
  assert.equal(m.linkStatus, 0, m.linkStderr.slice(0, 2000));
  // The count this whole file is about, taken from lld and not from the plugin.
  assert.ok(m.backendModules.length >= 2,
    `the fixture did not produce a multi-module LTO link; lld took ${JSON.stringify(m.backendModules)}`);
});

test('one log per backend module, and a manifest line for each', { skip: gate('logs') }, () => {
  requireToolchain('logs');
  const m = measure();
  const n = m.backendModules.length;
  assert.equal(m.logs.length, n,
    `${n} backend module(s), ${m.logs.length} log(s): ${JSON.stringify(m.produced.map((p) => basename(p)))}`);
  assert.notEqual(m.manifestRaw, null, `no manifest at ${m.manifestPath}`);
  assert.equal(m.manifest.length, n, `manifest:\n${m.manifestRaw}`);
  // The manifest is appended one line at a time under a mutex, so a line with
  // the wrong field count there means what a torn line in a log means.
  assert.deepEqual(m.manifest.filter((l) => l.fields !== 2), []);
  assert.equal(new Set(m.manifest.map((l) => l.moduleId)).size, n,
    `the manifest names the same module twice:\n${m.manifestRaw}`);
});

test('each log carries exactly one HANDSHAKE and names exactly one module', {
  skip: gate('handshake'),
}, () => {
  requireToolchain('handshake');
  const m = measure();
  for (const [p, r] of Object.entries(m.read)) {
    assert.equal(r.handshakes, 1, `${basename(p)}: ${r.handshakes} HANDSHAKE record(s)`);
    assert.deepEqual(r.moduleIds.length, 1,
      `${basename(p)}: module ids ${JSON.stringify(r.moduleIds)}`);
  }
  // Several backends' records spliced into one file is the defect the
  // per-module change removed, and it shows up as one log naming two modules;
  // this says the other half, that no two logs name the SAME module.
  const named = Object.values(m.read).map((r) => r.moduleIds[0]);
  assert.equal(new Set(named).size, named.length, `logs name ${JSON.stringify(named)}`);
  // Non-vacuous: a run in which the observer recorded nothing anywhere would
  // satisfy everything above.
  assert.ok(Object.values(m.read).some((r) => r.evRecords > 0),
    'no log carries an EV record, so nothing here was observed');
});

test('column 2 of each manifest line is the path that was actually opened', {
  skip: gate('manifest paths'),
}, () => {
  requireToolchain('manifest paths');
  const m = measure();
  // This is the property a reader depends on, and the reason it cannot be
  // re-derived: the tracker that claims index 0 keeps the UNSUFFIXED OBS_OUT,
  // and which backend that is, is a race. Measured on 2026-09-15: this
  // two-module link gave it to `a.o`, and the three-unit link that
  // scripts/noninvasive.mjs runs gave it to `opaque.o` three times, `target.o`
  // once and `main.o` once over five runs. So the assertion is that exactly
  // one line carries the stem and the rest carry a suffixed name -- never that
  // a particular module got it.
  const atStem = m.manifest.filter((l) => l.logPath === m.obsOut);
  assert.equal(atStem.length, 1, `lines naming the unsuffixed log:\n${m.manifestRaw}`);

  assert.deepEqual(
    m.manifest.map((l) => l.logPath).sort(),
    [...m.logs].sort(),
    `the manifest does not name the files on disk:\n${m.manifestRaw}`,
  );
  for (const line of m.manifest) {
    assert.ok(existsSync(line.logPath), `${line.moduleId}: no log at ${line.logPath}`);
    assert.deepEqual(m.read[line.logPath].moduleIds, [line.moduleId],
      `${line.logPath} does not belong to ${line.moduleId}`);
  }
});

test('no log carries a NUL byte or a torn line', { skip: gate('integrity') }, () => {
  requireToolchain('integrity');
  const m = measure();
  for (const [p, r] of Object.entries(m.read)) {
    assert.equal(r.nulBytes, 0, `${basename(p)}: ${r.nulBytes} NUL byte(s)`);
    assert.deepEqual(r.torn, [], `${basename(p)}: torn line(s)`);
    // A zero-byte log would pass both of those and mean the open failed.
    assert.ok(r.bytes > 0, `${basename(p)} is empty`);
  }
});
