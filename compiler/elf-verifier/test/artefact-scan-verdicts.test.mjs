// The three verdicts of the byte scan, each one measured against a real
// linked artefact.
//
//   node --test compiler/elf-verifier/test/artefact-scan-verdicts.test.mjs
//
// WHY THIS FILE EXISTS. `scanBytes` has three answers -- CLEAN, HITS, BROKEN
// -- and until 2026-09-14 the fixture matrix could only produce two of them.
// Every image built from fixture.c carries the control string AND the
// forbidden marker, so those rows are HITS by construction; the two rows built
// from wx.c and lib.c carry neither, so those are BROKEN by construction.
// Nothing in the matrix held the control and lacked the marker, which is the
// only shape that yields CLEAN. The satisfied case of a residue scan -- a live
// control, a forbidden string configured, and no hit -- had therefore never
// been observed on a real binary, and that is the reason the string-shaped
// must-not-appear entries in compiler/schema/properties.json stand at
// unimplemented with the FIXTURES named as the obstacle rather than the code.
// ../artefact-fixtures.sh now builds a `clean` row and this file reads it.
//
// WHAT A GREEN RUN HERE IS WORTH, and what it is not. It shows the scanner
// separates three real artefacts that differ in the way the verdicts are
// defined to differ. It does NOT show the scanner would find a secret nobody
// planted, and no assertion below claims it does: the needle is planted by the
// fixture generator and the clean row is the same translation unit with the
// planted line deleted.
//
// SKIP IS NOT PASS. Without gcc (and with no prebuilt matrix) these cases
// FAIL. VG_ART_ALLOW_SKIP=1 authorises the skip and names the case. This is
// deliberately stricter than the ../test/artifact-policy.test.mjs convention,
// where the real-binary cases skip by default: those need the whole 24-row
// matrix and a `-static` libc, this needs four invocations of cc over three
// sources that are read out of the generator, so "the fixtures are not here"
// is not a reason to prove nothing.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { readElf } from '../lib/elf.mjs';
import { scanBytes } from '../lib/artifact-policy.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '..', 'artefact-require.mjs');
const GENERATOR = join(HERE, '..', 'artefact-fixtures.sh');
const GENERATOR_TEXT = readFileSync(GENERATOR, 'utf8');

const CONTROL = 'artefact-control-string-always-present';
// The planted marker, named by its non-secret half, as in
// ./artefact-policy-run.test.mjs: the credential-shaped literal is allowlisted
// for the generator and the artifact-integrity suites only, and a copy here
// would be a new finding in a file whose job is not to hold one. The suffix
// belongs to the same string constant in the same source, so it selects the
// same bytes. It is also exactly what ../artefact-policy.matrix.json forbids.
const RESIDUE = '-artefact-residue-marker';

const REQUIREMENTS = 'pie,nx,relro-full,no-writable-executable-section';

// ── where the artefacts come from ───────────────────────────────────────────
//
// Two sources, in this order, and the run says which one it used:
//
//   MATRIX  a prebuilt matrix from ../artefact-fixtures.sh, if one is there
//           AND it has the clean row. A matrix built before 2026-09-14 does
//           not, and falling through to a fresh build is the right answer for
//           it -- the alternative is asserting the new verdict against a
//           directory that predates it.
//   BUILT   four rows compiled here from the generator's own sources. The
//           matrix is git-ignored and absent from a clean checkout and from
//           CI, and a file whose every real case skipped there would be
//           measuring nothing in the only place that runs it on every push.

const MATRIX = (() => {
  for (const c of [process.env.VG_ART_MATRIX, join(HERE, '..', '_results', 'artefact-matrix', 'bin')]) {
    if (c && existsSync(join(c, 'clean')) && existsSync(join(c, 'hardened'))) return c;
  }
  return null;
})();

/** One heredoc out of the generator, so the sources cannot drift from it. */
function sourceFromGenerator(name) {
  const m = GENERATOR_TEXT.match(
    new RegExp(`cat > ${name.replace('.', '\\.')} <<'EOF'\\n([\\s\\S]*?)\\nEOF\\n`));
  assert.ok(m, `${name} is no longer written by a heredoc in artefact-fixtures.sh`);
  return m[1];
}

// Copied from the generator rather than parsed out of it: the row lines are
// continued across two lines with a backslash, and a regex that had to survive
// that would be the fragile half of this file. Each row therefore carries the
// generator text it was copied from, checked by the last case in the file --
// which is the direction that matters, because a flag set that drifted would
// leave these builds representing a row the matrix no longer contains and
// nothing else would notice: the byte scan reads none of these flags.
const HARDENED_FLAGS = ['-O2', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2', '-fPIE', '-pie',
  '-Wl,-z,relro,-z,now', '-Wl,-z,noexecstack', '-Wl,--build-id=sha1', '-g0'];
const ROWS = [
  ['clean', 'clean.c', HARDENED_FLAGS,
    'build_src clean.c clean -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie'],
  ['hardened', 'fixture.c', HARDENED_FLAGS,
    'build hardened    -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie'],
  ['unhardened', 'fixture.c',
    ['-O0', '-fno-stack-protector', '-U_FORTIFY_SOURCE', '-fno-pie', '-no-pie',
      '-Wl,-z,norelro', '-Wl,-z,execstack', '-Wl,--build-id=none', '-g'],
    'build unhardened  -O0 -fno-stack-protector -U_FORTIFY_SOURCE -fno-pie -no-pie'],
  // The no-control row. In the matrix this image is re-flagged by objcopy
  // after the link so that `.vgwx` is W+A+X; that is a section-flag question
  // and touches no string, so the build here omits it and the two images are
  // the same artefact as far as a byte scan is concerned.
  ['wx-on', 'wx.c', ['-O2', '-Wl,-z,noexecstack'],
    'gcc -O2 -o "$BIN/wx-on" wx.c -Wl,-z,noexecstack'],
];

function haveCc() {
  for (const cc of ['gcc', 'cc']) {
    const r = spawnSync(cc, ['--version'], { encoding: 'utf8' });
    if (!r.error && r.status === 0) return cc;
  }
  return null;
}

let note = null;
function unavailable() {
  if (note !== null) return note;
  if (MATRIX) note = '';
  else if (haveCc()) note = '';
  else note = 'no prebuilt matrix with a clean row, and no gcc to build one';
  return note;
}

function gate(caseName) {
  if (unavailable() === '') return undefined;
  if (process.env.VG_ART_ALLOW_SKIP !== '1') return undefined;
  // eslint-disable-next-line no-console
  console.log(`SKIPPED CASE: ${caseName} -- ${unavailable()} (authorised by VG_ART_ALLOW_SKIP=1)`);
  return `${caseName}: ${unavailable()}`;
}

function requireArtefacts(caseName) {
  if (unavailable() === '') return;
  assert.fail(
    `${caseName}: ${unavailable()}. This is a failure, not a skip. Build the matrix with `
    + '`bash compiler/elf-verifier/artefact-fixtures.sh <workdir>` and point VG_ART_MATRIX at '
    + '<workdir>/bin, or set VG_ART_ALLOW_SKIP=1 to authorise skipping it.');
}

let bin = null;
/** The four artefacts, built once, and where they came from. */
function artefacts() {
  if (bin) return bin;
  if (MATRIX) {
    bin = { dir: MATRIX, origin: `prebuilt matrix ${MATRIX}` };
    return bin;
  }
  const cc = haveCc();
  assert.ok(cc, 'unavailable() said a compiler was there and it is not');
  const dir = mkdtempSync(join(tmpdir(), 'vg-scan-verdicts-'));
  for (const [name, src, flags] of ROWS) {
    const srcPath = join(dir, src);
    if (!existsSync(srcPath)) writeFileSync(srcPath, `${sourceFromGenerator(src)}\n`);
    const r = spawnSync(cc, ['-o', join(dir, name), srcPath, ...flags], { encoding: 'utf8' });
    // A compiler that is present and cannot build the row is a failure. It is
    // not the absent-toolchain case the skip is for, and reporting it as one
    // would hide a fixture source that stopped compiling.
    assert.equal(r.status, 0, `building ${name} from ${src} failed:\n${r.stderr}`);
  }
  bin = { dir, origin: `built here by ${cc} from the generator's sources` };
  return bin;
}

function artefact(name) {
  const { dir } = artefacts();
  const elf = readElf(join(dir, name));
  assert.ok(elf.supported, `${name}: ${elf.reason ?? 'unreadable'}`);
  return elf;
}

const scan = (name) => scanBytes(artefact(name), { forbid: [RESIDUE], expect: [CONTROL] });

function runCli(args) {
  try {
    return { code: 0, stdout: execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) };
  } catch (e) {
    return { code: e.status, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

// ════════════════════════════════════════════════════════════════════════════
// The three verdicts, on real artefacts
// ════════════════════════════════════════════════════════════════════════════

describe('scanBytes over built artefacts', () => {
  test('REAL: the clean row is CLEAN -- live control, forbidden string configured, no hit', {
    skip: gate('clean row'),
  }, () => {
    requireArtefacts('clean row');
    const r = scan('clean');
    assert.equal(r.verdict, 'CLEAN', JSON.stringify(r.brokenReasons));
    assert.equal(r.broken, false);
    assert.deepEqual(r.hits, []);
    assert.equal(r.unverifiedHits, 0);
    assert.equal(r.controlsChecked, 1);
    assert.equal(r.controls[0].found, true);
    // Without this the case passes on an empty file: zero bytes contain no
    // forbidden sequence either, and the control check is the only thing
    // standing between that and a clean report.
    assert.ok(r.bytesScanned > 1000, `scanned ${r.bytesScanned} bytes`);
  });

  test('REAL: hardened and unhardened are HITS -- the same control, and the marker present', {
    skip: gate('hits rows'),
  }, () => {
    requireArtefacts('hits rows');
    for (const name of ['hardened', 'unhardened']) {
      const r = scan(name);
      assert.equal(r.verdict, 'HITS', `${name}: ${JSON.stringify(r.brokenReasons)}`);
      assert.ok(r.hits.length >= 1, `${name} carries no hit`);
      assert.equal(r.hits[0].needle, RESIDUE);
      assert.equal(r.controls[0].found, true);
      assert.equal(r.unverifiedHits, 0);
    }
  });

  test('REAL: a row with no control is BROKEN, not CLEAN', { skip: gate('broken row') }, () => {
    requireArtefacts('broken row');
    const r = scan('wx-on');
    assert.equal(r.verdict, 'BROKEN');
    assert.deepEqual(r.hits, []);
    assert.equal(r.controls[0].found, false);
    assert.match(r.brokenReasons.join(' '), /control string .* is not in/);
  });

  test('REAL: all three verdicts come from real artefacts in one run', {
    skip: gate('three verdicts'),
  }, () => {
    requireArtefacts('three verdicts');
    // The point of the file in one assertion. A scanner that answered the same
    // thing for every input would satisfy any two of the cases above taken
    // alone -- before the clean row existed, the matrix could only ever
    // exercise two of the three branches, and the missing one was the branch
    // that reports nothing is wrong.
    const seen = ['clean', 'hardened', 'wx-on'].map((n) => `${n}=${scan(n).verdict}`);
    assert.deepEqual(seen, ['clean=CLEAN', 'hardened=HITS', 'wx-on=BROKEN']);
    process.stdout.write(`# artefacts: ${artefacts().origin}\n`);
  });

  test('REAL: clean and hardened differ in the marker and in nothing the control can see', {
    skip: gate('differential'),
  }, () => {
    requireArtefacts('differential');
    // What makes the CLEAN verdict evidence about the artefact rather than
    // about the test's own constants: the two images are built from the same
    // source under the same flags, one with the planted line and one without,
    // and the control is found in both. If a future edit to clean.c dropped
    // the control instead of the secret, this case fails where the CLEAN case
    // above would only turn BROKEN.
    const c = scanBytes(artefact('clean'), { forbid: [RESIDUE], expect: [CONTROL] });
    const h = scanBytes(artefact('hardened'), { forbid: [RESIDUE], expect: [CONTROL] });
    assert.equal(c.controls[0].found, true);
    assert.equal(h.controls[0].found, true);
    assert.equal(c.hits.length, 0);
    assert.ok(h.hits.length > 0);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// The same three verdicts through the command line, where the exit code is
// the thing a build reads
// ════════════════════════════════════════════════════════════════════════════

describe('artefact-require CLI over the clean row', () => {
  test('REAL: clean row, four requirements, a control AND a forbidden string -> exit 0', {
    skip: gate('cli clean'),
  }, () => {
    requireArtefacts('cli clean');
    // THIS is the state that had never been reached. ../artifact-policy.test.mjs
    // already runs the hardened row to exit 0, but with `--forbid` unset, so
    // its `scan=CLEAN` is a control with nothing to look for. Here the scan is
    // asked a question and answers no.
    const r = runCli(['--artifact', join(artefacts().dir, 'clean'),
      '--require', REQUIREMENTS, '--forbid', RESIDUE, '--expect', CONTROL]);
    assert.equal(r.code, 0, r.stdout + (r.stderr ?? ''));
    assert.match(r.stdout, /scan=CLEAN controls=1 hits=0 unverified=0/);
    assert.match(r.stdout, /findings=0 incomplete=0/);
  });

  test('REAL: the same policy against hardened -> exit 2 and VG-ART-005', {
    skip: gate('cli hits'),
  }, () => {
    requireArtefacts('cli hits');
    // The pair matters: a scanner wired to report CLEAN unconditionally would
    // pass the case above on its own.
    const r = runCli(['--artifact', join(artefacts().dir, 'hardened'),
      '--require', REQUIREMENTS, '--forbid', RESIDUE, '--expect', CONTROL]);
    assert.equal(r.code, 2, r.stdout + (r.stderr ?? ''));
    assert.match(r.stdout, /scan=HITS/);
    assert.match(r.stdout, /VG-ART-005/);
  });

  test('REAL: the same policy against a row with no control -> exit 3', {
    skip: gate('cli broken'),
  }, () => {
    requireArtefacts('cli broken');
    const r = runCli(['--artifact', join(artefacts().dir, 'wx-on'),
      '--require', 'nx', '--forbid', RESIDUE, '--expect', CONTROL]);
    assert.equal(r.code, 3, r.stdout + (r.stderr ?? ''));
    assert.match(r.stdout, /scan=BROKEN/);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// This suite refuses to report green for a run that examined nothing real
// ════════════════════════════════════════════════════════════════════════════

describe('coverage of this run', () => {
  test('the real-artefact cases either ran or were authorised to skip', () => {
    if (unavailable() !== '') {
      assert.equal(process.env.VG_ART_ALLOW_SKIP, '1',
        `no artefacts and no authorisation to skip: ${unavailable()}`);
      process.stdout.write(
        `# NOTE: the 8 real-artefact cases in artefact-scan-verdicts.test.mjs were SKIPPED. ${unavailable()}\n`);
      return;
    }
    assert.ok(existsSync(join(artefacts().dir, 'clean')), 'the clean row is not where this run said it was');
  });

  test('the rows built here still match the rows the generator builds', () => {
    for (const [name, , , generatorLine] of ROWS) {
      assert.ok(GENERATOR_TEXT.includes(generatorLine),
        `artefact-fixtures.sh no longer contains the ${name} row as this file builds it:\n  ${generatorLine}`);
    }
    // And the clean source still differs from fixture.c in the one way that is
    // the whole point of it.
    const clean = sourceFromGenerator('clean.c');
    const fixture = sourceFromGenerator('fixture.c');
    assert.ok(clean.includes(CONTROL), 'clean.c lost the control string');
    assert.ok(!clean.includes(RESIDUE), 'clean.c has acquired a forbidden marker');
    assert.ok(fixture.includes(CONTROL) && fixture.includes(RESIDUE),
      'fixture.c no longer carries both strings, so the HITS rows are not what this file assumes');
  });
});
