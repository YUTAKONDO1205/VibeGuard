// Tests for run-artefact-policy.mjs and lib/artefact-set.mjs — the runner that
// applies one policy to a set of artefacts by calling ../artefact-require.mjs.
//
//   node --test compiler/elf-verifier/test/
//
// WHAT IS ASSERTED WHERE, AND WHY THE SPLIT MATTERS
//
//   SELECTION   lib/artefact-set.mjs, unit-tested against real files in a temp
//               directory. No fixture matrix needed. This is the half that
//               fails SILENTLY when it is wrong — a dropped file is a file the
//               policy never sees — so it is tested without depending on a
//               git-ignored fixture set that a clean checkout does not have.
//
//   AGGREGATION the runner, driven as a subprocess. The cases that need no
//               matrix (empty directory, absent directory, absent policy,
//               usage errors) run everywhere; the ones that need real binaries
//               are skipped by name and the skip is printed, never green.
//
// THE CASE THIS FILE EXISTS FOR is `an absent artefact directory is exit 3`.
// The 23-row matrix is git-ignored. On a clean checkout the runner's normal
// state is "nothing to inspect", and the only wrong answer that would go
// unnoticed is exit 0.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

import { looksLikeElf64Lsb, collectArtefacts } from '../lib/artefact-set.mjs';
import { RANK, worse } from '../run-artefact-policy.mjs';
import { cleanPie } from './synth-elf64.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const RUNNER = join(HERE, '..', 'run-artefact-policy.mjs');

const CONTROL = 'artefact-control-string-always-present';
// The planted marker, referred to by its non-secret half on purpose: the
// secret-shaped literal is allowlisted for ../artefact-fixtures.sh and the
// artifact-integrity suites only, and a copy here would be a new finding in a
// file whose job is not to hold one. The suffix is in the same string constant
// in the same fixture source, so it selects the same images.
const RESIDUE = '-artefact-residue-marker';

const MATRIX = (() => {
  const candidates = [
    process.env.VG_ART_MATRIX,
    join(HERE, '..', '_results', 'artefact-matrix', 'bin'),
  ].filter(Boolean);
  for (const c of candidates) if (existsSync(c)) return c;
  return null;
})();

const skipReal = MATRIX
  ? false
  : 'no fixture matrix. Build it with `bash compiler/elf-verifier/artefact-fixtures.sh ' +
    '<workdir>` and copy <workdir>/bin to compiler/elf-verifier/_results/artefact-matrix/bin, ' +
    'or set VG_ART_MATRIX. A skip here is NOT a pass.';

let TMP;
before(() => { TMP = mkdtempSync(join(tmpdir(), 'vg-artpol-')); });
after(() => { if (TMP) rmSync(TMP, { recursive: true, force: true }); });

function policyFile(name, artifact, failOn = 'medium') {
  const p = join(TMP, name);
  writeFileSync(p, JSON.stringify({ failOn, artifact }));
  return p;
}

function run(args) {
  const r = spawnSync(process.execPath, [RUNNER, ...args], { encoding: 'utf8' });
  assert.equal(r.error, undefined, `spawn failed: ${r.error?.message}`);
  return { code: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** `artefacts=N inspected=N skipped=N findings=N incomplete=N`, as numbers. */
function counts(stdout) {
  const m = stdout.match(
    /artefacts=(\d+) inspected=(\d+) skipped=(\d+) findings=(\d+) incomplete=(\d+)/);
  assert.ok(m, `the counting line is missing from:\n${stdout}`);
  return {
    artefacts: Number(m[1]), inspected: Number(m[2]), skipped: Number(m[3]),
    findings: Number(m[4]), incomplete: Number(m[5]),
  };
}

// ════════════════════════════════════════════════════════════════════════════
// SELECTION — the half that is silent when it is wrong
// ════════════════════════════════════════════════════════════════════════════

describe('looksLikeElf64Lsb', () => {
  test('a synthetic ELF64 LSB image is accepted', () => {
    const p = join(TMP, 'good.elf');
    writeFileSync(p, cleanPie());
    assert.deepEqual(looksLikeElf64Lsb(p), { ok: true, reason: null });
  });

  test('a text file is refused, naming e_ident', () => {
    const p = join(TMP, 'prose.txt');
    writeFileSync(p, 'this is not an ELF image, it is a sentence.\n');
    const r = looksLikeElf64Lsb(p);
    assert.equal(r.ok, false);
    assert.match(r.reason, /no ELF magic in e_ident/);
  });

  test('a file shorter than e_ident is refused with its length', () => {
    const p = join(TMP, 'stub');
    writeFileSync(p, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
    const r = looksLikeElf64Lsb(p);
    assert.equal(r.ok, false);
    assert.match(r.reason, /shorter than an ELF e_ident \(4 bytes\)/);
  });

  test('ELF32 and big-endian are refused by the byte that decided it', () => {
    // Both carry ELF magic. A magic-only filter would hand them to a reader
    // that only parses ELF64 LSB, and the run would fill with exit 3.
    const b32 = Buffer.from(cleanPie().subarray(0, 64));
    b32[4] = 1; // EI_CLASS = ELFCLASS32
    const p32 = join(TMP, 'elf32');
    writeFileSync(p32, b32);
    assert.match(looksLikeElf64Lsb(p32).reason, /EI_CLASS\]=1/);

    const bbe = Buffer.from(cleanPie().subarray(0, 64));
    bbe[5] = 2; // EI_DATA = ELFDATA2MSB
    const pbe = join(TMP, 'elfbe');
    writeFileSync(pbe, bbe);
    assert.match(looksLikeElf64Lsb(pbe).reason, /EI_DATA\]=2/);
  });

  test('a path that is not there is a reason, not a throw', () => {
    const r = looksLikeElf64Lsb(join(TMP, 'no-such-file'));
    assert.equal(r.ok, false);
    assert.match(r.reason, /cannot open/);
  });
});

describe('collectArtefacts', () => {
  let dir;
  before(() => {
    dir = join(TMP, 'build-output');
    mkdirSync(join(dir, 'subdir'), { recursive: true });
    writeFileSync(join(dir, 'a.out'), cleanPie());
    writeFileSync(join(dir, 'lib.so'), cleanPie());
    writeFileSync(join(dir, 'build.log'), 'linking...\n');
    writeFileSync(join(dir, 'subdir', 'nested.out'), cleanPie());
  });

  test('a directory splits into ELF64 LSB images and named skips', () => {
    const r = collectArtefacts({ dirs: [dir] });
    assert.deepEqual(r.selected.map((s) => s.path.replace(/.*[\\/]/, '')).sort(),
      ['a.out', 'lib.so']);
    assert.deepEqual(r.problems, []);
    const whys = Object.fromEntries(r.skipped.map((s) => [s.path.replace(/.*[\\/]/, ''), s.why]));
    assert.match(whys['build.log'], /no ELF magic/);
    assert.match(whys.subdir, /does not recurse/);
  });

  test('nothing is dropped anonymously: selected + skipped covers every entry', () => {
    // The regression this guards is the one that cannot be seen in the exit
    // code: a file quietly missing from both lists is a file the policy never
    // saw, on a run that still prints findings=0.
    const r = collectArtefacts({ dirs: [dir] });
    assert.equal(r.selected.length + r.skipped.length, 4);
  });

  test('a named artefact is NOT filtered — it reaches the checker whatever it holds', () => {
    const r = collectArtefacts({ artifacts: [join(dir, 'build.log')] });
    assert.equal(r.selected.length, 1);
    assert.equal(r.selected[0].source, 'named');
    assert.deepEqual(r.skipped, []);
  });

  test('a named artefact that is absent is a problem, never a skip', () => {
    const r = collectArtefacts({ artifacts: [join(dir, 'never-built')] });
    assert.deepEqual(r.selected, []);
    assert.deepEqual(r.skipped, []);
    assert.equal(r.problems.length, 1);
    assert.match(r.problems[0], /not present/);
  });

  test('an absent directory is a problem that says it scanned nothing', () => {
    const r = collectArtefacts({ dirs: [join(TMP, 'no-such-dir')] });
    assert.equal(r.problems.length, 1);
    assert.match(r.problems[0], /not present/);
    assert.match(r.problems[0], /not the same as having scanned it and found nothing/);
  });

  test('an empty directory is a problem, not a clean scan of zero files', () => {
    const empty = join(TMP, 'empty-build');
    mkdirSync(empty, { recursive: true });
    const r = collectArtefacts({ dirs: [empty] });
    assert.deepEqual(r.selected, []);
    assert.equal(r.problems.length, 1);
    assert.match(r.problems[0], /no regular files/);
  });

  test('the same path named twice and scanned once is inspected once', () => {
    const r = collectArtefacts({ dirs: [dir], artifacts: [join(dir, 'a.out')] });
    const paths = r.selected.map((s) => s.path);
    assert.equal(new Set(paths).size, paths.length);
    assert.equal(paths.length, 2);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// AGGREGATION — the precedence over the codes the children returned
// ════════════════════════════════════════════════════════════════════════════

describe('exit-code precedence', () => {
  test('a finding outranks an incomplete check, and 3 never collapses into 0', () => {
    // exitCodeFor's own rule, one level up: a finding is a thing that was seen.
    assert.equal(worse(3, 2), 2);
    assert.equal(worse(2, 3), 2);
    assert.equal(worse(0, 3), 3);
    assert.equal(worse(3, 0), 3);
  });

  test('integrity outranks everything and a usage error outranks a finding', () => {
    assert.equal(worse(2, 4), 4);
    assert.equal(worse(4, 2), 4);
    assert.equal(worse(2, 1), 1);
  });

  test('the rank table is a total order over the five shared codes', () => {
    // Pinned rather than derived: `worse` is symmetric in its two arguments
    // only if the ranks are distinct, and two codes sharing a rank would make
    // the aggregate depend on the order the artefacts happened to be read in.
    const ranks = Object.values(RANK);
    assert.equal(new Set(ranks).size, ranks.length);
    assert.deepEqual(Object.keys(RANK).sort(), ['0', '1', '2', '3', '4']);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// THE RUNNER, as a process. These need no fixture matrix.
// ════════════════════════════════════════════════════════════════════════════

describe('run-artefact-policy: the cases a clean checkout hits', () => {
  test('an absent artefact directory is exit 3 and says nothing was inspected', () => {
    const p = policyFile('absent-dir.json', { require: ['pie'], expectStrings: [CONTROL] });
    const r = run(['--policy', p, '--dir', join(TMP, 'no-such-dir')]);
    assert.equal(r.code, 3, r.stdout);
    assert.match(r.stdout, /no artefact was inspected/);
    assert.deepEqual(counts(r.stdout), {
      artefacts: 0, inspected: 0, skipped: 0, findings: 0, incomplete: 2,
    });
  });

  test('a directory of non-ELF files is exit 3, and every file is named', () => {
    const d = join(TMP, 'no-elf-here');
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, 'build.log'), 'linking a.out from 3 objects\n');
    writeFileSync(join(d, 'manifest.json'), '{ "outputs": ["a.out"] }\n');
    const p = policyFile('no-elf.json', { require: ['pie'], expectStrings: [CONTROL] });
    const r = run(['--policy', p, '--dir', d]);
    assert.equal(r.code, 3, r.stdout);
    const c = counts(r.stdout);
    assert.equal(c.artefacts, 2);
    assert.equal(c.inspected, 0);
    assert.equal(c.skipped, 2);
    assert.match(r.stdout, /build\.log — no ELF magic/);
    assert.match(r.stdout, /manifest\.json — no ELF magic/);
    assert.match(r.stdout, /a skip is not a pass/);
  });

  test('a policy file that is not there is exit 4, before anything is read', () => {
    const r = run(['--policy', join(TMP, 'no-such-policy.json'), '--dir', TMP]);
    assert.equal(r.code, 4, r.stdout + r.stderr);
    assert.match(r.stderr, /policy not found/);
  });

  test('no --dir and no --artifact is a usage error, not an empty pass', () => {
    const p = policyFile('nowhere.json', { require: ['pie'], expectStrings: [CONTROL] });
    const r = run(['--policy', p]);
    assert.equal(r.code, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /nothing to check/);
  });

  test('no --policy is a usage error', () => {
    const r = run(['--dir', TMP]);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /--policy is required/);
  });

  test('an unknown option is a usage error, never a silent default', () => {
    const p = policyFile('unknown-opt.json', { require: ['pie'], expectStrings: [CONTROL] });
    const r = run(['--policy', p, '--dir', TMP, '--allow-empty']);
    assert.equal(r.code, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /unknown option --allow-empty/);
  });

  test('a synthetic ELF the checker cannot use is exit 3, not exit 0', () => {
    // cleanPie() parses, so this is not the unreadable case; it is an image
    // with no control string in it, which makes the scan BROKEN.
    const d = join(TMP, 'synth-only');
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, 'synth.out'), cleanPie());
    const p = policyFile('synth.json', { require: [], forbidStrings: [RESIDUE], expectStrings: [CONTROL] });
    const r = run(['--policy', p, '--dir', d]);
    assert.equal(r.code, 3, r.stdout);
    assert.match(r.stdout, /scan is BROKEN/);
    assert.equal(counts(r.stdout).inspected, 1);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// THE RUNNER over the 23 real binaries
// ════════════════════════════════════════════════════════════════════════════

describe('run-artefact-policy: the fixture matrix', () => {
  test('REAL: the whole matrix under the shipped policy is exit 2 and inspects all 23',
    { skip: skipReal }, () => {
      const p = join(HERE, '..', 'artefact-policy.matrix.json');
      const r = run(['--policy', p, '--dir', MATRIX]);
      assert.equal(r.code, 2, r.stdout);
      const c = counts(r.stdout);
      assert.equal(c.artefacts, 23);
      assert.equal(c.inspected, 23);
      assert.equal(c.skipped, 0);
      assert.ok(c.findings > 0, 'a run over the unhardened rows with no findings is not a pass');
      // The two rows built from other sources carry neither string, so their
      // scans are BROKEN — reported as incomplete, and the exit code is still 2
      // because a finding elsewhere outranks it.
      assert.match(r.stdout, /libshared\.so: forbidden-string scan is BROKEN/);
      assert.match(r.stdout, /wx-on: forbidden-string scan is BROKEN/);
    });

  test('REAL: the hardened row alone satisfies the four decidable requirements — exit 0',
    { skip: skipReal }, () => {
      // The runner's success path, demonstrated on a real binary. NOTE what
      // this does NOT show: the policy configures no forbidden string, so
      // `scan=CLEAN` here is a live control with nothing to look for. The
      // satisfied case of the byte scan — a live control, a forbidden string
      // configured, and no hit — is still unmeasured, because every image in
      // the matrix that carries the control also carries the marker. See
      // compiler/schema/properties.json, _notAnExtractor.artifactByteScan.
      const p = policyFile('hardened-only.json', {
        require: ['pie', 'nx', 'relro-full', 'no-writable-executable-section'],
        forbidStrings: [],
        expectStrings: [CONTROL],
      });
      const r = run(['--policy', p, '--artifact', join(MATRIX, 'hardened')]);
      assert.equal(r.code, 0, r.stdout);
      assert.deepEqual(counts(r.stdout), {
        artefacts: 1, inspected: 1, skipped: 0, findings: 0, incomplete: 0,
      });
      assert.match(r.stdout, /OK\s+hardened\s+exit=0/);
    });

  test('REAL: one unhardened row among passing ones drags the whole run to exit 2',
    { skip: skipReal }, () => {
      const p = policyFile('mixed.json', {
        require: ['pie', 'nx', 'relro-full'],
        forbidStrings: [],
        expectStrings: [CONTROL],
      });
      const r = run(['--policy', p,
        '--artifact', join(MATRIX, 'hardened'),
        '--artifact', join(MATRIX, 'unhardened')]);
      assert.equal(r.code, 2, r.stdout);
      assert.equal(counts(r.stdout).inspected, 2);
      assert.match(r.stdout, /OK\s+hardened/);
      assert.match(r.stdout, /FINDINGS\s+unhardened.*VG-ART-003/);
    });

  test('REAL: a requirement compiler/ cannot decide is exit 3 for the run, not a pass',
    { skip: skipReal }, () => {
      const p = policyFile('unsupported.json', {
        require: ['pie', 'stack-protector'],
        forbidStrings: [],
        expectStrings: [CONTROL],
      });
      const r = run(['--policy', p, '--artifact', join(MATRIX, 'hardened')]);
      assert.equal(r.code, 3, r.stdout);
      assert.match(r.stdout, /stack-protector: required by the policy and NOT CHECKED here/);
    });

  test('REAL: a malformed policy stops the run at the first artefact — exit 4, inspected=0',
    { skip: skipReal }, () => {
      // expectStrings as a scalar. artefact-require.mjs refuses it; the runner
      // does not re-parse the policy, so this is the child's judgement arriving
      // through the runner unchanged.
      const p = join(TMP, 'scalar-expect.json');
      writeFileSync(p, JSON.stringify({
        failOn: 'medium',
        artifact: { require: ['pie'], forbidStrings: [RESIDUE], expectStrings: CONTROL },
      }));
      const r = run(['--policy', p, '--dir', MATRIX]);
      assert.equal(r.code, 4, r.stdout);
      const c = counts(r.stdout);
      assert.equal(c.artefacts, 23, 'the artefacts were selected before the policy was refused');
      assert.equal(c.inspected, 0, 'exit 4 is a verdict about the policy, not about an image');
      assert.match(r.stdout, /must be an array/);
      assert.match(r.stdout, /nothing else runs/);
    });

  test('REAL: the --json record agrees with what was printed', { skip: skipReal }, () => {
    const p = join(HERE, '..', 'artefact-policy.matrix.json');
    const out = join(TMP, 'record.json');
    const r = run(['--policy', p, '--dir', MATRIX, '--json', out]);
    const rec = JSON.parse(readFileSync(out, 'utf8'));
    const c = counts(r.stdout);
    assert.equal(rec.recordType, 'artefact-policy-run');
    assert.equal(rec.exitCode, r.code);
    assert.deepEqual(rec.counts, {
      artefacts: c.artefacts, inspected: c.inspected, skipped: c.skipped,
      findings: c.findings, incomplete: c.incomplete,
    });
    assert.equal(rec.artefacts.length, 23);
    assert.equal(rec.context.host, 'redacted-by-policy');
    // Every inspected row carries the four properties the policy asked about.
    for (const a of rec.artefacts) {
      assert.ok(a.properties, `${a.path} has no properties block`);
      assert.ok(['PRESENT', 'ABSENT', 'NOT_APPLICABLE', 'NOT_OBSERVED'].includes(a.properties.pie));
      assert.ok(['none', 'partial', 'full'].includes(a.properties.relro));
    }
  });

  test('REAL: --fail-on is forwarded — the same three findings pass at critical and fail at high',
    { skip: skipReal }, () => {
      // The flag is not interpreted here; it is handed to each child, which
      // applies it in `exitCodeFor`. Asserted in both directions because a
      // forwarding bug that dropped the flag would leave the `high` case
      // passing and only the `critical` case wrong — and the wrong one is the
      // one that reports 0.
      const p = policyFile('failon.json', {
        require: ['pie', 'nx', 'relro-full'],
        forbidStrings: [],
        expectStrings: [CONTROL],
      });
      const at = (sev) => run(['--policy', p, '--fail-on', sev,
        '--artifact', join(MATRIX, 'unhardened')]);

      const high = at('high');
      assert.equal(high.code, 2, high.stdout);
      assert.equal(counts(high.stdout).findings, 3);

      const critical = at('critical');
      assert.equal(critical.code, 0, critical.stdout);
      // The findings are still counted and printed. Raising the threshold
      // changes the exit code, never whether the run looked.
      assert.equal(counts(critical.stdout).findings, 3);
    });

  test('REAL: the run finds the writable-executable section on wx-on', { skip: skipReal }, () => {
    const p = policyFile('wx.json', {
      require: ['no-writable-executable-section'],
      forbidStrings: [],
      expectStrings: [],
    });
    const r = run(['--policy', p, '--artifact', join(MATRIX, 'wx-on'), '--verbose']);
    assert.equal(r.code, 2, r.stdout);
    assert.match(r.stdout, /VG-ART-004/);
    assert.match(r.stdout, /\.vgwx/);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// This suite refuses to report green for a run that examined nothing real
// ════════════════════════════════════════════════════════════════════════════

describe('coverage of this run', () => {
  test('the real-binary cases either ran or are named as skipped', () => {
    if (!MATRIX) {
      assert.notEqual(process.env.VG_ART_MATRIX_REQUIRED, '1',
        'VG_ART_MATRIX_REQUIRED=1 was set and no fixture matrix was found. ' + skipReal);
      process.stdout.write(`# NOTE: the 7 real-binary cases in artefact-policy-run.test.mjs were SKIPPED. ${skipReal}\n`);
      return;
    }
    assert.ok(existsSync(join(MATRIX, 'hardened')), 'the matrix exists but has no hardened row');
    assert.ok(existsSync(join(MATRIX, 'wx-on')), 'the matrix exists but has no wx-on row');
  });

  test('the policy this repository ships for the matrix is the one the tests used', () => {
    // A policy file that drifted from what the suite asserts would leave the
    // documented command doing something no test covers.
    const p = JSON.parse(readFileSync(join(HERE, '..', 'artefact-policy.matrix.json'), 'utf8'));
    assert.deepEqual(p.artifact.require,
      ['pie', 'nx', 'relro-full', 'no-writable-executable-section']);
    assert.deepEqual(p.artifact.expectStrings, [CONTROL]);
    assert.deepEqual(p.artifact.forbidStrings, [RESIDUE]);
  });
});
