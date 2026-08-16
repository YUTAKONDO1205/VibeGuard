// Fixture construction for the driver's tests. Not a test file itself —
// `node --test` only picks up `*.test.mjs`.
//
// Scratch goes to ~/vg-lab/driver/test-scratch, not to the system temp
// directory. WSL's /tmp is emptied between sessions and a measurement that
// disappears half way through reads as an incompatibility rather than as a
// missing directory; that has cost time here before.

import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const DRIVER_DIR = resolve(HERE, '..');
export const CC_BIN = join(DRIVER_DIR, 'cli', 'vgcc.mjs');
export const CXX_BIN = join(DRIVER_DIR, 'cli', 'vg++.mjs');

/** The property observer the fallback tests hand to `--vg-observer`. */
export const OBSERVER_FIXTURE = join(HERE, 'observer-fixture.mjs');

export const SCRATCH_ROOT = process.env.VG_DRIVER_TEST_SCRATCH
  ?? join(homedir(), 'vg-lab', 'driver', 'test-scratch');

export function whichOrNull(name) {
  try {
    const p = execFileSync('sh', ['-c', `command -v ${JSON.stringify(name)}`], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    return p || null;
  } catch {
    return null;
  }
}

export const CLANG = process.platform === 'linux' ? whichOrNull('clang-18') : null;
export const CLANGXX = process.platform === 'linux' ? whichOrNull('clang++-18') : null;

/**
 * Reason to skip, or `undefined` when the toolchain for a live build is here.
 *
 * `undefined` and not `null`: node:test in Node 18 skips on `{ skip: null }`
 * — the check is for the property being present, not for it being truthy. That
 * turned every live test in this suite into `# SKIP` while the run stayed
 * green, which is the same failure the driver itself exists to prevent, one
 * level up. If this ever reads `null` again, 26 tests stop running and nothing
 * says so.
 */
export function liveBuildSkipReason() {
  if (process.platform !== 'linux') return `needs a linux toolchain; this is ${process.platform}`;
  if (!CLANG) return 'clang-18 is not on PATH';
  return undefined;
}

export function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export function makeScratch(label) {
  mkdirSync(SCRATCH_ROOT, { recursive: true });
  return mkdtempSync(join(SCRATCH_ROOT, `${label}-`));
}

export const HELLO_C = `#include <stdio.h>
#include <string.h>

/* A control effect that cannot be optimised away, so that "the build produced
   nothing" is distinguishable from "the build produced nothing interesting".
   interfaces.md section 4. */
int control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p) n += (unsigned char)*p;
  return n;
}

int main(void) {
  char buf[32];
  memset(buf, 0, sizeof buf);
  snprintf(buf, sizeof buf, "hello");
  printf("%s %d\\n", buf, control_sum(buf));
  return 0;
}
`;

/**
 * The fallback fixture. Two effects, measured on clang-18 (Ubuntu 1:18.1.3):
 *
 *   | level | `@vg_authorize` call sites | `@vg_control_sum` call sites |
 *   |-------|---------------------------|------------------------------|
 *   | -O0   | 1                         | 1                            |
 *   | -O1   | 0  (inlined away)         | 1                            |
 *   | -O2   | 0  (inlined away)         | 1                            |
 *
 * That is what makes both fallback controls real rather than staged: a build at
 * -O2 genuinely loses the guarded call, a recompile at -O0 genuinely brings it
 * back, and a recompile at -O1 genuinely does not. `noinline` on the control is
 * load-bearing — without it the control is inlined at -O1 too and the observer
 * would be reporting from an instrument that had itself been optimised away.
 */
export const GUARD_C = `/* A control effect that survives every level, so that "the property is gone"
   is distinguishable from "the measurement is gone". interfaces.md section 4. */
__attribute__((noinline)) int vg_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p) n += (unsigned char)*p;
  return n;
}

/* The guarded call. static, small, and therefore inlined out of existence at
   -O1 and above: the call site the policy asks to survive does not. */
static int vg_authorize(int uid) { return uid == 0; }

int open_vault(int uid, const char *tag) {
  if (!vg_authorize(uid)) return -1;
  return vg_control_sum(tag);
}
`;

export function makePin({ cc = CLANG, cxx = CLANGXX } = {}) {
  const packages = [];
  for (const [name, path] of [['clang-18', cc], ['clang++-18', cxx]]) {
    if (!path) continue;
    packages.push({
      name,
      path: path.replace(/^\//, ''),
      sha256: sha256File(path),
      version: null,
    });
  }
  const versionText = execFileSync(cc, ['--version'], { encoding: 'utf8' });
  const clang = /clang version (\d+\.\d+\.\d+)/.exec(versionText)?.[1] ?? null;
  return {
    pinVersion: 'toolchain-pin-v0',
    clang,
    root: '/',
    drivers: { cc: cc.replace(/^\//, ''), cxx: (cxx ?? cc).replace(/^\//, '') },
    packages,
  };
}

/**
 * A fixture directory holding hello.c, a pin, a policy, and an evidence
 * directory that is a sibling of the policy rather than under compiler/.
 */
export function makeFixture(label, policyOverrides = {}) {
  const dir = makeScratch(label);
  const src = join(dir, 'src');
  const evidence = join(dir, 'evidence');
  mkdirSync(src, { recursive: true });
  mkdirSync(evidence, { recursive: true });

  writeFileSync(join(src, 'hello.c'), HELLO_C, 'utf8');
  writeFileSync(join(src, 'guard.c'), GUARD_C, 'utf8');
  if (CLANG) writeFileSync(join(src, 'toolchain.pin.json'), `${JSON.stringify(makePin(), null, 2)}\n`, 'utf8');

  const policy = {
    policyVersion: 'policy-v0',
    failOn: 'high',
    verification: { failOnIncomplete: true },
    toolchain: {
      pin: 'toolchain.pin.json',
      requireDigestMatch: true,
      allowedPassPlugins: [],
      allowedFrontendPlugins: [],
    },
    flags: { required: [], forbidden: ['-fno-stack-protector'], optLevels: ['-O2'] },
    evidence: { out: '../evidence', sourceDateEpoch: 1700000000 },
    ...policyOverrides,
  };
  writeFileSync(join(src, '.vgpolicy.json'), `${JSON.stringify(policy, null, 2)}\n`, 'utf8');

  return {
    dir,
    src,
    evidence,
    policyPath: join(src, '.vgpolicy.json'),
    pinPath: join(src, 'toolchain.pin.json'),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/**
 * Run the driver as a subprocess, the way a build system would — so that what
 * is under test is the exit code the process actually leaves behind, not the
 * number an exported function returned.
 */
export function runDriver(argv, { cwd, bin = CC_BIN, env = {} } = {}) {
  const r = spawnSync(process.execPath, [bin, ...argv], {
    cwd,
    env: { ...process.env, ...env },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '', error: r.error ?? null };
}

/** Plain clang, same arguments, for the byte-for-byte comparison. */
export function runClang(argv, { cwd, bin = CLANG } = {}) {
  const r = spawnSync(bin, argv, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/**
 * Reason to skip a test that needs a file the operating system will execute,
 * or `undefined` when one can be made here.
 *
 * Node refuses to spawn a `.cmd`/`.bat` without a shell (EINVAL), and there is
 * no way to author a PE executable from a test, so a *convincing* fake compiler
 * — one that answers `--version` — only exists on a POSIX host. Everything the
 * fake is there to demonstrate is also covered by a cross-platform test that
 * injects the version probe, so this skip removes a duplicate rather than a
 * check; the pair is named in the test titles.
 */
export function posixFakeCompilerSkipReason() {
  if (process.platform === 'win32') return 'needs a file the OS will exec; win32 cannot make one from a test';
  return undefined;
}

/**
 * A stand-in compiler. On POSIX it is a real script that prints `versionText`;
 * on Windows it is an inert file, because the driver's pin reconciliation
 * refuses it before anything is spawned and the version probe swallows the
 * spawn error.
 */
export function writeFakeCompiler(dir, name, versionText = 'clang version 18.1.3 (fake)') {
  const p = join(dir, name);
  // The name goes into the bytes so that two fakes are never byte-identical by
  // accident. A test that means to show "same digest, different file" says so
  // itself by copying one; it must not get that for free here.
  if (process.platform === 'win32') {
    writeFileSync(p, `not an executable: ${name}\n${versionText}\n`, 'utf8');
    return p;
  }
  writeFileSync(p, `#!/bin/sh\n# ${name}\nprintf '%s\\n' ${JSON.stringify(versionText)}\n`, 'utf8');
  chmodSync(p, 0o755);
  return p;
}

/** A pin over files this test made, so that no real toolchain is needed. */
export function makeSyntheticPin(dir, files, extra = {}) {
  return {
    pinVersion: 'toolchain-pin-v0',
    root: dir,
    drivers: { cc: files[0].name, cxx: files[0].name },
    packages: files.map((f) => ({
      name: f.name,
      path: f.name,
      sha256: sha256File(join(dir, f.name)),
      version: f.version ?? null,
    })),
    ...extra,
  };
}

/** Evidence records the driver has written into `<evidenceDir>/driver`. */
export function evidenceRecords(evidenceDir) {
  const dir = join(evidenceDir, 'driver');
  let names;
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  return names
    .filter((n) => n.startsWith('driver-') && n.endsWith('.json'))
    .map((n) => ({ name: n, path: join(dir, n), record: JSON.parse(readFileSync(join(dir, n), 'utf8')) }));
}
