import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { buildFixtureBundle, scratchDir } from './_fixture.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const BIN = join(HERE, '..', 'bin');

function run(script, args) {
  const r = spawnSync(process.execPath, [join(BIN, script), ...args], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout ?? '', err: r.stderr ?? '' };
}

// ── The counting contract, proved rather than described ─────────────────────

test('verifying an EMPTY directory prints inputs=0 and exits non-zero', () => {
  const scratch = scratchDir('eca-cli-empty-');
  try {
    const empty = join(scratch.dir, 'bundles');
    mkdirSync(empty, { recursive: true });
    const r = run('verify-bundle.mjs', ['--bundles', empty]);
    assert.match(r.out, /^inputs=0 checked=0 skipped=0$/m, r.out + r.err);
    assert.equal(r.code, 3, 'an empty scan is not a clean scan');
    assert.match(r.err, /no bundles found/);
    assert.match(r.err, /--allow-empty/);
  } finally {
    scratch.dispose();
  }
});

test('an empty scan passes only when the caller says so on the command line', () => {
  const scratch = scratchDir('eca-cli-empty-ok-');
  try {
    const empty = join(scratch.dir, 'bundles');
    mkdirSync(empty, { recursive: true });
    const r = run('verify-bundle.mjs', ['--bundles', empty, '--allow-empty']);
    assert.match(r.out, /^inputs=0 checked=0 skipped=0$/m);
    assert.equal(r.code, 0);
  } finally {
    scratch.dispose();
  }
});

test('a clean bundle exits 0, counts itself, and prints its limits', () => {
  const built = buildFixtureBundle({ prefix: 'eca-cli-clean-' });
  try {
    const r = run('verify-bundle.mjs', ['--bundle', built.bundleDir]);
    assert.match(r.out, /^inputs=1 checked=1 skipped=0$/m, r.out + r.err);
    assert.match(r.out, /calibration: 30\/30 vectors reproduced/);
    assert.match(r.out, /VERIFIED_CLEAN/);
    assert.match(r.out, /limits of this verification/);
    assert.match(r.out, /REGENERATED/);
    assert.equal(r.code, 0);
  } finally {
    built.scratch.dispose();
  }
});

test('a modified bundle exits 2 and names the finding', () => {
  const built = buildFixtureBundle({ prefix: 'eca-cli-bad-' });
  try {
    writeFileSync(join(built.bundleDir, 'artifact', 'wipe.o'), 'different bytes entirely');
    const r = run('verify-bundle.mjs', ['--bundle', built.bundleDir]);
    assert.match(r.out, /^inputs=1 checked=1 skipped=0$/m);
    assert.match(r.out, /VG-ART-08[45]/);
    assert.match(r.out, /VG-ART-061/);
    assert.equal(r.code, 2);
  } finally {
    built.scratch.dispose();
  }
});

test('several bundles under one root are all counted', () => {
  const scratch = scratchDir('eca-cli-many-');
  const built = [];
  try {
    for (const name of ['one', 'two', 'three']) {
      const b = buildFixtureBundle({ prefix: `eca-cli-${name}-` });
      built.push(b);
      // Re-home each bundle under a common root.
      const dest = join(scratch.dir, name);
      mkdirSync(dest, { recursive: true });
      copyTree(b.bundleDir, dest);
    }
    const r = run('verify-bundle.mjs', ['--bundles', scratch.dir]);
    assert.match(r.out, /^inputs=3 checked=3 skipped=0$/m, r.out + r.err);
    assert.equal(r.code, 0);
  } finally {
    scratch.dispose();
    for (const b of built) b.scratch.dispose();
  }
});

test('the contract-copies runner counts what it compared', () => {
  const r = run('check-contract-copies.mjs', []);
  assert.match(r.out, /^inputs=\d+ checked=\d+ skipped=\d+$/m, r.out + r.err);
  const [, inputs, checked] = /^inputs=(\d+) checked=(\d+) skipped=(\d+)$/m.exec(r.out);
  assert.ok(Number(inputs) >= 2, `only ${inputs} copies were found`);
  assert.equal(inputs, checked);
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /all \d+ copies agree/);
});

test('the fence runner always reports a count and a definite answer', () => {
  const r = run('check-fence.mjs', []);
  assert.match(r.out, /^inputs=2 checked=2 skipped=0$/m, r.out + r.err);
  // Exit 0 means fenced, 2 means the gap is open. Either is a definite answer;
  // 3 would mean the probe could not read the packaging script, which is the
  // only outcome this test refuses.
  assert.notEqual(r.code, 3, r.out + r.err);
  assert.ok(r.code === 0 || r.code === 2, `unexpected exit ${r.code}: ${r.out}${r.err}`);
  if (r.code === 2) {
    assert.match(r.out, /NOT FENCED/);
    assert.match(r.err, /CLI_ONLY_PACKAGES/);
  } else {
    assert.match(r.out, /both packages are on both lists/);
  }
});

function copyTree(from, to) {
  cpSync(from, to, { recursive: true });
}
