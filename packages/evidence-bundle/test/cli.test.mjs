import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { FIXED_CONTEXT, demoRecord, scratchDir } from './_fixture.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const BIN = join(HERE, '..', 'bin');

function run(script, args) {
  const r = spawnSync(process.execPath, [join(BIN, script), ...args], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout ?? '', err: r.stderr ?? '' };
}

// ── The counting contract ───────────────────────────────────────────────────

test('calibrate prints the counting line and exits 0', () => {
  const r = run('calibrate.mjs', []);
  assert.match(r.out, /^inputs=30 checked=30 skipped=0$/m, r.out + r.err);
  assert.equal(r.code, 0);
});

test('seal-bundle over an EMPTY directory exits non-zero and says so', () => {
  const scratch = scratchDir('eca-empty-');
  try {
    const empty = join(scratch.dir, 'records');
    mkdirSync(empty, { recursive: true });
    const r = run('seal-bundle.mjs', ['--out', join(scratch.dir, 'out'), '--records', empty]);
    assert.match(r.out, /^inputs=0 checked=0 skipped=0$/m, r.out + r.err);
    assert.equal(r.code, 3, 'an empty scan is not a clean scan');
    assert.match(r.err, /no records to seal found/);
  } finally {
    scratch.dispose();
  }
});

test('an empty run is allowed only when the caller says so out loud', () => {
  const scratch = scratchDir('eca-empty-ok-');
  try {
    const empty = join(scratch.dir, 'records');
    mkdirSync(empty, { recursive: true });
    const r = run('seal-bundle.mjs', [
      '--out',
      join(scratch.dir, 'out'),
      '--records',
      empty,
      '--allow-empty',
    ]);
    assert.match(r.out, /^inputs=0 checked=0 skipped=0$/m);
    assert.equal(r.code, 0);
  } finally {
    scratch.dispose();
  }
});

test('seal-bundle seals a real record and counts it', () => {
  const scratch = scratchDir('eca-seal-');
  try {
    const records = join(scratch.dir, 'records');
    mkdirSync(records, { recursive: true });
    writeFileSync(
      join(records, 'wipe.json'),
      JSON.stringify(demoRecord({ context: FIXED_CONTEXT }), null, 2),
      'utf8',
    );
    writeFileSync(join(records, 'wipe.bin'), Buffer.from('object-bytes'));
    const r = run('seal-bundle.mjs', ['--out', join(scratch.dir, 'out'), '--records', records]);
    assert.match(r.out, /^inputs=1 checked=1 skipped=0$/m, r.out + r.err);
    assert.match(r.out, /sealed wipe /);
    assert.equal(r.code, 0);
  } finally {
    scratch.dispose();
  }
});

test('a record with no artefact is SKIPPED BY NAME, never silently', () => {
  const scratch = scratchDir('eca-noart-');
  try {
    const records = join(scratch.dir, 'records');
    mkdirSync(records, { recursive: true });
    const record = demoRecord({ context: FIXED_CONTEXT });
    delete record.artifact;
    writeFileSync(join(records, 'bare.json'), JSON.stringify(record, null, 2), 'utf8');
    const r = run('seal-bundle.mjs', ['--out', join(scratch.dir, 'out'), '--records', records]);
    assert.match(r.out, /^inputs=1 checked=1 skipped=1$/m, r.out + r.err);
    assert.match(r.out, /skipped: bare: no artefact/);
    assert.equal(r.code, 0);
  } finally {
    scratch.dispose();
  }
});

test('a directory that does not exist is INCOMPLETE, not empty', () => {
  const scratch = scratchDir('eca-missing-');
  try {
    const r = run('seal-bundle.mjs', [
      '--out',
      join(scratch.dir, 'out'),
      '--records',
      join(scratch.dir, 'nope'),
    ]);
    assert.match(r.out, /^inputs=0 checked=0 skipped=0$/m);
    assert.equal(r.code, 3);
    assert.match(r.err, /not a directory/);
  } finally {
    scratch.dispose();
  }
});
