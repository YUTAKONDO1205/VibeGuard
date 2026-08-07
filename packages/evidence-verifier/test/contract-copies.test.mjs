import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  CONTRACT_BASENAME,
  COPY_FLOOR,
  ContractScanError,
  compareContractCopies,
  fingerprintFile,
  repoRootFrom,
} from '../src/contract-copies.mjs';
import { VECTORS_FINGERPRINT } from '../src/vectors.mjs';
import { scratchDir } from './_fixture.mjs';

/** A throwaway git repository with the given files in it. */
function tinyRepo(files, prefix) {
  const scratch = scratchDir(prefix);
  execFileSync('git', ['init', '-q'], { cwd: scratch.dir, stdio: 'ignore' });
  for (const [rel, text] of Object.entries(files)) {
    const abs = join(scratch.dir, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, text, 'utf8');
  }
  return scratch;
}

const CONTRACT_A = JSON.stringify({ vectors: [{ name: 'a', digest: '00' }] }, null, 2);
const CONTRACT_A_REFORMATTED = JSON.stringify({ vectors: [{ name: 'a', digest: '00' }] });
const CONTRACT_B = JSON.stringify({ vectors: [{ name: 'a', digest: '11' }] }, null, 2);

// ── Both directions, on repositories the test owns ──────────────────────────

test('copies that agree are reported as agreeing', () => {
  const repo = tinyRepo(
    { [`x/${CONTRACT_BASENAME}`]: CONTRACT_A, [`y/${CONTRACT_BASENAME}`]: CONTRACT_A },
    'eca-agree-',
  );
  try {
    const result = compareContractCopies({ repoRoot: repo.dir });
    assert.equal(result.inputs, 2);
    assert.equal(result.checked, 2);
    assert.equal(result.skipped, 0);
    assert.equal(result.agree, true);
    assert.equal(result.belowFloor, false);
    assert.equal(result.groups.length, 1);
  } finally {
    repo.dispose();
  }
});

test('copies that differ only in FORMATTING still agree', () => {
  // The reason the comparison is over parsed content: this checkout converts
  // line endings, so a byte comparison would fail on a difference that is not
  // a difference, and a check that cries wolf gets deleted.
  const repo = tinyRepo(
    {
      [`x/${CONTRACT_BASENAME}`]: CONTRACT_A,
      [`y/${CONTRACT_BASENAME}`]: CONTRACT_A_REFORMATTED,
      [`z/${CONTRACT_BASENAME}`]: CONTRACT_A.replace(/\n/g, '\r\n'),
    },
    'eca-format-',
  );
  try {
    const result = compareContractCopies({ repoRoot: repo.dir });
    assert.equal(result.checked, 3);
    assert.equal(result.agree, true, JSON.stringify(result.groups, null, 2));
  } finally {
    repo.dispose();
  }
});

test('copies that differ in CONTENT are reported as disagreeing, with both groups named', () => {
  const repo = tinyRepo(
    { [`x/${CONTRACT_BASENAME}`]: CONTRACT_A, [`y/${CONTRACT_BASENAME}`]: CONTRACT_B },
    'eca-drift-',
  );
  try {
    const result = compareContractCopies({ repoRoot: repo.dir });
    assert.equal(result.agree, false);
    assert.equal(result.groups.length, 2);
    assert.deepEqual(
      result.groups.flatMap((g) => g.paths).sort(),
      [`x/${CONTRACT_BASENAME}`, `y/${CONTRACT_BASENAME}`],
    );
  } finally {
    repo.dispose();
  }
});

test('one copy is BELOW THE FLOOR: nothing was compared, so nothing may be claimed', () => {
  const repo = tinyRepo({ [`x/${CONTRACT_BASENAME}`]: CONTRACT_A }, 'eca-one-');
  try {
    const result = compareContractCopies({ repoRoot: repo.dir });
    assert.equal(result.checked, 1);
    assert.equal(result.belowFloor, true);
    assert.equal(result.agree, true, '"agree" is trivially true here, which is exactly the trap');
    assert.equal(result.floor, COPY_FLOOR);
  } finally {
    repo.dispose();
  }
});

test('no copies at all is below the floor too', () => {
  const repo = tinyRepo({ 'readme.txt': 'nothing here' }, 'eca-none-');
  try {
    const result = compareContractCopies({ repoRoot: repo.dir });
    assert.equal(result.inputs, 0);
    assert.equal(result.belowFloor, true);
  } finally {
    repo.dispose();
  }
});

test('a copy that does not parse is SKIPPED BY NAME, never silently dropped', () => {
  const repo = tinyRepo(
    {
      [`x/${CONTRACT_BASENAME}`]: CONTRACT_A,
      [`y/${CONTRACT_BASENAME}`]: CONTRACT_A,
      [`z/${CONTRACT_BASENAME}`]: '{ this is not json',
    },
    'eca-badparse-',
  );
  try {
    const result = compareContractCopies({ repoRoot: repo.dir });
    assert.equal(result.inputs, 3);
    assert.equal(result.checked, 2);
    assert.equal(result.skipped, 1);
    assert.equal(result.skippedNames.length, 1);
    assert.match(result.skippedNames[0], /z\//);
    assert.match(result.skippedNames[0], /does not parse/);
  } finally {
    repo.dispose();
  }
});

test('a directory that is not a git checkout FAILS rather than reporting agreement', () => {
  const scratch = scratchDir('eca-nogit-');
  try {
    assert.throws(
      () => compareContractCopies({ repoRoot: scratch.dir }),
      ContractScanError,
      'no git, no answer',
    );
  } finally {
    scratch.dispose();
  }
});

// ── The real repository ─────────────────────────────────────────────────────

test('every copy of the contract in THIS repository agrees', () => {
  const result = compareContractCopies();
  assert.ok(
    result.checked >= COPY_FLOOR,
    `only ${result.checked} copy/copies found under ${result.repoRoot}: ` +
      `${result.copies.map((c) => c.path).join(', ')}`,
  );
  assert.equal(result.agree, true, JSON.stringify(result.groups, null, 2));
  assert.equal(result.groups[0].fingerprint, VECTORS_FINGERPRINT);
  assert.deepEqual(result.skippedNames, []);
});

test('the vendored copy in this package is one of them', () => {
  const result = compareContractCopies();
  assert.ok(
    result.copies.some((c) => c.path.includes('evidence-verifier')),
    result.copies.map((c) => c.path).join(', '),
  );
  assert.ok(
    result.copies.some((c) => c.path.includes('evidence-bundle')),
    result.copies.map((c) => c.path).join(', '),
  );
});

test('the repository root is the nearest ancestor holding .git, not a guess', () => {
  const repo = tinyRepo({ 'deep/nested/file.txt': 'x' }, 'eca-root-');
  try {
    assert.equal(repoRootFrom(join(repo.dir, 'deep', 'nested')), repo.dir);
  } finally {
    repo.dispose();
  }
  // And the real one resolves from this package.
  const root = repoRootFrom();
  assert.ok(root.length > 0);
  assert.ok(compareContractCopies({ repoRoot: root }).inputs > 0);
});

test('fingerprintFile is content-based, not byte-based', () => {
  const repo = tinyRepo(
    { 'a.json': CONTRACT_A, 'b.json': CONTRACT_A_REFORMATTED, 'c.json': CONTRACT_B },
    'eca-fp-',
  );
  try {
    assert.equal(fingerprintFile(join(repo.dir, 'a.json')), fingerprintFile(join(repo.dir, 'b.json')));
    assert.notEqual(
      fingerprintFile(join(repo.dir, 'a.json')),
      fingerprintFile(join(repo.dir, 'c.json')),
    );
  } finally {
    repo.dispose();
  }
});
