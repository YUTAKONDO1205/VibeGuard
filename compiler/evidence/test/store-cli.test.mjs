// The store validator and the writer as processes, because what a build system
// branches on is the exit code the process left behind, not the number an
// exported function returned.

import { strict as assert } from 'node:assert';
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import {
  cleanup,
  countingOf,
  EVIDENCE_DIR,
  linkDir,
  makeQuiescentRepo,
  makeScratch,
  putRecord,
  RECORD_RUN,
  REPO_ROOT,
  run,
  VALIDATE,
} from './helpers.mjs';

test('--self-test fires every positive control and silences every negative one', () => {
  const r = run(VALIDATE, ['--self-test']);
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  const m = /positive controls: (\d+)\/(\d+) fired; negative controls: (\d+)\/(\d+) stayed silent/.exec(r.stdout);
  assert.ok(m, r.stdout);
  assert.equal(m[1], m[2], 'a positive control did not fire');
  assert.equal(m[3], m[4], 'a negative control fired');
  assert.ok(Number(m[2]) >= 10, `only ${m[2]} positive controls`);
  const c = countingOf(r);
  assert.ok(c && c.inputs === Number(m[2]) + Number(m[4]));
});

test('--self-test proves the delegated shape checker still fires its own needles', () => {
  const r = run(VALIDATE, ['--self-test']);
  assert.match(r.stdout, /delegate scripts\/check-disclosure-shape\.mjs passed its own self-test/);
});

test('an empty store exits 3, and exits 0 only when told the emptiness was expected', () => {
  const dir = makeScratch('cli-empty');
  try {
    const a = run(VALIDATE, ['--store', dir]);
    assert.equal(a.status, 3, `${a.stdout}${a.stderr}`);
    assert.deepEqual(countingOf(a), { inputs: 0, checked: 0, skipped: 0 });
    assert.match(`${a.stdout}${a.stderr}`, /no record was examined/);

    const b = run(VALIDATE, ['--store', dir, '--allow-empty']);
    assert.equal(b.status, 0, `${b.stdout}${b.stderr}`);
  } finally {
    cleanup(dir);
  }
});

test('a store that does not exist exits 3, not 0', () => {
  const dir = makeScratch('cli-missing');
  try {
    const r = run(VALIDATE, ['--store', join(dir, 'no-such-store')]);
    assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
  } finally {
    cleanup(dir);
  }
});

test('a store pointed inside the checkout exits 2 and names the rule', () => {
  const r = run(VALIDATE, ['--store', join(REPO_ROOT, 'compiler', 'evidence')]);
  assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
  assert.match(r.stdout, /VG-ART-070/);
  assert.match(r.stdout, /inside the checkout/);
});

test('a good pair validates clean, with the counting line and exit 0', async () => {
  const dir = makeScratch('cli-good');
  try {
    await putRecord(dir, 'p', 1);
    await putRecord(dir, 'p', 2);
    const r = run(VALIDATE, ['--store', dir]);
    assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
    assert.deepEqual(countingOf(r), { inputs: 2, checked: 2, skipped: 0 });
    assert.match(r.stdout, /pairs: 1/);
  } finally {
    cleanup(dir);
  }
});

test('a bad record makes the store exit 2 and names the finding', async () => {
  const dir = makeScratch('cli-bad');
  try {
    await putRecord(dir, 'p', 1);
    await putRecord(dir, 'p', 2, { toolchain: [{ name: 'cc', version: '18.1.3' }] });
    const r = run(VALIDATE, ['--store', dir]);
    assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
    assert.match(r.stdout, /VG-ART-074/);
  } finally {
    cleanup(dir);
  }
});

test('a store reached through a link exits 2 and reads nothing', async () => {
  const dir = makeScratch('cli-link');
  try {
    const real = join(dir, 'real');
    mkdirSync(real, { recursive: true });
    await putRecord(real, 'p', 1);
    await putRecord(real, 'p', 2);
    linkDir(real, join(dir, 'link'));
    const r = run(VALIDATE, ['--store', join(dir, 'link')]);
    assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
    assert.match(r.stdout, /VG-ART-071/);
    assert.deepEqual(countingOf(r), { inputs: 0, checked: 0, skipped: 0 });
  } finally {
    cleanup(dir);
  }
});

test('--record on one file reports byte-identity as UNCHECKED and exits 3', async () => {
  const dir = makeScratch('cli-one');
  try {
    const { file } = await putRecord(dir, 'p', 1);
    const r = run(VALIDATE, ['--record', file, '--no-delegate']);
    assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
    assert.match(r.stdout, /reproduction\.byteIdentity/);
    assert.deepEqual(countingOf(r), { inputs: 1, checked: 1, skipped: 0 });
  } finally {
    cleanup(dir);
  }
});

test('--no-delegate turns the disclosure check into UNCHECKED, never into clean', async () => {
  const dir = makeScratch('cli-nodelegate');
  try {
    await putRecord(dir, 'p', 1);
    await putRecord(dir, 'p', 2);
    const r = run(VALIDATE, ['--store', dir, '--no-delegate']);
    assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
    assert.match(`${r.stdout}${r.stderr}`, /disclosure check NOT COMPLETED/);
  } finally {
    cleanup(dir);
  }
});

test('the delegate really runs over the store and catches a shape in a record', async () => {
  const dir = makeScratch('cli-delegate');
  try {
    // The shape has to be one the LOCAL checks do not already catch, or the
    // test would pass without the delegate ever being consulted. A home path
    // is out: `sealRecord` refuses to write one at all, which is the
    // generation gate doing its job. So the fixture carries the shape checker's
    // own PLAN-LABEL needle — an ideograph glued to a lone Latin capital —
    // which nothing here looks for and which it finds in a file it has never
    // seen. It is assembled from a code point at runtime for the same reason
    // the checker assembles its controls: this file is tracked, and a literal
    // one would make the repository fail its own scan.
    const shaped = `${String.fromCodePoint(0x5c71)}Q section`;
    await putRecord(dir, 'p', 1);
    await putRecord(dir, 'p', 2, { recordId: shaped });
    const r = run(VALIDATE, ['--store', dir]);
    assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
    assert.match(r.stdout, /VG-ART-076/, r.stdout);
    assert.match(r.stdout, /PLAN-LABEL/, r.stdout);
  } finally {
    cleanup(dir);
  }
});

test('no file in this component is invisible to the shape checker', () => {
  // Found the hard way. A single stray NUL byte in machine.mjs made
  // check-disclosure-shape.mjs classify it as binary and SKIP it — counted in
  // its `skipped:` line, invisible in a normal run, and the file was then never
  // scanned again. A source file that the disclosure check cannot read is a
  // file that can carry anything.
  const files = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(mjs|md|json)$/.test(e.name)) files.push(p);
    }
  };
  walk(EVIDENCE_DIR);
  assert.ok(files.length > 10, `only found ${files.length} files to check`);
  const binary = files.filter((f) => readFileSync(f).includes(0));
  assert.deepEqual(binary, [], 'these files hold a NUL byte and are skipped as binary');
});

// ── The writer ──────────────────────────────────────────────────────────────

function writeObs(dir, extra = {}) {
  const f = join(dir, 'obs.json');
  writeFileSync(
    f,
    JSON.stringify({
      recordId: 'writer-fixture',
      oracle: { kind: 'call-site', pattern: 'call void @llvm.memset' },
      toolchainBinaries: [process.execPath],
      observations: [{ config: 'O0', subject: 2, control: 1 }, { config: 'O2', subject: 1, control: 1 }],
      ...extra,
    }),
    'utf8',
  );
  return f;
}

test('the writer measures the toolchain rather than believing the caller', () => {
  const dir = makeScratch('writer-toolchain');
  const repo = makeQuiescentRepo('writer-toolchain-repo');
  try {
    const obs = writeObs(dir, { toolchainBinaries: [process.execPath] });
    const store = join(dir, 'store');
    const r = run(RECORD_RUN, ['--observations', obs, '--store', store, '--pair-id', 'w', '--run', '1', '--repo', repo]);
    assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
    const rec = JSON.parse(readFileSync(join(store, 'w', 'run-1.json'), 'utf8'));
    assert.equal(rec.toolchain.length, 1);
    assert.match(rec.toolchain[0].sha256, /^[0-9a-f]{64}$/);
    assert.ok(rec.toolchain[0].version.length > 0);
    assert.match(rec.provenance.gitSha, /^[0-9a-f]{40}$/);
    assert.equal(rec.provenance.dirty, false, 'the fixture repository is clean');
    assert.equal(rec.provenance.diffSha256, null);
  } finally {
    cleanup(dir);
    cleanup(repo);
  }
});

test('the dirty flag and its diff digest move when an untracked file appears', () => {
  const dir = makeScratch('writer-dirty');
  const repo = makeQuiescentRepo('writer-dirty-repo');
  try {
    const obs = writeObs(dir);
    const store = join(dir, 'store');
    const read = (n) => JSON.parse(readFileSync(join(store, 'w', `run-${n}.json`), 'utf8')).provenance;

    run(RECORD_RUN, ['--observations', obs, '--store', store, '--pair-id', 'w', '--run', '1', '--repo', repo]);
    assert.equal(read(1).dirty, false);

    // `git diff HEAD` cannot see an untracked file at all, so a diff digest
    // built from it alone would not move here — while `git status` calls the
    // tree dirty. That combination is the hole this asserts is closed.
    writeFileSync(join(repo, 'untracked.txt'), 'new\n', 'utf8');
    run(RECORD_RUN, ['--observations', obs, '--store', store, '--pair-id', 'w', '--run', '2', '--repo', repo]);
    assert.equal(read(2).dirty, true);
    assert.match(read(2).diffSha256, /^[0-9a-f]{64}$/);

    // And it moves again when the untracked file's CONTENT changes, not only
    // when its name appears.
    writeFileSync(join(repo, 'untracked.txt'), 'different\n', 'utf8');
    run(RECORD_RUN, ['--observations', obs, '--store', store, '--pair-id', 'x', '--run', '1', '--repo', repo]);
    const third = JSON.parse(readFileSync(join(store, 'x', 'run-1.json'), 'utf8')).provenance;
    assert.notEqual(third.diffSha256, read(2).diffSha256);
  } finally {
    cleanup(dir);
    cleanup(repo);
  }
});

test('two runs of the writer are byte-identical outside context, and the validator says so', () => {
  const dir = makeScratch('writer-pair');
  const repo = makeQuiescentRepo('writer-pair-repo');
  try {
    const obs = writeObs(dir);
    const store = join(dir, 'store');
    for (const n of ['1', '2']) {
      const w = run(RECORD_RUN, ['--observations', obs, '--store', store, '--pair-id', 'w', '--run', n, '--repo', repo]);
      assert.equal(w.status, 0, `${w.stdout}${w.stderr}`);
    }
    const a = JSON.parse(readFileSync(join(store, 'w', 'run-1.json'), 'utf8'));
    const b = JSON.parse(readFileSync(join(store, 'w', 'run-2.json'), 'utf8'));
    delete a.context; delete a.evidenceDigest; delete a.reproduction;
    delete b.context; delete b.evidenceDigest; delete b.reproduction;
    assert.deepEqual(a, b);

    const v = run(VALIDATE, ['--store', store]);
    assert.equal(v.status, 0, `${v.stdout}${v.stderr}`);
    assert.equal(v.stdout.includes('VG-ART-078'), false);
  } finally {
    cleanup(dir);
    cleanup(repo);
  }
});

test('two runs against a tree that changed between them are NOT byte-identical', () => {
  const dir = makeScratch('writer-drift');
  const repo = makeQuiescentRepo('writer-drift-repo');
  try {
    const obs = writeObs(dir);
    const store = join(dir, 'store');
    run(RECORD_RUN, ['--observations', obs, '--store', store, '--pair-id', 'w', '--run', '1', '--repo', repo]);
    writeFileSync(join(repo, 'README'), 'edited between the two runs\n', 'utf8');
    run(RECORD_RUN, ['--observations', obs, '--store', store, '--pair-id', 'w', '--run', '2', '--repo', repo]);

    const v = run(VALIDATE, ['--store', store]);
    assert.equal(v.status, 2, `${v.stdout}${v.stderr}`);
    assert.match(v.stdout, /VG-ART-078/);
    assert.match(v.stdout, /not byte-identical/);
  } finally {
    cleanup(dir);
    cleanup(repo);
  }
});

test('the writer refuses an observation set with nothing in it, and writes no file', () => {
  const dir = makeScratch('writer-empty');
  try {
    const obs = writeObs(dir, { observations: [] });
    const store = join(dir, 'store');
    const r = run(RECORD_RUN, ['--observations', obs, '--store', store, '--pair-id', 'w', '--run', '1']);
    assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
    assert.deepEqual(countingOf(r), { inputs: 0, checked: 0, skipped: 0 });
    assert.throws(() => readFileSync(join(store, 'w', 'run-1.json')), /ENOENT/);
  } finally {
    cleanup(dir);
  }
});

test('the writer refuses to write inside the checkout', () => {
  const dir = makeScratch('writer-intree');
  try {
    const obs = writeObs(dir);
    const r = run(RECORD_RUN, ['--observations', obs, '--store', join(REPO_ROOT, 'compiler', 'evidence', 'no'), '--pair-id', 'w', '--run', '1']);
    assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
    assert.match(r.stderr, /inside the checkout/);
  } finally {
    cleanup(dir);
  }
});

test('the writer refuses a linked store and leaves no directory behind in it', () => {
  const dir = makeScratch('writer-link');
  try {
    const obs = writeObs(dir);
    const real = join(dir, 'real');
    mkdirSync(real, { recursive: true });
    linkDir(real, join(dir, 'link'));
    const r = run(RECORD_RUN, ['--observations', obs, '--store', join(dir, 'link'), '--pair-id', 'w', '--run', '1']);
    assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
    assert.throws(() => readFileSync(join(real, 'w', 'run-1.json')), /ENOENT/);
  } finally {
    cleanup(dir);
  }
});
