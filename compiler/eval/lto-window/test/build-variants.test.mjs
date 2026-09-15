// The compile-link-read plumbing, with a compiler that behaves the way the real
// one was MEASURED to behave.
//
// WHY THIS FILE EXISTS
//
// lib/plumbing-gates.mjs refuses to grade three byte counts until it has been
// shown that they came from three compilations. The evidence it was given was
// the sha256 of each variant's object -- and until 2026-09-14 that evidence was
// worthless, for a reason no test in this lane could have found, because nothing
// tested the builder at all:
//
//   each variant was written to `<tag>_use.c` and compiled to `<tag>_use.o`,
//   and clang puts the source path into what it emits.
//
// Measured in WSL Ubuntu-24.04 by hand: two BYTE-IDENTICAL .c files under
// different filenames, at `clang-18 -O2 -flto -c`, produce objects with
// different sha256; the same two without `-flto` also differ. So three distinct
// digests were guaranteed by three filenames, whatever the three sources said.
// The gate could not fail. It would have passed a cut that deleted nothing --
// which is the exact failure it exists to detect, and which reads out as this
// lane's published answer.
//
// The fix is in lib/build-variants.mjs: one path for every variant, built in
// order. This file holds that fix down. The compiler here is a fake, and it is
// fake in one specific, honest way -- its output depends on the source PATH as
// well as on the source TEXT, which is the property the real compiler was
// measured to have. Under that compiler:
//
//   three different sources  -> three different objects   (the gate can pass)
//   three identical sources  -> ONE object, three times   (the gate must fail)
//
// and the second line is the one that was false before. What this file cannot
// establish is that clang is deterministic for one path and one text; that is
// not a claim any test in this repository makes, and README.md says so where it
// states the limitation.

import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { after } from 'node:test';

import {
  BuildFailure, buildAndRead, digestOfText, editedPaths, readAgain, writeAndVerify,
} from '../lib/build-variants.mjs';
import { GATE } from '../lib/plumbing-gates.mjs';
import { VARIANTS, runFamily } from '../lib/plumbing-run.mjs';

const ROOT = mkdtempSync(join(tmpdir(), 'lto-window-build-'));
after(() => rmSync(ROOT, { recursive: true, force: true }));

/** A lab: three unedited units the builder compiles beside the edited one. */
function lab(name) {
  const fixtures = join(ROOT, name, 'fixtures');
  const work = join(ROOT, name, 'work');
  mkdirSync(fixtures, { recursive: true });
  mkdirSync(work, { recursive: true });
  for (const u of ['io', 'main', 'wipe']) writeFileSync(join(fixtures, `${u}.c`), `/* ${u} */\n`, 'utf8');
  return { fixtures, work };
}

/** The exception itself, not just the fact of one: assert.throws returns nothing. */
function thrown(fn, kind = BuildFailure) {
  try { fn(); } catch (e) {
    assert.ok(e instanceof kind, `threw ${e.name}, not ${kind.name}: ${e.message}`);
    return e;
  }
  return assert.fail('expected a failure, and nothing was thrown');
}

const READING = (bytes) => ({ verdict: 'PRESENT', inlined: true, where: 'main', bytes, stores: 1, memsetCalls: 0, helperCalls: [], lines: [], why: null });

/**
 * A compiler whose object carries the source PATH as well as the source TEXT.
 *
 * That is not a convenience for the test: it is the measured behaviour of
 * clang-18 (see the header), and it is the whole reason the builder may not put
 * a per-variant tag in the filename. Everything this fake does beyond that is
 * bookkeeping -- it writes a file where it was told to and reports rc 0.
 */
function fakeToolchain({ fill = () => 32, log = [] } = {}) {
  const objectFor = (src) => `path=${src}\n${readFileSync(src, 'utf8')}`;
  const exec = (cmd, args) => {
    log.push({ cmd, args });
    const out = args[args.indexOf('-o') + 1];
    if (args.includes('-c')) {
      const src = args[args.indexOf('-c') + 1];
      writeFileSync(out, objectFor(src), 'utf8');
      return { cmd, args, rc: 0, stdout: '', stderr: '', spawnError: null };
    }
    if (cmd.startsWith('python')) {
      const exe = args[1];
      const bytes = fill(readFileSync(exe, 'utf8'));
      return {
        cmd, args, rc: 0, spawnError: '', stderr: '',
        stdout: JSON.stringify({ subject: READING(bytes), control: READING(bytes), objdump: 'GNU objdump (fake) 0' }),
      };
    }
    // the link: everything the objects hold, so the "executable" responds to its
    // inputs the way a linked program does.
    writeFileSync(out, args.filter((a) => a.endsWith('.o')).map((o) => readFileSync(o, 'utf8')).join('\n'), 'utf8');
    return { cmd, args, rc: 0, stdout: '', stderr: '', spawnError: null };
  };
  return { exec, log, objectFor };
}

const SOURCE = [
  'void handle(void) {',
  '    unsigned char key[32];',
  '    derive(key, sizeof key);',
  '    use(key, sizeof key);',
  '    secure_wipe(key, sizeof key);',
  '}',
  'void wipe_kept(void) {',
  '    unsigned char keep[32];',
  '    derive(keep, sizeof keep);',
  '    memset(keep, 0, sizeof keep);',
  '    use(keep, sizeof keep);',
  '}',
].join('\n');

const CUT = (text) => text.split('\n').filter((l) => !/secure_wipe\(key/.test(l)).join('\n');

/* ------------------------------------------------------- the path policy -- */

test('the edited unit has ONE source path and ONE object path, and neither carries the variant', () => {
  // The defect, as an assertion about names. If a tag ever comes back into
  // either of these, the object digests stop being about the source text and
  // the gate that reads them goes back to being unfailable.
  const p = editedPaths('/w', 'use');
  const seen = new Set();
  for (const tag of VARIANTS) {
    seen.add(JSON.stringify(editedPaths('/w', 'use')));
    assert.ok(!p.source.includes(tag), `${tag} is in the source path`);
    assert.ok(!p.object.includes(tag), `${tag} is in the object path`);
  }
  assert.equal(seen.size, 1, 'the three variants must resolve to one pair of paths');
  assert.ok(p.source.endsWith('use.c'));
  assert.ok(p.object.endsWith('use.o'));
});

test('a variant reports the digest of the source that was on disk, and of the object it produced', () => {
  const { fixtures, work } = lab('one');
  const { exec } = fakeToolchain();
  const r = buildAndRead({ fixtures, work, tag: 'asWritten', useSource: SOURCE, exec });
  assert.equal(r.sourceDigest, digestOfText(SOURCE));
  assert.equal(r.useDigest, createHash('sha256').update(`path=${editedPaths(work).source}\n${SOURCE}`).digest('hex'));
  assert.equal(r.subject.bytes, 32);
  assert.equal(r.objdump, 'GNU objdump (fake) 0');
});

test('the opaque unit is the only one compiled without -flto', () => {
  // The control depends on it: with the consumer in the merged module the
  // buffer is promoted out of memory and the control stops being a control.
  const { fixtures, work } = lab('flto');
  const { exec, log } = fakeToolchain();
  buildAndRead({ fixtures, work, tag: 'asWritten', useSource: SOURCE, exec });
  const compiles = log.filter((c) => c.args.includes('-c'));
  const withoutLto = compiles.filter((c) => !c.args.includes('-flto')).map((c) => c.args[c.args.indexOf('-c') + 1]);
  assert.equal(withoutLto.length, 1);
  assert.ok(withoutLto[0].endsWith('io.c'));
});

/* ------------------------------- the gate that could not fail, end to end -- */

test('three sources that differ give three object digests -- and three that do NOT give one', () => {
  const { fixtures, work } = lab('digests');
  const { exec } = fakeToolchain();
  const build = (tag, text) => buildAndRead({ fixtures, work, tag, useSource: text, exec });

  const differing = [SOURCE, CUT(SOURCE), `${SOURCE}\n/* third */`].map((t, i) => build(VARIANTS[i], t).useDigest);
  assert.equal(new Set(differing).size, 3, 'the gate has to be able to pass');

  // The no-op cut: the same text three times, which is what a pattern that
  // matched nothing produces. One digest, three times.
  const identical = VARIANTS.map((tag) => build(tag, SOURCE).useDigest);
  assert.equal(new Set(identical).size, 1, 'byte-identical sources must produce byte-identical objects');

  // AND THE REASON THIS TEST IS NOT CIRCULAR. Under the old scheme the same
  // three identical sources were written to three per-variant filenames. The
  // compiler here puts the path into the object -- which is what clang-18 was
  // measured to do -- so those three would have come out DISTINCT, and the gate
  // would have read three distinct digests off a cut that deleted nothing.
  const { objectFor } = fakeToolchain();
  const oldWay = VARIANTS.map((tag) => {
    const path = join(work, `${tag}_use.c`);
    writeFileSync(path, SOURCE, 'utf8');
    return createHash('sha256').update(objectFor(path)).digest('hex');
  });
  assert.equal(new Set(oldWay).size, 3, 'the per-variant filename is what made the old digests differ');
});

test('a no-op cut driven through the whole pipe stops at the gates', () => {
  // The same thing again, but through runFamily() with the REAL builder, so
  // that what is being tested is the wiring a measurement uses rather than a
  // property of three calls made by hand.
  const { fixtures, work } = lab('noop');
  const { exec } = fakeToolchain();
  const spec = { fixtures, work, caller: 'main', helper: 'secure_wipe', bufferBytes: 32, exec };
  const noop = { asWritten: SOURCE, subjectCut: { text: SOURCE }, controlCut: { text: SOURCE } };

  const r = runFamily({ spec, variants: noop });
  assert.equal(r.result.failed, GATE.DISTINCT_SOURCES);
  assert.equal(r.word, null, 'no word may be reached from a cut that removed nothing');
  // and the object gate, one step behind it, saw the collision too
  const objectGate = r.result.gates.find((g) => g.gate === GATE.DISTINCT_COMPILATIONS);
  assert.equal(objectGate.ok, false, 'the object digests collided as well, which is the fix working');
});

test('a real cut driven through the whole pipe reaches a word', () => {
  const { fixtures, work } = lab('real');
  // 32B as written and with the subject cut, 0B with the control cut: the
  // lane's published shape, produced here by a fake whose fill responds to
  // whether the control's line is in the executable.
  const { exec } = fakeToolchain({ fill: (exe) => (/memset\(keep/.test(exe) ? 32 : 0) });
  const spec = { fixtures, work, caller: 'main', helper: 'secure_wipe', bufferBytes: 32, exec };
  const variants = {
    asWritten: SOURCE,
    subjectCut: { text: CUT(SOURCE) },
    controlCut: { text: SOURCE.split('\n').filter((l) => !/memset\(keep/.test(l)).join('\n') },
  };
  const r = runFamily({ spec, variants });
  assert.equal(r.result.failed, null, JSON.stringify(r.result.gates.filter((g) => !g.ok)));
  assert.deepEqual(r.fill, { asWritten: 32, subjectCut: 32, controlCut: 0 });
  assert.equal(r.word, 'SUBJECT_GONE');
});

/* ------------------------------------------------- the failures that raise -- */

test('a write that did not land is a BuildFailure, not a build of the previous variant', () => {
  // The guard that makes one shared path safe. `write` and `read` are injected
  // because a short write cannot be arranged on a real filesystem, and a
  // failure branch that has never run is a branch nobody has checked.
  const short = { text: null };
  const e = thrown(() => writeAndVerify({
    path: '/nowhere/use.c',
    text: `${SOURCE}\n/* the tail that did not land */`,
    tag: 'subjectCut',
    edited: 'use',
    write: (_p, t) => { short.text = String(t).slice(0, 10); },
    read: () => short.text,
  }));
  assert.equal(e.step, 'write');
  assert.match(e.message, /the compiler would have read the previous variant/);
  // and it returns the digest of what came BACK, not of what went in
  assert.equal(
    writeAndVerify({ path: 'x', text: SOURCE, tag: 'asWritten', edited: 'use', write: () => {}, read: () => SOURCE }),
    digestOfText(SOURCE),
  );
});

test('a compiler that exits 0 and writes no object is a failure, not a missing digest', () => {
  const { fixtures, work } = lab('silent');
  const { exec } = fakeToolchain();
  const quiet = (cmd, args) => (args.includes('-c') && args.includes(editedPaths(work).source)
    ? { cmd, args, rc: 0, stdout: '', stderr: '', spawnError: null }
    : exec(cmd, args));
  const e = thrown(() => buildAndRead({ fixtures, work, tag: 'asWritten', useSource: SOURCE, exec: quiet }));
  assert.equal(e.step, 'compile');
  assert.match(e.message, /exited 0 and wrote no object/);
});

test('each step names itself when it fails', () => {
  const { fixtures, work } = lab('steps');
  const base = fakeToolchain().exec;
  const failAt = (pred) => (cmd, args) => (pred(cmd, args)
    ? { cmd, args, rc: 1, stdout: '', stderr: 'nope', spawnError: null }
    : base(cmd, args));
  const build = (exec) => buildAndRead({ fixtures, work, tag: 'asWritten', useSource: SOURCE, exec });

  assert.equal(thrown(() => build(failAt((_c, a) => a.includes('-c')))).step, 'compile');
  assert.equal(thrown(() => build(failAt((c, a) => !a.includes('-c') && !c.startsWith('python')))).step, 'link');
  assert.equal(thrown(() => build(failAt((c) => c.startsWith('python')))).step, 'read');

  const notJson = (cmd, args) => (cmd.startsWith('python')
    ? { cmd, args, rc: 0, stdout: 'objdump: not JSON', stderr: '', spawnError: null }
    : base(cmd, args));
  assert.match(thrown(() => build(notJson)).message, /did not print JSON/);
});

/* ------------------------------------------------------------- readAgain -- */

test('readAgain says whether it could read at all, separately from what it read', () => {
  // It used to return null for every one of these. A diagnosis that prints null
  // beside a function name reads as "that function is not in the binary", which
  // is a reading; "no read was taken" is not one, and they are not the same news
  // to somebody looking at a failed gate.
  const ok = readAgain({ exe: 'x', caller: 'main', exec: () => ({ rc: 0, stdout: JSON.stringify({ subject: READING(32) }), stderr: '', spawnError: null }) });
  assert.equal(ok.ok, true);
  assert.equal(ok.reading.bytes, 32);
  assert.equal(ok.why, null);

  const spawn = readAgain({ exe: 'x', caller: 'main', exec: () => ({ rc: null, stdout: '', stderr: '', spawnError: 'ENOENT' }) });
  assert.equal(spawn.ok, false);
  assert.match(spawn.why, /could not be spawned \(ENOENT\)/);

  const rc = readAgain({ exe: 'x', caller: 'main', exec: () => ({ rc: 3, stdout: '', stderr: 'objdump exited 1', spawnError: null }) });
  assert.equal(rc.ok, false);
  assert.match(rc.why, /exited 3: objdump exited 1/);

  const junk = readAgain({ exe: 'x', caller: 'main', exec: () => ({ rc: 0, stdout: 'not json', stderr: '', spawnError: null }) });
  assert.equal(junk.ok, false);
  assert.match(junk.why, /did not print JSON/);

  const empty = readAgain({ exe: 'x', caller: 'main', exec: () => ({ rc: 0, stdout: '{}', stderr: '', spawnError: null }) });
  assert.equal(empty.ok, false);
  assert.match(empty.why, /no subject reading/);

  // NOT_OBSERVED is a reading, and comes back as one rather than as a failure.
  const missing = { verdict: 'NOT_OBSERVED', where: 'handle', bytes: 0, memsetCalls: 0, why: 'handle is not in the output' };
  const nobody = readAgain({ exe: 'x', caller: 'handle', exec: () => ({ rc: 0, stdout: JSON.stringify({ subject: missing }), stderr: '', spawnError: null }) });
  assert.equal(nobody.ok, true);
  assert.equal(nobody.reading.verdict, 'NOT_OBSERVED');
});
