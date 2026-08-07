// Residue: secrets and build-host paths.
//
// The control is the point of this file. `properties.json` states the rule for
// this property class — "a string that is expected to be present, so that an
// extractor which has stopped finding anything is distinguishable from an
// artefact that is clean" — and the last test here is what makes that rule
// enforceable rather than aspirational.

import test from 'node:test';
import assert from 'node:assert/strict';

import { readElf } from '../src/elf.mjs';
import {
  extractStrings, findForbiddenStrings, checkResidueControls, findBuildPaths,
  debugSections, redactPath, buildPathShapes, selfTestShapes, sectionAt,
} from '../src/residue.mjs';
import { buildElf, RECIPES } from './synth-elf.mjs';

const SEP = String.fromCharCode(47);
const BSL = String.fromCharCode(92);
// Assembled at runtime for the same reason the patterns are: this file is
// tracked, and a literal home-directory path here is itself the disclosure the
// repository's shape check forbids.
const HOME = `${SEP}h${'ome'}${SEP}`;
const ROOTH = `${SEP}r${'oot'}${SEP}`;
const MACH = `${SEP}U${'sers'}${SEP}`;

function withRodata(text) {
  return readElf(buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts'], rodata: text,
  }), { path: 'rodata' });
}

test('extractStrings finds printable runs and their offsets, like strings -a', () => {
  const b = Buffer.from('\x00\x01hello world\x00\x02ab\x00longer-string\x00');
  const s = extractStrings(b, 4);
  assert.deepEqual(s.map((x) => x.value), ['hello world', 'longer-string']);
  assert.equal(b.toString('latin1', s[0].offset, s[0].offset + 11), 'hello world');
});

test('a forbidden literal in .rodata is found, with its section', () => {
  const elf = withRodata('AKIAIOSFODNN7EXAMPLE-residue-marker\0keep-me');
  const hits = findForbiddenStrings(elf, ['AKIAIOSFODNN7EXAMPLE']);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].section, '.rodata');
  assert.equal(sectionAt(elf, hits[0].offset), '.rodata');
});

test('a clean artefact yields no forbidden hits — the negative direction', () => {
  const elf = withRodata('nothing sensitive here at all');
  assert.deepEqual(findForbiddenStrings(elf, ['AKIAIOSFODNN7EXAMPLE', 'hunter2']), []);
});

test('the search is over bytes, so a secret next to a non-printable byte is still found', () => {
  // An extractor that only looked at printable runs of length >= 4 would split
  // this and report the artefact clean.
  const elf = withRodata(Buffer.from('ab\x01SECRET-VALUE-42\x01cd\x00', 'latin1'));
  const hits = findForbiddenStrings(elf, ['SECRET-VALUE-42']);
  assert.equal(hits.length, 1);
});

test('every occurrence is reported, not just the first', () => {
  const elf = withRodata('tok-XYZ\0filler\0tok-XYZ\0');
  assert.equal(findForbiddenStrings(elf, ['tok-XYZ']).length, 2);
});

test('CONTROL: a control string that is present is reported found', () => {
  const elf = withRodata('artefact-integrity-control-string');
  const c = checkResidueControls(elf, ['artefact-integrity-control-string']);
  assert.deepEqual(c, [{ needle: 'artefact-integrity-control-string', found: true }]);
});

test('CONTROL: a control string that is missing is reported missing, so the scan cannot claim clean', () => {
  // This is the 0-vs-nonzero control for the residue extractor. If it ever
  // stops finding anything, the run says INCOMPLETE rather than clean; see
  // verify.test.mjs for the exit code that follows from this.
  const elf = withRodata('this artefact does not contain the control');
  const c = checkResidueControls(elf, ['artefact-integrity-control-string']);
  assert.equal(c[0].found, false);
});

// ── build-path residue ──────────────────────────────────────────────────────

test('a per-user home directory in the debug info is caught', () => {
  const elf = readElf(buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts'],
    debugSections: ['.debug_line_str'],
    debugPayload: `${HOME}someone${SEP}projects${SEP}widget`,
  }), { path: 'dbg' });
  const hits = findBuildPaths(elf);
  assert.ok(hits.some((h) => h.shape === 'UNIX-HOME'), JSON.stringify(hits));
  assert.ok(hits.some((h) => h.section === '.debug_line_str'));
});

test("the superuser's home directory is caught too", () => {
  const elf = readElf(buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts'], debugSections: ['.debug_str'],
    debugPayload: `${ROOTH}scratch${SEP}build`,
  }), { path: 'dbg2' });
  assert.ok(findBuildPaths(elf).some((h) => h.shape === 'UNIX-SUPERUSER-HOME'));
});

test('a Windows and a subsystem-mount path are caught', () => {
  const win = `C:${BSL}U${'sers'}${BSL}someone${BSL}src`;
  const wsl = `${SEP}mnt${SEP}c${SEP}work${SEP}tree`;
  const elf = readElf(buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts'], debugSections: ['.debug_str'], debugPayload: `${win} ${wsl}`,
  }), { path: 'dbg3' });
  const shapes = new Set(findBuildPaths(elf).map((h) => h.shape));
  assert.ok(shapes.has('WINDOWS-DRIVE'), [...shapes].join(','));
  assert.ok(shapes.has('WSL-MOUNT'), [...shapes].join(','));
});

test('a macOS per-user path is caught', () => {
  const elf = readElf(buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts'], debugSections: ['.debug_str'], debugPayload: `${MACH}someone${SEP}dev`,
  }), { path: 'dbg4' });
  assert.ok(findBuildPaths(elf).some((h) => h.shape === 'MAC-HOME'));
});

test('the interpreter path is not build residue — the negative direction', () => {
  // Every dynamic executable carries /lib64/ld-linux-x86-64.so.2 in .interp.
  // A detector that flags any absolute path reports every binary on the system.
  const elf = readElf(RECIPES['pie-on'](), { path: 'pie-on' });
  const hits = findBuildPaths(elf);
  assert.deepEqual(hits, [], `flagged: ${JSON.stringify(hits)}`);
});

test('a stripped release build has neither debug sections nor build paths', () => {
  const elf = readElf(RECIPES.hardened(), { path: 'hardened' });
  assert.deepEqual(debugSections(elf), []);
  assert.deepEqual(findBuildPaths(elf), []);
});

test('debug sections are listed when they are there', () => {
  const elf = readElf(RECIPES.unhardened(), { path: 'unhardened' });
  assert.deepEqual(debugSections(elf).sort(), ['.debug_info', '.debug_line', '.debug_line_str', '.debug_str']);
});

test('a reported path is redacted: the shape survives, the content does not', () => {
  const p = `${HOME}someone${SEP}projects${SEP}secret-client`;
  const r = redactPath(p);
  assert.equal(r.includes('someone'), false);
  assert.equal(r.includes('secret-client'), false);
  assert.match(r, /3 further segment\(s\)/);
});

test('the shape patterns are assembled at runtime, so this source carries no literal home path', () => {
  const shapes = buildPathShapes();
  assert.equal(shapes.length, 5);
  for (const s of shapes) assert.ok(s.re instanceof RegExp && typeof s.why === 'string');
});

test('SELF-TEST: every shape fires against its own positive control', () => {
  // The WINDOWS-DRIVE shape once compiled cleanly, ran on every scan, and
  // matched nothing at all, because inside a character class `\/` is an escaped
  // forward slash and the backslash had vanished. A confident zero from a
  // broken needle is the failure mode this whole component exists to avoid, so
  // the needles are held to the same rule as the artefacts they inspect.
  const results = selfTestShapes();
  assert.equal(results.length, 5);
  const dead = results.filter((r) => !r.fires).map((r) => r.id);
  assert.deepEqual(dead, [], `these shapes did not match their own control: ${dead.join(', ')}`);
});
