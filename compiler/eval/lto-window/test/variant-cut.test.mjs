// The cut that the which-wipe reading is made of, tested against the fixture
// this lane actually generates.
//
// WHY THIS FILE EXISTS
//
// tools/which-wipe-survived.mjs answers "which of the two absorbed wipes is
// gone" by deleting one wipe from the source, rebuilding, and comparing. Its
// grading function, whichWipeSurvived(), has six tests in record.test.mjs
// including the ordering of its BLIND guard. The step that MAKES the three
// sources had none: it was a `filter` over a regex inside the tool, and a
// `filter` cannot tell one match from three -- it removes them all and reports
// only that the line count fell.
//
// Both failures are silent and both produce the tool's headline answer:
//
//   the pattern matches nothing   -> the "subject cut" build is the as-written
//                                    build under another name, so the fill is
//                                    unchanged, which reads as "deleting the
//                                    subject's wipe changed nothing".
//   the pattern matches twice     -> two lines go, and a reading attributed to
//                                    one wipe is about both.
//
// The README's 32/32/0 is this tool's output, so these tests are underneath a
// published number.
//
// The source under test is the GENERATOR'S OWN TEMPLATE, read out of
// tools/make-lto-fixtures.sh. The fixture is written into a lab directory and is
// deliberately not tracked (a path segment `fixtures` under compiler/ is refused
// by scripts/check-packaging-invariants.mjs), so the heredoc in that script is
// the only tracked copy of the text the cut runs against. A toy string here
// would test the regex against itself.

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { PC_EXPECTED, PC_USE_C } from '../lib/pc-fixture.mjs';
import {
  CUT_REFUSAL, NOINLINE_MARKER, VariantCutError, WIPE_LINES,
  cutOneLine, cutWipeVariants, renderUseC, useTemplateFrom,
} from '../lib/variant-cut.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const GENERATOR = readFileSync(join(HERE, '..', 'tools', 'make-lto-fixtures.sh'), 'utf8');
const TEMPLATE = useTemplateFrom(GENERATOR);
const FAMILIES = ['xtu', 'xtu-inline'];
const rendered = Object.fromEntries(FAMILIES.map((f) => [f, renderUseC(TEMPLATE, f)]));

/** The refusal itself, not just the fact of one: node's assert.throws returns nothing. */
function refusal(fn) {
  try { fn(); } catch (e) { return e; }
  return assert.fail('expected a refusal, and nothing was thrown');
}

test('the generator still holds one use.c template with exactly one intervention in it', () => {
  // useTemplateFrom refuses on a different count, so reaching here is half the
  // assertion; the other half is that the template is the file it looks like.
  assert.equal(TEMPLATE.split('\n').filter((l) => l.trim() === NOINLINE_MARKER).length, 2);
  assert.match(TEMPLATE, /void handle\(void\) \{/);
  assert.match(TEMPLATE, /void wipe_kept\(void\) \{/);
  assert.ok(TEMPLATE.length > 500, 'a truncated template would make every cut below this vacuous');
});

test('the two families differ by exactly the two attribute lines, and nothing else', () => {
  // The generator prints `diff` on the two files and says two deleted lines is
  // the expected output. This is that sentence as an assertion.
  const a = rendered.xtu.split('\n');
  const b = rendered['xtu-inline'].split('\n');
  assert.equal(a.length - b.length, 2);
  assert.equal(a.filter((l) => l === '__attribute__((noinline))').length, 2);
  assert.equal(b.filter((l) => l.includes('__attribute__')).length, 0);
  assert.deepEqual(a.filter((l) => l !== '__attribute__((noinline))'), b);
});

for (const family of FAMILIES) {
  test(`${family}: the subject cut removes exactly one line, and it is the subject's wipe`, () => {
    const before = rendered[family].split('\n');
    const cut = cutOneLine(rendered[family], WIPE_LINES.subject, "subject's");
    assert.equal(cut.removedLine.trim(), 'secure_wipe(key, sizeof key);');
    const after = cut.text.split('\n');
    assert.equal(after.length, before.length - 1, 'exactly one line');
    // every other line is byte-identical, in order: the cut is a deletion, not
    // a rewrite that happens to be one line shorter.
    assert.deepEqual(after, before.filter((_, i) => i !== cut.lineNumber - 1));
    // and the control's wipe is untouched by the subject's cut
    assert.equal(after.filter((l) => WIPE_LINES.control.test(l)).length, 1);
  });

  test(`${family}: the control cut removes exactly one line, and it is the control's wipe`, () => {
    const before = rendered[family].split('\n');
    const cut = cutOneLine(rendered[family], WIPE_LINES.control, "control's");
    assert.equal(cut.removedLine.trim(), 'memset(keep, 0, sizeof keep);');
    const after = cut.text.split('\n');
    assert.equal(after.length, before.length - 1);
    assert.deepEqual(after, before.filter((_, i) => i !== cut.lineNumber - 1));
    assert.equal(after.filter((l) => WIPE_LINES.subject.test(l)).length, 1);
  });

  test(`${family}: the subject's cut and the control's cut are different lines`, () => {
    const v = cutWipeVariants(rendered[family]);
    assert.notEqual(v.subjectCut.lineNumber, v.controlCut.lineNumber);
    assert.notEqual(v.subjectCut.text, v.controlCut.text);
    assert.notEqual(v.subjectCut.text, v.asWritten);
    assert.notEqual(v.controlCut.text, v.asWritten);
  });
}

test('a pattern that matches nothing is a named refusal, not a source that came back unchanged', () => {
  // This is the failure mode that reads as the tool's headline answer: a
  // "subject cut" build identical to the as-written build gives an unchanged
  // fill, which whichWipeSurvived() grades as `subject-store-already-gone`.
  const once = cutOneLine(rendered.xtu, WIPE_LINES.subject).text;
  const e = refusal(() => cutOneLine(once, WIPE_LINES.subject, "subject's"));
  assert.ok(e instanceof VariantCutError);
  assert.equal(e.reason, CUT_REFUSAL.NO_MATCH);
  assert.equal(e.detail.matched, 0);
  assert.match(e.message, /deleting it changed nothing/);
});

test('two matching lines are a refusal, and the first one is NOT taken', () => {
  const lines = rendered.xtu.split('\n');
  const at = lines.findIndex((l) => WIPE_LINES.subject.test(l));
  const doubled = lines.slice(0, at + 1).concat(lines[at], lines.slice(at + 1)).join('\n');
  const e = refusal(() => cutOneLine(doubled, WIPE_LINES.subject, "subject's"));
  assert.ok(e instanceof VariantCutError);
  assert.equal(e.reason, CUT_REFUSAL.AMBIGUOUS);
  assert.equal(e.detail.matched, 2);
  assert.deepEqual(e.detail.lineNumbers, [at + 1, at + 2]);
  // the refusal is the point: a `filter` here would have removed both and
  // returned a source with no subject wipe at all, silently.
  assert.match(e.message, /refusing rather than taking the first/);
});

test('cutWipeVariants refuses the whole set when either cut is ambiguous', () => {
  const doubled = rendered.xtu.replace('    memset(keep, 0, sizeof keep);\n', '    memset(keep, 0, sizeof keep);\n    memset(keep, 0, sizeof keep);\n');
  const e = refusal(() => cutWipeVariants(doubled));
  assert.ok(e instanceof VariantCutError);
  assert.equal(e.reason, CUT_REFUSAL.AMBIGUOUS);
});

test('useTemplateFrom refuses a generator whose shape has changed, rather than returning something short', () => {
  for (const [what, script] of [
    ['no template function', GENERATOR.replace('xtu_use_c() {', 'other_use_c() {')],
    ['an unclosed heredoc', GENERATOR.split('\n').filter((l) => l.trim() !== 'FIXTURE_EOF').join('\n')],
    ['one marker instead of two', GENERATOR.replace(`${NOINLINE_MARKER}\nvoid wipe_kept`, 'void wipe_kept')],
  ]) {
    assert.throws(() => useTemplateFrom(script), VariantCutError, what);
  }
});

test('renderUseC names the families the generator writes, and refuses any other', () => {
  assert.throws(() => renderUseC(TEMPLATE, 'erasure'), VariantCutError);
});

/* ------------------------------------------ the anchors, as sed has them -- */
//
// The generator writes the two families with
//
//   sed 's/^@NOINLINE@$/__attribute__((noinline))/'   (family xtu)
//   sed '/^@NOINLINE@$/d'                             (family xtu-inline)
//
// and opens its template with <<'FIXTURE_EOF', which bash closes only on a
// FIXTURE_EOF in column 0. Every one of those is anchored. The lifted copies in
// lib/variant-cut.mjs matched with `l.trim() === ...` until 2026-09-14, which
// matches MORE than the thing it stands in for -- and a copy that matches more
// than the original is not a copy of it. These tests are the difference.

test('an indented marker is left alone here, because sed leaves it alone there', () => {
  const withStray = TEMPLATE.replace(`${NOINLINE_MARKER}\nvoid handle`, `  ${NOINLINE_MARKER}\n${NOINLINE_MARKER}\nvoid handle`);
  const xtu = renderUseC(withStray, 'xtu').split('\n');
  const inline = renderUseC(withStray, 'xtu-inline').split('\n');
  assert.equal(xtu.filter((l) => l === `  ${NOINLINE_MARKER}`).length, 1, 'sed would not have substituted an indented marker');
  assert.equal(inline.filter((l) => l === `  ${NOINLINE_MARKER}`).length, 1, 'sed would not have deleted an indented marker');
  // and the two real markers are still handled
  assert.equal(xtu.filter((l) => l === '__attribute__((noinline))').length, 2);
  assert.equal(inline.filter((l) => l === NOINLINE_MARKER).length, 0);
});

test('an indented FIXTURE_EOF does not close the heredoc, so the template is not truncated', () => {
  // bash keeps reading; a trimmed match here would have stopped at this line,
  // handed back a template with one marker in it and no wipe_kept at all, and
  // every cut test in this file would have been run against the wrong text.
  const script = GENERATOR.replace('/* wipe.c -- compiled -flto. */', '    FIXTURE_EOF\n/* wipe.c -- compiled -flto. */');
  const template = useTemplateFrom(script);
  assert.match(template, /void wipe_kept\(void\) \{/, 'the template must run to the end of the heredoc');
  assert.equal(template.split('\n').filter((l) => l === NOINLINE_MARKER).length, 2);
  assert.ok(template.includes('    FIXTURE_EOF'), 'the indented line is part of the body, as it is in bash');
});

test('an indented line that looks like the template function is not the template function', () => {
  // Placed BEFORE the real definition, a trimmed match takes it, and then the
  // first heredoc it finds is io.c's -- so the `template` would be a different
  // fixture file entirely, with no markers in it.
  // The decoy is a whole indented block, heredoc and all. The other heredocs
  // in the script are spelled `cat > "$FX/..." <<'FIXTURE_EOF'` and would never
  // be mistaken for the template's bare `cat <<'FIXTURE_EOF'`, so a decoy that a
  // trimmed match could not actually follow would prove nothing.
  const decoy = [
    `    ${'xtu_use_c() {'}`,
    "cat <<'FIXTURE_EOF'",
    'a decoy body, with no markers in it',
    'FIXTURE_EOF',
    'set -u',
  ].join('\n');
  const script = GENERATOR.replace('set -u', decoy);
  const template = useTemplateFrom(script);
  assert.match(template, /void handle\(void\) \{/);
  assert.equal(template.split('\n').filter((l) => l === NOINLINE_MARKER).length, 2);
});

test('a generator with CR line endings is refused, not parsed', () => {
  // Under CRLF, bash does not close the heredoc and sed's ^...$ matches no
  // marker line: the script does not write the fixture this lane measures, so
  // nothing lifted out of it here would be the text the cut runs against.
  const e = refusal(() => useTemplateFrom(GENERATOR.replaceAll('\n', '\r\n')));
  assert.ok(e instanceof VariantCutError);
  assert.equal(e.reason, CUT_REFUSAL.NO_MATCH);
  assert.match(e.message, /CR line endings/);
  // and the tracked generator is not one of those
  assert.ok(!GENERATOR.includes('\r'));
});

/* ------------------------------------------------- the positive control -- */

test("the positive control's use.c cuts the same two lines as the measured family", () => {
  const v = cutWipeVariants(PC_USE_C);
  assert.equal(v.subjectCut.removedLine.trim(), 'secure_wipe(key, sizeof key);');
  assert.equal(v.controlCut.removedLine.trim(), 'memset(keep, 0, sizeof keep);');
  assert.equal(v.subjectCut.text.split('\n').length, PC_USE_C.split('\n').length - 1);
});

test("the positive control's subject wipe is read afterwards, which is what makes it un-removable", () => {
  // The measured family's subject is derive, use, wipe -- a dead store. This
  // one is derive, wipe, use: the zeroes are handed to a unit that is never
  // compiled -flto, so no level may drop them and the tool is REQUIRED to
  // report survival. If this order is ever edited back, the positive control
  // silently becomes a second copy of the subject and stops controlling
  // anything.
  const body = PC_USE_C.split('void handle(void) {')[1].split('}')[0].split('\n');
  const wipeAt = body.findIndex((l) => WIPE_LINES.subject.test(l));
  const useAt = body.findIndex((l) => /^\s*use\(key, sizeof key\);\s*$/.test(l));
  assert.ok(wipeAt >= 0 && useAt >= 0, 'the subject must both wipe and then read');
  assert.ok(wipeAt < useAt, 'the wipe must come BEFORE the read, or the store is dead and removable');
  assert.equal(PC_EXPECTED.reading, 'SUBJECT_PRESENT');
  assert.equal(PC_EXPECTED.controlBytes, 2 * PC_EXPECTED.subjectBytes, 'both wipes land in one absorbed body');
});
