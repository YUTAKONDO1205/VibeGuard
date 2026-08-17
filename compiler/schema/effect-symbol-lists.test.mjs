/**
 * The fence for effect-symbol-lists.json.
 *
 * An effect-symbol list is configuration: interfaces.md section 4 forbids deciding
 * an effect's presence by searching for a symbol NAME, so an extractor is handed a
 * list of spellings and counts call sites whose resolved callee matches one. Two
 * components handed different lists are asking different questions about the same
 * build and reporting in the same vocabulary.
 *
 * Before the registry existed the list was a bare literal in ten places with nothing
 * comparing any two. This file is what makes that impossible to repeat. It does NOT
 * assert that all lists are equal -- they are not, and effect-symbol-lists.json's
 * `divergence` block says why that is registered rather than repaired. It asserts:
 *
 *   1. every literal in the tree is one the registry DECLARES;
 *   2. every file the registry names still carries the list it is named under;
 *   3. no file carries two different lists;
 *   4. the registry's `literal` string and its `symbols` array agree;
 *   5. the declared divergence is still exactly the one recorded -- so that a group
 *      silently converging or diverging further is a failure rather than a surprise.
 *
 * (5) is the one worth defending. A test that only forbade NEW lists would go green
 * on the day someone edited the observer group to match the ladder, which is a
 * measurement change to harnesses whose numbers are quoted. Pinning the difference
 * means that edit has to arrive with this file.
 *
 * No compiler is required and nothing is measured here: this reads tracked source.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const COMPILER = path.resolve(HERE, '..');
const REGISTRY = JSON.parse(readFileSync(path.join(HERE, 'effect-symbol-lists.json'), 'utf8'));

/** Extensions a symbol list can be configured in. */
const SCANNED = new Set(['.sh', '.json', '.mjs', '.py']);

/**
 * Files exempt from (1), each for a stated reason rather than because they were
 * inconvenient. The registry's own `whatThisFileDoesNotDo` carries the same list in
 * prose; if the two disagree, the prose is what a reader trusts and this is a bug.
 */
const EXEMPT = new Map([
  ['compiler/schema/effect-symbol-lists.json', 'the registry itself'],
  ['compiler/schema/effect-symbol-lists.test.mjs', 'this file'],
  ['compiler/eval/calibration/scripts/witness-asm.mjs',
    'the ASSEMBLY-checkpoint list, deliberately different: no llvm.memset, which no listing '
    + 'can contain, plus __explicit_bzero_chk. Documented at its definition.'],
]);

/** Any comma-joined run of memset-ish spellings, however it is quoted. */
const LITERAL_RE = /["']((?:llvm\.memset|memset|explicit_bzero|bzero|__memset_chk|memset_s)(?:\s*,\s*[A-Za-z0-9_.]+)+)["']/g;

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    // The lab and any build output live outside the repo (interfaces.md section 1),
    // so there is nothing to skip here but version control and node_modules.
    if (name === 'node_modules' || name === '.git') continue;
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (SCANNED.has(path.extname(name))) out.push(full);
  }
  return out;
}

const rel = (p) => path.relative(path.resolve(COMPILER, '..'), p).split(path.sep).join('/');

/** Every literal found in the tree, as relPath -> Set of normalised literals. */
function surveyTree() {
  const found = new Map();
  for (const file of walk(COMPILER)) {
    const r = rel(file);
    if (EXEMPT.has(r)) continue;
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(LITERAL_RE)) {
      const normalised = m[1].split(',').map((s) => s.trim()).join(',');
      if (!found.has(r)) found.set(r, new Set());
      found.get(r).add(normalised);
    }
  }
  return found;
}

const byLiteral = new Map(
  Object.entries(REGISTRY.lists).map(([id, spec]) => [spec.literal, id]),
);

test('the registry is internally consistent: literal and symbols say the same thing', () => {
  for (const [id, spec] of Object.entries(REGISTRY.lists)) {
    assert.equal(
      spec.literal, spec.symbols.join(','),
      `${id}: literal ${JSON.stringify(spec.literal)} and symbols ${JSON.stringify(spec.symbols)} `
      + 'disagree. The literal is what a grep finds and the array is what a reader reasons about; '
      + 'a registry whose two halves differ pins nothing.',
    );
  }
});

test('every effect-symbol literal in the tree is one the registry declares', () => {
  const found = surveyTree();
  const undeclared = [];
  for (const [file, literals] of found) {
    for (const lit of literals) {
      if (!byLiteral.has(lit)) undeclared.push(`${file}: ${lit}`);
    }
  }
  assert.deepEqual(
    undeclared, [],
    'an effect-symbol list appeared that compiler/schema/effect-symbol-lists.json does not declare. '
    + 'A list is configuration for an extractor, so a new one means some component is asking a '
    + 'different question about the same build. Declare it in the registry with what each spelling '
    + 'is and which components use it, or use a declared one.',
  );
});

test('no single file configures two different effect-symbol lists', () => {
  const found = surveyTree();
  const mixed = [...found].filter(([, s]) => s.size > 1)
    .map(([f, s]) => `${f}: ${[...s].join(' | ')}`);
  assert.deepEqual(
    mixed, [],
    'one file carries two different lists. Whatever the reason, a reader cannot tell which of them '
    + 'a given record was measured under, and neither can this fence.',
  );
});

test('every file the registry names still carries the list it is named under', () => {
  const found = surveyTree();
  const wrong = [];
  for (const [id, spec] of Object.entries(REGISTRY.lists)) {
    for (const named of spec.usedBy) {
      const literals = found.get(named);
      if (!literals) {
        wrong.push(`${named} is registered under ${id} and carries no effect-symbol list at all`);
        continue;
      }
      if (!literals.has(spec.literal)) {
        wrong.push(`${named} is registered under ${id} (${spec.literal}) and carries ${[...literals].join(' | ')}`);
      }
    }
  }
  assert.deepEqual(
    wrong, [],
    'a component moved between lists, or stopped carrying one. Either is a measurement change: the '
    + 'set of spellings an extractor counts decides what it reports as present.',
  );
});

test('the declared divergence is still exactly the one recorded', () => {
  // The load-bearing assertion. A fence that only forbade NEW lists would go green
  // the day someone edited the observer group to match the ladder -- a change to the
  // symbol set of harnesses whose readings are quoted. Pinning the difference means
  // such an edit has to arrive together with the registry that describes it.
  const six = REGISTRY.lists['wipe-6'];
  const five = REGISTRY.lists['wipe-5-observer'];
  assert.ok(six && five, 'both declared wipe lists must be present');

  const missing = six.symbols.filter((s) => !five.symbols.includes(s));
  const extra = five.symbols.filter((s) => !six.symbols.includes(s));

  assert.deepEqual(
    missing, five.differsFrom.missing,
    'the difference between the two declared wipe lists is not the one the registry records. '
    + 'If the groups converged, say so in the registry and in whatever write-up quotes the '
    + 'observer harnesses; if they diverged further, the same.',
  );
  assert.deepEqual(
    extra, [],
    'the observer list gained a spelling the six-symbol list does not have, which the registry '
    + 'does not describe.',
  );
  assert.equal(five.differsFrom.list, 'wipe-6');

  // And the divergence must still be DISCLOSED, not merely true. A registry that
  // recorded the two lists and dropped the paragraph explaining why they differ
  // would leave the next reader to rediscover it.
  for (const field of ['found', 'theDifference', 'howMuchItMatters', 'whyItIsNotFixedHere']) {
    assert.ok(
      typeof REGISTRY.divergence?.[field] === 'string' && REGISTRY.divergence[field].length > 40,
      `divergence.${field} must still explain itself; a bare pair of lists is not a disclosure`,
    );
  }
});

test('the survey actually found something -- an empty scan is not a pass', () => {
  // The failure mode every check in this tree is written against: a scan whose
  // target resolved to nothing reports clean. Ten literals were found on
  // 2026-08-17; the floor is deliberately below that so ordinary edits do not trip
  // it, and far above zero.
  const found = surveyTree();
  const total = [...found.values()].reduce((n, s) => n + s.size, 0);
  assert.ok(
    total >= 8,
    `only ${total} effect-symbol literal(s) found across ${found.size} file(s). Ten were found `
    + 'when this fence was written. A scan that has stopped finding them is not evidence that the '
    + 'tree is consistent -- it is evidence that this test is looking in the wrong place.',
  );
});
