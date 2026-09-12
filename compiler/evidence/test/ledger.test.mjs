// The double-entry ledger, both directions.
//
// Positive: a record whose planned cells are all posted verifies clean.
// Negative: one that leaves a cell in no account does not. A suite with only
// the second would be satisfied by a check that failed everything, and a suite
// with only the first by a check that did nothing at all — which is what the
// v1 fixtures did get before this existed: every one of them exited 0.
//
// THE TEST THAT MATTERS
//
//   `a record that lists only the properties it observed must fail`. If
//   `declaredPropertyCount` is ever taken from `record.properties.length` the
//   identity holds for every record that was ever written and the check is
//   theatre. That test is the one that fails when it is, and the unit test
//   under it says the same thing in arithmetic: the denominator and
//   `properties.length` are different numbers for that fixture.
//
// THE LIMIT, TESTED RATHER THAN ASSERTED
//
//   `the record's own declaration cannot catch a record that shrank both books`
//   asserts exit 0 — on purpose. A record that dropped a property from
//   `properties[]` AND from `declaredProperties` balances, and nothing inside
//   it can say otherwise. The test immediately after it names an outside
//   declaration and the same record exits 2. That pair is the whole argument
//   for `--declared`, and writing the first half as a passing expectation is
//   how it stays honest.
//
// THE BLOCK AT THE BOTTOM
//
//   Four verdicts that were bought by writing LESS — a ledger of checkpoint
//   names with no counts, a property planned at no checkpoint, a narrowed
//   checkpoint list, and (in `record-v0.test.mjs`) an unreadable manifest. Each
//   one exited 0 against this verifier before the check it now fails, and each
//   differs from a fixture above by one field. They are at the bottom rather
//   than beside their relatives because what they have in common is not the
//   check they defeat but the shape of the defeat: a comparison written as
//   "compare the fields that are there" reports agreement over the empty set.

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import {
  ACCOUNTS,
  DeclarationError,
  auditLedger,
  postLedger,
  readDeclaration,
  unresolvedCovers,
} from '../ledger.mjs';
import { EVIDENCE_DIR, run, VERIFY } from './helpers.mjs';

const TD = join(EVIDENCE_DIR, 'testdata');
const RECORDS = join(TD, 'records');
const BUNDLES = join(TD, 'bundles');
const DECLS = join(TD, 'declarations');

const load = (p) => JSON.parse(readFileSync(p, 'utf8'));

/** `--record --json`: stdout is the report. */
function record(name, extra = []) {
  const r = run(VERIFY, ['--record', join(RECORDS, name), '--json', ...extra]);
  return { ...r, report: JSON.parse(r.stdout) };
}

const ids = (report) => report.findings.map((f) => f.id);

// ── The CLI, end to end ─────────────────────────────────────────────────────

test('a balanced v1 record exits 0', () => {
  const r = run(VERIFY, ['--record', join(BUNDLES, 'v1-balanced', 'evidence.json'), '--json']);
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  const report = JSON.parse(r.stdout);
  assert.deepEqual(report.findings, []);
  assert.deepEqual(report.unchecked, []);
  assert.ok(report.checked.includes('ledger'), `checked: ${report.checked.join(', ')}`);
  assert.ok(report.checked.includes('ledger.entries'));
  assert.equal(report.ledger.source, 'record');
  // Every planned cell is posted, and the suspense account carries the one the
  // run did not reach. A ledger whose unresolved column is empty because the
  // run skipped nothing and one that is empty because the skips went missing
  // look identical; this fixture has a non-empty one so the column is exercised.
  for (const e of report.ledger.posted.entries) {
    assert.equal(ACCOUNTS.reduce((n, a) => n + e[a], 0), e.declared);
    assert.equal(e.unresolved, 1);
  }
});

test('a balanced v1 bundle verifies clean', () => {
  const r = run(VERIFY, ['--bundle', join(BUNDLES, 'v1-balanced'), '--json']);
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  const [b] = JSON.parse(r.stdout);
  assert.equal(b.verdict, 'VERIFIED_CLEAN');
  assert.ok(b.checked.includes('artifact.sha256'));
  assert.ok(b.checked.includes('ledger'));
});

test('an unbalanced v1 record is VG-ART-064 and exits 2', () => {
  const r = record('v1-unbalanced.json');
  assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
  assert.deepEqual(ids(r.report), ['VG-ART-064', 'VG-ART-064']);
  const detail = r.report.findings.map((f) => f.detail).join(' ');
  assert.match(detail, /demo\.stackprot/);
  assert.match(detail, /opens 4 account\(s\) here and present \+ absent \+ unobserved \+ unresolved posts 3/);
  // The point of this fixture: `unresolved[]` is NOT empty, so VG-ART-059 —
  // the only instrument that existed before — stays silent while the ledger
  // catches it. The entry names a checkpoint the run did not plan, and an
  // entry that settles no planned cell settles nothing.
  assert.ok(!ids(r.report).includes('VG-ART-059'), 'VG-ART-059 fired; this fixture is meant to slip past it');
  // The record's own totals agreed with the recomputation. It kept honest books
  // that did not balance, which is a different complaint from keeping wrong ones.
  assert.ok(r.report.checked.includes('ledger.entries'));
});

test('a v1 record with no ledger block exits 3, not 0', () => {
  const r = record('v1-no-ledger.json');
  assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
  assert.deepEqual(r.report.findings, []);
  assert.deepEqual(r.report.unchecked, ['ledger']);
  assert.equal(r.report.ledger.checkable, false);
  assert.match(r.report.ledger.why, /carries no usable ledger block/);
});

test('a record that lists only the properties it observed must fail', () => {
  // The anti-theatre test. Four declared, two carried, and the two that are
  // carried are internally consistent with each other and with the record's own
  // ledger entries. Taking the denominator from `properties.length` makes every
  // line of this record add up.
  const r = record('v1-observed-only.json');
  assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
  assert.deepEqual(ids(r.report), ['VG-ART-064', 'VG-ART-064']);
  assert.match(r.report.findings[0].detail, /demo\.stackprot/);
  assert.equal(r.report.ledger.posted.declaredPropertyCount, 4);
});

test('the denominator is the declaration, not properties.length', () => {
  // The same claim as the test above, in arithmetic rather than through a CLI,
  // so that a future refactor that reintroduces `properties.length` fails here
  // with a message that says which number went wrong.
  const rec = load(join(RECORDS, 'v1-observed-only.json'));
  const audit = auditLedger(rec);
  assert.equal(rec.properties.length, 2);
  assert.equal(audit.posted.declaredPropertyCount, 4);
  for (const e of audit.posted.entries) {
    assert.equal(e.declared, 4, `${e.checkpoint} was counted against ${e.declared} accounts`);
    assert.equal(ACCOUNTS.reduce((n, a) => n + e[a], 0), 3);
  }
  assert.equal(audit.imbalances.length, 2);
});

test("the record's own ledger disagreeing with the recomputed one is its own finding", () => {
  const r = record('v1-ledger-disagrees.json');
  assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
  assert.deepEqual(ids(r.report), ['VG-ART-065']);
  assert.match(r.report.findings[0].detail, /the ledger says present=2, the recomputation gives 1/);
  // The books balance; only the summary is wrong. The two findings are separate
  // because they say different things about the producer.
  assert.ok(r.report.checked.includes('ledger'));
});

test('a property the declaration never opened an account for is VG-ART-066', () => {
  const r = record('v1-undeclared.json');
  assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
  assert.deepEqual(ids(r.report), ['VG-ART-066']);
  assert.match(r.report.findings[0].detail, /demo\.rop/);
  assert.ok(r.report.checked.includes('ledger'), 'the declared accounts still balance');
});

test("the record's own declaration cannot catch a record that shrank both books", () => {
  // Exit 0, deliberately. Stated in the README as the limit this design has and
  // pinned here so that nobody later reports it as a pass the check earned.
  const r = record('v1-shrunk-declaration.json');
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  assert.deepEqual(r.report.findings, []);
  assert.equal(r.report.ledger.source, 'record');
});

test('an outside declaration catches the record that shrank both books', () => {
  const r = record('v1-shrunk-declaration.json', ['--declared', join(DECLS, 'four-properties.json')]);
  assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
  assert.equal(r.report.ledger.source, 'external');
  const seen = ids(r.report);
  assert.ok(seen.includes('VG-ART-064'), `ids: ${seen.join(', ')}`);
  assert.ok(seen.includes('VG-ART-067'), `ids: ${seen.join(', ')}`);
  assert.match(
    r.report.findings.map((f) => f.detail).join(' '),
    /the record does not declare \["demo\.fortify","demo\.stackprot"\]/,
  );
});

test('a manifest that declares the accounts is the declaration in force', () => {
  const r = run(VERIFY, ['--bundle', join(BUNDLES, 'v1-manifest-declared'), '--json']);
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  const [b] = JSON.parse(r.stdout);
  assert.equal(b.verdict, 'VERIFIED_CLEAN');
  assert.equal(b.ledger.source, 'manifest');
  assert.ok(b.checked.includes('ledger.declaration'), `checked: ${b.checked.join(', ')}`);
});

test('an outside declaration checks the balance of a record with no ledger block', () => {
  // The two halves of `ledger` are separable and are reported separately. The
  // balance is checkable from an outside declaration alone, so it is checked
  // and it holds; the record's own tally and its own declaration are not there
  // to be compared with, so they are UNCHECKED. The run still exits 3, because
  // a v1 record that omits a field its schema has is not a record that passed.
  const r = record('v1-no-ledger.json', ['--declared', join(DECLS, 'four-properties.json')]);
  assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
  assert.deepEqual(r.report.findings, []);
  assert.ok(r.report.checked.includes('ledger'));
  assert.deepEqual(r.report.unchecked, ['ledger.entries', 'ledger.declaration']);
  assert.equal(r.report.ledger.source, 'external');
  assert.equal(r.report.ledger.imbalances.length, 0);
});

test('a ledger block that is not an object is UNCHECKED, not silently skipped', () => {
  const rec = load(join(BUNDLES, 'v1-balanced', 'evidence.json'));
  const audit = auditLedger({ ...rec, ledger: 'nope' });
  assert.equal(audit.checkable, false);
  assert.match(audit.why, /no usable ledger block/);
});

test('a declaration that cannot be read is exit 3, never a fall back to the record', () => {
  const r = run(VERIFY, [
    '--record',
    join(RECORDS, 'v1-shrunk-declaration.json'),
    '--declared',
    join(DECLS, 'there-is-no-such-file.json'),
  ]);
  assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
  assert.match(`${r.stdout}${r.stderr}`, /cannot read the declaration/);
});

// ── The arithmetic, without a subprocess ────────────────────────────────────

test('UNOBSERVED posts to its own account and never to absent', () => {
  // interfaces.md §3: "we did not see it" and "it is not there" are different
  // claims. Here that is an arithmetic fact about two different columns.
  const rec = load(join(BUNDLES, 'v1-balanced', 'evidence.json'));
  const audit = auditLedger(rec);
  const pre = audit.posted.entries.find((e) => e.checkpoint === 'ir-pre');
  assert.equal(pre.unobserved, 1);
  assert.equal(pre.absent, 0);
  const cell = audit.posted.cells.find((c) => c.propertyId === 'demo.fortify' && c.checkpoint === 'ir-pre');
  assert.equal(cell.account, 'unobserved');
});

test('an unresolved entry that names no checkpoint settles nothing', () => {
  assert.equal(unresolvedCovers({ propertyId: 'p', reason: 'because' }, 'p', 'ir-pre'), false);
  assert.equal(unresolvedCovers({ propertyId: 'p', checkpoint: 'ir-pre' }, 'p', 'ir-pre'), true);
  assert.equal(unresolvedCovers({ propertyId: 'p', checkpoints: ['ir-pre'] }, 'p', 'ir-post'), false);
  assert.equal(unresolvedCovers({ propertyId: 'q', checkpoint: 'ir-pre' }, 'p', 'ir-pre'), false);
});

test('a verdict outside the three lands in no account and is named', () => {
  const declaration = readDeclaration(
    { plannedCheckpoints: ['ir-pre'], properties: [{ propertyId: 'p' }] },
    'test',
  );
  const posted = postLedger(
    { properties: [{ propertyId: 'p', states: [{ checkpoint: 'ir-pre', verdict: 'MAYBE' }] }], unresolved: [] },
    declaration,
  );
  assert.equal(posted.entries[0].present + posted.entries[0].absent + posted.entries[0].unobserved, 0);
  assert.equal(posted.unaccounted.length, 1);
  assert.match(posted.unaccounted[0].reason, /"MAYBE"/);
});

test('a property carried twice posts its cell twice, so it is refused instead', () => {
  const declaration = readDeclaration(
    { plannedCheckpoints: ['ir-pre'], properties: [{ propertyId: 'p' }] },
    'test',
  );
  const posted = postLedger(
    {
      properties: [
        { propertyId: 'p', states: [{ checkpoint: 'ir-pre', verdict: 'PRESENT' }] },
        { propertyId: 'p', states: [{ checkpoint: 'ir-pre', verdict: 'ABSENT' }] },
      ],
      unresolved: [],
    },
    declaration,
  );
  assert.equal(posted.unaccounted.length, 1);
  assert.match(posted.unaccounted[0].reason, /more than once/);
});

test('a property may narrow the planned checkpoints and may not widen them', () => {
  const narrowed = readDeclaration(
    {
      plannedCheckpoints: ['ir-pre', 'ir-post'],
      properties: [{ propertyId: 'p' }, { propertyId: 'q', plannedCheckpoints: ['ir-pre'] }],
    },
    'test',
  );
  const posted = postLedger({ properties: [], unresolved: [] }, narrowed);
  assert.equal(posted.entries.find((e) => e.checkpoint === 'ir-pre').declared, 2);
  assert.equal(posted.entries.find((e) => e.checkpoint === 'ir-post').declared, 1);
  assert.throws(
    () =>
      readDeclaration(
        { plannedCheckpoints: ['ir-pre'], properties: [{ propertyId: 'q', plannedCheckpoints: ['asm'] }] },
        'test',
      ),
    DeclarationError,
  );
});

test('a declaration with no accounts is refused rather than balanced against', () => {
  // A ledger with nothing in it balances for every record ever written, which
  // is the empty-input-set bug that counting.mjs exists for, one layer in.
  for (const bad of [
    {},
    { plannedCheckpoints: [], properties: [{ propertyId: 'p' }] },
    { plannedCheckpoints: ['ir-pre'], properties: [] },
    { plannedCheckpoints: ['ir-pre', 'ir-pre'], properties: [{ propertyId: 'p' }] },
    { plannedCheckpoints: ['ir-pre'], properties: [{ propertyId: 'p' }, { propertyId: 'p' }] },
    { plannedCheckpoints: ['ir-pre'], properties: [{}] },
  ]) {
    assert.throws(() => readDeclaration(bad, 'test'), DeclarationError, JSON.stringify(bad));
  }
});

test('a declaration document that says it is something else is refused', () => {
  assert.throws(
    () =>
      readDeclaration(
        { schemaVersion: 'policy-v0', plannedCheckpoints: ['ir-pre'], properties: [{ propertyId: 'p' }] },
        'external',
      ),
    DeclarationError,
  );
  // A manifest's `declares` block and the record's own pair of fields carry no
  // version and must stay readable.
  assert.equal(
    readDeclaration({ plannedCheckpoints: ['ir-pre'], properties: [{ propertyId: 'p' }] }, 'manifest')
      .properties.length,
    1,
  );
});

test('a v1 record whose declaration is unusable is UNCHECKED, not clean and not a finding', () => {
  const rec = load(join(BUNDLES, 'v1-balanced', 'evidence.json'));
  rec.declaredProperties = [];
  const audit = auditLedger(rec);
  assert.equal(audit.checkable, false);
  assert.match(audit.why, /lists no properties/);
});

// ── Four verdicts that were bought by writing less ──────────────────────────
//
// Each test below starts from a fixture that verified clean and differs from it
// by one field. None of them is a hypothetical: every one was built against this
// verifier and exited 0 before the check it now fails.

test('a ledger of checkpoint names with no counts is UNCHECKED, not CHECKED', () => {
  // `entries` carrying `[{"checkpoint":"ir-pre"},{"checkpoint":"ir-post"}]` —
  // the planned names and not one number — used to compare nothing at all and
  // still land `ledger.entries` on CHECKED, so the record exited 0. Omitting the
  // `entries` key honestly cost exit 3. That is the incentive upside down: a
  // producer escaped VERIFICATION_INCOMPLETE by writing LESS. An entry of a v1
  // ledger carries `declared` and all four accounts; what it leaves out is a
  // number nobody compared, and the block is UNCHECKED for it.
  const r = record('v1-count-free-ledger.json');
  assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
  assert.deepEqual(r.report.findings, []);
  assert.deepEqual(r.report.unchecked, ['ledger.entries']);
  // The balance itself is still checked and still holds: this fixture is
  // `v1-balanced` with the counts taken out of its own tally, nothing else.
  assert.ok(r.report.checked.includes('ledger'), `checked: ${r.report.checked.join(', ')}`);
  assert.equal(r.report.ledger.imbalances.length, 0);
});

test('an empty shell of a ledger is worth exactly what omitting it is worth', () => {
  // The rule stated as the comparison it exists to make. Writing less must never
  // answer better than writing nothing, so both land on the same list.
  const balanced = load(join(BUNDLES, 'v1-balanced', 'evidence.json'));
  const noEntries = JSON.parse(JSON.stringify(balanced));
  delete noEntries.ledger.entries;
  const omitted = auditLedger(noEntries);
  assert.equal(omitted.writtenLedger.comparable, false);
  assert.deepEqual(omitted.writtenLedger.problems, []);

  const shell = auditLedger(load(join(RECORDS, 'v1-count-free-ledger.json')));
  assert.equal(shell.writtenLedger.comparable, true);
  assert.deepEqual(shell.writtenLedger.problems, []);
  // Two checkpoints times `declared` plus the four accounts: ten numbers the
  // record did not write and nobody compared.
  assert.equal(shell.writtenLedger.uncompared.length, 10);
  assert.ok(shell.writtenLedger.uncompared.includes('ir-pre.present'));
  assert.ok(shell.writtenLedger.uncompared.includes('ir-post.declared'));

  // And one number present is one number compared: the rest stay uncompared.
  const partial = JSON.parse(JSON.stringify(balanced));
  partial.ledger.entries = [{ checkpoint: 'ir-pre', present: 2 }, { checkpoint: 'ir-post', present: 1 }];
  const some = auditLedger(partial);
  assert.deepEqual(some.writtenLedger.problems, []);
  assert.equal(some.writtenLedger.uncompared.length, 8);
  partial.ledger.entries[0].present = 99;
  assert.equal(auditLedger(partial).writtenLedger.problems.length, 1);
});

test('a property planned at no checkpoint is refused, not dropped from every column', () => {
  // `"plannedCheckpoints": []` on a declared property passed the widening check
  // vacuously, matched no checkpoint, opened no account and posted nowhere —
  // while `declaredProperties` still listed it and the report still printed the
  // full count of declared properties. It defeated the anti-theatre fixture
  // itself: `v1-observed-only` with this one key added to its two unobserved
  // properties exited 0 with no findings. A property planned nowhere is not a
  // declared property, so the declaration is refused and the ledger is UNCHECKED
  // — not a finding, because nothing was counted, which is exit 3's business.
  const r = record('v1-planned-nowhere.json');
  assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
  assert.deepEqual(r.report.findings, []);
  assert.deepEqual(r.report.unchecked, ['ledger']);
  assert.equal(r.report.ledger.checkable, false);
  assert.match(r.report.ledger.why, /demo\.fortify plans no checkpoints at all/);
  // The record still says it declared four. That is the point: the count and the
  // columns had come apart, and the count was the half that kept being printed.
  assert.equal(JSON.parse(readFileSync(join(RECORDS, 'v1-planned-nowhere.json'), 'utf8')).declaredProperties.length, 4);
  assert.throws(
    () =>
      readDeclaration(
        { plannedCheckpoints: ['ir-pre'], properties: [{ propertyId: 'p', plannedCheckpoints: [] }] },
        'test',
      ),
    DeclarationError,
  );
});

test('narrowing the plan does not take a column out of the ledger silently', () => {
  // The same defeat along the other axis: `ledger.plannedCheckpoints` cut to
  // `['ir-pre']` while both properties keep their `ir-post` states. Half of
  // every observation the record carries is then posted to no column, the two
  // remaining cells balance, and the run exited 0 with no finding. A state at a
  // checkpoint the declaration does not plan for its property is `VG-ART-068`.
  const r = record('v1-narrowed-plan.json');
  assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
  assert.deepEqual(ids(r.report), ['VG-ART-068']);
  assert.match(r.report.findings[0].detail, /demo\.authz at ir-post; demo\.erasure at ir-post/);
  assert.deepEqual(r.report.ledger.posted.offPlan, [
    { propertyId: 'demo.authz', checkpoint: 'ir-post' },
    { propertyId: 'demo.erasure', checkpoint: 'ir-post' },
  ]);
});

test('a narrowed plan whose states went with it is the disclosed limit, and an outside declaration closes it', () => {
  // Exit 0, deliberately, and for the same reason `v1-shrunk-declaration` exits
  // 0: a record that drops the checkpoint from BOTH books — the plan and the
  // states — is internally consistent, and nothing inside a document can hold
  // the document to a plan it also wrote. The second book is what closes it.
  const rec = JSON.parse(readFileSync(join(RECORDS, 'v1-narrowed-plan.json'), 'utf8'));
  for (const p of rec.properties) p.states = p.states.filter((s) => s.checkpoint !== 'ir-post');
  const unaided = auditLedger(rec);
  assert.equal(unaided.imbalances.length, 0);
  assert.deepEqual(unaided.posted.offPlan, []);

  const outside = record('v1-narrowed-plan.json', ['--declared', join(DECLS, 'four-properties.json')]);
  assert.equal(outside.status, 2, `${outside.stdout}${outside.stderr}`);
  assert.ok(ids(outside.report).includes('VG-ART-067'), `ids: ${ids(outside.report).join(', ')}`);
  assert.match(
    outside.report.findings.map((f) => f.detail).join(' '),
    /the record does not plan \["ir-post"\], which the external declaration plans/,
  );
});

test('a declaration NARROWER than the record\'s own is compared, and the extra is named', () => {
  // `testdata/declarations/two-properties.json` was written, committed and read
  // by nothing: every `--declared` test named the four-property document, which
  // is WIDER than the record, so `compareDeclarations`' `extra` branch — "the
  // record declares X, which the declaration does not" — had no test at all. The
  // narrower document exercises it, and with it the case where the record's own
  // book is the larger of the two.
  const r = run(VERIFY, [
    '--record',
    join(BUNDLES, 'v1-balanced', 'evidence.json'),
    '--declared',
    join(DECLS, 'two-properties.json'),
    '--json',
  ]);
  assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
  const report = JSON.parse(r.stdout);
  assert.equal(report.ledger.source, 'external');
  const seen = report.findings.map((f) => f.id);
  assert.ok(seen.includes('VG-ART-067'), `ids: ${seen.join(', ')}`);
  assert.match(
    report.findings.map((f) => f.detail).join(' '),
    /the record declares \["demo\.fortify","demo\.stackprot"\], which the external declaration does not/,
  );
  // The two accounts the narrow declaration opens do balance, so this is not an
  // imbalance report: it is two books that disagree about which accounts exist.
  assert.equal(report.ledger.imbalances.length, 0);
});

test('--fail-on is a gate on the exit code, not on the check, and the run says so', () => {
  // Measured rather than reasoned about. Every ledger finding is high or medium,
  // so `--fail-on critical` suppresses all of them and an unbalanced record
  // exits 0. That is what the flag means — the caller chose the threshold — but
  // a 0 that a threshold produced must not read as "nothing was found", so the
  // run prints what it suppressed. The default is `low`, where nothing is.
  const suppressed = run(VERIFY, ['--record', join(RECORDS, 'v1-unbalanced.json'), '--fail-on', 'critical']);
  assert.equal(suppressed.status, 0, `${suppressed.stdout}${suppressed.stderr}`);
  assert.match(suppressed.stdout, /VG-ART-064/);
  assert.match(
    suppressed.stdout,
    /note: 2 finding\(s\) are below --fail-on and do not change the exit code: VG-ART-064/,
  );
  const gated = run(VERIFY, ['--record', join(RECORDS, 'v1-unbalanced.json'), '--fail-on', 'high']);
  assert.equal(gated.status, 2, `${gated.stdout}${gated.stderr}`);
  assert.ok(!/below --fail-on/.test(gated.stdout), gated.stdout);
});
