// `policy.fallback.profile: "auto"` — reading the level out of a measured table
// instead of taking one on faith from a policy file.
//
// Like fallback.test.mjs, none of this spawns a compiler: `auto` is resolved
// before anything is built, so every decision here is reachable on any host,
// and the `compiler` handed in below is a name that does not exist so that a
// case which somehow reached a spawn fails instead of quietly measuring.
//
// The tables are written by hand rather than produced by
// tools/derive-fallback-table.mjs. The generator and this reader agree on a
// contract, and a test that fed the reader the generator's output would go
// green whenever the two drifted together — which is the failure the contract
// exists to stop.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { normalise } from '../lib/cmdline.mjs';
import {
  AUTO_PROFILE, DRIVER_KNOWN_AXES, FALLBACK_TABLE_SCHEMA_VERSION, driverConfigAxes, evaluateFallback,
  readFallbackPolicy, resolveAutoProfile, shippingOptLevel,
} from '../lib/fallback.mjs';
import { findAbsolutePaths } from '../lib/paths.mjs';

const NOWHERE = 'clang-that-must-never-be-spawned';
const PROP = 'survive.authorization-check';
const OTHER = 'survive.key-erasure';

const ENVELOPE_TEXT = '{"schemaVersion":"security-configuration-envelope-v0","cells":[]}\n';
const ENVELOPE_SHA = createHash('sha256').update(ENVELOPE_TEXT).digest('hex');

/** One `fallback` row of the contract, with the fields the reader looks at. */
function row({ propertyId = PROP, opt = '-O2', to = '-O0', resolution = 'fallback' } = {}) {
  const from = { cc: 'clang-18', freestanding: false, lto: 'none', ndebug: false, opt, target: 'host' };
  return {
    evidence: [{ cellId: `subject+opt=${to}`, controlHeld: true, measurement: 'OK', state: 'PRESENT', subject: 'authz-folded' }],
    from,
    lostSubjects: ['authz-folded'],
    profile: resolution === 'fallback' ? to : null,
    propertyId,
    rejected: [],
    resolution,
    to: resolution === 'fallback' ? { ...from, opt: to } : null,
  };
}

function tableDoc(rows, { sha256 = ENVELOPE_SHA, path = 'envelope.json', schemaVersion = FALLBACK_TABLE_SCHEMA_VERSION } = {}) {
  return {
    anomalies: [],
    counts: { cells: 74, controlCells: 2, lostCells: rows.length, rows: rows.length },
    generator: { name: 'derive-fallback-table', version: '1' },
    policy: { direction: 'weaken-only' },
    rows,
    schemaVersion,
    source: { cells: 74, path, schemaVersion: 'security-configuration-envelope-v0', sha256 },
  };
}

/**
 * A policy directory with a table in it. `envelope` decides whether the file
 * the table claims to come from is on disk at all, which is the difference
 * between checking staleness and recording that it could not be checked.
 */
function withRoot(t, { table, envelope = null, tableText = null } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'vg-fb-auto-'));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  if (tableText !== null) writeFileSync(join(root, 'table.json'), tableText);
  else if (table !== undefined) writeFileSync(join(root, 'table.json'), JSON.stringify(table, null, 2));
  if (envelope !== null) writeFileSync(join(root, 'envelope.json'), envelope);
  return root;
}

function policyFor(fallback, { properties = [{ id: PROP, kind: 'must-survive' }], flags } = {}) {
  const p = { failOn: 'high', policyVersion: 'policy-v0', properties, fallback };
  if (flags) p.flags = flags;
  return p;
}

function ctx(root, policy, argv = ['-c', 'guard.c', '-O2'], extra = {}) {
  return {
    blocked: null,
    compiler: NOWHERE,
    compilerArgv: argv,
    cwd: root,
    env: {},
    normalised: normalise(argv, { mode: 'c' }),
    observer: null,
    policy,
    root,
    workDir: 'work-dir-never-written',
    ...extra,
  };
}

const AUTO = { enabled: true, profile: AUTO_PROFILE, profileTable: 'table.json' };

// ---------------------------------------------------------------------------
// What the driver is allowed to match on
// ---------------------------------------------------------------------------

test('the axes matched on are the ones cmdline.mjs normalises, and that is opt alone', () => {
  // If this list ever grows, the growth has to come with a rule in cmdline.mjs
  // that recovers the axis from a command line — not with a convention about
  // what an absent flag probably meant.
  assert.deepEqual([...DRIVER_KNOWN_AXES], ['opt']);
  assert.deepEqual(driverConfigAxes(normalise(['-c', 'a.c', '-O2'])), { opt: '-O2' });
  // Last -O wins, and no -O is -O0 — clang's own rule, and the same one the
  // record's `shippingProfile` uses.
  assert.equal(shippingOptLevel(normalise(['-c', 'a.c', '-O3', '-O1'])), '-O1');
  assert.equal(shippingOptLevel(normalise(['-c', 'a.c'])), '-O0');
});

// ---------------------------------------------------------------------------
// The positive case. Without it every assertion below is satisfied by a
// resolver that refuses unconditionally, because refusing is the safe answer.
// ---------------------------------------------------------------------------

test('a table with a matching row resolves auto to the level it measured', (t) => {
  const root = withRoot(t, { table: tableDoc([row({ to: '-O0' })]), envelope: ENVELOPE_TEXT });
  const r = resolveAutoProfile({
    normalised: normalise(['-c', 'guard.c', '-O2']), requested: [PROP], root, tablePath: 'table.json',
  });
  assert.equal(r.ok, true);
  assert.equal(r.profile, '-O0');
  assert.equal(r.record.error, null);
  assert.equal(r.record.envelopeCheck, 'matched');
  assert.equal(r.record.table.path, 'table.json');
  assert.equal(r.record.table.schemaVersion, FALLBACK_TABLE_SCHEMA_VERSION);
  assert.match(r.record.table.sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(r.record.matchedOn, { opt: '-O2' });
  // The five axes of the table's key the driver could not read are named, so
  // that the looseness of the match is in the record rather than implied by it.
  assert.deepEqual(r.record.unmatchedAxes, ['cc', 'freestanding', 'lto', 'ndebug', 'target']);
  assert.deepEqual(r.record.rows, [{
    from: { cc: 'clang-18', freestanding: false, lto: 'none', ndebug: false, opt: '-O2', target: 'host' },
    profile: '-O0',
    propertyId: PROP,
    resolution: 'fallback',
    to: { cc: 'clang-18', freestanding: false, lto: 'none', ndebug: false, opt: '-O0', target: 'host' },
  }]);
});

test('evaluateFallback carries the resolved level into the record, and says it came from the table', (t) => {
  const root = withRoot(t, { table: tableDoc([row({ to: '-O0' })]), envelope: ENVELOPE_TEXT });
  const r = evaluateFallback(ctx(root, policyFor(AUTO)));

  // `-O0`, not `auto`: the word was spent during resolution and never travels.
  assert.equal(r.record.profile, '-O0');
  assert.equal(r.record.profileSource, 'auto');
  assert.equal(r.record.profileResolution.rows[0].propertyId, PROP);
  assert.equal(r.record.profileResolution.rows[0].resolution, 'fallback');
  assert.equal(r.record.profileResolution.table.path, 'table.json');

  // And resolution really succeeded: the run stopped at the NEXT unmet
  // precondition, which on this context is the missing observer. Any auto
  // failure would have reported its own reason here instead.
  assert.equal(r.record.reason, 'no-observer');
});

test('the resolved level is a real flag downstream, not a word that looks like one', (t) => {
  // `flags.optLevels` is checked against `fb.profile` after resolution. The
  // policy has been evaluated only at -O2, the table answers -O0, and the
  // pre-existing VG-CFG-003 rule refuses it — which it could only do if what
  // reached that check was the string `-O0`.
  const root = withRoot(t, { table: tableDoc([row({ to: '-O0' })]), envelope: ENVELOPE_TEXT });
  const r = evaluateFallback(ctx(root, policyFor(AUTO, { flags: { optLevels: ['-O2'] } })));
  assert.equal(r.record.reason, 'profile-not-in-evaluated-opt-levels');
  assert.match(r.findings[0].detail, /policy\.fallback\.profile is -O0/);
  assert.equal(r.record.profileSource, 'auto');

  // The same policy with -O0 evaluated gets past that check.
  const ok = evaluateFallback(ctx(root, policyFor(AUTO, { flags: { optLevels: ['-O2', '-O0'] } })));
  assert.equal(ok.record.reason, 'no-observer');
});

test('an envelope that is not on this machine is a skipped check, not a passed one', (t) => {
  const root = withRoot(t, { table: tableDoc([row()]) }); // no envelope written
  const r = resolveAutoProfile({
    normalised: normalise(['-c', 'guard.c', '-O2']), requested: [PROP], root, tablePath: 'table.json',
  });
  assert.equal(r.ok, true);
  assert.equal(r.record.envelopeCheck, 'skipped-envelope-not-present');
});

test('rows for properties the policy did not declare are not matched', (t) => {
  const root = withRoot(t, { table: tableDoc([row({ propertyId: OTHER })]) });
  const r = resolveAutoProfile({
    normalised: normalise(['-c', 'guard.c', '-O2']), requested: [PROP], root, tablePath: 'table.json',
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'fallback-no-matching-row');
});

// ---------------------------------------------------------------------------
// The refusals, each with its own name
// ---------------------------------------------------------------------------

const REFUSALS = [
  {
    name: 'auto with no table named',
    reason: 'no-profile-table',
    fallback: { enabled: true, profile: AUTO_PROFILE },
    setup: {},
    detail: /profileTable names no table/,
  },
  {
    name: 'a table that is not on disk',
    reason: 'fallback-table-unreadable',
    setup: {},
    detail: /could not be read \(ENOENT\)/,
  },
  {
    name: 'a table that is not JSON',
    reason: 'fallback-table-unreadable',
    setup: { tableText: 'derive-fallback-table.mjs: exit 3\n' },
    detail: /is not JSON/,
  },
  {
    name: 'a table written to a schema this driver does not read',
    reason: 'fallback-table-unreadable',
    setup: { table: tableDoc([row()], { schemaVersion: 'vibeguard.fallback-table/2' }) },
    detail: /schemaVersion is "vibeguard\.fallback-table\/2"/,
  },
  {
    name: 'a table that cannot say which envelope it came from',
    reason: 'fallback-table-unreadable',
    setup: { table: tableDoc([row()], { sha256: 'not-a-digest' }) },
    detail: /source\.sha256 is not a sha-256 digest/,
  },
  {
    name: 'a table derived from an envelope that has since changed',
    reason: 'fallback-table-stale',
    setup: { table: tableDoc([row()]), envelope: '{"schemaVersion":"security-configuration-envelope-v0","cells":[1]}\n' },
    detail: /now digests to/,
  },
  {
    name: 'a table with nothing to say about this configuration',
    reason: 'fallback-no-matching-row',
    setup: { table: tableDoc([row({ opt: '-O3' })]) },
    detail: /none of them is about a must-survive property this policy declares at opt=-O2/,
  },
  {
    name: 'a row that measured every weaker configuration and found none that held',
    reason: 'fallback-resolution-no-safe-target',
    setup: { table: tableDoc([row({ resolution: 'no-safe-target' })]) },
    detail: /every weaker configuration it measured lost the property/,
  },
  {
    name: 'a row whose weaker configurations were never all measured',
    reason: 'fallback-resolution-not-observed',
    setup: { table: tableDoc([row({ resolution: 'not-observed' })]) },
    detail: /a gap in the sweep, not a level/,
  },
  {
    name: 'a row naming a level policy.fallback.profile does not admit',
    reason: 'fallback-profile-not-permitted',
    setup: { table: tableDoc([row({ opt: '-O3', to: '-O2' })]) },
    argv: ['-c', 'guard.c', '-O3'],
    detail: /admits only -O0, -O1/,
  },
  {
    name: 'a row that disagrees with itself about what it is recommending',
    reason: 'fallback-table-unreadable',
    setup: {
      table: tableDoc([{ ...row({ to: '-O0' }), to: { cc: 'clang-18', freestanding: false, lto: 'none', ndebug: false, opt: '-O1', target: 'host' } }]),
    },
    detail: /disagrees with itself/,
  },
  {
    name: 'a row whose resolution is a word the contract does not define',
    reason: 'fallback-table-unreadable',
    setup: { table: tableDoc([{ ...row(), resolution: 'probably-fine' }]) },
    detail: /is not one of fallback, no-safe-target, not-observed/,
  },
];

for (const c of REFUSALS) {
  test(`auto is refused, by name, for ${c.name}`, (t) => {
    const root = withRoot(t, c.setup);
    const policy = policyFor(c.fallback ?? AUTO);
    const r = evaluateFallback(ctx(root, policy, c.argv ?? ['-c', 'guard.c', '-O2']));

    assert.equal(r.record.reason, c.reason);
    assert.equal(r.record.status, 'unsupported');
    assert.equal(r.record.verdict, 'unsupported');
    assert.equal(r.complete, false, 'an unresolved auto must not report a complete check');
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].id, 'VG-CFG-022');
    assert.match(r.findings[0].detail, c.detail);

    // The refusal is recorded as a refusal to resolve, not as a level.
    assert.equal(r.record.profileSource, AUTO_PROFILE);
    assert.equal(r.record.profileResolution.profile, null);
    assert.equal(r.record.profileResolution.error.reason, c.reason);

    // interfaces.md §5: nothing this path writes may carry an absolute path,
    // and these details all quote a file the driver just resolved.
    assert.deepEqual(findAbsolutePaths(r.record), []);
    assert.deepEqual(findAbsolutePaths(r.findings), []);
  });
}

test('the four failures the contract names are four reason codes, not one', () => {
  // "there is no table", "the table is out of date", "the table has no row for
  // this build" and "the row says there is nowhere safe" send a reader to four
  // different places. Collapsing any pair sends them to the wrong one.
  const names = REFUSALS.map((c) => c.reason);
  assert.ok(names.includes('fallback-table-unreadable'));
  assert.ok(names.includes('fallback-table-stale'));
  assert.ok(names.includes('fallback-no-matching-row'));
  assert.notEqual(
    REFUSALS.find((c) => c.reason.startsWith('fallback-resolution-no-safe')).reason,
    REFUSALS.find((c) => c.reason.startsWith('fallback-resolution-not-obs')).reason,
    'a measured dead end and an unmeasured one are not the same finding',
  );
  assert.equal(new Set(names).size, 7);
});

test('no-safe-target is reported over not-observed when both match', (t) => {
  // The stronger claim wins. `no-safe-target` means the sweep was run and
  // answered; reporting `not-observed` on top of it would ask for a measurement
  // that already exists.
  const root = withRoot(t, {
    table: tableDoc([
      row({ propertyId: OTHER, resolution: 'not-observed' }),
      row({ propertyId: PROP, resolution: 'no-safe-target' }),
    ]),
  });
  const policy = policyFor(AUTO, {
    properties: [{ id: PROP, kind: 'must-survive' }, { id: OTHER, kind: 'must-survive' }],
  });
  assert.equal(evaluateFallback(ctx(root, policy)).record.reason, 'fallback-resolution-no-safe-target');
});

// ---------------------------------------------------------------------------
// Two properties, one recompile
// ---------------------------------------------------------------------------

test('two lost properties that need different levels cannot both be rescued, and neither is', (t) => {
  const root = withRoot(t, {
    table: tableDoc([row({ propertyId: PROP, to: '-O0' }), row({ propertyId: OTHER, to: '-O1' })]),
  });
  const policy = policyFor(AUTO, {
    properties: [{ id: PROP, kind: 'must-survive' }, { id: OTHER, kind: 'must-survive' }],
  });
  const r = evaluateFallback(ctx(root, policy));
  assert.equal(r.record.reason, 'fallback-profile-disagreement');
  assert.match(r.findings[0].detail, /name different levels \(-O0, -O1\)/);
  // Both rows are still in the record. The reason a run stopped is not improved
  // by dropping the evidence for it.
  assert.equal(r.record.profileResolution.rows.length, 2);
});

test('two lost properties that agree on a level resolve to it', (t) => {
  const root = withRoot(t, {
    table: tableDoc([row({ propertyId: PROP, to: '-O0' }), row({ propertyId: OTHER, to: '-O0' })]),
  });
  const policy = policyFor(AUTO, {
    properties: [{ id: PROP, kind: 'must-survive' }, { id: OTHER, kind: 'must-survive' }],
  });
  const r = evaluateFallback(ctx(root, policy));
  assert.equal(r.record.profile, '-O0');
  assert.equal(r.record.reason, 'no-observer');
  assert.equal(r.record.profileResolution.rows.length, 2);
});

// ---------------------------------------------------------------------------
// Nothing about the default path moved
// ---------------------------------------------------------------------------

test('a policy that never mentions fallback is untouched by any of this', () => {
  assert.deepEqual(readFallbackPolicy({ policyVersion: 'policy-v0' }), {
    configured: false, enabled: false, profile: null, rejectIfStillLost: true,
  });
  // run.mjs writes `checks.fallback` only when `configured` is true, so an
  // unconfigured policy still gets no such key and this file cannot reach it.
});

test('the reader still returns exactly its four fields, so auto added no key to it', () => {
  assert.deepEqual(readFallbackPolicy({ fallback: { enabled: true, profile: AUTO_PROFILE, profileTable: 't.json' } }), {
    configured: true, enabled: true, profile: AUTO_PROFILE, rejectIfStillLost: true,
  });
});

test('a hand-written profile is recorded as hand-written and consults no table', (t) => {
  const root = withRoot(t, {});           // deliberately no table on disk
  const r = evaluateFallback(ctx(root, policyFor({ enabled: true, profile: '-O0', profileTable: 'table.json' })));
  assert.equal(r.record.profile, '-O0');
  assert.equal(r.record.profileSource, 'policy');
  assert.equal(r.record.profileResolution, null, 'a stated level is not a lookup and must not grow a lookup record');
  assert.equal(r.record.reason, 'no-observer');
});

test('auto changes none of the refusals that come before it', (t) => {
  const root = withRoot(t, { table: tableDoc([row()]) });

  // Disabled stays disabled, and the record says `auto` because that is what
  // the policy said — nothing was resolved because nothing was attempted.
  const off = evaluateFallback(ctx(root, policyFor({ ...AUTO, enabled: false })));
  assert.deepEqual(off.findings, []);
  assert.equal(off.record.status, 'disabled');
  assert.equal(off.record.profile, AUTO_PROFILE);
  assert.equal(off.record.profileResolution, null);

  // A build already stopped is not given a second opinion, table or no table.
  const blocked = evaluateFallback(ctx(root, policyFor(AUTO), ['-c', 'guard.c', '-O2'], { blocked: 'findings-at-threshold' }));
  assert.equal(blocked.record.status, 'not-attempted');
  assert.equal(blocked.record.profileResolution, null);

  // Nothing to rescue is still reported before the table is opened.
  const nothing = evaluateFallback(ctx(root, policyFor(AUTO, { properties: [] })));
  assert.equal(nothing.record.reason, 'no-must-survive-property');
  assert.equal(nothing.record.profileResolution, null);
});

// ── two ways a table can look answerable and not be ─────────────────────────
//
// Both were found by re-reading the resolver against the real table rather than
// against the fixtures: the first fires on a two-property policy, the second on
// any row whose target moved along an axis `cmdline.mjs` does not normalise.

test('a must-survive property with no row of its own does not ride along on another', (t) => {
  // The table speaks about PROP and says nothing about OTHER. Resolving on the
  // strength of PROP alone would pick a level observed to keep one property and
  // apply it to a policy that requires two — the same substitution the table
  // refuses one level down, where it insists every *subject* of a property hold
  // at the target before the target is adopted.
  const root = withRoot(t, { table: tableDoc([row({ propertyId: PROP })]) });
  const r = resolveAutoProfile({
    normalised: normalise(['-c', 'guard.c', '-O2'], { mode: 'c' }),
    requested: [PROP, OTHER],
    root,
    tablePath: 'table.json',
  });

  assert.equal(r.ok, false);
  assert.equal(r.reason, 'fallback-property-not-in-table');
  assert.deepEqual(r.record.uncoveredProperties, [OTHER]);
  assert.match(r.detail, new RegExp(OTHER));

  // and the single-property policy the table *does* cover still resolves, so
  // the check is about coverage rather than about having two properties.
  const ok = resolveAutoProfile({
    normalised: normalise(['-c', 'guard.c', '-O2'], { mode: 'c' }),
    requested: [PROP],
    root,
    tablePath: 'table.json',
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.profile, '-O0');
});

test('a row whose target moves an axis the driver cannot apply is refused', (t) => {
  // This fallback recompiles one translation unit at a different -O level. A row
  // pointing at a different lto mode is asking for a whole-programme link
  // decision, and its evidence was measured somewhere the recompile does not go.
  // The driver cannot read lto from the command line, so it compares the row
  // against itself rather than against the build.
  const bad = row();
  bad.to = { ...bad.to, lto: 'thin-prelink' };
  const root = withRoot(t, { table: tableDoc([bad]) });

  const r = resolveAutoProfile({
    normalised: normalise(['-c', 'guard.c', '-O2'], { mode: 'c' }),
    requested: [PROP],
    root,
    tablePath: 'table.json',
  });

  assert.equal(r.ok, false);
  assert.equal(r.reason, 'fallback-row-moves-inapplicable-axis');
  assert.match(r.detail, /lto/);
  // Distinct from the row-disagrees-with-itself case, which is about `to.opt`
  // and `profile` contradicting each other rather than about the axis moved.
  assert.notEqual(r.reason, 'fallback-table-unreadable');
});
