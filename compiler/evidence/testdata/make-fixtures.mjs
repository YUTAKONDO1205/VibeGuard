// Rebuild every fixture under `testdata/bundles`, `testdata/records` and
// `testdata/declarations` from the record bodies written below.
//
//     node testdata/make-fixtures.mjs
//
// WHY THE FIXTURES ARE COMMITTED BYTES AND THIS IS ONLY A REBUILD
//
//   `testdata/digest-vectors.json` set the convention: expected values are
//   produced once and committed, so that a verifier is calibrated against
//   something it did not compute. The same applies here — the tests read the
//   files on disk, never what this script would produce today. Run this when a
//   fixture's CONTENT has to change; a record whose body changed needs a new
//   `evidenceDigest`, and computing one by hand is how a fixture ends up
//   asserting that a wrong digest is right.
//
//   It seals through `canon.mjs`, the generation side, exactly as a real writer
//   would. `verify.mjs` re-derives from the rules without importing it, so the
//   digest each fixture carries is a real claim the verifier has to reproduce.
//   That is why this file is a fixture BUILDER and not a fixture CHECKER.
//
// NO CLOCK IS READ HERE. `verify.mjs --clock-audit` walks this directory, and
// the context block below is pinned so that a rebuild is byte-identical.
//
// The artefact is `wipe-object.txt` and not `wipe.o` for two separate reasons,
// both of which cost a round trip to find: `.gitignore` carries
// `compiler/**/*.o`, so under the obvious name the file is never committed and
// every bundle test fails on a fresh clone with VG-ART-060; and
// `scripts/check-packaging-invariants.mjs` refuses a committable file under
// `compiler/` whose extension its egress tripwire cannot read, which rules out
// inventing an extension for it.

import { mkdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { sealRecord } from '../canon.mjs';

/** This directory. No absolute path is written down; there is nowhere to put one. */
const TD = dirname(fileURLToPath(import.meta.url));

const CONTEXT = {
  generatedAt: '2020-01-01T00:00:00.000Z',
  timeSource: 'SOURCE_DATE_EPOCH',
  sourceDateEpoch: 1577836800,
  host: { node: 'v20.0.0', platform: 'linux', arch: 'x64' },
};

const ARTIFACT = 'not-really-an-object-file-just-fixture-bytes-for-a-digest\n';
const ARTIFACT_SHA = createHash('sha256').update(Buffer.from(ARTIFACT, 'latin1')).digest('hex');

const TOOLCHAIN = {
  digest: '0'.repeat(64),
  clang: '18.1.3',
  packages: [{ name: 'llvm-18-dev', version: '18.1.3' }],
};
const COMMAND = { argv: ['cc', '-O2', '-c', '-o', 'build/wipe.o', 'src/wipe.c'] };
// NOT named wipe.o: .gitignore line 100 is `compiler/**/*.o`, so an artefact
// fixture under that name is never committed and every bundle test fails on a
// fresh clone with VG-ART-060, and .txt because check-packaging-invariants.mjs
// refuses an extension its egress tripwire cannot read. The bytes are ASCII
// file; nothing here parses them, only hashes them.
const ART = { path: 'artifact/wipe-object.txt', sha256: ARTIFACT_SHA, kind: 'object' };

const erasure = () => ({
  propertyId: 'demo.erasure',
  states: [
    { checkpoint: 'ir-pre', verdict: 'PRESENT', state: 'PRESENT', measurement: 'OK', effect: 1, control: 1 },
    { checkpoint: 'ir-post', verdict: 'ABSENT', state: 'LOST', measurement: 'OK', effect: 0, control: 1 },
  ],
  firstLoss: { stage: 'ir-pass', pass: 'DemoPass', unit: 'wipe', occurrence: 1 },
  agreement: { level: 'single', methods: ['ir'], reportedUnits: { ir: 'wipe' } },
  confidence: 'provisional',
  fragility: { lost: 1, evaluated: 4 },
});
const authz = () => ({
  propertyId: 'demo.authz',
  states: [
    { checkpoint: 'ir-pre', verdict: 'PRESENT', state: 'PRESENT', measurement: 'OK', effect: 1, control: 1 },
    { checkpoint: 'ir-post', verdict: 'PRESENT', state: 'PRESENT', measurement: 'OK', effect: 1, control: 1 },
  ],
  firstLoss: { stage: null, pass: null, unit: null, occurrence: null },
  agreement: { level: 'not-applicable', methods: ['ir'], reportedUnits: { ir: 'check' } },
  confidence: 'no-loss-observed',
  fragility: { lost: 0, evaluated: 4 },
});
const fortify = () => ({
  propertyId: 'demo.fortify',
  states: [
    { checkpoint: 'ir-pre', verdict: 'UNOBSERVED', state: 'NOT_OBSERVED', measurement: 'BROKEN_MEASUREMENT', effect: null, control: null },
    { checkpoint: 'ir-post', verdict: 'UNOBSERVED', state: 'NOT_OBSERVED', measurement: 'BROKEN_MEASUREMENT', effect: null, control: null },
  ],
  firstLoss: { stage: null, pass: null, unit: null, occurrence: null },
  agreement: { level: 'none', methods: [], reportedUnits: {} },
  confidence: 'unresolved',
  fragility: { lost: 0, evaluated: 0 },
});
const rop = () => ({
  propertyId: 'demo.rop',
  states: [
    { checkpoint: 'ir-pre', verdict: 'PRESENT', state: 'PRESENT', measurement: 'OK', effect: 1, control: 1 },
    { checkpoint: 'ir-post', verdict: 'PRESENT', state: 'PRESENT', measurement: 'OK', effect: 1, control: 1 },
  ],
  firstLoss: { stage: null, pass: null, unit: null, occurrence: null },
  agreement: { level: 'not-applicable', methods: ['ir'], reportedUnits: { ir: 'gadget' } },
  confidence: 'no-loss-observed',
  fragility: { lost: 0, evaluated: 4 },
});

const base = (extra) => ({
  schemaVersion: 'evidence-v0',
  toolchain: TOOLCHAIN,
  command: COMMAND,
  artifact: ART,
  ...extra,
});

const DECL4 = [
  { propertyId: 'demo.erasure' },
  { propertyId: 'demo.authz' },
  { propertyId: 'demo.fortify' },
  { propertyId: 'demo.stackprot' },
];
const PLANNED = ['ir-pre', 'ir-post'];

const ledger = (entries, declarationSource = 'policy') => ({
  declarationSource,
  plannedCheckpoints: PLANNED,
  entries,
});

const BALANCED_ENTRIES = [
  { checkpoint: 'ir-pre', declared: 4, present: 2, absent: 0, unobserved: 1, unresolved: 1 },
  { checkpoint: 'ir-post', declared: 4, present: 1, absent: 1, unobserved: 1, unresolved: 1 },
];

const recs = {};

// evidence-v0 regression fixtures.
recs['bundles/v0-complete/evidence.json'] = base({
  coverage: { observed: 4, planned: 4 },
  properties: [erasure(), authz()],
  unresolved: [],
});

const v0Unchecked = base({ properties: [erasure(), authz()], unresolved: [] });
recs['records/v0-unchecked.json'] = v0Unchecked;

const v0Finding = base({
  coverage: { observed: 4, planned: 4 },
  properties: [erasure(), authz()],
  unresolved: [],
});
v0Finding.properties[0].confidence = 'confirmed';
recs['records/v0-finding.json'] = v0Finding;

// evidence-v1 fixtures.
const v1 = (extra) => ({ ...base({}), schemaVersion: 'evidence-v1', ...extra });

recs['bundles/v1-balanced/evidence.json'] = v1({
  coverage: { observed: 4, planned: 8 },
  declaredProperties: DECL4,
  ledger: ledger(BALANCED_ENTRIES),
  properties: [erasure(), authz(), fortify()],
  unresolved: [
    {
      propertyId: 'demo.stackprot',
      checkpoints: PLANNED,
      reason: 'the observer for this property never registered, so neither planned checkpoint was reached',
    },
  ],
});

recs['records/v1-unbalanced.json'] = v1({
  coverage: { observed: 4, planned: 8 },
  declaredProperties: DECL4,
  ledger: ledger([
    { checkpoint: 'ir-pre', declared: 4, present: 2, absent: 0, unobserved: 1, unresolved: 0 },
    { checkpoint: 'ir-post', declared: 4, present: 1, absent: 1, unobserved: 1, unresolved: 0 },
  ]),
  properties: [erasure(), authz(), fortify()],
  unresolved: [
    {
      propertyId: 'demo.stackprot',
      checkpoints: ['asm'],
      reason: 'booked against a checkpoint this run did not plan, so it settles none of the planned cells',
    },
  ],
});

recs['records/v1-no-ledger.json'] = v1({
  coverage: { observed: 4, planned: 8 },
  declaredProperties: DECL4,
  properties: [erasure(), authz(), fortify()],
  unresolved: [
    { propertyId: 'demo.stackprot', checkpoints: PLANNED, reason: 'the observer for this property never registered' },
  ],
});

recs['records/v1-observed-only.json'] = v1({
  coverage: { observed: 4, planned: 8 },
  declaredProperties: DECL4,
  ledger: ledger([
    { checkpoint: 'ir-pre', declared: 4, present: 2, absent: 0, unobserved: 0, unresolved: 1 },
    { checkpoint: 'ir-post', declared: 4, present: 1, absent: 1, unobserved: 0, unresolved: 1 },
  ]),
  properties: [erasure(), authz()],
  unresolved: [
    { propertyId: 'demo.fortify', checkpoints: PLANNED, reason: 'the observer never registered' },
  ],
});

recs['records/v1-shrunk-declaration.json'] = v1({
  coverage: { observed: 4, planned: 4 },
  declaredProperties: [{ propertyId: 'demo.erasure' }, { propertyId: 'demo.authz' }],
  ledger: ledger([
    { checkpoint: 'ir-pre', declared: 2, present: 2, absent: 0, unobserved: 0, unresolved: 0 },
    { checkpoint: 'ir-post', declared: 2, present: 1, absent: 1, unobserved: 0, unresolved: 0 },
  ]),
  properties: [erasure(), authz()],
  unresolved: [],
});

recs['records/v1-ledger-disagrees.json'] = v1({
  coverage: { observed: 4, planned: 8 },
  declaredProperties: DECL4,
  ledger: ledger([
    { checkpoint: 'ir-pre', declared: 4, present: 2, absent: 0, unobserved: 1, unresolved: 1 },
    { checkpoint: 'ir-post', declared: 4, present: 2, absent: 0, unobserved: 1, unresolved: 1 },
  ]),
  properties: [erasure(), authz(), fortify()],
  unresolved: [
    { propertyId: 'demo.stackprot', checkpoints: PLANNED, reason: 'the observer for this property never registered' },
  ],
});

recs['records/v1-undeclared.json'] = v1({
  coverage: { observed: 6, planned: 8 },
  declaredProperties: DECL4,
  ledger: ledger(BALANCED_ENTRIES),
  properties: [erasure(), authz(), fortify(), rop()],
  unresolved: [
    { propertyId: 'demo.stackprot', checkpoints: PLANNED, reason: 'the observer for this property never registered' },
  ],
});

// Four fixtures for four ways a record bought a cleaner verdict than it had
// earned. Each one is a record that exited 0 before the check that now answers
// it, and each differs from a fixture above by one field.

// (a) A ledger block carrying the planned checkpoint names and not one count.
// Everything else is `v1-balanced`, so nothing but the rule that a number
// nobody wrote is a number nobody compared stands between it and exit 0.
// Omitting `entries` costs exit 3; this must not cost less.
recs['records/v1-count-free-ledger.json'] = v1({
  coverage: { observed: 4, planned: 8 },
  declaredProperties: DECL4,
  ledger: {
    declarationSource: 'policy',
    plannedCheckpoints: PLANNED,
    entries: [{ checkpoint: 'ir-pre' }, { checkpoint: 'ir-post' }],
  },
  properties: [erasure(), authz(), fortify()],
  unresolved: [
    { propertyId: 'demo.stackprot', checkpoints: PLANNED, reason: 'the observer for this property never registered' },
  ],
});

// (b) Two of the four declared properties are planned at NO checkpoint. They
// stay in `declaredProperties`, so the record still says it declared four,
// while an empty `plannedCheckpoints` matches no checkpoint and opens no
// account: the two the run did not carry drop out of every column and the
// remaining two balance. It is `v1-observed-only` with one key added per
// property, and it must not answer better than `v1-observed-only` does.
recs['records/v1-planned-nowhere.json'] = v1({
  coverage: { observed: 4, planned: 4 },
  declaredProperties: [
    { propertyId: 'demo.erasure' },
    { propertyId: 'demo.authz' },
    { propertyId: 'demo.fortify', plannedCheckpoints: [] },
    { propertyId: 'demo.stackprot', plannedCheckpoints: [] },
  ],
  ledger: ledger([
    { checkpoint: 'ir-pre', declared: 2, present: 2, absent: 0, unobserved: 0, unresolved: 0 },
    { checkpoint: 'ir-post', declared: 2, present: 1, absent: 1, unobserved: 0, unresolved: 0 },
  ]),
  properties: [erasure(), authz()],
  unresolved: [],
});

// (c) The same trick along the other axis: the plan is narrowed to `ir-pre`
// while both properties keep their `ir-post` states. Half of every property's
// observations are then posted to no column, and the ledger balances over what
// is left. The record still carries the states, so the check has something to
// notice; a record that dropped those too is the disclosed limit and is
// `v1-shrunk-declaration` one axis over.
recs['records/v1-narrowed-plan.json'] = v1({
  coverage: { observed: 4, planned: 4 },
  declaredProperties: [{ propertyId: 'demo.erasure' }, { propertyId: 'demo.authz' }],
  ledger: {
    declarationSource: 'policy',
    plannedCheckpoints: ['ir-pre'],
    entries: [{ checkpoint: 'ir-pre', declared: 2, present: 2, absent: 0, unobserved: 0, unresolved: 0 }],
  },
  properties: [erasure(), authz()],
  unresolved: [],
});

recs['bundles/v1-manifest-declared/evidence.json'] = v1({
  coverage: { observed: 4, planned: 8 },
  declaredProperties: DECL4,
  ledger: ledger(BALANCED_ENTRIES, 'manifest'),
  properties: [erasure(), authz(), fortify()],
  unresolved: [
    {
      propertyId: 'demo.stackprot',
      checkpoints: PLANNED,
      reason: 'the observer for this property never registered, so neither planned checkpoint was reached',
    },
  ],
});

// (d) `v1-unbalanced` relabelled to a version this verifier does not know, and
// resealed so that the digest is right for the bytes. Its content is two
// unaccounted cells; the label alone must not turn that into exit 0 on any
// entry point. Built from the record above so the two can never drift apart.
recs['records/v2-relabelled.json'] = {
  ...JSON.parse(JSON.stringify(recs['records/v1-unbalanced.json'])),
  schemaVersion: 'evidence-v2',
};

const written = {};
for (const [rel, rec] of Object.entries(recs)) {
  const sealed = sealRecord(rec, { context: CONTEXT });
  const p = join(TD, rel);
  mkdirSync(join(p, '..'), { recursive: true });
  writeFileSync(p, JSON.stringify(sealed, null, 2) + '\n', 'utf8');
  written[rel] = sealed.evidenceDigest;
}

for (const b of ['v0-complete', 'v1-balanced', 'v1-manifest-declared']) {
  mkdirSync(join(TD, 'bundles', b, 'artifact'), { recursive: true });
  writeFileSync(join(TD, 'bundles', b, 'artifact', 'wipe-object.txt'), ARTIFACT, 'latin1');
  const man = {
    schemaVersion: 'evidence-bundle-v0',
    evidenceDigest: written['bundles/' + b + '/evidence.json'],
  };
  if (b === 'v1-manifest-declared') {
    man.declares = { plannedCheckpoints: PLANNED, properties: DECL4 };
  }
  writeFileSync(join(TD, 'bundles', b, 'manifest.json'), JSON.stringify(man, null, 2) + '\n', 'utf8');
}

mkdirSync(join(TD, 'declarations'), { recursive: true });
writeFileSync(
  join(TD, 'declarations', 'four-properties.json'),
  JSON.stringify({ schemaVersion: 'evidence-declaration-v1', plannedCheckpoints: PLANNED, properties: DECL4 }, null, 2) + '\n',
  'utf8',
);
writeFileSync(
  join(TD, 'declarations', 'two-properties.json'),
  JSON.stringify(
    {
      schemaVersion: 'evidence-declaration-v1',
      plannedCheckpoints: PLANNED,
      properties: [{ propertyId: 'demo.erasure' }, { propertyId: 'demo.authz' }],
    },
    null,
    2,
  ) + '\n',
  'utf8',
);

console.log(JSON.stringify({ artifactSha: ARTIFACT_SHA, written }, null, 2));
