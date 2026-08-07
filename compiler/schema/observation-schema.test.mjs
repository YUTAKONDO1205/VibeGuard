// Tests for compiler/schema/observation.schema.json and validate-observation.mjs.
//
//   node --test "compiler/schema/*.test.mjs"
//
// Passing the DIRECTORY to `node --test` throws MODULE_NOT_FOUND on this runtime.
// Always glob.
//
// Three things are checked, and the third is the one that matters:
//
//   1. Both directions. Every valid sample validates and every invalid sample
//      fails -- and each invalid sample fails for the reason it was written to
//      provoke, not incidentally. A suite that only asserts "it was rejected"
//      passes just as happily when one bug rejects everything.
//   2. The claim about the validator. validate-observation.mjs mirrors the
//      keyword set of compiler/driver/lib/jsonschema.mjs, which does not export
//      it. The mirror is probed against the real validator here rather than
//      trusted, in both directions: every mirrored keyword must be accepted and
//      a keyword deliberately left out must be refused.
//   3. The counting contract. The runner prints inputs/checked/skipped and
//      refuses an empty scan. An empty scan reporting success has happened in
//      this repository before, so it is asserted rather than assumed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validate as validateSchema } from '../driver/lib/jsonschema.mjs';
import {
  run,
  loadSchema,
  semanticErrors,
  validateDocument,
  keywordsUsedBy,
  capabilityReport,
  MIRRORED_SUPPORTED_KEYWORDS,
  EXIT_OK,
  EXIT_TOOL_FAILED,
  EXIT_INCOMPLETE,
  EXIT_INTEGRITY,
} from './validate-observation.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SAMPLES = join(HERE, 'observation-samples');
const VALID_DIR = join(SAMPLES, 'valid');
const INVALID_DIR = join(SAMPLES, 'invalid');

const schema = loadSchema();
const read = (dir, name) => {
  const raw = readFileSync(join(dir, name), 'utf8');
  return { raw, doc: JSON.parse(raw) };
};
const list = (dir) => readdirSync(dir).filter((n) => n.endsWith('.json')).sort();

/** Collects stdout/stderr from `run` so exit code AND output can be asserted. */
function capture(argv) {
  const out = [];
  const err = [];
  const code = run(argv, (m) => out.push(String(m)), (m) => err.push(String(m)));
  return { code, out: out.join('\n'), err: err.join('\n') };
}

// ── the intended failure of every invalid sample ────────────────────────────
//
// `kind` is 'schema' when the shape itself is wrong and 'semantic' when the
// shape is fine and the document is lying. `rule` is the semantic rule id, or a
// substring of the schema error. Keeping this table here rather than inside the
// samples is deliberate: a sample carrying its own expected error could not also
// be a document the schema accepts the shape of.
const EXPECTED = {
  'invalid-absolute-path-in-detail.json': ['semantic', 'OBS-S11'],
  'invalid-additional-property.json': ['schema', 'unknown property `confidence`'],
  'invalid-artifact-path-absolute.json': ['schema', '/layers/artifact/path'],
  'invalid-broken-control.json': ['semantic', 'OBS-S09'],
  'invalid-clean-lto-backend-unobserved.json': ['semantic', 'OBS-S07'],
  'invalid-clean-unobserved.json': ['semantic', 'OBS-S07'],
  'invalid-clean-with-findings.json': ['semantic', 'OBS-S07'],
  'invalid-dangling-finding-property.json': ['semantic', 'OBS-S14'],
  'invalid-dangling-point-ref.json': ['semantic', 'OBS-S01'],
  'invalid-duplicate-point-id.json': ['semantic', 'OBS-S02'],
  'invalid-empty-findings-present.json': ['semantic', 'OBS-S13'],
  'invalid-final-state-mismatch.json': ['semantic', 'OBS-S04'],
  'invalid-finding-namespace.json': ['schema', '/findings/0/id'],
  'invalid-findings-under-unsupported.json': ['semantic', 'OBS-S13'],
  'invalid-float-in-context.json': ['semantic', 'OBS-S10'],
  'invalid-history-index-out-of-order.json': ['semantic', 'OBS-S03'],
  'invalid-integer-written-as-float.json': ['semantic', 'OBS-S10'],
  'invalid-lost-without-present.json': ['semantic', 'OBS-S05'],
  'invalid-missing-required-control.json': ['schema', 'missing required property `control`'],
  'invalid-missing-required-oracle.json': ['schema', 'missing required property `oracle`'],
  'invalid-missing-required-verdict.json': ['schema', 'missing required property `verdict`'],
  'invalid-name-oracle.json': ['schema', 'must be "call-site"'],
  'invalid-truncated-history-clean.json': ['semantic', 'OBS-S06'],
  'invalid-unknown-state.json': ['schema', '/properties/0/history/3/state'],
  'invalid-unknown-verdict.json': ['schema', '/verdict/state'],
  'invalid-unreached-no-reason.json': ['semantic', 'OBS-S12'],
  'invalid-verdict-exit-mismatch.json': ['semantic', 'OBS-S08'],
};

// ── 1. the schema is really checked by the in-repo validator ────────────────

test('the schema uses no keyword the in-repo validator refuses', () => {
  const report = capabilityReport(schema);
  const missing = report.filter((r) => !r.supported).map((r) => r.keyword);
  assert.deepEqual(missing, [], `the schema would be silently half-checked on: ${missing.join(', ')}`);
  assert.ok(report.length > 8, 'the keyword walk found suspiciously little');
});

test('the mirrored keyword list matches the validator, in both directions', () => {
  // Positive: every keyword the mirror claims is supported must not be refused.
  for (const keyword of MIRRORED_SUPPORTED_KEYWORDS) {
    const probe = { [keyword]: keyword === 'type' ? 'string' : (keyword === 'required' ? [] : 'x') };
    const errors = validateSchema(probe, 'x');
    const refused = errors.filter((e) => e.message.includes('unsupported keyword'));
    assert.equal(refused.length, 0, `the mirror claims \`${keyword}\` is supported but the validator refuses it`);
  }
  // Negative: a keyword left out of the mirror must actually be refused. Without
  // this half the mirror could list every word in the language and still pass.
  for (const keyword of ['minItems', 'oneOf', 'allOf', 'if', 'format', 'uniqueItems', 'minimum']) {
    assert.ok(!MIRRORED_SUPPORTED_KEYWORDS.includes(keyword), `${keyword} should not be in the mirror`);
    const errors = validateSchema({ [keyword]: 1 }, 'x');
    const refused = errors.filter((e) => e.message.includes('unsupported keyword'));
    assert.equal(refused.length, 1, `the validator was expected to refuse \`${keyword}\` and did not`);
  }
});

test('a schema keyword the validator refuses is reported as a mismatch, not as a pass', () => {
  const grown = structuredClone(schema);
  grown.properties.findings.minItems = 1; // the keyword a maintainer would reach for
  const { doc } = read(VALID_DIR, 'valid-clean.json');
  const result = validateDocument(grown, doc);
  assert.equal(result.ok, false);
  assert.equal(result.kind, 'validator-mismatch');
  assert.match(result.errors.join('\n'), /unsupported keyword `minItems`/);
});

test('keywordsUsedBy does not mistake a property name for a keyword', () => {
  const used = keywordsUsedBy({
    type: 'object',
    properties: { minItems: { type: 'integer' }, oneOf: { type: 'string' } },
  });
  assert.deepEqual(used, ['properties', 'type']);
});

// ── 2. both directions over the samples ─────────────────────────────────────

test('every valid sample validates', () => {
  const names = list(VALID_DIR);
  assert.ok(names.length >= 5, `expected the valid corpus to exist, found ${names.length}`);
  for (const name of names) {
    const { raw, doc } = read(VALID_DIR, name);
    const result = validateDocument(schema, doc, raw);
    assert.equal(result.ok, true, `${name} should validate but did not:\n${result.errors.join('\n')}`);
  }
});

test('the valid corpus covers all five verdict states', () => {
  const seen = new Set(list(VALID_DIR).map((n) => read(VALID_DIR, n).doc.verdict.state));
  for (const state of ['VERIFIED_CLEAN', 'FINDINGS_PRESENT', 'VERIFICATION_INCOMPLETE', 'UNSUPPORTED', 'EVIDENCE_MISMATCH']) {
    assert.ok(seen.has(state), `no valid sample carries the verdict ${state}`);
  }
});

test('the valid corpus exercises the whole six-state property vocabulary', () => {
  const seen = new Set();
  for (const name of list(VALID_DIR)) {
    for (const prop of read(VALID_DIR, name).doc.properties) {
      for (const entry of prop.history) seen.add(entry.state);
    }
  }
  for (const state of ['PRESENT', 'ABSENT', 'LOST', 'REINTRODUCED', 'NOT_APPLICABLE', 'NOT_OBSERVED']) {
    assert.ok(seen.has(state), `no valid sample records the state ${state}`);
  }
});

test('a history is kept past its first loss, not truncated there', () => {
  const { doc } = read(VALID_DIR, 'valid-state-vocabulary.json');
  const states = doc.properties[0].history.map((h) => h.state);
  assert.deepEqual(states, ['PRESENT', 'LOST', 'REINTRODUCED', 'NOT_APPLICABLE', 'NOT_OBSERVED']);
  assert.equal(doc.properties[0].firstLoss.historyIndex, 1, 'the first loss is recorded as its own fact');
  assert.ok(states.length > 2, 'stopping at the first PRESENT -> LOST would have lost the reintroduction');
});

test('every invalid sample fails, and fails for the reason it was written for', () => {
  const names = list(INVALID_DIR);
  assert.ok(names.length >= 20, `expected the invalid corpus to exist, found ${names.length}`);
  const untabled = names.filter((n) => !(n in EXPECTED));
  assert.deepEqual(untabled, [], 'these invalid samples have no expected reason recorded');
  for (const name of names) {
    const { raw, doc } = read(INVALID_DIR, name);
    const result = validateDocument(schema, doc, raw);
    assert.equal(result.ok, false, `${name} validated and should not have`);
    const [kind, needle] = EXPECTED[name];
    assert.equal(result.kind, kind, `${name} failed as ${result.kind}, expected ${kind}:\n${result.errors.join('\n')}`);
    const haystack = kind === 'semantic' ? (result.rules ?? []).join(' ') : result.errors.join('\n');
    assert.ok(haystack.includes(needle), `${name} failed, but not on ${needle}:\n${result.errors.join('\n')}`);
  }
});

test('a missing required field never validates, at every level it is required', () => {
  const { doc } = read(VALID_DIR, 'valid-clean.json');
  const drops = [
    [(d) => delete d.observationVersion, 'observationVersion'],
    [(d) => delete d.context, 'context'],
    [(d) => delete d.toolchain, 'toolchain'],
    [(d) => delete d.verdict, 'verdict'],
    [(d) => delete d.counts, 'counts'],
    [(d) => delete d.observationPoints, 'observationPoints'],
    [(d) => delete d.properties, 'properties'],
    [(d) => delete d.layers, 'layers'],
    [(d) => delete d.findings, 'findings'],
    [(d) => delete d.verdict.state, 'state'],
    [(d) => delete d.verdict.exitCode, 'exitCode'],
    [(d) => delete d.counts.checked, 'checked'],
    [(d) => delete d.observationPoints[0].reached, 'reached'],
    [(d) => delete d.observationPoints[0].checkpoint, 'checkpoint'],
    [(d) => delete d.observationPoints[0].stage, 'stage'],
    [(d) => delete d.properties[0].control, 'control'],
    [(d) => delete d.properties[0].history, 'history'],
    [(d) => delete d.properties[0].historyComplete, 'historyComplete'],
    [(d) => delete d.properties[0].finalState, 'finalState'],
    [(d) => delete d.properties[0].history[0].attribution, 'attribution'],
    [(d) => delete d.properties[0].history[0].attribution.pass, 'pass'],
    [(d) => delete d.properties[0].history[0].count.callSites, 'callSites'],
    [(d) => delete d.properties[0].control.count, 'count'],
    [(d) => delete d.layers.link, 'link'],
    [(d) => delete d.layers.link.ltoMode, 'ltoMode'],
    [(d) => delete d.layers.link.backendObserved, 'backendObserved'],
    [(d) => delete d.layers.artifact.observed, 'observed'],
    [(d) => delete d.layers.artifact.checks[0].decidedBy, 'decidedBy'],
    [(d) => delete d.toolchain.digest, 'digest'],
  ];
  for (const [drop, field] of drops) {
    const broken = structuredClone(doc);
    drop(broken);
    const errors = validateSchema(schema, broken);
    assert.ok(errors.length > 0, `dropping \`${field}\` still validated`);
    assert.match(errors.map((e) => e.message).join('\n'), new RegExp(`missing required property .${field}.`));
  }
});

// ── 3. the honest-verdict rule, on its own ──────────────────────────────────

test('VERIFIED_CLEAN is refused for anything that was not observed', () => {
  const { doc } = read(VALID_DIR, 'valid-clean.json');
  const cases = [
    ['a finding is present', (d) => { d.findings.push(structuredClone(read(VALID_DIR, 'valid-findings.json').doc.findings[0])); d.findings[0].point = 'pre-opt'; d.findings[0].property = 'prop.erasure.escaping-buffer'; }],
    ['a point was not reached', (d) => { d.observationPoints[1].reached = false; d.observationPoints[1].unreachedReason = 'the compiler crashed'; }],
    ['a state is NOT_OBSERVED', (d) => { d.properties[0].history[3].state = 'NOT_OBSERVED'; d.properties[0].finalState = 'NOT_OBSERVED'; }],
    ['the link layer was not observed', (d) => { d.layers.link.observed = false; d.layers.link.unobservedReason = 'no link was run'; }],
    ['the artefact layer was not observed', (d) => { d.layers.artifact.observed = false; d.layers.artifact.unobservedReason = 'no artefact'; }],
    ['an LTO backend ran unwatched', (d) => { d.layers.link.backendObserved = false; d.layers.link.backendUnobservedReason = 'the plugin path did not resolve and the linker ignored the request'; }],
    ['an artefact requirement was not observed', (d) => { d.layers.artifact.checks[0].result = 'NOT_OBSERVED'; }],
    ['verdict.unobserved is non-empty', (d) => { d.verdict.unobserved.push('the object checkpoint'); }],
    ['a property is not itself clean', (d) => { d.properties[0].verdict = 'VERIFICATION_INCOMPLETE'; }],
  ];
  for (const [why, mutate] of cases) {
    const broken = structuredClone(doc);
    mutate(broken);
    const rules = semanticErrors(broken).map((e) => e.rule);
    assert.ok(rules.includes('OBS-S07'), `VERIFIED_CLEAN survived even though ${why}`);
  }
});

test('the same document without VERIFIED_CLEAN is accepted, so OBS-S07 is about the claim', () => {
  // The negative fixture for OBS-S07: an unreached point is not an error in
  // itself. It is only an error next to a claim of cleanliness. Without this,
  // OBS-S07 could be a rule that rejects every incomplete run.
  const { doc } = read(VALID_DIR, 'valid-clean.json');
  const d = structuredClone(doc);
  d.observationPoints[3].reached = false;
  d.observationPoints[3].unreachedReason = 'the artefact was never produced';
  d.properties[0].history[3].state = 'NOT_OBSERVED';
  d.properties[0].finalState = 'NOT_OBSERVED';
  d.properties[0].verdict = 'VERIFICATION_INCOMPLETE';
  d.verdict = { state: 'VERIFICATION_INCOMPLETE', exitCode: 3, reason: 'the artefact was never produced', unobserved: ['the linked checkpoint'] };
  d.counts.pointCoverage = { num: 3, den: 4 };
  const result = validateDocument(schema, d);
  assert.equal(result.ok, true, `expected acceptance, got:\n${result.errors.join('\n')}`);
});

test('the control discipline: a dead control is a broken measurement, not a finding', () => {
  const { doc } = read(VALID_DIR, 'valid-findings.json');
  const dead = structuredClone(doc);
  dead.properties[0].control = { unit: 'wipe_kept', state: 'LOST', count: { callSites: 0, oracle: 'call-site', naiveSymbolMatches: 1 } };
  assert.ok(semanticErrors(dead).map((e) => e.rule).includes('OBS-S09'));

  // Negative fixture: the identical document reported as EVIDENCE_MISMATCH is fine.
  const owned = structuredClone(dead);
  owned.verdict = { state: 'EVIDENCE_MISMATCH', exitCode: 4, reason: 'the control did not survive, so the subject count is not attributable', unobserved: [] };
  owned.properties[0].verdict = 'EVIDENCE_MISMATCH';
  owned.findings = [];
  assert.deepEqual(semanticErrors(owned).map((e) => e.rule), []);
});

test('the verdict and the exit code are one decision', () => {
  const { doc } = read(VALID_DIR, 'valid-clean.json');
  for (const [state, code] of [['VERIFIED_CLEAN', 0], ['FINDINGS_PRESENT', 2], ['VERIFICATION_INCOMPLETE', 3], ['UNSUPPORTED', 3], ['EVIDENCE_MISMATCH', 4]]) {
    const d = structuredClone(doc);
    d.verdict.state = state;
    d.verdict.exitCode = code === 0 ? 1 : 0;
    assert.ok(semanticErrors(d).map((e) => e.rule).includes('OBS-S08'), `${state} with the wrong exit code was accepted`);
  }
  // 3 is never conflated with 0.
  const d = structuredClone(doc);
  d.verdict.state = 'VERIFICATION_INCOMPLETE';
  d.verdict.exitCode = 0;
  const messages = semanticErrors(d).map((e) => e.message).join('\n');
  assert.match(messages, /must carry exit code 3, not 0/);
});

test('the oracle rule is structural: a name-search count cannot be written down', () => {
  const { doc } = read(VALID_DIR, 'valid-findings.json');
  const d = structuredClone(doc);
  d.properties[0].history[0].count.oracle = 'symbol-name';
  assert.ok(validateSchema(schema, d).length > 0);
  // And the naive number may be carried, but only beside a call-site count.
  const ok = structuredClone(doc);
  assert.equal(ok.properties[0].history[0].count.oracle, 'call-site');
  assert.equal(ok.properties[0].history[0].count.naiveSymbolMatches, 3);
  assert.equal(ok.properties[0].history[1].count.callSites, 0);
  assert.equal(ok.properties[0].history[1].count.naiveSymbolMatches, 2,
    'the declare line survives the call it declared, which is why a name search is not the oracle');
});

test('an absolute path anywhere is refused, and a relative one is not', () => {
  const { doc } = read(VALID_DIR, 'valid-findings.json');
  for (const bad of ['/opt/build/secret.c', 'D:\\build\\secret.c', 'read from ~/fixtures/secret.c']) {
    const d = structuredClone(doc);
    d.findings[0].detail = `something happened: ${bad}`;
    assert.ok(semanticErrors(d).map((e) => e.rule).includes('OBS-S11'), `${bad} was not refused`);
  }
  for (const good of ['fixtures/secret.c', 'build/app', 'a note with no path at all', 'the option -O2 was used']) {
    const d = structuredClone(doc);
    d.findings[0].detail = `something happened: ${good}`;
    assert.deepEqual(semanticErrors(d).map((e) => e.rule), [], `${good} should not have been refused`);
  }
});

// ── 4. the counting contract ────────────────────────────────────────────────

test('the runner prints inputs/checked/skipped on every path', () => {
  for (const argv of [[VALID_DIR], [INVALID_DIR, '--expect-invalid'], ['--capability']]) {
    const { out } = capture(argv);
    assert.match(out, /inputs=\d+ checked=\d+ skipped=\d+/, `no count line for ${argv.join(' ')}`);
  }
});

test('an empty scan is not a pass', () => {
  const dir = mkdtempSync(join(tmpdir(), 'obs-empty-'));
  try {
    const bare = capture([dir]);
    assert.equal(bare.code, EXIT_INCOMPLETE, 'an empty directory reported success');
    assert.notEqual(bare.code, EXIT_OK);
    assert.match(bare.out, /inputs=0 checked=0 skipped=0/);
    assert.match(bare.err, /empty scan is not a pass/);

    const authorised = capture([dir, '--allow-empty']);
    assert.equal(authorised.code, EXIT_OK, 'the explicit authorisation should be honoured');
    assert.match(authorised.out, /inputs=0 checked=0 skipped=0/);
    assert.match(authorised.out, /explicitly authorised/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the counts reported are the counts checked', () => {
  const { out } = capture([VALID_DIR]);
  const n = list(VALID_DIR).length;
  assert.match(out, new RegExp(`inputs=${n} checked=${n} skipped=0`));
  assert.match(out, new RegExp(`all ${n} document\\(s\\) valid`));
});

test('a malformed document is a failure, and an unparseable one is not a skip', () => {
  const dir = mkdtempSync(join(tmpdir(), 'obs-bad-'));
  try {
    writeFileSync(join(dir, 'a.json'), readFileSync(join(VALID_DIR, 'valid-clean.json')));
    writeFileSync(join(dir, 'b.json'), '{ this is not json', 'utf8');
    const { code, out, err } = capture([dir]);
    assert.equal(code, EXIT_INTEGRITY);
    assert.match(out, /inputs=2 checked=2 skipped=0/, 'the unparseable file must still be counted as checked');
    assert.match(err, /FAIL .*b\.json \(parse\)/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('--expect-invalid fails when a document it expected to reject validates', () => {
  const dir = mkdtempSync(join(tmpdir(), 'obs-flip-'));
  try {
    writeFileSync(join(dir, 'clean.json'), readFileSync(join(VALID_DIR, 'valid-clean.json')));
    const { code, err } = capture([dir, '--expect-invalid']);
    assert.equal(code, EXIT_INTEGRITY);
    assert.match(err, /expected to fail and did not/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a missing target is incomplete, never a silent success', () => {
  const { code, out } = capture([join(SAMPLES, 'no-such-directory')]);
  assert.equal(code, EXIT_INCOMPLETE);
  assert.match(out, /inputs=0 checked=0 skipped=0/);
});

test('the exit codes are the ones interfaces.md fixes', () => {
  assert.equal(EXIT_OK, 0);
  assert.equal(EXIT_TOOL_FAILED, 1);
  assert.equal(EXIT_INCOMPLETE, 3);
  assert.equal(EXIT_INTEGRITY, 4);
  assert.equal(capture([VALID_DIR]).code, EXIT_OK);
  assert.equal(capture([INVALID_DIR]).code, EXIT_INTEGRITY);
  assert.equal(capture([INVALID_DIR, '--expect-invalid']).code, EXIT_OK);
});

// ── 5. the finding shape agrees with the rest of the directory ──────────────

test('the finding id namespaces are exactly the six that are reserved', () => {
  const pattern = schema.definitions.finding.properties.id.pattern;
  for (const id of ['VG-CFG-001', 'VG-PLG-002', 'VG-PROP-001', 'VG-INTRO-010', 'VG-LINK-099', 'VG-ART-005']) {
    assert.ok(new RegExp(pattern).test(id), `${id} should be a legal finding id`);
  }
  for (const id of ['VG-FOO-001', 'VG-PROP-1', 'VG-PROP-0001', 'PROP-001', 'vg-prop-001', 'VG-PROP-001x']) {
    assert.ok(!new RegExp(pattern).test(id), `${id} should not be a legal finding id`);
  }
});

test('the property kinds and artefact requirements match policy.schema.json', () => {
  const policy = JSON.parse(readFileSync(join(HERE, 'policy.schema.json'), 'utf8'));
  assert.deepEqual(
    schema.definitions.propertyObservation.properties.kind.enum,
    policy.properties.properties.items.properties.kind.enum,
    'the record and the policy must use one vocabulary for property kinds',
  );
  assert.deepEqual(
    schema.definitions.checkpoint.enum,
    policy.properties.properties.items.properties.observeAt.items.enum,
    'the record and the policy must use one vocabulary for checkpoints',
  );
  assert.deepEqual(
    schema.definitions.layers.properties.artifact.properties.checks.items.properties.require.enum,
    policy.properties.artifact.properties.require.items.enum,
    'the record and the policy must use one vocabulary for artefact requirements',
  );
  assert.deepEqual(
    schema.properties.policy.properties.failOn.enum,
    policy.properties.failOn.enum,
  );
});

test('context and evidenceDigest are the only digest-excluded subtrees', () => {
  // interfaces.md section 5 rule 1. Asserting it here keeps a later field from
  // being added at the top level "because it is volatile" instead of into context.
  const top = Object.keys(schema.properties).sort();
  assert.deepEqual(top, [
    'context', 'counts', 'evidenceDigest', 'findings', 'layers',
    'observationPoints', 'observationVersion', 'policy', 'properties', 'toolchain', 'verdict',
  ]);
  assert.equal(schema.properties.context.properties.timeSource.enum.join(','), 'SOURCE_DATE_EPOCH,wall-clock');
});
