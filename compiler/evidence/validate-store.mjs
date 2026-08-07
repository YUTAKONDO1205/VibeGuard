#!/usr/bin/env node
// The measurement-record validator.
//
// It was written before the first record existed, and that is the point. This
// tree does not rewrite history — a force-push breaks every installed consumer
// of the published channels — so the first record that reaches a commit
// carrying an account name, a hostname or a disclosure-shaped string is
// permanent. A validator added after the fact can only report what can no
// longer be taken back.
//
//   node validate-store.mjs --store <dir>        every record in a store
//   node validate-store.mjs --record <file>      one record, no pair check
//   node validate-store.mjs --self-test          fire every detector, both ways
//
//   --allow-empty      an empty store is an expected outcome, not a failure
//   --json             machine-readable; the counting line goes to stderr
//   --fail-on <sev>    threshold for exit 2 (default low)
//   --no-delegate      do not run the shape checker (the check becomes UNCHECKED)
//
// EXIT CODES (interfaces.md §7)
//
//   0  everything asked for was checked and nothing was found
//   2  findings at or above the threshold
//   3  a check could not be completed — including a run that examined nothing
//   4  a record cannot be canonicalised, so nothing derived from it means anything
//
// THE COUNTING CONTRACT
//
//   Every run prints `inputs=N checked=N skipped=S`, and `inputs=0` exits 3
//   unless `--allow-empty` was passed. See counting.mjs for why that is a
//   module rather than a habit.

import { existsSync, readFileSync, statSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { reportCounts } from './counting.mjs';
import { assertNoSymlink, SymlinkRefused } from './fsguard.mjs';
import { currentIdentity, describeIdentity, runShapeChecker, shapeCheckerSelfTest, SHAPE_CHECKER } from './machine.mjs';
import { MEASUREMENT_SCHEMA, REPO_ROOT, STORE_ENV, resolveStoreRoot, validateRecord, validateStore } from './store.mjs';
import { MalformedRecordError } from './verify.mjs';

const SEVERITY_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

const EXIT_OK = 0;
const EXIT_FINDINGS = 2;
const EXIT_INCOMPLETE = 3;
const EXIT_INTEGRITY = 4;

function usage() {
  return [
    'usage: node validate-store.mjs <mode> [options]',
    '',
    `  --store <dir>      validate every record under <dir> (or $${STORE_ENV})`,
    '  --record <file>    validate one record file',
    '  --self-test        fire every detector against a positive and a negative control',
    '',
    '  --allow-empty      an empty input set is expected; do not exit 3 for it',
    '  --json             machine-readable output; the counting line goes to stderr',
    '  --fail-on <sev>    low|medium|high|critical, default low',
    '  --no-delegate      skip the delegated shape check (it becomes UNCHECKED, not clean)',
    '  --link-boundary <dir>  stop the symlink walk at <dir> (for a machine whose home is a link)',
    '',
    'exit: 0 clean, 2 findings, 3 could not complete, 4 a record is malformed',
  ].join('\n');
}

function printFindings(fs, out) {
  for (const f of fs) {
    out.write(`  [${f.severity}] ${f.id} ${f.title}\n`);
    out.write(`      ${f.detail.split('\n').join('\n      ')}\n`);
    if (f.where && f.where.path) out.write(`      at ${f.where.path}\n`);
  }
}

// ---------------------------------------------------------------------------
// Self-test: every detector, in both directions.
// ---------------------------------------------------------------------------

/**
 * A record that passes everything. Sealed through the generation side so the
 * digest is not produced by the same code that checks it.
 */
async function cleanRecord(overrides = {}) {
  const { sealRecord } = await import('./canon.mjs');
  return sealRecord({
    schemaVersion: MEASUREMENT_SCHEMA,
    recordId: 'control',
    provenance: { gitSha: 'a'.repeat(40), dirty: false, diffSha256: null },
    toolchain: [{ name: 'cc', version: '18.1.3', path: 'usr/bin/cc', sha256: 'b'.repeat(64) }],
    oracle: { kind: 'call-site', pattern: 'call void @llvm.memset' },
    observations: [
      { config: 'O0', subject: 1, control: 1 },
      { config: 'O2', subject: 0, control: 1 },
    ],
    reproduction: { pairId: 'control-pair', run: 1 },
    ...overrides,
  }, { context: { generatedAt: '1970-01-01T00:00:00.000Z', timeSource: 'SOURCE_DATE_EPOCH', sourceDateEpoch: 0 } });
}

/** Break one field of a clean record and re-seal, unless the break IS the seal. */
async function brokenRecord(mutate, { reseal = true } = {}) {
  const { sealRecord } = await import('./canon.mjs');
  const base = await cleanRecord();
  const copy = JSON.parse(JSON.stringify(base));
  mutate(copy);
  if (!reseal) return copy;
  delete copy.evidenceDigest;
  return sealRecord(copy, { context: copy.context });
}

async function selfTest({ log = () => {} } = {}) {
  const identity = { hostname: 'a-machine-name', account: 'a-person' };
  const cases = [];

  const expectId = async (id, mutate, opts) => ({ id, record: await brokenRecord(mutate, opts) });

  cases.push(await expectId('VG-ART-050', (r) => { r.evidenceDigest = 'c'.repeat(64); }, { reseal: false }));
  cases.push(await expectId('VG-ART-072', (r) => { delete r.provenance.gitSha; }));
  cases.push(await expectId('VG-ART-073', (r) => { delete r.provenance.dirty; }));
  cases.push(await expectId('VG-ART-073', (r) => { r.provenance.dirty = true; r.provenance.diffSha256 = null; }));
  cases.push(await expectId('VG-ART-074', (r) => { delete r.toolchain[0].sha256; }));
  cases.push(await expectId('VG-ART-074', (r) => { delete r.toolchain[0].version; }));
  cases.push(await expectId('VG-ART-077', (r) => { r.oracle = { kind: 'symbol-name', pattern: 'llvm.memset' }; }));
  cases.push(await expectId('VG-ART-079', (r) => { r.observations = []; }));
  cases.push(await expectId('VG-ART-079', (r) => { r.observations[1].control = 0; }));
  cases.push(await expectId('VG-ART-078', (r) => { delete r.reproduction; }));
  cases.push(await expectId('VG-ART-075', (r) => { r.toolchain[0].path = 'home/a-person/bin/cc'; }));
  cases.push(await expectId('VG-ART-075', (r) => { r.recordId = 'run on a-machine-name'; }));
  cases.push(await expectId('VG-ART-075', (r) => { r.recordId = 'copied from a-person@a-machine-name'; }));
  cases.push(await expectId('VG-ART-051', (r) => { r.toolchain[0].path = '/usr/bin/cc'; }, { reseal: false }));

  const results = { total: 0, passed: 0, failed: [], negativeTotal: 0, negativePassed: 0, delegate: null };

  for (const c of cases) {
    results.total += 1;
    let r;
    try {
      r = validateRecord(c.record, { path: 'control', identity, shapeHits: [] });
    } catch (e) {
      results.failed.push(`${c.id}: the validator threw instead of reporting — ${e.message}`);
      continue;
    }
    if (r.findings.some((f) => f.id === c.id)) {
      results.passed += 1;
      log(`  ok   positive control fires ${c.id}`);
    } else {
      results.failed.push(`${c.id}: the positive control did not fire it (got ${r.findings.map((f) => f.id).join(', ') || 'nothing'})`);
    }
  }

  // The other direction. A detector that fires on everything is a detector
  // that gets switched off, and a one-directional test suite never notices.
  const clean = await cleanRecord();
  results.negativeTotal += 1;
  const cleanRes = validateRecord(clean, { path: 'control', identity, shapeHits: [] });
  if (cleanRes.findings.length === 0) {
    results.negativePassed += 1;
    log('  ok   negative control: a clean record produces no finding');
  } else {
    results.failed.push(`negative control: a clean record produced ${cleanRes.findings.map((f) => f.id).join(', ')}`);
  }

  // A dirty tree WITH a diff digest is legitimate and must not be flagged.
  results.negativeTotal += 1;
  const dirtyOk = await brokenRecord((r) => { r.provenance.dirty = true; r.provenance.diffSha256 = 'd'.repeat(64); });
  const dirtyRes = validateRecord(dirtyOk, { path: 'control', identity, shapeHits: [] });
  if (dirtyRes.findings.length === 0) {
    results.negativePassed += 1;
    log('  ok   negative control: a dirty tree with a pinned diff is not flagged');
  } else {
    results.failed.push(`negative control: a pinned dirty tree produced ${dirtyRes.findings.map((f) => f.id).join(', ')}`);
  }

  // A record mentioning an account-shaped word that is a ROLE, not a person.
  results.negativeTotal += 1;
  const roleOk = await brokenRecord((r) => { r.toolchain[0].path = 'home/runner/bin/cc'; });
  const roleRes = validateRecord(roleOk, { path: 'control', identity, shapeHits: [] });
  if (!roleRes.findings.some((f) => f.id === 'VG-ART-075')) {
    results.negativePassed += 1;
    log('  ok   negative control: a CI role account is not reported as a person');
  } else {
    results.failed.push('negative control: a CI role account was reported as machine identity');
  }

  results.delegate = shapeCheckerSelfTest();
  if (!results.delegate.ok) {
    results.failed.push(`the delegated shape checker failed its own self-test: ${results.delegate.detail}`);
  } else {
    log(`  ok   delegate ${relative(REPO_ROOT, SHAPE_CHECKER).split('\\').join('/')} passed its own self-test`);
  }

  return results;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

async function main(argv, io = {}) {
  const out = io.out ?? process.stdout;
  const err = io.err ?? process.stderr;
  const flag = (n) => argv.includes(n);
  const val = (n, d = null) => {
    const i = argv.indexOf(n);
    return i >= 0 && i + 1 < argv.length && !argv[i + 1].startsWith('--') ? argv[i + 1] : d;
  };
  const asJson = flag('--json');
  const allowEmpty = flag('--allow-empty');
  const failOn = SEVERITY_ORDER[val('--fail-on', 'low')] ?? 0;

  if (argv.length === 0 || flag('--help') || flag('-h')) {
    out.write(`${usage()}\n`);
    return EXIT_OK;
  }

  // ── self-test
  if (flag('--self-test')) {
    const r = await selfTest({ log: asJson ? () => {} : (s) => out.write(`${s}\n`) });
    const counts = reportCounts(
      { inputs: r.total + r.negativeTotal, checked: r.passed + r.negativePassed, skipped: 0, allowEmpty, what: 'control' },
      { json: asJson, out, err },
    );
    if (asJson) out.write(`${JSON.stringify({ ...r, counts: { inputs: r.total + r.negativeTotal, checked: r.passed + r.negativePassed } }, null, 2)}\n`);
    else {
      out.write(`positive controls: ${r.passed}/${r.total} fired; negative controls: ${r.negativePassed}/${r.negativeTotal} stayed silent\n`);
      for (const f of r.failed) err.write(`  FAIL ${f}\n`);
    }
    if (r.failed.length > 0) return EXIT_INCOMPLETE;
    return counts.code ?? EXIT_OK;
  }

  // ── one record
  if (flag('--record')) {
    const f = val('--record');
    if (!f) {
      err.write('--record needs a path\n');
      return EXIT_INCOMPLETE;
    }
    let abs;
    try {
      abs = assertNoSymlink(f, { role: 'the record', boundary: val('--link-boundary') });
    } catch (e) {
      if (!(e instanceof SymlinkRefused)) throw e;
      err.write(`${e.message}\n`);
      reportCounts({ inputs: 1, checked: 0, skipped: 1, allowEmpty: true, what: 'record' }, { json: asJson, out, err });
      return EXIT_FINDINGS;
    }
    if (!existsSync(abs) || !statSync(abs).isFile()) {
      err.write(`cannot read ${abs}\n`);
      reportCounts({ inputs: 1, checked: 0, skipped: 1, allowEmpty: true, what: 'record' }, { json: asJson, out, err });
      return EXIT_INCOMPLETE;
    }
    let rec;
    try {
      rec = JSON.parse(readFileSync(abs, 'utf8'));
    } catch (e) {
      err.write(`does not parse: ${e.message}\n`);
      reportCounts({ inputs: 1, checked: 0, skipped: 1, allowEmpty: true, what: 'record' }, { json: asJson, out, err });
      return EXIT_INCOMPLETE;
    }
    const delegate = flag('--no-delegate')
      ? { available: false, reason: 'delegation disabled by --no-delegate', hits: [] }
      : runShapeChecker([abs]);
    let r;
    try {
      r = validateRecord(rec, { path: relative(process.cwd(), abs) || abs, shapeHits: delegate.available ? delegate.hits : null });
    } catch (e) {
      if (e instanceof MalformedRecordError) {
        err.write(`malformed record: ${e.message}\n`);
        reportCounts({ inputs: 1, checked: 0, skipped: 1, allowEmpty: true, what: 'record' }, { json: asJson, out, err });
        return EXIT_INTEGRITY;
      }
      throw e;
    }
    // Byte-identity is a two-record property; one file cannot have it checked.
    r.unchecked.push('reproduction.byteIdentity');
    if (!delegate.available && delegate.reason) err.write(`disclosure check NOT COMPLETED: ${delegate.reason}\n`);

    if (asJson) out.write(`${JSON.stringify({ ...r, counts: { inputs: 1, checked: 1, skipped: 0 } }, null, 2)}\n`);
    else {
      out.write(`checked: ${r.checked.join(', ') || '(nothing)'}\n`);
      out.write(`unchecked: ${r.unchecked.join(', ')}\n`);
      printFindings(r.findings, out);
    }
    const counts = reportCounts({ inputs: 1, checked: 1, skipped: 0, allowEmpty, what: 'record' }, { json: asJson, out, err });
    if (r.findings.some((x) => SEVERITY_ORDER[x.severity] >= failOn)) return EXIT_FINDINGS;
    if (counts.code) return counts.code;
    return r.unchecked.length > 0 ? EXIT_INCOMPLETE : EXIT_OK;
  }

  // ── a whole store
  const store = resolveStoreRoot({ cli: val('--store') });
  if (!asJson) {
    out.write(`store: ${store.root}\n`);
    out.write(`source: ${store.source}${store.source === 'default' ? ` (neither --store nor $${STORE_ENV} was set)` : ''}\n`);
    out.write(`identity check: ${describeIdentity(currentIdentity())}\n`);
  }

  const r = validateStore(store.root, { delegate: !flag('--no-delegate'), linkBoundary: val('--link-boundary') });
  if (r.error && !asJson) err.write(`${r.error}\n`);
  if (!r.delegate.available && r.delegate.reason) err.write(`disclosure check NOT COMPLETED: ${r.delegate.reason}\n`);

  if (asJson) {
    out.write(`${JSON.stringify({ ...r, counts: { inputs: r.inputs, checked: r.checked, skipped: r.skipped } }, null, 2)}\n`);
  } else {
    for (const rec of r.records) {
      const n = rec.findings.length;
      out.write(`${n === 0 ? 'ok  ' : 'FAIL'} ${rec.file}  checked=${rec.checked.length} unchecked=${rec.unchecked.length}\n`);
    }
    printFindings(r.findings, out);
    out.write(`pairs: ${r.pairs ?? 0}\n`);
    if (r.unchecked.length > 0) out.write(`unchecked: ${r.unchecked.join(', ')}\n`);
  }

  const counts = reportCounts(
    { inputs: r.inputs, checked: r.checked, skipped: r.skipped, allowEmpty, what: 'record', where: r.root },
    { json: asJson, out, err },
  );

  if (r.malformed > 0) return EXIT_INTEGRITY;
  if (r.findings.some((x) => SEVERITY_ORDER[x.severity] >= failOn)) return EXIT_FINDINGS;
  if (counts.code) return counts.code;
  return r.unchecked.length > 0 ? EXIT_INCOMPLETE : EXIT_OK;
}

export { main, selfTest, cleanRecord };

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      process.stderr.write(`${e.stack ?? e}\n`);
      process.exit(EXIT_INCOMPLETE);
    },
  );
}
