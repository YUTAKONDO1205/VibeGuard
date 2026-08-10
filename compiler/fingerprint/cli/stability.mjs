#!/usr/bin/env node
// The measurement: is a security property's shape comparable across
// optimisation levels when the normaliser is property-class independent?
//
//   node stability.mjs [--ir <dir>] [--out <dir>] [--allow-empty] [--quiet]
//
// Default `--ir` is the scratch directory tools/make-fixtures.sh writes to.
// The run needs, per optimisation level, four modules built from the same
// source by tools/make-fixtures.sh:
//
//   fixture.O<n>.ll           the subject and the control, with debug info
//   fixture-nodbg.O<n>.ll     the same, without debug info
//   fixture-renamed.O<n>.ll   the same program, every local renamed, different
//                             source path  -- MUST fingerprint the same
//   fixture-nowipe.O<n>.ll    the control's wipe deleted -- MUST fingerprint
//                             differently
//
// The last two are the point. A cross-level stability number with no
// perturbation and no semantic control underneath it is a number about the
// compiler, not about the fingerprint.
//
// Exit 0 clean, 2 findings, 3 the check could not be completed (including: no
// inputs), 1 a tool failed.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { parseModule } from '../lib/parse.mjs';
import { fingerprintFunction } from '../lib/fingerprint.mjs';
import { countCallSites, naiveNameHits } from '../lib/oracle.mjs';
import { EXIT, reportCounts, skipAuthorised, SKIP_ENV } from '../lib/count.mjs';
import { digestOf, findAbsolutePaths, makeFinding } from '../lib/record.mjs';

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const opt = (n, d) => {
  const i = argv.indexOf(n);
  return i === -1 || i + 1 >= argv.length ? d : argv[i + 1];
};

// Computed from the invoking user's home directory rather than written down.
// An absolute path in a tracked file names one machine, and this package is the
// one that imports `findAbsolutePaths` to keep such paths out of its own
// records — a default that hardcodes one is the checker exempting itself. The
// `vg-lab` root is the same one `compiler/evidence/store.mjs` and the sibling
// `compiler/clang-plugin/tools/make-fixtures.sh` already use; the scratch tree
// stays outside the repository either way, because IR is measurement input and
// not source.
const SCRATCH = join(homedir(), 'vg-lab', 'fingerprint');
const IR = opt('--ir', join(SCRATCH, 'ir'));
const OUT = opt('--out', join(SCRATCH, 'out'));
const allowEmpty = flag('--allow-empty');
const quiet = flag('--quiet');
const say = quiet ? () => {} : (s) => console.log(s);

const LEVELS = ['O0', 'O1', 'O2', 'O3'];
const VARIANTS = ['fixture', 'fixture-nodbg', 'fixture-renamed', 'fixture-nowipe'];

/** The unit whose effect cannot be removed. Every verdict is read against it. */
const CONTROL = '@control_wipe';
const SUBJECT = '@subject_wipe';
/** Functions whose source the `nowipe` variant does not touch. */
const UNTOUCHED_BY_NOWIPE = ['@subject_wipe', '@control_pure', '@subject_branch', '@control_branch'];

// ── load ────────────────────────────────────────────────────────────────────

const wanted = [];
for (const v of VARIANTS) for (const L of LEVELS) wanted.push({ variant: v, level: L, file: `${v}.${L}.ll` });

const modules = new Map();
const skippedNames = [];
for (const w of wanted) {
  const p = join(IR, w.file);
  if (!existsSync(p)) {
    if (!skipAuthorised()) {
      console.error(`missing input: ${w.file}`);
      console.error(`run tools/make-fixtures.sh first. A missing prerequisite fails; it does not skip.`);
      console.error(`(set ${SKIP_ENV}=1 to authorise a skip, and every skipped case will be listed)`);
      console.log(`inputs=${wanted.length} checked=0 skipped=${wanted.length}`);
      process.exit(EXIT.INCOMPLETE);
    }
    skippedNames.push(w.file);
    continue;
  }
  const text = readFileSync(p, 'utf8');
  modules.set(`${w.variant}.${w.level}`, { text, mod: parseModule(text) });
}

if (modules.size === 0) {
  const code = reportCounts({
    inputs: wanted.length, checked: 0, skipped: skippedNames.length, allowEmpty, skippedNames,
  });
  process.exit(code === EXIT.OK ? EXIT.INCOMPLETE : code);
}

const base = modules.get('fixture.O0') ?? [...modules.values()][0];
const FUNCTIONS = base.mod.functions.map((f) => f.name);

const fpOf = (key, fn) => {
  const m = modules.get(key);
  if (m === undefined || !m.mod.byName.has(fn)) return null;
  return fingerprintFunction(m.mod, fn);
};

const findings = [];
let comparisons = 0;

// ── 1. the control's effect must survive every level ────────────────────────

say('== oracle: call sites, not symbol names (interfaces.md section 4) ==');
const oracle = {};
let controlHeld = true;
for (const L of LEVELS) {
  const m = modules.get(`fixture.${L}`);
  if (m === undefined) continue;
  const row = {};
  for (const fn of FUNCTIONS) row[fn] = countCallSites(m.mod.byName.get(fn), 'llvm.memset');
  row['#naive-name-hits'] = naiveNameHits(m.text, 'llvm.memset');
  row['#module-call-sites'] = FUNCTIONS.reduce((a, fn) => a + row[fn], 0);
  oracle[L] = row;
  say(`  ${L}  subject=${row[SUBJECT]}  control=${row[CONTROL]}  module-call-sites=${row['#module-call-sites']}  naive-name-hits=${row['#naive-name-hits']}`);
  if (row[CONTROL] === 0) controlHeld = false;
}
if (!controlHeld) {
  findings.push(makeFinding({
    id: 'VG-PROP-003',
    severity: 'high',
    title: 'The measurement\'s control did not hold',
    detail: 'The control unit\'s effect count reached zero, so this run cannot tell a removed effect from an oracle that stopped working.',
    where: { kind: 'ir', unit: CONTROL },
  }));
}

// ── 2. both directions, at each level ───────────────────────────────────────
//
// A perturbation that must not change the fingerprint, and a semantic
// difference that must. Neither is worth anything alone.

say('');
say('== both directions, per level ==');
const perturbation = [];
for (const L of LEVELS) {
  for (const fn of FUNCTIONS) {
    const a = fpOf(`fixture.${L}`, fn);
    for (const [variant, mustMatch] of [['fixture-nodbg', true], ['fixture-renamed', true], ['fixture-nowipe', null]]) {
      const b = fpOf(`${variant}.${L}`, fn);
      if (a === null || b === null) continue;
      comparisons += 1;
      const same = a.digest === b.digest;
      const expectSame = mustMatch === null ? UNTOUCHED_BY_NOWIPE.includes(fn) : mustMatch;
      perturbation.push({
        level: L, unit: fn, variant, same: same ? 1 : 0, expectedSame: expectSame ? 1 : 0,
      });
      if (same === expectSame) continue;
      findings.push(makeFinding({
        id: same ? 'VG-PROP-012' : 'VG-PROP-011',
        severity: 'high',
        title: same
          ? 'A semantic difference did not change the fingerprint'
          : 'A perturbation that must not change the fingerprint changed it',
        detail: same
          ? `${fn} at ${L}: the ${variant} variant differs in what the program does, and the fingerprint is identical.`
          : `${fn} at ${L}: the ${variant} variant is the same program, and the fingerprint differs.`,
        where: { kind: 'ir', unit: fn, path: `${variant}.${L}.ll` },
      }));
    }
  }
}
for (const L of LEVELS) {
  const rows = perturbation.filter((r) => r.level === L);
  const ok = rows.filter((r) => r.same === r.expectedSame).length;
  say(`  ${L}  ${ok}/${rows.length} both-direction checks as expected`);
}

// ── 3. the headline: stability across optimisation levels ───────────────────

say('');
say('== cross-level stability of the general fingerprint ==');
const stability = [];
for (const fn of FUNCTIONS) {
  const digests = {};
  for (const L of LEVELS) {
    const r = fpOf(`fixture.${L}`, fn);
    if (r !== null) digests[L] = r.digest;
  }
  const seen = [...new Set(Object.values(digests))];
  const optOnly = [...new Set(['O1', 'O2', 'O3'].map((L) => digests[L]).filter(Boolean))];
  const row = {
    unit: fn,
    distinctAcrossAllLevels: seen.length,
    distinctAcrossO1toO3: optOnly.length,
    stableAcrossAllLevels: seen.length === 1 ? 1 : 0,
    stableAcrossO1toO3: optOnly.length === 1 ? 1 : 0,
  };
  stability.push(row);
  say(`  ${fn.padEnd(18)} distinct O0..O3 = ${row.distinctAcrossAllLevels}   distinct O1..O3 = ${row.distinctAcrossO1toO3}`);
}

const controlRow = stability.find((r) => r.unit === CONTROL);
if (controlRow !== undefined && controlRow.stableAcrossAllLevels === 0) {
  findings.push(makeFinding({
    id: 'VG-PROP-010',
    severity: 'medium',
    title: 'The general fingerprint of a control unit is not stable across optimisation levels',
    detail: `${CONTROL} keeps its effect at every level (the targeted call-site oracle says so), and the general fingerprint still produces ${controlRow.distinctAcrossAllLevels} distinct values across O0..O3 and ${controlRow.distinctAcrossO1toO3} across O1..O3. A cross-level comparison built on this fingerprint would report a change in a unit that did not lose anything.`,
    where: { kind: 'ir', unit: CONTROL },
  }));
}

// ── 4. the general version against the targeted one ─────────────────────────

say('');
say('== general fingerprint vs targeted extractor, transition by transition ==');
const transitions = [];
for (let i = 1; i < LEVELS.length; i += 1) {
  const from = LEVELS[i - 1];
  const to = LEVELS[i];
  for (const fn of FUNCTIONS) {
    const a = fpOf(`fixture.${from}`, fn);
    const b = fpOf(`fixture.${to}`, fn);
    if (a === null || b === null) continue;
    const targetedBefore = oracle[from]?.[fn] ?? 0;
    const targetedAfter = oracle[to]?.[fn] ?? 0;
    transitions.push({
      unit: fn,
      from,
      to,
      generalSaysChanged: a.digest === b.digest ? 0 : 1,
      targetedEffectBefore: targetedBefore,
      targetedEffectAfter: targetedAfter,
      targetedSaysLost: targetedBefore > 0 && targetedAfter === 0 ? 1 : 0,
    });
  }
}
const wipeUnits = [SUBJECT, CONTROL];
let generalAlarms = 0;
let targetedAlarms = 0;
let generalAlarmsOnControl = 0;
for (const t of transitions.filter((x) => wipeUnits.includes(x.unit))) {
  generalAlarms += t.generalSaysChanged;
  targetedAlarms += t.targetedSaysLost;
  if (t.unit === CONTROL) generalAlarmsOnControl += t.generalSaysChanged;
  say(`  ${t.unit.padEnd(16)} ${t.from}->${t.to}  general:${t.generalSaysChanged ? 'CHANGED' : 'same   '}  targeted:${t.targetedSaysLost ? 'LOST   ' : 'held   '}  (effect ${t.targetedEffectBefore} -> ${t.targetedEffectAfter})`);
}
say(`  general raises ${generalAlarms} alarm(s) over ${transitions.filter((x) => wipeUnits.includes(x.unit)).length} transitions; targeted raises ${targetedAlarms}.`);
say(`  of the general alarms, ${generalAlarmsOnControl} are on the control -- a unit that lost nothing.`);

// ── record ──────────────────────────────────────────────────────────────────

const record = {
  controlHeld: controlHeld ? 1 : 0,
  findings,
  measurement: {
    bothDirections: perturbation,
    crossLevelStability: stability,
    generalVsTargeted: {
      generalAlarms,
      generalAlarmsOnControl,
      targetedAlarms,
      transitions,
    },
    oracle,
  },
  schemaVersion: 1,
  unitOfCount: 'call-site',
};
const abs = findAbsolutePaths(record);
if (abs.length > 0) {
  console.error(`record contains ${abs.length} absolute path(s); refusing to write it`);
  process.exit(EXIT.INCOMPLETE);
}
record.evidenceDigest = digestOf(record);
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'stability.json'), `${JSON.stringify(record, null, 2)}\n`, 'utf8');

say('');
if (findings.length === 0) say('findings: none');
else for (const f of findings) say(`FINDING ${f.id} [${f.severity}] ${f.title}\n         ${f.detail}`);

const code = reportCounts({
  inputs: wanted.length,
  checked: modules.size,
  skipped: skippedNames.length,
  allowEmpty,
  skippedNames,
});
if (code !== EXIT.OK) process.exit(code);
process.exit(findings.length > 0 ? EXIT.FINDINGS : EXIT.OK);
