// second-language-record — turn a measurement directory into evidence records.
//
//   node second-language-record.mjs --lab <dir> [--out <dir>] [--allow-empty]
//
// The measurement directory is written by second-language-measure.sh and is
// never under compiler/: a measurement input kept beside its script is a
// boundary violation, and it also lets a run quietly use a hand-edited copy.
//
//   <lab>/meta.json                 what was measured, and with which toolchain
//   <lab>/ir/<fixture>-O<n>.ll      textual IR, one file per optimisation level
//   <lab>/trace/<fixture>-O<n>.jsonl  per-pass census from the loaded observer
//
// One record is written per fixture, and it carries EVERY optimisation level it
// was measured at. That is deliberate. A record showing only the absence at the
// highest level is not evidence that anything was lost — it is consistent with
// the effect never having been there. The presence reading and the absence
// reading have to be in the same record, produced by the same run, or the pair
// proves nothing.
//
// This program decides nothing about pass or fail. second-language-check.mjs
// does that, so the thing that produces the number is not the thing that grades
// it.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, basename } from 'node:path';
import { countCallSitesByUnit, deriveStateHistory, firstLoss } from './second-language-oracle.mjs';

export const EXIT = { OK: 0, TOOL_FAILED: 1, FINDINGS: 2, INCOMPLETE: 3, INTEGRITY: 4 };

// ── canonicalisation (interfaces.md section 5) ──────────────────────────────

/** Sort keys at every level, including inside arrays of objects. Array order is
 * significant and is never sorted. */
export function canonicalise(value) {
  if (Array.isArray(value)) return value.map(canonicalise);
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = canonicalise(value[k]);
    return out;
  }
  return value;
}

/** Every number in a record is an integer. A ratio is a pair, never a float. */
export function assertIntegers(value, path = '$') {
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error(`non-integer number at ${path}: ${value}`);
    return;
  }
  if (Array.isArray(value)) return value.forEach((v, i) => assertIntegers(v, `${path}[${i}]`));
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) assertIntegers(v, `${path}.${k}`);
  }
}

const ABSOLUTE_PATH = /(^|[\s"'=(])(?:[A-Za-z]:[\\/]|\/(?:home|root|Users|mnt|tmp|var)\b)/;

/** Absolute paths must not appear anywhere in a record — not even in context. */
export function assertNoAbsolutePaths(value, path = '$') {
  if (typeof value === 'string') {
    if (ABSOLUTE_PATH.test(value)) throw new Error(`absolute path at ${path}: ${value}`);
    return;
  }
  if (Array.isArray(value)) return value.forEach((v, i) => assertNoAbsolutePaths(v, `${path}[${i}]`));
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) assertNoAbsolutePaths(v, `${path}.${k}`);
  }
}

/** sha256 over the canonical bytes, with context and evidenceDigest removed as
 * whole subtrees from the top level and nothing else removed at any depth. */
export function digestRecord(record) {
  const { context, evidenceDigest, ...rest } = record;
  void context;
  void evidenceDigest;
  assertIntegers(rest);
  const bytes = JSON.stringify(canonicalise(rest));
  return createHash('sha256').update(bytes, 'utf8').digest('hex');
}

// ── building a record ───────────────────────────────────────────────────────

/** Run-length encode a state sequence. Lossless: the whole sequence survives,
 * which is what interfaces.md section 3 requires. Truncating at the first
 * PRESENT -> LOST would hide a later REINTRODUCED. */
export function runLength(entries) {
  const runs = [];
  for (const e of entries) {
    const tail = runs[runs.length - 1];
    if (tail && tail.state === e.state) tail.count++;
    else runs.push({ count: 1, pass: e.label, state: e.state });
  }
  return runs;
}

export function parseTrace(text) {
  const rows = [];
  let lineNo = 0;
  for (const line of text.split('\n')) {
    lineNo++;
    const s = line.trim();
    if (!s) continue;
    let row;
    try {
      row = JSON.parse(s);
    } catch {
      throw new Error(`trace line ${lineNo} is not JSON`);
    }
    rows.push(row);
  }
  return rows;
}

/**
 * @param {object} fixture  entry from meta.fixtures
 * @param {object} meta
 * @param {{optLevel:number, ir:string}[]} irs   ascending optimisation level
 * @param {{optLevel:number, rows:object[]}|null} trace
 */
export function buildRecord(fixture, meta, irs, trace, context) {
  const readings = [];
  const points = [];
  for (const { optLevel, ir } of irs) {
    const counted = countCallSitesByUnit(ir);
    if (counted.defineCount === 0) {
      throw new Error(`${fixture.name} -O${optLevel}: the IR contains no function definitions`);
    }
    const target = counted.units[fixture.subject] ?? 0;
    const control = counted.units[fixture.control];
    if (control === undefined) {
      throw new Error(
        `${fixture.name} -O${optLevel}: the control unit ${fixture.control} is not in the IR; ` +
          'a measurement without a control is not a measurement',
      );
    }
    readings.push({
      controlCallSites: control,
      declareLines: counted.declareLines,
      naiveTotal: counted.naiveTotal,
      optLevel,
      targetCallSites: target,
    });
    points.push({ label: `O${optLevel}`, targetCallSites: target, controlCallSites: control });
  }

  const derived = deriveStateHistory(points);
  readings.forEach((r, i) => {
    r.state = derived.history[i].state;
  });

  let passObservation = null;
  if (trace) {
    const attribution = firstLoss(trace.rows, {
      target: fixture.subject,
      control: fixture.control,
    });
    // The subject's and the control's rows are interleaved, and a function-level
    // pass sees only one of them. The control's count is therefore carried
    // forward from the last row that actually reported it, rather than assumed:
    // assuming it would defeat the point of having a control at all.
    const perPass = [];
    let lastControl = 0;
    for (const r of trace.rows) {
      if (r.unit === fixture.control) lastControl = r.callSites;
      if (r.unit !== fixture.subject) continue;
      perPass.push({
        label: `${r.phase}:${r.pass}`,
        targetCallSites: r.callSites,
        controlCallSites: lastControl,
      });
    }
    const passStates = deriveStateHistory(perPass);
    passObservation = {
      brokenControlAt: passStates.brokenControlAt,
      controlMin: attribution.controlMin,
      firstLoss: attribution.firstLoss
        ? {
            from: attribution.firstLoss.from,
            pass: attribution.firstLoss.pass,
            phase: attribution.firstLoss.phase,
            seq: attribution.firstLoss.seq,
          }
        : null,
      observedPasses: attribution.observedPasses,
      optLevel: trace.optLevel,
      points: attribution.targetRows,
      stateRuns: runLength(passStates.history),
      transitions: attribution.transitions,
    };
  }

  const record = {
    context,
    evidenceDigest: '',
    expectation: fixture.expectation,
    fixture: fixture.name,
    language: meta.language,
    oracle: {
      countsDeclarations: false,
      effect: 'llvm.memset',
      kind: 'ir-call-site',
      scope: 'ir-unit',
    },
    passObservation,
    property: { control: fixture.control, id: fixture.propertyId, subject: fixture.subject },
    readings,
    schemaVersion: 1,
    sourceRel: fixture.sourceRel,
    stateHistory: derived.states,
    toolchain: meta.toolchain,
  };
  assertNoAbsolutePaths({ ...record, context });
  record.evidenceDigest = digestRecord(record);
  return record;
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { lab: null, out: null, allowEmpty: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--lab') args.lab = argv[++i];
    else if (argv[i] === '--out') args.out = argv[++i];
    else if (argv[i] === '--allow-empty') args.allowEmpty = true;
    else throw new Error(`unknown argument ${argv[i]}`);
  }
  return args;
}

export function main(argv, log = console.log, err = console.error) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    err(`second-language-record: ${e.message}`);
    return EXIT.INCOMPLETE;
  }
  if (!args.lab) {
    err('second-language-record: --lab <dir> is required');
    return EXIT.INCOMPLETE;
  }
  const metaPath = join(args.lab, 'meta.json');
  if (!existsSync(metaPath)) {
    err(`second-language-record: no meta.json in the measurement directory`);
    log('inputs=0 checked=0 skipped=0');
    return EXIT.INCOMPLETE;
  }
  let meta;
  try {
    meta = JSON.parse(readFileSync(metaPath, 'utf8'));
  } catch (e) {
    err(`second-language-record: meta.json is not readable JSON: ${e.message}`);
    return EXIT.INTEGRITY;
  }

  const fixtures = Array.isArray(meta.fixtures) ? meta.fixtures : [];
  const outDir = args.out ?? join(args.lab, 'records');
  const allowSkip = process.env.SECOND_LANGUAGE_ALLOW_SKIP === '1';
  let checked = 0;
  const skipped = [];
  const failures = [];

  mkdirSync(outDir, { recursive: true });

  for (const fx of fixtures) {
    const irs = [];
    let missing = null;
    for (const optLevel of meta.optLevels) {
      const p = join(args.lab, 'ir', `${fx.name}-O${optLevel}.ll`);
      if (!existsSync(p)) {
        missing = basename(p);
        break;
      }
      irs.push({ optLevel, ir: readFileSync(p, 'utf8') });
    }
    if (missing) {
      // skip is not pass. Without the authorising variable this is a failure.
      if (allowSkip) skipped.push(`${fx.name} (missing ${missing})`);
      else failures.push(`${fx.name}: ${missing} was not produced`);
      continue;
    }
    let trace = null;
    const tp = join(args.lab, 'trace', `${fx.name}-O${meta.traceOptLevel}.jsonl`);
    if (existsSync(tp)) {
      trace = { optLevel: meta.traceOptLevel, rows: parseTrace(readFileSync(tp, 'utf8')) };
    }
    try {
      const record = buildRecord(fx, meta, irs, trace, meta.context ?? {});
      writeFileSync(join(outDir, `${fx.name}.json`), `${JSON.stringify(record, null, 2)}\n`);
      checked++;
    } catch (e) {
      failures.push(`${fx.name}: ${e.message}`);
    }
  }

  log(`inputs=${fixtures.length} checked=${checked} skipped=${skipped.length}`);
  for (const s of skipped) log(`skipped: ${s}`);
  for (const f of failures) err(`second-language-record: ${f}`);

  if (fixtures.length === 0) {
    if (args.allowEmpty) {
      log('second-language-record: nothing to do, and --allow-empty was given');
      return EXIT.OK;
    }
    err('second-language-record: no fixtures were declared; an empty run is not a clean run');
    return EXIT.INCOMPLETE;
  }
  // Same hole as in the check script, and for the same reason: the guard above
  // asks whether anything was FOUND, and every skip moves the emptiness into
  // `checked` where it cannot see it. Measured before this line: with the skip
  // environment variable set, `inputs=1 checked=0 skipped=1` and exit 0.
  // A recording run that recorded nothing must not report success.
  if (checked === 0) {
    err(`second-language-record: all ${fixtures.length} fixture(s) were skipped, so nothing `
      + 'was recorded. That is incomplete, not clean.');
    return EXIT.INCOMPLETE;
  }
  if (failures.length) return EXIT.INCOMPLETE;
  return EXIT.OK;
}

const invokedDirectly =
  process.argv[1] && basename(process.argv[1]) === 'second-language-record.mjs';
if (invokedDirectly) process.exit(main(process.argv.slice(2)));
