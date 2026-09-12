/**
 * Guard 1 second half, and guard 2: two independent readings of the same link's
 * pipeline, and what it means when they disagree.
 *
 * The linker can say what it ran without any plugin at all:
 * `-Wl,--lto-debug-pass-manager` (an exact alias of
 * `-Wl,--plugin-opt=debug-pass-manager`) prints one `Running pass:` line per
 * pass run, on STDERR. That reading is the guard, precisely because it does not
 * depend on the thing being guarded. A non-LTO link prints zero such lines --
 * measured here: 0 -- which is what makes "the plugin was silently ignored"
 * detectable.
 *
 * The observer's own log is the second reading. If the two disagree, the run is
 * a BROKEN_MEASUREMENT and not a result: either the observer saw a pipeline the
 * linker did not run, or the linker ran passes the observer never saw, and in
 * both cases an attribution taken from the observer names a pass that may not
 * have been where it says.
 *
 * One asymmetry is structural rather than a disagreement, and it has to be
 * spelled out or the guard fires on every healthy run. LLVM's own
 * PrintPassInstrumentation suppresses the pass-manager and pass-adaptor shapes
 * unless it is asked to be verbose; the observer's callbacks receive them like
 * any other pass. Measured on the xtu full-LTO link: the observer recorded 224
 * before-pass callbacks, the linker printed 176 lines, and the 5 pass ids the
 * observer had and the linker did not were exactly
 *
 *   FunctionToLoopPassAdaptor, ModuleToFunctionPassAdaptor,
 *   ModuleToPostOrderCGSCCPassAdaptor, PassManager<Function>,
 *   PassManager<LazyCallGraph::SCC, CGSCCAnalysisManager, LazyCallGraph &,
 *   CGSCCUpdateResult &>
 *
 * -- every one of them a `PassManager` or a `PassAdaptor`. With those removed
 * the two readings were 176 and 176 and the ORDERED sequences of (pass, unit)
 * were equal, 0 mismatches. So the subset the task requires holds, and equality
 * holds, and this module reports both rather than the weaker one alone.
 *
 * Everything here is a pure function over text. No compiler is run.
 */

/**
 * The shapes LLVM's printer treats as "special" and omits. Matched as substrings
 * of the pass id, which is how `isSpecialPass` does it upstream.
 *
 * Anything the observer saw that is NOT one of these and NOT in the linker's log
 * is a real disagreement, and this list is the only thing standing between the
 * guard and a rubber stamp -- so it is short, it is justified above, and the
 * result reports exactly which ids it excluded.
 */
export const SPECIAL_PASS_SHAPES = Object.freeze(['PassManager', 'PassAdaptor']);

export const isSpecialPass = (id) => SPECIAL_PASS_SHAPES.some((s) => id.includes(s));

/**
 * lld prints a size next to the unit: `handle (7 instructions)`,
 * `(secure_wipe) (1 node)`. The observer records the bare name. Stripping the
 * suffix is what lets the two be compared as sequences; without it 151 of 176
 * pairs "disagreed" on this lane's own healthy run.
 */
const UNIT_SIZE_SUFFIX = / \((\d+) (instruction|instructions|node|nodes|block|blocks)\)$/;

export const normaliseUnit = (u) => String(u).replace(UNIT_SIZE_SUFFIX, '');

/** The name lld uses for a module-level unit. */
export const MODULE_UNIT = '[module]';

/**
 * Parse `--lto-debug-pass-manager` output.
 *
 * Splitting on the LAST ` on ` rather than the first is load-bearing: pass ids
 * contain spaces (`PassManager<LazyCallGraph::SCC, CGSCCAnalysisManager, ...>`),
 * and a first-space split silently truncated three ids into nonsense the first
 * time this comparison was run by hand.
 */
export function parseLldPassLog(text) {
  const runs = [];
  const kinds = new Map();
  for (const raw of String(text ?? '').split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (line === '') continue;
    const colon = line.indexOf(':');
    if (colon > 0) {
      const k = line.slice(0, colon);
      kinds.set(k, (kinds.get(k) ?? 0) + 1);
    }
    if (!line.startsWith('Running pass: ')) continue;
    const body = line.slice('Running pass: '.length);
    const at = body.lastIndexOf(' on ');
    const pass = at >= 0 ? body.slice(0, at) : body;
    const unit = at >= 0 ? normaliseUnit(body.slice(at + 4)) : '';
    runs.push({ pass, unit });
  }
  return { runs, lineKinds: Object.fromEntries([...kinds].sort()) };
}

/** The record types this lane knows how to read. Anything else is a torn line. */
const KNOWN_RECORDS = new Set([
  'HANDSHAKE', 'SUBJECTRES', 'PASS', 'EV', 'UNIT', 'SNAP', 'SKIP', 'SUMMARY', 'HIST', 'STATS',
]);

/**
 * Parse an observer TSV log, and say how intact it is.
 *
 * The integrity half exists because of ThinLTO. Under `-flto=thin` lld builds
 * one PassBuilder per backend module, the plugin's registration callback runs
 * once per PassBuilder, and each run replaces a process-global tracker whose
 * constructor opens OBS_OUT truncating. With the default thread pool the
 * backends run concurrently, so this is not "the last log wins" -- measured on
 * this lane's own fixture, the file came back as `data` rather than text: 190766
 * bytes, 9 NUL bytes, 119 HANDSHAKE records across 3 module ids, and torn lines
 * whose first field was `ANDSHAKE`, `EPass`, `t &>24S`. A parser that quietly
 * skipped the garbage would hand a caller a plausible-looking history.
 */
export function parseObserverLog(buf) {
  const bytes = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf ?? ''), 'utf8');
  let nulBytes = 0;
  for (const b of bytes) if (b === 0) nulBytes++;
  const text = bytes.toString('utf8');

  const out = {
    handshakes: [], subjectRes: [], passes: [], ev: [], units: [], summaries: [], hist: [], stats: [],
    tornLines: [], counts: {}, nulBytes,
  };
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '').replace(/\0/g, '');
    if (line === '') continue;
    const f = line.split('\t');
    const type = f[0];
    if (!KNOWN_RECORDS.has(type)) { out.tornLines.push(line.slice(0, 120)); continue; }
    out.counts[type] = (out.counts[type] ?? 0) + 1;
    if (type === 'HANDSHAKE') out.handshakes.push({ schema: f[1], moduleId: f[2], target: f[3], control: f[4] });
    else if (type === 'SUBJECTRES') out.subjectRes.push({ moduleId: f[2], role: f[3], name: f[4], resolution: f[5] });
    else if (type === 'PASS') out.passes.push({ seq: Number(f[1]), phase: f[2], pass: f[3], unitKind: f[4], unitName: f[5] });
    else if (type === 'EV') out.ev.push({ seq: Number(f[1]), phase: f[2], pass: f[3], unit: f[5], role: f[7], count: Number(f[8]), state: f[9] });
    else if (type === 'UNIT') out.units.push({ seq: Number(f[1]), pass: f[2], unit: f[4], event: f[5] });
    else if (type === 'SUMMARY') out.summaries.push(parseSummaryRow(f));
    else if (type === 'HIST') out.hist.push({ unit: f[1], idx: Number(f[2]), seq: Number(f[3]), phase: f[4], pass: f[5], count: Number(f[6]), state: f[7] });
    else if (type === 'STATS') out.stats.push({ passesSeen: Number(f[1]), evRecords: Number(f[2]), unitsTracked: Number(f[3]), lineages: Number(f[4]), skipped: Number(f[5]), mode: f[6] });
  }
  out.intact = nulBytes === 0 && out.tornLines.length === 0 && out.handshakes.length <= 1;
  return out;
}

/** SUMMARY field order is fixed by History.h; only the fields this lane reads are named. */
function parseSummaryRow(f) {
  return {
    unit: f[1], lineage: f[2], role: f[3],
    firstLossSeq: f[5] === '-' ? null : Number(f[5]),
    firstLossPass: f[6] === '-' ? null : f[6],
    finalState: f[10],
    everPresent: f[11] === '1', everLost: f[12] === '1', everReintroduced: f[13] === '1',
    fate: f[15],
  };
}

/**
 * `<OBS_OUT>.summary.tsv` carries SUMMARY/HIST/STATS on their own.
 *
 * It has to be read separately, and this is not a convenience. Under full LTO
 * the MAIN log has no SUMMARY at all: lld exits without unwinding, so the
 * tracker's destructor -- which is what calls finish() -- never runs. Measured:
 * the main log of a healthy full-LTO link held HANDSHAKE 1, SUBJECTRES 2, PASS
 * 448, EV 388, UNIT 2 and no SUMMARY, HIST or STATS; the side file held all
 * three. A reader that only looked at the main log would find no attribution in
 * a run that produced one.
 */
export function parseObserverSummaryFile(text) {
  return parseObserverLog(Buffer.from(String(text ?? ''), 'utf8'));
}

/**
 * Guard 2. Compare the observer's before-pass callbacks with the linker's own
 * log, in both directions, as sets and as ordered sequences.
 *
 * `comparable` is false when either side is empty. That is deliberately NOT a
 * pass and NOT a failure: it is "these two readings cannot be compared", and the
 * caller decides which of UNSUPPORTED / BROKEN_MEASUREMENT that is, from what
 * else it knows.
 */
export function comparePassReadings(observerPasses, lldRuns) {
  const obs = observerPasses
    .filter((p) => p.phase === 'before')
    .map((p) => ({ pass: p.pass, unit: p.unitKind === 'module' ? MODULE_UNIT : p.unitName }));
  const excluded = obs.filter((p) => isSpecialPass(p.pass));
  const kept = obs.filter((p) => !isSpecialPass(p.pass));
  const lld = lldRuns.map((r) => ({ pass: r.pass, unit: r.unit }));

  const lldSet = new Set(lld.map((r) => r.pass));
  const keptSet = new Set(kept.map((r) => r.pass));
  const observerOnly = [...keptSet].filter((p) => !lldSet.has(p)).sort();
  const lldOnly = [...lldSet].filter((p) => !keptSet.has(p)).sort();

  // The separator is NUL because a pass id contains whatever a C++ template
  // spells -- spaces, commas, `&` -- so a separator an id can contain would make
  // two different pairs compare equal. Written as an escape rather than as the
  // raw byte it used to be: as a raw byte this file is `data` to file(1) and
  // binary to grep, which skips it without saying so.
  const key = (r) => `${r.pass}\u0000${r.unit}`;
  const sequenceEqual = kept.length === lld.length && kept.every((r, i) => key(r) === key(lld[i]));
  const mismatches = [];
  for (let i = 0; i < Math.min(kept.length, lld.length) && mismatches.length < 5; i++) {
    if (key(kept[i]) !== key(lld[i])) mismatches.push({ index: i, observer: kept[i], lld: lld[i] });
  }

  return {
    comparable: kept.length > 0 && lld.length > 0,
    // The requirement the task states: nothing the observer reports may be
    // outside what the linker says it ran.
    subset: observerOnly.length === 0,
    // Strictly stronger, and it held on every healthy cell this lane has run.
    sequenceEqual,
    counts: {
      observerBeforeCallbacks: obs.length,
      observerSpecialExcluded: excluded.length,
      observerCompared: kept.length,
      lldRunningPassLines: lld.length,
    },
    excludedPassIds: [...new Set(excluded.map((p) => p.pass))].sort(),
    observerOnly,
    lldOnly,
    firstMismatches: mismatches,
  };
}
