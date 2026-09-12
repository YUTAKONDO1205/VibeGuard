/**
 * The row a cell produces, and the rules a row has to obey before it is written
 * anywhere.
 *
 * Pure. Two rules from compiler/schema are enforced here rather than trusted:
 *
 *   1. EVERY NUMBER IS AN INTEGER. Ratios are {num, den}; there are no floats in
 *      a record in this directory, because a float is a rounding decision made
 *      by whoever wrote it and nobody downstream can undo it. `assertIntegers`
 *      walks the row and names the first offender.
 *   2. NO ABSOLUTE PATHS. A record is meant to be checkable on another machine
 *      and a lab path is not portable, so nothing under a home directory, a
 *      mount point or a drive letter may appear in a value. `assertNoPaths` is
 *      the same scan the provenance check applies, applied before the file is
 *      written rather than after it is committed.
 *
 * Also here: the cell id, which is the only thing that ties an observation, an
 * assembly listing, an object file and a verdict together, so it is built in one
 * place and parsed in one place.
 */

/** The measurement matrix this lane defines. Levels and vendors in a fixed order. */
export const OPTS = Object.freeze(['-O0', '-O1', '-O2', '-O3', '-Os']);
export const VENDORS = Object.freeze(['clang-18', 'gcc-13']);
export const IDIOMS = Object.freeze(['memset', 'volatile-loop', 'explicit-bzero']);
export const ARMS = Object.freeze(['stock', 'wipepin']);

/**
 * A cell id, and the only permitted spelling of one.
 *
 * `<arm>/<cc>/<opt>/<subject>` -- subject being an idiom or a control name. The
 * opt level keeps its leading dash because that is what the compiler was handed,
 * and a record that renames a flag is a record a reader has to translate.
 */
export function cellId({ arm, cc, opt, subject }) {
  for (const [k, v] of Object.entries({ arm, cc, opt, subject })) {
    if (typeof v !== 'string' || !v) throw new TypeError(`cellId: ${k} must be a non-empty string`);
    if (v.includes('/')) throw new TypeError(`cellId: ${k} must not contain a slash`);
  }
  return `${arm}/${cc}/${opt}/${subject}`;
}

export function parseCellId(id) {
  if (typeof id !== 'string') return null;
  const p = id.split('/');
  if (p.length !== 4) return null;
  return { arm: p[0], cc: p[1], opt: p[2], subject: p[3] };
}

/** The full matrix, controls first. Controls come first so a run that is cut short still has them. */
export function plannedCells({ opts = OPTS, vendors = VENDORS, idioms = IDIOMS, arms = ARMS, controls } = {}) {
  const cells = [];
  for (const [name, spec] of Object.entries(controls || {})) {
    // Controls are stock-only and, where the control pins a level, at that level
    // alone: a control whose whole point is that -O0 cannot remove a memset is
    // not a control at -O2.
    const levels = spec.opt ? [spec.opt] : opts;
    for (const cc of vendors) for (const opt of levels) {
      cells.push({ kind: 'control', control: name, arm: 'stock', cc, opt, subject: name, target: spec.target, expect: spec.expect });
    }
  }
  for (const arm of arms) for (const cc of vendors) for (const opt of opts) for (const idiom of idioms) {
    cells.push({ kind: 'subject', control: null, arm, cc, opt, subject: idiom, target: idiom, expect: null });
  }
  return cells.map((c) => ({ ...c, cell: cellId({ arm: c.arm, cc: c.cc, opt: c.opt, subject: c.subject }) }));
}

/**
 * What no cell observes, named rather than left to silence.
 *
 * The observer writes this same list into every record (see the literal in
 * observer/residue-observer.c); this is the value a row carries when there is no
 * record to take it from, and the two are held identical by a test.
 */
export const UNOBSERVED = Object.freeze(['ymm-upper', 'zmm-upper', 'heap', 'other-threads',
  'kernel-saved-state', 'stack-below-the-window', 'stack-above-the-window']);

const PATHISH = [/(^|[^A-Za-z0-9])\/home\//, /(^|[^A-Za-z0-9])\/root\//, /(^|[^A-Za-z0-9])\/mnt\//,
  /(^|[^A-Za-z0-9])\/Users\//, /\b[A-Za-z]:[\\/]/, /\\\\/];

/** Every string value in the row, with the key path that reached it. */
function* strings(value, path = '') {
  if (typeof value === 'string') { yield [path, value]; return; }
  if (Array.isArray(value)) { for (let i = 0; i < value.length; i++) yield* strings(value[i], `${path}[${i}]`); return; }
  if (value && typeof value === 'object') {
    for (const k of Object.keys(value)) yield* strings(value[k], path ? `${path}.${k}` : k);
  }
}

function* numbers(value, path = '') {
  if (typeof value === 'number') { yield [path, value]; return; }
  if (Array.isArray(value)) { for (let i = 0; i < value.length; i++) yield* numbers(value[i], `${path}[${i}]`); return; }
  if (value && typeof value === 'object') {
    for (const k of Object.keys(value)) yield* numbers(value[k], path ? `${path}.${k}` : k);
  }
}

export function assertIntegers(row) {
  const bad = [];
  for (const [path, n] of numbers(row)) {
    if (!Number.isInteger(n)) bad.push(`${path} = ${n} is not an integer`);
    else if (!Number.isSafeInteger(n)) bad.push(`${path} = ${n} is outside the exactly-representable range`);
  }
  return { ok: bad.length === 0, problems: bad };
}

export function assertNoPaths(row) {
  const bad = [];
  for (const [path, s] of strings(row)) {
    for (const re of PATHISH) if (re.test(s)) { bad.push(`${path} carries an absolute path: ${s}`); break; }
  }
  return { ok: bad.length === 0, problems: bad };
}

/**
 * Assemble one row.
 *
 * Deliberately flat and deliberately dull: the interesting judgement already
 * happened in grade.mjs, and a row builder that decided anything would be a
 * second place to look for a verdict.
 */
export function buildRow({ planned, confirm, graded, obs, digests, needleLen, controlNeedleLen, scanAgrees, frame }) {
  const stop = (obs && obs.stop) || {};
  const win = (obs && obs.window) || {};
  const text = (obs && obs.text) || {};
  const fr = frame || {};
  const row = {
    cell: planned.cell,
    kind: planned.kind,
    control: planned.control,
    arm: planned.arm,
    cc: planned.cc,
    opt: planned.opt,
    subject: planned.subject,
    idiom: planned.kind === 'subject' ? planned.subject : null,

    // The find step's own verdict, from the find step's own code, on the very
    // listing that was assembled and run. See the runner for why that matters.
    confirmVerdict: confirm ? confirm.verdict : 'NOT_RUN',
    confirmControl: confirm ? (confirm.control ?? null) : null,
    confirmControlVia: confirm ? (confirm.control_via ?? null) : null,
    nSpans: confirm && Number.isInteger(confirm.nSpans) ? confirm.nSpans : null,

    measurement: graded.measurement,
    reason: graded.reason,
    controlHeld: graded.controlHeld,
    residue: graded.residue,
    longestRunBytes: graded.longestRunBytes,
    controlRunBytes: graded.controlRunBytes,
    needleLen: Number.isInteger(needleLen) ? needleLen : null,
    controlNeedleLen: Number.isInteger(controlNeedleLen) ? controlNeedleLen : null,
    scanAgrees: scanAgrees === undefined ? null : scanAgrees,

    stop: {
      expectedRip: Number.isInteger(stop.expectedRip) ? stop.expectedRip : null,
      rip: Number.isInteger(stop.rip) ? stop.rip : null,
      matched: stop.matched === undefined ? null : stop.matched,
      expectedRsp: Number.isInteger(stop.expectedRsp) ? stop.expectedRsp : null,
      rsp: Number.isInteger(stop.rsp) ? stop.rsp : null,
      rspMatched: stop.rspMatched === undefined ? null : stop.rspMatched,
    },
    window: {
      lo: Number.isInteger(win.lo) ? win.lo : null,
      hi: Number.isInteger(win.hi) ? win.hi : null,
      bytesRead: Number.isInteger(win.bytesRead) ? win.bytesRead : null,
      // How far below the stop rsp the window actually reached, which is the
      // number the frame bound is compared against. Derived from the record
      // rather than from the flag that was passed, so a row says what was read.
      belowReached: Number.isInteger(win.lo) && Number.isInteger(stop.rsp) ? stop.rsp - win.lo : null,
      sha256: (digests && digests.window) || null,
    },
    // The subject function's own frame, read out of the binary that was run.
    // `parsed: false` is why a cell can be BROKEN_MEASUREMENT with the window
    // intact: nothing established that the window reached the buffer. See
    // lib/frame.mjs.
    frame: {
      parsed: fr.parsed === undefined ? null : fr.parsed,
      subjectBytes: Number.isInteger(fr.subjectBytes) ? fr.subjectBytes : null,
      form: typeof fr.form === 'string' ? fr.form : null,
      requiredBelow: Number.isInteger(fr.requiredBelow) ? fr.requiredBelow : null,
      why: typeof fr.why === 'string' ? fr.why : null,
    },
    textRestoredMatchesFile: text.restoredMatchesFile === undefined ? null : text.restoredMatchesFile,
    exe: {
      sha256Before: (digests && digests.exeBefore) || null,
      sha256After: (digests && digests.exeAfter) || null,
      unmodified: digests && digests.exeBefore && digests.exeAfter
        ? digests.exeBefore === digests.exeAfter : null,
    },
    asmSha256: (digests && digests.asm) || null,
    objSha256: (digests && digests.obj) || null,
    // Not measured, in every cell, and named so that a reader is not left to
    // infer it from silence. BOTH sides of the window are named: the earlier list
    // had only `stack-below-the-window`, which left the caller frames between the
    // window's top and the stack's top unnamed even though the README's prose
    // ("the stack outside that 4160-byte window") already counted them out. A
    // machine-readable field that is narrower than the prose is the half a script
    // would believe. Kept in step with the observer's own literal by
    // test/observer-record.test.mjs.
    unobserved: (obs && Array.isArray(obs.unobserved)) ? obs.unobserved : [...UNOBSERVED],
  };
  return row;
}

/** The cross-tab, rendered. Counts only; the interpretation is the README's job. */
export function renderCrossTab(tab) {
  const L = [];
  L.push('confirm verdict          residue NONE   PARTIAL      FULL');
  for (const v of ['WIPE_SURVIVED', 'WIPE_ELIMINATED']) {
    const n = tab.cells[`${v}|NONE`], p = tab.cells[`${v}|PARTIAL`], f = tab.cells[`${v}|FULL`];
    L.push(`${v.padEnd(24)}${String(n).padStart(12)}${String(p).padStart(10)}${String(f).padStart(10)}`);
  }
  L.push(`graded cells: ${tab.graded}`);
  const ex = Object.entries(tab.excluded).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (ex.length === 0) L.push('excluded: none');
  else for (const [k, n] of ex) L.push(`excluded: ${n} x ${k}`);
  return L.join('\n');
}
