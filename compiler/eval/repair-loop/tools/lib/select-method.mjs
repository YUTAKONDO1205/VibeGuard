/**
 * Choosing the next repair method: the selection step of the r6b auto-loop, as
 * pure functions.
 *
 * The loop (a lab tool outside this tree) compiled a cell, read it with the find
 * step's verdictOf, and when a wipe was eliminated chose a repair METHOD -- one
 * of a small set of plugin configurations a person wrote -- from four sources,
 * in this order:
 *
 *   1. fromTable        the table (`tables.<name>.rows`): one method per
 *                       (compiler, stage, shape) cell, each row citing the run
 *                       it was taken from
 *   2. byClaims         the first method, by `order`, whose declared shapes
 *                       (`claims`) cover every shape seen
 *   3. byPartialClaims  the untried method covering the most of them
 *   4. route            none: SOURCE when a shape is one the compiler cannot
 *                       hold (`sourceSideShapes`), otherwise HUMAN
 *
 * and, when the chosen method did not retain the wipe, read the plugin record's
 * `unhandled` counters (`counterToShape`) and chose again from 2-4 among the
 * methods not yet tried, up to three attempts. The record chose the next method;
 * it never decided survival -- the verdict did.
 *
 * What this file does NOT do. It does not make methods: every method in a set is
 * a repair a person wrote, and its `claims` are copied from that person's
 * description, not learned. It does not compile, read a file, or decide whether
 * anything survived. The one thing that grows from measurements is the table,
 * and only by `learnRows`, whose rule is r6b's learn.py: a row is added for a
 * cell only when every measured instance of it was repaired on the first attempt
 * by the same method, and the row cites that run.
 *
 * The functions are r6b's vgloop.mjs selection (fromTable, byClaims,
 * byPartialClaims, route, shapesFromRecord, stageOf, and the loop's control
 * flow), with the set and the table passed in rather than read at import. The
 * `why` strings are r6b's, character for character, so that a replay can be
 * compared with what the loop wrote; the two stop messages r6b wrote in another
 * language are worded here in English and are compared by outcome only.
 */

export const SET_SCHEMA = 'select-method-set-v1';
export const CONDS = Object.freeze(['L0', 'L1', 'L2']);
export const MAX_ATTEMPTS = 3;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isName = (v) => typeof v === 'string' && v.length > 0;

/**
 * The set's own integrity. Returns a list of problems, empty when it is usable.
 * Nothing here says whether a claim is true; claims are a person's declaration.
 */
export function validateSet(set) {
  const p = [];
  if (!isObj(set)) return ['the method set is not an object'];
  if (set.schemaVersion !== SET_SCHEMA) p.push(`schemaVersion is ${JSON.stringify(set.schemaVersion)}, not ${SET_SCHEMA}`);
  if (!isObj(set.methods) || !Object.keys(set.methods).length) return [...p, 'methods is not a non-empty object'];
  for (const [n, m] of Object.entries(set.methods)) {
    if (!isName(m.cc)) p.push(`methods.${n}.cc is not a compiler name`);
    if (!Number.isInteger(m.order)) p.push(`methods.${n}.order is not an integer`);
    if (!Array.isArray(m.claims) || !m.claims.every(isName)) p.push(`methods.${n}.claims is not a list of shape names`);
    if (!isName(m.source)) p.push(`methods.${n}.source must say where the claims were copied from`);
    if (!isObj(m.env)) p.push(`methods.${n}.env is not an object`);
  }
  for (const [cc, n] of Object.entries(set.default ?? {})) {
    if (!set.methods[n]) p.push(`default.${cc} names no method`);
    else if (set.methods[n].cc !== cc) p.push(`default.${cc} is ${n}, a method for ${set.methods[n].cc}`);
  }
  if (!isObj(set.counterToShape)) p.push('counterToShape is not an object');
  if (!Array.isArray(set.sourceSideShapes)) p.push('sourceSideShapes is not a list');
  for (const [tn, t] of Object.entries(set.tables ?? {})) {
    if (!Array.isArray(t.rows)) { p.push(`tables.${tn}.rows is not a list`); continue; }
    const seen = new Set();
    t.rows.forEach((r, i) => {
      const at = `tables.${tn}.rows[${i}]`;
      for (const k of ['cc', 'stage', 'shape', 'method', 'evidence']) if (!isName(r[k])) p.push(`${at}.${k} is missing`);
      const m = set.methods[r.method];
      if (!m) p.push(`${at} names method ${r.method}, which is not in the set`);
      else if (m.cc !== r.cc) p.push(`${at} gives ${r.cc} the ${m.cc} method ${r.method}`);
      const key = `${r.cc}|${r.stage}|${r.shape}`;
      if (seen.has(key)) p.push(`${at} repeats the cell ${key}`);
      seen.add(key);
    });
  }
  return p;
}

/** The methods for one compiler, by `order`. */
export function methodsFor(set, cc) {
  return Object.entries(set.methods).filter(([, m]) => m.cc === cc).sort((a, b) => a[1].order - b[1].order);
}

/** Does `name` declare every one of `shapes`? */
export const covers = (set, name, shapes) => shapes.every((s) => set.methods[name].claims.includes(s));

/** 2: the first untried method, by order, that declares every shape. */
export function byClaims(set, cc, shapes, tried) {
  if (!shapes.length) return null;
  const c = methodsFor(set, cc).find(([n]) => !tried.includes(n) && covers(set, n, shapes));
  return c ? { method: c[0], why: `claims(${shapes.join('+')})` } : null;
}

/** 3: the untried method declaring the most of the shapes (ties: the lower order). */
export function byPartialClaims(set, cc, shapes, tried) {
  if (!shapes.length) return null;
  const c = methodsFor(set, cc).filter(([n]) => !tried.includes(n))
    .map(([n, m]) => ({ n, k: shapes.filter((s) => m.claims.includes(s)).length, o: m.order })).filter((x) => x.k > 0)
    .sort((a, b) => b.k - a.k || a.o - b.o)[0];
  return c ? { method: c.n, why: `partial-claims(${c.k}/${shapes.length} of ${shapes.join('+')})` } : null;
}

/** 4: no method. SOURCE when a shape is one the compiler cannot hold, HUMAN otherwise. */
export function route(set, shapes, why) {
  if (shapes.some((s) => set.sourceSideShapes.includes(s))) {
    return { method: null, route: 'SOURCE', why: `${why}; source-side shape ${shapes.join('+')}` };
  }
  return { method: null, route: 'HUMAN', why: `${why}; no method claims ${shapes.join('+') || '(no shape)'}` };
}

/**
 * 1: the table. Every shape must have a row for this compiler and stage, and the
 * method those rows name must be untried and declare every shape.
 */
export function fromTable(set, table, cc, stage, shapes, tried) {
  if (!shapes.length || !table) return null;
  const rows = shapes.map((s) => table.rows.find((t) => t.cc === cc && t.stage === stage.cls && t.shape === s));
  if (rows.some((x) => !x)) return null;
  const ms = [...new Set(rows.map((x) => x.method))].filter((n) => !tried.includes(n) && covers(set, n, shapes))
    .sort((a, b) => set.methods[a].order - set.methods[b].order);
  return ms.length ? { method: ms[0], why: `table(${cc},${stage.cls},${shapes.join('+')})`, fromTable: true } : null;
}

/**
 * The shapes a plugin record names: every `unhandled` counter above 0, through
 * `counterToShape`; a counter the set has no shape for is kept as
 * `counter:<name>`, so that no method claims it and it routes to a person rather
 * than disappearing. `record` is the record (or {pinnedCount, unhandled}), or
 * null when the compile wrote none.
 */
export function shapesFromRecord(set, record) {
  if (!record) return { shapes: [], why: 'no-record' };
  const u = record.unhandled ?? {};
  const shapes = Object.entries(u).filter(([, v]) => v > 0).map(([k]) => set.counterToShape[k] ?? `counter:${k}`);
  return { shapes: [...new Set(shapes)].sort(), pinned: record.pinnedCount ?? null,
    why: `record pinned=${record.pinnedCount ?? '-'} unhandled=${JSON.stringify(u)}` };
}

/**
 * The stage class of one cell from the stage tools' row (r6b: stage_clang.mjs's
 * second reading, stage_gcc.mjs's GIMPLE walk): clang `ir` when an IR pass was
 * found and no zero store is left at the end of the IR, gcc `gimple` when a
 * GIMPLE dump was named; otherwise the reason.
 */
export function stageOf(row, cc) {
  if (!row) return { cls: 'unknown', why: 'no-stage-row' };
  if (row.status !== 'OK') return { cls: 'unknown', why: row.status };
  const p = row.read2;
  if (cc.startsWith('clang')) {
    if (p && p.first > 0 && p.zeroAtEnd === 0) return { cls: 'ir', pass: p.pass, index: p.first };
    return { cls: 'after-ir', why: `read2 first=${p?.first} zeroAtEnd=${p?.zeroAtEnd}` };
  }
  if (p && p.first) return { cls: 'gimple', pass: p.first.key };
  return { cls: 'after-gimple', why: `zeroAtEnd=${p?.zeroAtEnd}` };
}

/**
 * The first method for a cell. L0 and L1 take the compiler's default (the
 * current design); L2 reads the table, then the declarations, then routes.
 */
export function firstSelection({ set, table, cc, cond, stage, shapes = [] }) {
  if (!CONDS.includes(cond)) throw new Error(`firstSelection: cond ${JSON.stringify(cond)} is not one of ${CONDS.join(', ')}`);
  if (cond !== 'L2') {
    const m = set.default[cc];
    if (!m) throw new Error(`firstSelection: the set has no default method for ${cc}`);
    return { method: m, why: 'default' };
  }
  const st = stage ?? { cls: 'unknown' };
  return fromTable(set, table, cc, st, shapes, []) ?? byClaims(set, cc, shapes, []) ?? byPartialClaims(set, cc, shapes, [])
    ?? route(set, shapes, `L2 stage=${st.cls}`);
}

/**
 * The method after a failed attempt: the record's shapes, then the
 * declarations, then a route. `tried` holds every method already applied.
 */
export function nextSelection({ set, cc, k, record, tried }) {
  const d = shapesFromRecord(set, record);
  const next = byClaims(set, cc, d.shapes, tried) ?? byPartialClaims(set, cc, d.shapes, tried) ?? route(set, d.shapes, `after k=${k}: ${d.why}`);
  return { rediagnosis: d, next };
}

/**
 * The next method for a v3 record, the one-call form a repair loop needs: given
 * what was tried and the record of the last failed attempt (or none, for the
 * first choice), the method to try, or a route.
 *
 * It decides with the set it is given, nothing else. The copied r6b set
 * (../select-method.r6b.json) is r6b's as of 2026-10-04: its methods know no
 * buffer barrier, and its sourceSideShapes routes `wipe-written-as-stores` to
 * SOURCE because pin-families.json then had no compiler-side row for that shape.
 * Since 2026-11-09 the table has two (WPIN_BUFFER_BARRIER=1, `unmeasured`). A
 * loop over wipe-pin-v3 records therefore has to build its set from
 * pin-families.json as it stands -- methods, claims and source-side shapes --
 * rather than call this with the r6b copy, which is kept to replay r6b only.
 */
export function selectMethod({ set, table = null, cc, cond = 'L2', stage = null, shapes = [], record = null, tried = [] }) {
  if (!tried.length && !record) return firstSelection({ set, table, cc, cond, stage, shapes });
  return nextSelection({ set, cc, k: tried.length, record, tried }).next;
}

/**
 * Replay the loop's control flow over the attempts it observed. `attempts[i]` is
 * {verdict, record} for the method applied at k = i + 1, the verdict the loop
 * read (WIPE_SURVIVED, WIPE_ELIMINATED or another word), the record as above.
 * Returns the steps (each choice and why) and the outcome the loop would write.
 */
export function replayLoop({ set, table, cc, cond, stage, shapes = [], attempts = [] }) {
  const steps = [];
  const tried = [];
  let next = firstSelection({ set, table, cc, cond, stage, shapes });
  for (let k = 1; k <= MAX_ATTEMPTS; k++) {
    if (!next.method) return { steps, outcome: next.route, why: next.why };
    const at = attempts[k - 1];
    if (!at) return { steps, outcome: null, pending: next };
    tried.push(next.method);
    const step = { k, method: next.method, why: next.why, fromTable: !!next.fromTable };
    steps.push(step);
    if (at.verdict === 'WIPE_SURVIVED') return { steps, outcome: 'REPAIRED', method: next.method, k };
    if (at.verdict !== 'WIPE_ELIMINATED') return { steps, outcome: 'HUMAN', why: `repaired build verdict ${at.verdict}` };
    if (cond === 'L0') return { steps, outcome: 'FAILED', why: 'L0 does not go back: the current design applies its one method' };
    const n = nextSelection({ set, cc, k, record: at.record, tried });
    step.rediagnosis = n.rediagnosis;
    next = n.next;
  }
  return { steps, outcome: 'FAILED', why: `${MAX_ATTEMPTS} attempts, and none retained the wipe` };
}

/**
 * One r6b loop row against its replay. The row is as vgloop.mjs wrote it
 * ({cc, cond, stage, shapes, iters: [{k, why, fromTable, method, verdict,
 * pinned, unhandled, component, rediagnosis?}], outcome, why, method, k}).
 * The record of an attempt is rebuilt from what the row kept of it
 * ({pinnedCount, unhandled}); an attempt that wrote no record kept component
 * null. Returns the differences, empty when every choice and the outcome agree.
 */
export function compareLoopRow(row, { set, table }) {
  const attempts = (row.iters ?? []).map((it) => ({
    verdict: it.verdict,
    record: it.component === null || it.component === undefined ? null : { pinnedCount: it.pinned, unhandled: it.unhandled },
  }));
  const rep = replayLoop({ set, table, cc: row.cc, cond: row.cond, stage: row.stage, shapes: row.shapes ?? [], attempts });
  const diff = [];
  const its = row.iters ?? [];
  if (rep.steps.length !== its.length) diff.push(`steps: replay ${rep.steps.length}, row ${its.length}`);
  rep.steps.forEach((s, i) => {
    const it = its[i];
    if (!it) return;
    if (s.method !== it.method) diff.push(`k=${s.k} method: replay ${s.method}, row ${it.method}`);
    if (s.why !== it.why) diff.push(`k=${s.k} why: replay ${JSON.stringify(s.why)}, row ${JSON.stringify(it.why)}`);
    if (s.fromTable !== !!it.fromTable) diff.push(`k=${s.k} fromTable: replay ${s.fromTable}, row ${!!it.fromTable}`);
    if (s.rediagnosis || it.rediagnosis) {
      const a = JSON.stringify(s.rediagnosis?.shapes ?? null), b = JSON.stringify(it.rediagnosis?.shapes ?? null);
      if (a !== b) diff.push(`k=${s.k} rediagnosis.shapes: replay ${a}, row ${b}`);
      if ((s.rediagnosis?.why ?? null) !== (it.rediagnosis?.why ?? null)) diff.push(`k=${s.k} rediagnosis.why differs`);
    }
  });
  if (rep.outcome !== row.outcome) diff.push(`outcome: replay ${rep.outcome}, row ${row.outcome}`);
  if (rep.outcome === 'REPAIRED' && (rep.method !== row.method || rep.k !== row.k)) {
    diff.push(`repaired by: replay ${rep.method} k=${rep.k}, row ${row.method} k=${row.k}`);
  }
  // A route is a selection and its sentence is compared; the two stops (L0, and
  // three failed attempts) are the loop's control flow, compared by outcome.
  const routed = rep.outcome === 'SOURCE' || rep.outcome === 'HUMAN';
  if (routed && rep.why !== row.why) diff.push(`why: replay ${JSON.stringify(rep.why)}, row ${JSON.stringify(row.why)}`);
  return diff;
}

/**
 * The table's only way to grow: r6b's learn.py over the L2 rows of one run.
 * Group the L2 rows by (compiler, stage class, shapes). A group the table does
 * not already cover in full is a candidate; it is adopted when it has exactly
 * one shape and every row of it was REPAIRED at k = 1 by the same method. The
 * adopted row cites the run (`evidenceOf(group)`); every candidate, adopted or
 * not, is returned in `considered`, so a group left out is visible.
 */
export function learnRows(loopRows, table, evidenceOf) {
  const groups = new Map();
  for (const r of loopRows ?? []) {
    if (r.cond !== 'L2' || !r.stage) continue;
    const shapes = r.shapes ?? [];
    const key = JSON.stringify([r.cc, r.stage.cls, shapes]);
    if (!groups.has(key)) groups.set(key, { cc: r.cc, stage: r.stage.cls, shapes, rows: [] });
    groups.get(key).rows.push(r);
  }
  const adopted = [];
  const considered = [];
  // learn.py's sorted() over (cc, stage, tuple(shapes)): element by element, a
  // shorter tuple before a longer one it is a prefix of
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  const tupleCmp = (x, y) => {
    for (let i = 0; i < Math.min(x.length, y.length); i++) { const c = cmp(x[i], y[i]); if (c) return c; }
    return x.length - y.length;
  };
  const ordered = [...groups.values()].sort((a, b) => cmp(a.cc, b.cc) || cmp(a.stage, b.stage) || tupleCmp(a.shapes, b.shapes));
  for (const g of ordered) {
    const known = g.shapes.length > 0 && g.shapes.every((s) => table.rows.some((t) => t.cc === g.cc && t.stage === g.stage && t.shape === s));
    if (known) continue;
    const outs = new Map();
    for (const r of g.rows) {
      const k = `${r.outcome}:${r.method ?? null}:k${r.k ?? null}`;
      outs.set(k, (outs.get(k) ?? 0) + 1);
    }
    const only = outs.size === 1 ? g.rows[0] : null;
    const ok = only && only.outcome === 'REPAIRED' && only.k === 1;
    const rec = { cc: g.cc, stage: g.stage, shapes: g.shapes, cells: g.rows.length, outcomes: Object.fromEntries(outs), adopted: null };
    if (ok && g.shapes.length === 1) {
      rec.adopted = only.method;
      adopted.push({ cc: g.cc, stage: g.stage, shape: g.shapes[0], method: only.method, evidence: evidenceOf(g) });
    }
    considered.push(rec);
  }
  return { rows: [...table.rows, ...adopted], adopted, considered };
}
