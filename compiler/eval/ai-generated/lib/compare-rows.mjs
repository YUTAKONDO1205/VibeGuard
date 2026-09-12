/**
 * Are two build-row files the same measurement?
 *
 *   node compare-rows.mjs <a.json> <b.json>
 *
 * build-analyze.mjs pushes rows in pool completion order, so two runs of the same
 * code over the same corpus are not expected to be byte-identical files. They are
 * expected to hold the same MULTISET of rows. Each row is canonicalised as
 * JSON.stringify(row) - key order preserved, because key order is part of what the
 * row writer promises - and the two multisets are compared.
 *
 * Prints the row count of each file and how many rows are only in a, only in b,
 * and identical. When they differ, rows are also paired by (id, kind, cc, opt) and
 * the fields that differ are counted, so a verdict that flipped can be told apart
 * from a row that is missing. Exit 0 iff the multisets are equal, 1 if they are
 * not, 2 on a usage or input error.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { createHash } from 'node:crypto';

// --record <path> writes the comparison itself, so that "the two runs held the
// same multiset" is a file a test can read back rather than a sentence in a
// README. It carries the two files' sha256 and their BASENAMES only: the whole
// point of the record is that it can be tracked, and a lab path names the
// machine that ran it (scripts/check-disclosure-shape.mjs).
const argv = process.argv.slice(2);
const positional = [];
let recordPath = null;
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--record') {
    if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) {
      process.stderr.write('--record needs a value\n'); process.exit(2);
    }
    recordPath = argv[++i];
  } else if (argv[i].startsWith('--')) {
    process.stderr.write(`unknown argument ${argv[i]}\n`); process.exit(2);
  } else positional.push(argv[i]);
}
const [aPath, bPath] = positional;
if (!aPath || !bPath) {
  process.stderr.write('usage: node compare-rows.mjs <a.json> <b.json> [--record <path>]\n');
  process.exit(2);
}

function load(p) {
  let rows;
  try { rows = JSON.parse(readFileSync(p, 'utf8')); }
  catch (e) { process.stderr.write(`cannot read ${p}: ${e.message}\n`); process.exit(2); }
  if (!Array.isArray(rows)) { process.stderr.write(`${p}: top level is not an array of rows\n`); process.exit(2); }
  return rows;
}

const a = load(aPath);
const b = load(bPath);

const counts = (rows) => {
  const m = new Map();
  for (const r of rows) { const k = JSON.stringify(r); m.set(k, (m.get(k) || 0) + 1); }
  return m;
};
const ca = counts(a), cb = counts(b);

let identical = 0;
const onlyA = [], onlyB = [];
for (const [k, n] of ca) {
  const m = cb.get(k) || 0;
  identical += Math.min(n, m);
  for (let i = m; i < n; i++) onlyA.push(k);
}
for (const [k, n] of cb) {
  const m = ca.get(k) || 0;
  for (let i = m; i < n; i++) onlyB.push(k);
}
onlyA.sort(); onlyB.sort();

const out = {
  a: aPath, b: bPath,
  rows_a: a.length, rows_b: b.length,
  identical, only_in_a: onlyA.length, only_in_b: onlyB.length,
  equal: onlyA.length === 0 && onlyB.length === 0,
};

if (!out.equal) {
  // Pair the leftovers by cell identity to say WHAT differs, not only how much.
  const cellKey = (r) => JSON.stringify([r.id, r.kind, r.cc ?? null, r.opt ?? null]);
  const byCell = new Map();
  for (const k of onlyA) { const r = JSON.parse(k); const c = cellKey(r); if (!byCell.has(c)) byCell.set(c, { a: [], b: [] }); byCell.get(c).a.push(r); }
  for (const k of onlyB) { const r = JSON.parse(k); const c = cellKey(r); if (!byCell.has(c)) byCell.set(c, { a: [], b: [] }); byCell.get(c).b.push(r); }
  const fieldDiffs = {};
  const transitions = {};
  let paired = 0, unpairedA = 0, unpairedB = 0;
  const examples = [];
  for (const [c, { a: ra, b: rb }] of byCell) {
    const n = Math.min(ra.length, rb.length);
    paired += n; unpairedA += ra.length - n; unpairedB += rb.length - n;
    for (let i = 0; i < n; i++) {
      const x = ra[i], y = rb[i];
      const keys = new Set([...Object.keys(x), ...Object.keys(y)]);
      const diff = [];
      for (const key of keys) if (JSON.stringify(x[key]) !== JSON.stringify(y[key])) diff.push(key);
      if (!diff.length) diff.push('(key order)');
      for (const key of diff) fieldDiffs[key] = (fieldDiffs[key] || 0) + 1;
      if (x.verdict !== y.verdict) {
        const t = `${x.verdict} -> ${y.verdict}`;
        transitions[t] = (transitions[t] || 0) + 1;
      }
      if (examples.length < 10) examples.push({ cell: JSON.parse(c), fields: diff, a: Object.fromEntries(diff.filter((d) => d in x).map((d) => [d, x[d]])), b: Object.fromEntries(diff.filter((d) => d in y).map((d) => [d, y[d]])) });
    }
  }
  Object.assign(out, { paired_by_cell: paired, unpaired_only_in_a: unpairedA, unpaired_only_in_b: unpairedB, differing_fields: fieldDiffs, verdict_transitions: transitions, examples });
}

process.stdout.write(JSON.stringify(out, null, 2) + '\n');

if (recordPath) {
  const digest = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
  const record = {
    tool: 'compare-rows', generatedAt: new Date().toISOString(), node: process.version,
    a: { file: basename(aPath), sha256: digest(aPath), rows: a.length },
    b: { file: basename(bPath), sha256: digest(bPath), rows: b.length },
    identical, only_in_a: onlyA.length, only_in_b: onlyB.length, equal: out.equal,
  };
  if (!out.equal) {
    record.differing_fields = out.differing_fields ?? {};
    record.verdict_transitions = out.verdict_transitions ?? {};
    record.paired_by_cell = out.paired_by_cell ?? 0;
  }
  const text = JSON.stringify(record, null, 2) + '\n';
  for (const re of [/\/home\//, /\/root\//, /\/mnt\//, /\/Users\//, /\b[A-Za-z]:[\\/]/]) {
    if (re.test(text)) { process.stderr.write(`a path naming this machine would have been recorded (${re}); nothing written\n`); process.exit(2); }
  }
  writeFileSync(recordPath, text, 'utf8');
  process.stderr.write(`wrote the comparison to ${basename(recordPath)}\n`);
}

process.exit(out.equal ? 0 : 1);
