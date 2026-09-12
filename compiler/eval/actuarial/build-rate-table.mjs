/**
 * Derive the disappearance-rate table from the tracked r2 build rows.
 *
 *   node compiler/eval/actuarial/build-rate-table.mjs            # print, write nothing
 *   node compiler/eval/actuarial/build-rate-table.mjs --write    # rewrite data/
 *   node compiler/eval/actuarial/build-rate-table.mjs --check    # exit 1 on drift
 *
 * This is the only executable in the lane and it is NOT called `run-actuarial.mjs`,
 * which is the layout the other lanes follow. The deviation is deliberate and is
 * the honest name: every other `run-*` invokes a toolchain and produces a
 * measurement. This one invokes nothing. It reads a record another lane measured
 * and counts it, so the whole of its output is a derivation of bytes that are
 * already tracked, and `--check` can be run on any machine, with no compiler
 * installed, and get the same answer.
 *
 * No shebang on purpose. A shebang line terminated by CRLF silently stops a module
 * from loading under WSL, which has cost this project two sessions; `node <path>`
 * needs no shebang and cannot acquire the fault.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildTable, renderText } from './lib/rate-table.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../..'); // repository root

/**
 * Repo-relative, and it stays repo-relative into the record. `provenance` that
 * names a path on the machine that ran it is a disclosure (scripts/check-disclosure-shape.mjs
 * classifies a home directory as one) and is also useless to the reader, who has
 * this tree and not that machine.
 */
export const SOURCE_REL = 'compiler/eval/ai-generated/data/r2-build-rows.json';
export const CORPUS_ID = 'r2';
/**
 * The protocol is cited by id, not by digest. It is a living document -- its own
 * change log has entries from after the rows were produced -- so pinning its hash
 * here would make this table drift every time a sentence of prose is added to it,
 * and a drift alarm that fires on prose is one nobody reads. What must not move is
 * the rows file, and that is pinned by sha256 below.
 */
export const PROTOCOL_ID = 'PROTOCOL-r2.md';

export const OUT_JSON = join(HERE, 'data', 'rate-table.json');
export const OUT_TEXT = join(HERE, 'data', 'rate-table.txt');

/** Read the rows and digest exactly the bytes that were parsed. */
export function loadRows(root = ROOT) {
  const buf = readFileSync(join(root, SOURCE_REL));
  const rows = JSON.parse(buf.toString('utf8'));
  return {
    rows,
    provenance: {
      file: SOURCE_REL,
      sha256: createHash('sha256').update(buf).digest('hex'),
      bytes: buf.length,
      corpusId: CORPUS_ID,
      protocol: PROTOCOL_ID,
    },
  };
}

export function currentTable(root = ROOT) {
  const { rows, provenance } = loadRows(root);
  return buildTable(rows, provenance);
}

export const serialise = (table) => `${JSON.stringify(table, null, 2)}\n`;

function main(argv) {
  const write = argv.includes('--write');
  const check = argv.includes('--check');
  const table = currentTable();
  const json = serialise(table);
  const text = renderText(table);

  if (write) {
    mkdirSync(dirname(OUT_JSON), { recursive: true });
    writeFileSync(OUT_JSON, json, 'utf8');
    writeFileSync(OUT_TEXT, text, 'utf8');
    process.stderr.write(`wrote data/rate-table.json and data/rate-table.txt (${table.cells.length} cells)\n`);
    return 0;
  }

  if (check) {
    // Compared with newlines normalised. `.gitattributes` already forces LF for
    // compiler/**, so this is not papering over a real difference -- it stops a
    // checkout policy from being reported as a drift in the numbers, which is
    // what this check is for.
    const norm = (s) => s.replace(/\r\n/g, '\n');
    const bad = [];
    for (const [path, want] of [[OUT_JSON, json], [OUT_TEXT, text]]) {
      let have;
      try {
        have = readFileSync(path, 'utf8');
      } catch {
        bad.push(`${path}: missing`);
        continue;
      }
      if (norm(have) !== norm(want)) bad.push(`${path}: differs from what the rows say now`);
    }
    if (bad.length) {
      process.stderr.write(`${bad.join('\n')}\nrun with --write after deciding which side is right\n`);
      return 1;
    }
    process.stderr.write('data/ matches the rows\n');
    return 0;
  }

  process.stdout.write(text);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('build-rate-table.mjs')) {
  process.exitCode = main(process.argv.slice(2));
}
