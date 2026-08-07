#!/usr/bin/env node
// Write one measurement into the store.
//
// WHAT THIS DOES AND DOES NOT MEASURE
//
//   It does not run a compiler. Observations come in as data — produced by
//   whichever harness owns the measurement — and this file's job is the part
//   that has to be identical for every measurement in the store: attach
//   provenance that can be re-run from, attach the toolchain that actually
//   executed, seal through the one canonicaliser, and put the result somewhere
//   outside the checkout. Keeping the compiler out of here is what lets the
//   same writer serve a frontend measurement, an IR measurement and a link
//   measurement without any of them teaching it their vocabulary.
//
//   The toolchain block is MEASURED here rather than declared by the caller:
//   each named binary is hashed and asked for its version. A caller that could
//   write its own sha256 into the record would be writing a claim, and the
//   whole reason the field exists is that two machines with the same version
//   string routinely run different bytes.
//
// TWO RUNS
//
//   `--run 1` and `--run 2` of the same `--pair-id` are the re-run pair. The
//   two files must be byte-identical outside the top-level `context` subtree,
//   which is where every volatile field lives; `validate-store.mjs` compares
//   them and reports the pair as NOT CHECKED while only one half exists.
//
//   node record-run.mjs --observations obs.json --store <dir> --pair-id p --run 1
//
// INPUT (`--observations`)
//
//   { "recordId": "...",
//     "oracle": { "kind": "call-site", "pattern": "call void @llvm.memset" },
//     "toolchainBinaries": ["/usr/bin/clang-18"],
//     "observations": [ { "config": "O0", "subject": 1, "control": 1 } ] }

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { writeRecordSync } from './canon.mjs';
import { reportCounts } from './counting.mjs';
import { assertNoSymlink, SymlinkRefused } from './fsguard.mjs';
import { REPO_ROOT, resolveStoreRoot, MEASUREMENT_SCHEMA, STORE_ENV } from './store.mjs';

const EXIT_OK = 0;
const EXIT_TOOL_FAILED = 1;
const EXIT_FINDINGS = 2;
const EXIT_INCOMPLETE = 3;

function sha256File(p) {
  return createHash('sha256').update(readFileSync(p)).digest('hex');
}

/** A version number if the tool prints one, otherwise its first line. */
function toolVersion(bin) {
  let text;
  try {
    text = execFileSync(bin, ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch (e) {
    throw new Error(`${basename(bin)} --version failed: ${e.message}`);
  }
  const m = /(\d+\.\d+\.\d+)/.exec(text);
  return m ? m[1] : text.split('\n')[0].trim();
}

/**
 * The provenance of the checkout the measurement was taken against.
 *
 * A dirty tree is recorded rather than refused — refusing it would only teach
 * people to commit before measuring, which does not make the measurement
 * reproducible, it makes the irreproducibility invisible. What it must carry
 * instead is the digest of the difference, so that the pair
 * (gitSha, diffSha256) names the inputs exactly.
 *
 * The digest covers UNTRACKED files as well as modified ones. `git diff HEAD`
 * does not see an untracked file at all, so a digest built from it alone is
 * unchanged by adding, editing or deleting the very file the measurement is
 * about — and `git status --porcelain` calls that tree dirty, so the record
 * would carry a `true` flag beside a digest that could not move. Untracked
 * paths are enumerated through `ls-files --others --exclude-standard`, which
 * honours the ignore rules, and each one contributes its path and the sha256
 * of its bytes.
 */
export function gitProvenance(repo = REPO_ROOT) {
  const git = (args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  const gitSha = git(['rev-parse', 'HEAD']).trim();
  const status = git(['status', '--porcelain']).trim();
  const dirty = status !== '';
  if (!dirty) return { gitSha, dirty, diffSha256: null };

  const h = createHash('sha256');
  h.update('status\n', 'utf8');
  h.update(`${status}\n`, 'utf8');
  h.update('diff\n', 'utf8');
  h.update(git(['diff', 'HEAD']), 'utf8');
  h.update('untracked\n', 'utf8');
  const untracked = git(['ls-files', '--others', '--exclude-standard', '-z']).split('\0').filter(Boolean).sort();
  for (const rel of untracked) {
    h.update(`${rel}\n`, 'utf8');
    try {
      h.update(sha256File(join(repo, rel)), 'utf8');
    } catch (e) {
      // A path that cannot be read is recorded as unreadable rather than
      // omitted: omitting it would make two different trees hash the same.
      h.update(`unreadable:${e.code ?? 'error'}`, 'utf8');
    }
    h.update('\n', 'utf8');
  }
  return { gitSha, dirty, diffSha256: h.digest('hex') };
}

/** The measured toolchain block. Paths lose their leading slash, per paths.mjs. */
export function toolchainBlock(binaries) {
  return binaries.map((b) => {
    const abs = resolve(b);
    statSync(abs);
    return {
      name: basename(abs),
      version: toolVersion(abs),
      path: abs.replace(/^\//, '').replace(/^([A-Za-z]):[\\/]/, '$1/').split('\\').join('/'),
      sha256: sha256File(abs),
    };
  });
}

function usage() {
  return [
    'usage: node record-run.mjs --observations <file> --pair-id <id> --run <1|2> [--store <dir>]',
    '',
    `  --store <dir>       where the record goes (or $${STORE_ENV}); never under the checkout`,
    '  --repo <dir>        the checkout whose sha is recorded (default: this one)',
    '  --allow-empty       write a record with no observations (it will not validate)',
    '  --link-boundary <dir>  stop the symlink walk at <dir>',
    '  --json              machine-readable output',
    '',
    'exit: 0 written, 1 a tool failed, 2 refused (store inside the checkout, or a link), 3 could not complete',
  ].join('\n');
}

export function main(argv, io = {}) {
  const out = io.out ?? process.stdout;
  const err = io.err ?? process.stderr;
  const flag = (n) => argv.includes(n);
  const val = (n, d = null) => {
    const i = argv.indexOf(n);
    return i >= 0 && i + 1 < argv.length && !argv[i + 1].startsWith('--') ? argv[i + 1] : d;
  };
  const asJson = flag('--json');
  const allowEmpty = flag('--allow-empty');

  if (argv.length === 0 || flag('--help') || flag('-h')) {
    out.write(`${usage()}\n`);
    return EXIT_OK;
  }

  const obsPath = val('--observations');
  const pairId = val('--pair-id');
  const run = Number(val('--run', '0'));
  if (!obsPath || !pairId || ![1, 2].includes(run)) {
    err.write(`${usage()}\n`);
    return EXIT_INCOMPLETE;
  }

  const linkBoundary = val('--link-boundary');
  let spec;
  try {
    assertNoSymlink(obsPath, { role: 'the observations file', boundary: linkBoundary });
    spec = JSON.parse(readFileSync(obsPath, 'utf8'));
  } catch (e) {
    err.write(`${e.message}\n`);
    return e instanceof SymlinkRefused ? EXIT_FINDINGS : EXIT_INCOMPLETE;
  }

  const observations = Array.isArray(spec.observations) ? spec.observations : [];

  // The counting contract is applied BEFORE anything is written. A run with no
  // observations that reports its emptiness only after leaving a file behind
  // has still left the file behind, and the next tool to read the store finds a
  // record that says nothing while looking exactly like one that says something.
  const counts = reportCounts(
    { inputs: observations.length, checked: observations.length, skipped: 0, allowEmpty, what: 'observation', where: obsPath },
    { json: asJson, out, err },
  );
  if (counts.code !== null) return counts.code;

  const store = resolveStoreRoot({ cli: val('--store') });
  if (store.insideWorkTree) {
    err.write(
      `refusing to write into ${store.root}: it is inside the checkout. Records embed one machine's\n` +
        "toolchain digests and one checkout's state, and this tree does not rewrite history, so a\n" +
        `record committed here is permanent. Set $${STORE_ENV} or pass --store to a path outside it.\n`,
    );
    return EXIT_FINDINGS;
  }
  const pairDir = join(store.root, pairId);
  const outFile = join(pairDir, `run-${run}.json`);
  try {
    // The root is checked BEFORE the directory is created. Creating first and
    // checking after leaves a directory inside the substituted store even when
    // the write is refused, which is a footprint in exactly the place the
    // refusal was meant to keep clean.
    assertNoSymlink(store.root, { boundary: linkBoundary, role: 'the store root' });
    mkdirSync(pairDir, { recursive: true });
    assertNoSymlink(pairDir, { boundary: linkBoundary, role: 'the pair directory' });
  } catch (e) {
    err.write(`${e.message}\n`);
    return e instanceof SymlinkRefused ? EXIT_FINDINGS : EXIT_INCOMPLETE;
  }

  let provenance;
  let toolchain;
  try {
    provenance = gitProvenance(val('--repo') ?? REPO_ROOT);
    toolchain = toolchainBlock(Array.isArray(spec.toolchainBinaries) ? spec.toolchainBinaries : []);
  } catch (e) {
    err.write(`${e.message}\n`);
    return EXIT_TOOL_FAILED;
  }

  const record = {
    schemaVersion: MEASUREMENT_SCHEMA,
    recordId: String(spec.recordId ?? basename(obsPath, '.json')),
    provenance,
    toolchain,
    oracle: spec.oracle ?? null,
    observations,
    reproduction: { pairId, run },
  };

  try {
    writeRecordSync(outFile, record);
  } catch (e) {
    err.write(`${e.message}\n`);
    return EXIT_FINDINGS;
  }

  if (asJson) out.write(`${JSON.stringify({ file: outFile, pairId, run, observations: observations.length }, null, 2)}\n`);
  else out.write(`wrote ${outFile}\n`);

  return EXIT_OK;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(main(process.argv.slice(2)));
}
