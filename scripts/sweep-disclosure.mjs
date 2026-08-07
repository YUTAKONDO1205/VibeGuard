// sweep-disclosure — the single supported way to run a disclosure sweep, and a
// sweep that proves its own instrument before it says anything about the tree.
//
// WHY THIS WRAPPER EXISTS WHEN THE DETECTOR ALREADY DID
//
// scripts/check-disclosure-shape.mjs holds the needles and is good at what it
// does. It is not the thing that broke. What broke, twice, was the PLUMBING
// around it, and both times the symptom was identical and reassuring:
//
//   * a path-conversion layer between two operating systems swallowed a pattern
//     that began with a slash, so the pattern was never handed to the matcher;
//   * a here-doc ate one level of backslash, so the needle that reached the
//     matcher was not the needle that had been written.
//
// In both cases the run completed, printed a small confident number, and the
// number was zero. Nobody re-ran anything, because there was nothing to re-run:
// a clean sweep is what you hope for and it arrived. The detector's own
// `--self-test` could not have caught either one — it fires the needles against
// in-memory strings inside a single process, which is upstream of every layer
// that was actually broken.
//
// So this program does the only thing that closes that hole. Before it reports
// anything at all, it WRITES known-positive files to disk, hands their paths to
// the detector as a real child process, reads the detector's real stdout, and
// checks that every planted needle came back — byte for byte, not merely "some
// hit was reported". If one did not, the run stops with a non-zero code and
// prints NOTHING about the real tree. A broken instrument must not produce a
// reading, and "0 hits" from a broken instrument is the most dangerous reading
// there is.
//
// The second half is the other failure this repository actually had: a whole
// audit conducted against a remote-tracking ref that was sixty-odd commits old.
// That is delegated to scripts/ref-freshness.mjs, which is runnable on its own,
// and gated here.
//
// USAGE
//
//   node scripts/sweep-disclosure.mjs                 # sweep the tracked tree
//   node scripts/sweep-disclosure.mjs --dir <path>    # sweep a directory instead
//   node scripts/sweep-disclosure.mjs --allow-empty   # 0 inputs is not an error
//   node scripts/sweep-disclosure.mjs --verbose
//   node scripts/sweep-disclosure.mjs --detector <p>  # substitute the detector
//   node scripts/sweep-disclosure.mjs --plant-dir <p> # where the positives go
//   node scripts/sweep-disclosure.mjs --ls-remote-from <f>   # see ref-freshness
//
// EXIT CODES (interfaces.md section 7)
//
//   0  swept, instrument verified, nothing found  → `VERDICT: CLEAN`
//   1  the tool failed (no git, the detector could not be spawned)
//   2  disclosure-shaped strings found            → `VERDICT: FINDINGS`
//   3  no answer available: a planted positive was not detected, the negative
//      control fired, nothing was scanned, or the target ref is stale
//
// The string `VERDICT` is emitted on exactly one line and only when the run is
// entitled to one. Every failure path above is silent about the tree on purpose,
// so `grep VERDICT` is a sound test of whether an answer was given.
//
// ON THE LITERALS
//
// Every needle below is assembled from fragments or code points at runtime, and
// none of them appears whole in this file. That is not style. This file is
// tracked, so the sweep it runs scans it; written literally, the planted
// positives would be found in the planter and a clean repository would fail.
// The same constraint governs scripts/check-disclosure-shape.mjs:40. Do not
// "tidy" these into literal strings.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPTS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(SCRIPTS_DIR, '..');
const DEFAULT_DETECTOR = join(SCRIPTS_DIR, 'check-disclosure-shape.mjs');
const FRESHNESS = join(SCRIPTS_DIR, 'ref-freshness.mjs');

// Duplicated from the driver's exit module; see the same note in
// scripts/ref-freshness.mjs. Pinned by scripts/sweep-disclosure.test.ts.
export const EXIT_OK = 0;
export const EXIT_TOOL_FAILED = 1;
export const EXIT_FINDINGS = 2;
export const EXIT_INCOMPLETE = 3;
export const EXIT_INTEGRITY = 4;

/** Property states, interfaces.md section 3. Only the ones this check can observe. */
const PRESENT = 'PRESENT';
const ABSENT = 'ABSENT';
const NOT_APPLICABLE = 'NOT_APPLICABLE';
const NOT_OBSERVED = 'NOT_OBSERVED';

/** Authorises running without the freshness gate, and only that. */
const ALLOW_STALE_ENV = 'VG_SWEEP_ALLOW_STALE_REF';

const CP = String.fromCodePoint;
const IDEOGRAPH = CP(0x5c71);
const ENCLOSED_DIGIT = CP(0x2462);
/**
 * An account name that is deliberately not in the detector's allow-list. The
 * detector's OWN positive control for this shape uses an allow-listed name,
 * which is correct for an in-process regex test and useless here: run end to
 * end, that control is matched and then exempted, and the plant would be scored
 * as not detected. This one has to survive the whole pipeline.
 */
const ACCOUNT = 'q' + 'wertyacct';

/** The first year the detector treats as an unpublished target rather than a citation. */
const NEXT_YEAR = String(new Date().getFullYear() + 1);
const LAST_YEAR = String(new Date().getFullYear() - 1);

// ── The planted positives ───────────────────────────────────────────────────
//
// One per shape the detector declares, plus a second HOME-DIRECTORY plant. The
// pair is the point: the first begins with a slash and the second is built out
// of backslashes, which are precisely the two characters the two historical
// plumbing failures destroyed. A single plant would have survived one of them.
export const PLANTS = [
  {
    name: 'PLAN-LABEL-ENCLOSED',
    shape: 'PLAN-LABEL-ENCLOSED',
    file: 'plant-enclosed.md',
    needle: IDEOGRAPH + ENCLOSED_DIGIT,
    line: (n) => `the ${n} section comes after this one`,
  },
  {
    name: 'PLAN-LABEL-LATIN',
    shape: 'PLAN-LABEL-LATIN',
    file: 'plant-latin.md',
    needle: IDEOGRAPH + 'C',
    line: (n) => `the ${n} section comes after this one`,
  },
  {
    name: 'ACRONYM-YEAR',
    shape: 'ACRONYM-YEAR',
    file: 'plant-acronym.md',
    needle: 'AB' + 'CD' + ' ' + NEXT_YEAR,
    line: (n) => `we are sending it to ${n} probably`,
  },
  {
    name: 'HOME-DIRECTORY-LEADING-SLASH',
    shape: 'HOME-DIRECTORY',
    file: 'plant-home-slash.md',
    needle: '/' + 'home/' + ACCOUNT,
    line: (n) => `the corpus lives in ${n}/data`,
  },
  {
    name: 'HOME-DIRECTORY-BACKSLASH',
    shape: 'HOME-DIRECTORY',
    file: 'plant-home-backslash.md',
    needle: 'C:' + '\\' + 'Users' + '\\' + ACCOUNT,
    line: (n) => `the corpus lives in ${n}${'\\'}data`,
  },
  {
    // Scoped by the detector to ignore-file basenames, so the plant has to BE
    // one. A plant written to plant-ignore.md would never be scanned by this
    // shape and would score as an instrument failure.
    name: 'IGNORE-RATIONALE',
    shape: 'IGNORE-RATIONALE',
    file: '.gitignore',
    needle: 'att' + 'ack',
    line: (n) => `# holds the ${n} corpus`,
  },
];

/**
 * The other half of the measurement. Every positive above shows the instrument
 * can fire; this shows it can also NOT fire. Without it, a detector that
 * flagged every line in the repository would pass every assertion above and
 * report the tree as catastrophically dirty, which is a different way of being
 * useless.
 *
 * Each line here is a shape-adjacent string the detector is supposed to exempt:
 * two ordinary ideographs, an acronym next to a PAST year (a citation), and
 * home-directory paths whose account segment is a placeholder or a CI account.
 * They are assembled from fragments for the same reason the positives are — the
 * exemptions are allow-list entries and an allow-list can be edited.
 */
const NEGATIVE_CONTROL = {
  name: 'negative-control',
  file: 'negative-control.md',
  body: [
    '# ordinary notes',
    '',
    `prose with two plain ideographs ${CP(0x767b) + CP(0x5c71)} in the middle of it`,
    `a citation to ${'AC' + 'M'} ${LAST_YEAR} and to ${'IS' + 'O'} ${NEXT_YEAR}`,
    `a runner path ${'/' + 'home/runner/work'} and a placeholder ${'C:' + '\\' + 'Users' + '\\' + 'user'}`,
    `an unexpanded variable ${'/' + 'home/' + '${USER}'}/cache`,
    '',
  ].join('\n'),
};

// ── Detector invocation ─────────────────────────────────────────────────────

/**
 * One hit line of the detector's stdout.
 *
 * The match is read back out of the JSON the detector prints and compared byte
 * for byte against the needle that was planted. "A hit was reported for this
 * file" is not enough: the backslash-eating failure produced hits, just for a
 * different string than the one written.
 */
const HIT_LINE = /^(.*):(\d+): ([A-Z][A-Z0-9_-]*) \("((?:[^"\\]|\\.)*)"\) \| /;

/** Argv budget per child. Well under the Windows 32 KiB command-line ceiling. */
const CHUNK_CHARS = 24_000;

function chunkPaths(paths) {
  const chunks = [];
  let current = [];
  let used = 0;
  for (const p of paths) {
    if (current.length > 0 && used + p.length + 1 > CHUNK_CHARS) {
      chunks.push(current);
      current = [];
      used = 0;
    }
    current.push(p);
    used += p.length + 1;
  }
  if (current.length > 0) chunks.push(current);
  return chunks;
}

/**
 * Run the detector over an explicit path list (or, with `null`, over whatever it
 * enumerates for itself) and return a structured reading.
 *
 * `relPaths` must never be an empty array: the detector falls back to scanning
 * the whole tracked tree when `--paths` is given with nothing after it, so an
 * empty chunk would silently turn a directory sweep into a repository sweep.
 */
function runDetector(detector, relPaths) {
  const chunks = relPaths === null ? [null] : chunkPaths(relPaths);
  const hits = [];
  let scanned = 0;
  let skipped = 0;
  let sawSummary = false;
  const raw = [];

  for (const chunk of chunks) {
    if (chunk !== null && chunk.length === 0) {
      return { error: 'internal: an empty path chunk was about to be handed to the detector' };
    }
    const args = chunk === null ? [detector] : [detector, '--paths', ...chunk];
    let out;
    try {
      out = execFileSync(process.execPath, args, {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      const e = /** @type {{ stdout?: string; stderr?: string; status?: number }} */ (err);
      if (typeof e.status !== 'number') {
        return { error: `the detector could not be run: ${String(e.stderr ?? '').trim() || String(err)}` };
      }
      // Status 1 is "hits found", which is a normal reading here. Anything else
      // is the detector declining to answer, and this program must decline too.
      if (e.status !== 1) {
        return {
          error: `the detector exited ${e.status} (not 0 or 1), so it did not produce a reading.\n${String(e.stdout ?? '')}${String(e.stderr ?? '')}`,
        };
      }
      out = String(e.stdout ?? '');
    }
    raw.push(out);

    const scannedM = /^scanned:\s+(\d+) file/m.exec(out);
    const skippedM = /^skipped:\s+(\d+)/m.exec(out);
    const hitsM = /^hits:\s+(\d+)/m.exec(out);
    if (scannedM === null || skippedM === null || hitsM === null) {
      return {
        error:
          'the detector printed no parseable summary. Its output contract changed, and this\n' +
          'runner cannot tell a clean scan from a scan that never happened.',
      };
    }
    sawSummary = true;
    scanned += Number.parseInt(scannedM[1], 10);
    skipped += Number.parseInt(skippedM[1], 10);

    const parsed = [];
    for (const line of out.split(/\r?\n/)) {
      const m = HIT_LINE.exec(line);
      if (m === null) continue;
      parsed.push({ file: m[1], line: Number.parseInt(m[2], 10), shape: m[3], match: JSON.parse(`"${m[4]}"`) });
    }
    // The detector's own hit COUNT and the hit LINES it printed have to agree,
    // or one of the two is being filtered by something between here and there.
    if (parsed.length !== Number.parseInt(hitsM[1], 10)) {
      return {
        error:
          `the detector reported ${hitsM[1]} hit(s) but printed ${parsed.length} hit line(s).\n` +
          'Something between the matcher and this process is dropping output.',
      };
    }
    hits.push(...parsed);
  }

  if (!sawSummary) return { error: 'the detector produced no summary at all' };
  return { hits, scanned, skipped, raw: raw.join('') };
}

// ── Instrument verification ─────────────────────────────────────────────────

/** The shape ids the detector declares, read out of its source. */
export function declaredShapes(detectorSource) {
  return [...String(detectorSource).matchAll(/^\s*id:\s*'([A-Z][A-Z0-9_-]*)',/gm)].map((m) => m[1]);
}

/** Write the plants and read every one of them back. */
function plant(dir) {
  mkdirSync(dir, { recursive: true });
  const written = [];
  const mangled = [];
  for (const p of PLANTS) {
    const abs = join(dir, p.file);
    writeFileSync(abs, `# notes\n\n${p.line(p.needle)}\n`, 'utf8');
    // Read-back. A layer that normalises, re-encodes or eats an escape between
    // this process and the filesystem is exactly one of the two failures this
    // program exists for, and it is cheaper to catch here than to diagnose from
    // a missing hit later.
    const back = readFileSync(abs, 'utf8');
    if (!back.includes(p.needle)) mangled.push(`${p.name}: the needle did not survive being written to disk`);
    written.push([p, abs]);
  }
  const negAbs = join(dir, NEGATIVE_CONTROL.file);
  writeFileSync(negAbs, NEGATIVE_CONTROL.body, 'utf8');
  return { written, negAbs, mangled };
}

function relForDetector(abs) {
  const r = relative(REPO_ROOT, abs);
  if (r === '' || isAbsolute(r)) return null;
  return r.split(sep).join('/');
}

/**
 * Plant, scan, and decide whether the instrument may be trusted. Returns
 * `{ ok, lines, failures, inputs, checked, skipped }`. Nothing about the real
 * tree is computed before this returns ok.
 */
function verifyInstrument(detector, plantDir) {
  const { written, negAbs, mangled } = plant(plantDir);
  const failures = [...mangled];
  const lines = [];

  const rels = [];
  for (const [, abs] of written) {
    const r = relForDetector(abs);
    if (r === null) {
      return {
        ok: false,
        lines,
        failures: [
          `the planting area ${plantDir} cannot be expressed relative to the repository root\n` +
            '  (a different volume, most likely). Pass --plant-dir with a path on the same volume.',
        ],
        inputs: 0,
        checked: 0,
        skipped: 0,
      };
    }
    rels.push(r);
  }
  const negRel = relForDetector(negAbs);
  if (negRel === null) {
    return { ok: false, lines, failures: ['the negative control could not be addressed relatively'], inputs: 0, checked: 0, skipped: 0 };
  }

  const reading = runDetector(detector, [...rels, negRel]);
  if (reading.error !== undefined) {
    return { ok: false, lines, failures: [reading.error], inputs: rels.length + 1, checked: 0, skipped: 0 };
  }

  for (const [p, abs] of written) {
    const rel = relForDetector(abs);
    const forFile = reading.hits.filter((h) => h.file.split(/[\\/]/).join('/') === rel && h.shape === p.shape);
    const exact = forFile.filter((h) => h.match === p.needle);
    if (exact.length > 0) {
      lines.push(`  ${p.name.padEnd(30)} ${PRESENT}`);
    } else if (forFile.length > 0) {
      lines.push(`  ${p.name.padEnd(30)} ${ABSENT}  (the shape fired but the matched text was not the planted one)`);
      failures.push(
        `${p.name}: detected as ${p.shape}, but the matched text was ${JSON.stringify(forFile[0].match)} ` +
          `and the planted needle was ${JSON.stringify(p.needle)}. Something between this process ` +
          'and the matcher altered the bytes.',
      );
    } else {
      lines.push(`  ${p.name.padEnd(30)} ${ABSENT}  (not detected)`);
      failures.push(`${p.name}: a known positive was planted and the sweep did not detect it.`);
    }
  }

  const negHits = reading.hits.filter((h) => h.file.split(/[\\/]/).join('/') === negRel);
  if (negHits.length === 0) {
    lines.push(`  ${NEGATIVE_CONTROL.name.padEnd(30)} ${ABSENT}  (0 hits, as required)`);
  } else {
    lines.push(`  ${NEGATIVE_CONTROL.name.padEnd(30)} ${PRESENT}  (${negHits.length} hit(s) — must be 0)`);
    failures.push(
      `the negative control fired ${negHits.length} time(s) (${negHits.map((h) => h.shape).join(', ')}). ` +
        'A sweep that flags a clean file cannot distinguish a leak from noise, and the count it ' +
        'reports for the real tree means nothing.',
    );
  }

  const inputs = rels.length + 1;
  return {
    ok: failures.length === 0,
    lines,
    failures,
    inputs,
    checked: reading.scanned,
    skipped: reading.skipped,
  };
}

// ── Input enumeration ───────────────────────────────────────────────────────

function walk(dirAbs, out = []) {
  let entries;
  try {
    entries = readdirSync(dirAbs, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (e.name === '.git' || e.name === 'node_modules') continue;
    const abs = join(dirAbs, e.name);
    if (e.isDirectory()) walk(abs, out);
    else if (e.isFile()) out.push(abs);
  }
  return out;
}

// ── Main ────────────────────────────────────────────────────────────────────

function flagValue(argv, name) {
  const i = argv.indexOf(name);
  return i === -1 || i + 1 >= argv.length ? null : argv[i + 1];
}

export function main(argv) {
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log('node scripts/sweep-disclosure.mjs [--dir <path>] [--allow-empty] [--verbose]');
    console.log('  [--detector <path>] [--plant-dir <path>] [--ls-remote-from <file>] [--remote <name>]');
    return EXIT_OK;
  }
  const verbose = argv.includes('--verbose');
  const allowEmpty = argv.includes('--allow-empty');
  const detector = resolve(flagValue(argv, '--detector') ?? DEFAULT_DETECTOR);
  const dirArg = flagValue(argv, '--dir');
  const lsRemoteFrom = flagValue(argv, '--ls-remote-from');
  const remote = flagValue(argv, '--remote');
  const plantDirArg = flagValue(argv, '--plant-dir');
  const authorisedSkips = [];

  console.log('sweep-disclosure — a sweep that verifies its instrument before it reports');
  console.log('');
  console.log(`detector: ${relForDetector(detector) ?? detector}`);

  // ---- 1. Coverage: is every shape the detector declares actually planted? --
  //
  // Before the instrument check can mean anything, the set of things it checks
  // has to cover the set of things the detector claims to detect. A shape added
  // to the detector and not planted here would sit unverified behind a green
  // tick, which is the same hole in a smaller box.
  let detectorSource;
  try {
    detectorSource = readFileSync(detector, 'utf8');
  } catch (err) {
    console.error(`could not read the detector at ${detector}: ${String(err)}`);
    return EXIT_TOOL_FAILED;
  }
  const declared = declaredShapes(detectorSource);
  if (declared.length === 0) {
    console.error('');
    console.error('no shape ids could be read out of the detector source, so this runner cannot');
    console.error('tell whether its planted positives cover what the detector claims to detect.');
    return EXIT_INCOMPLETE;
  }
  const planted = new Set(PLANTS.map((p) => p.shape));
  const unplanted = declared.filter((id) => !planted.has(id));
  if (unplanted.length > 0) {
    console.error('');
    for (const id of unplanted) console.error(`UNVERIFIED SHAPE  ${id} — the detector declares it and no positive is planted for it`);
    console.error('');
    console.error('Refusing to report. An unplanted shape is one whose needle could have rotted');
    console.error('away without anything going red; adding the shape and adding its plant are the');
    console.error('same change.');
    return EXIT_INCOMPLETE;
  }
  console.log(`shapes:   ${declared.length} declared, ${PLANTS.length} positive(s) planted, all shapes covered`);

  // ---- 2. Instrument verification ------------------------------------------
  //
  // Run FIRST, before the freshness gate, and deliberately: it needs no network,
  // so an operator working offline still finds out that their instrument is
  // broken rather than only that their refs are unverifiable.
  const plantDir = plantDirArg !== null
    ? resolve(plantDirArg)
    : mkdtempSync(join(tmpdir(), 'vg-sweep-'));
  const ownsPlantDir = plantDirArg === null;
  let instrument;
  try {
    instrument = verifyInstrument(detector, plantDir);
  } finally {
    if (ownsPlantDir) {
      try {
        rmSync(plantDir, { recursive: true, force: true });
      } catch {
        /* a leftover temp directory is not worth failing a security check over */
      }
    }
  }

  console.log('');
  console.log('instrument (known positives written to disk and scanned through the real detector):');
  for (const l of instrument.lines) console.log(l);
  console.log(`instrument inputs=${instrument.inputs} checked=${instrument.checked} skipped=${instrument.skipped}`);

  if (!instrument.ok) {
    console.error('');
    for (const f of instrument.failures) console.error(`INSTRUMENT FAILED  ${f}`);
    console.error('');
    console.error('Refusing to report anything about the tree. A planted positive that is not');
    console.error('detected means this sweep cannot tell a clean repository from a broken sweep,');
    console.error('and the only honest output in that state is no output.');
    return EXIT_INCOMPLETE;
  }
  if (instrument.inputs !== instrument.checked + instrument.skipped) {
    console.error('');
    console.error(`INSTRUMENT FAILED  ${instrument.inputs} file(s) were planted but the detector accounted`);
    console.error(`for ${instrument.checked + instrument.skipped}. Files are being lost between this runner and the matcher.`);
    return EXIT_INCOMPLETE;
  }

  // ---- 3. Freshness gate ---------------------------------------------------
  let freshnessState;
  if (dirArg !== null) {
    freshnessState = `${NOT_APPLICABLE} (the target is a directory, not a ref)`;
  } else if (process.env[ALLOW_STALE_ENV] === '1') {
    freshnessState = `${NOT_OBSERVED} (authorised skip)`;
    authorisedSkips.push(`ref-freshness — skipped by ${ALLOW_STALE_ENV}=1`);
  } else {
    const args = [FRESHNESS];
    if (lsRemoteFrom !== null) args.push('--ls-remote-from', lsRemoteFrom);
    if (remote !== null) args.push('--remote', remote);
    let freshOut = '';
    let freshStatus = 0;
    try {
      freshOut = execFileSync(process.execPath, args, { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err) {
      const e = /** @type {{ stdout?: string; stderr?: string; status?: number }} */ (err);
      freshOut = `${String(e.stdout ?? '')}${String(e.stderr ?? '')}`;
      freshStatus = typeof e.status === 'number' ? e.status : EXIT_TOOL_FAILED;
    }
    if (freshStatus !== 0) {
      console.log('');
      console.log('freshness gate:');
      for (const l of freshOut.split(/\r?\n/)) if (l.trim() !== '') console.log(`  ${l}`);
      console.error('');
      console.error(`Refusing to report anything about the tree: ref-freshness exited ${freshStatus}.`);
      console.error(`The target may be stale. Fetch and re-run, or set ${ALLOW_STALE_ENV}=1 to sweep`);
      console.error('anyway and have the result recorded as unverified against the remote.');
      return EXIT_INCOMPLETE;
    }
    freshnessState = 'IN_SYNC';
    if (verbose) for (const l of freshOut.split(/\r?\n/)) if (l.trim() !== '') console.log(`  ${l}`);
  }
  console.log('');
  console.log(`freshness: ${freshnessState}`);

  // ---- 4. The actual sweep -------------------------------------------------
  let inputs;
  let reading;
  let targetLabel;

  if (dirArg !== null) {
    const dirAbs = resolve(dirArg);
    let isDir = false;
    try {
      isDir = statSync(dirAbs).isDirectory();
    } catch {
      isDir = false;
    }
    if (!isDir) {
      console.error(`--dir ${dirArg} is not a directory.`);
      return EXIT_TOOL_FAILED;
    }
    const files = walk(dirAbs);
    const rels = [];
    for (const abs of files) {
      const r = relForDetector(abs);
      if (r === null) {
        console.error(`${abs} cannot be expressed relative to the repository root; the detector`);
        console.error('addresses its inputs that way, so this directory cannot be swept from here.');
        return EXIT_INCOMPLETE;
      }
      rels.push(r);
    }
    inputs = rels.length;
    targetLabel = `directory ${dirArg}`;
    reading = inputs === 0 ? { hits: [], scanned: 0, skipped: 0 } : runDetector(detector, rels);
  } else {
    let listed;
    try {
      // The same enumeration the detector uses, and the same one the push will
      // use: tracked files PLUS un-ignored new ones. Listing only tracked files
      // here was not merely narrower — it disagreed with the detector, and the
      // cross-check below turned that disagreement into a refusal to report,
      // which is how this mismatch was found rather than shipped.
      //
      // The narrower question is worth asking too, but it is a different
      // question: a branch that has just written two hundred files is exactly
      // the branch whose new files most need looking at.
      listed = execFileSync(
        'git',
        ['ls-files', '-z', '--cached', '--others', '--exclude-standard'],
        { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
      ).split('\0').filter(Boolean);
    } catch (err) {
      console.error(`could not list the files a push would carry: ${String(err)}`);
      return EXIT_TOOL_FAILED;
    }
    inputs = listed.length;
    let head = 'unknown';
    try {
      head = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
    } catch {
      head = 'unknown';
    }
    targetLabel = `tracked tree at ${head}`;
    reading = inputs === 0 ? { hits: [], scanned: 0, skipped: 0 } : runDetector(detector, null);
  }

  if (reading.error !== undefined) {
    console.error('');
    console.error(`the sweep could not be completed: ${reading.error}`);
    return EXIT_INCOMPLETE;
  }

  console.log('');
  console.log(`target:   ${targetLabel}`);
  console.log(`inputs=${inputs} checked=${reading.scanned} skipped=${reading.skipped}`);
  console.log(`hits=${reading.hits.length}`);
  for (const s of authorisedSkips) console.log(`skipped case: ${s}`);

  if (inputs === 0) {
    if (!allowEmpty) {
      console.error('');
      console.error('Nothing was scanned. A sweep of zero files finds zero disclosures, and that');
      console.error('sentence is true of a clean repository and of a broken enumerator alike. This');
      console.error('has happened three times here. Pass --allow-empty if an empty input is expected.');
      return EXIT_INCOMPLETE;
    }
    console.log('');
    console.log(`VERDICT: ${NOT_OBSERVED} — 0 inputs, and --allow-empty was passed. Nothing was examined.`);
    return EXIT_OK;
  }

  // The enumerator and the matcher must agree about how many files exist. When
  // they disagree, one of them is losing paths — the class of failure that
  // produced two false clean sweeps here — and neither number can be reported.
  if (inputs !== reading.scanned + reading.skipped) {
    console.error('');
    console.error(`this runner enumerated ${inputs} input(s); the detector accounted for`);
    console.error(`${reading.scanned + reading.skipped} (${reading.scanned} scanned + ${reading.skipped} skipped). Paths are being lost between`);
    console.error('the two, which is how a pattern that never reached the matcher became a clean sweep.');
    return EXIT_INCOMPLETE;
  }

  if (reading.hits.length > 0) {
    for (const h of reading.hits) console.log(`${h.file}:${h.line}: ${h.shape}`);
    console.log('');
    console.log(`VERDICT: FINDINGS — ${reading.hits.length} disclosure-shaped string(s) in ${targetLabel}`);
    console.log('Run `node scripts/check-disclosure-shape.mjs` for the matched text of each.');
    return EXIT_FINDINGS;
  }

  console.log('');
  console.log(`VERDICT: CLEAN — ${reading.scanned} file(s) scanned with an instrument verified this run`);
  if (freshnessState.startsWith(NOT_OBSERVED)) {
    console.log(`  (freshness ${NOT_OBSERVED}: this is CLEAN against the local refs, which were not`);
    console.log('   checked against the remote. The target may not be the current tree.)');
  }
  return EXIT_OK;
}

const invokedDirectly =
  process.argv[1] != null && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (invokedDirectly) process.exit(main(process.argv.slice(2)));
