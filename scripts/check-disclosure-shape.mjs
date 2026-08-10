// check-disclosure-shape — catch a disclosure by its SHAPE, not by its spelling.
//
// WHY THIS EXISTS, AND WHY IT IS DIFFERENT FROM EVERY OTHER CHECK HERE
//
// Three things reached this repository's public history that were never meant
// to, and all three were missed by the same kind of check: a list of forbidden
// words, greped for before a push. That kind of check has a structural blind
// spot, and it is not a bug in any particular list —
//
//   * A label written in a form nobody enumerated. The needle looked for the
//     label followed by a Latin letter; the plan writes it followed by a circled
//     digit. The check reported zero for as long as the label was there.
//   * A path naming one machine's account. No word list contains an account
//     name, because the account name is not a word — it is whatever the person
//     who installed the OS typed.
//   * An ignore file that annotated WHY each withheld path was withheld. Not a
//     forbidden word anywhere in it. The disclosure was the explanation.
//
// A word list cannot be completed, because the next leak is by definition
// spelled in a way nobody thought to add. What CAN be enumerated is the small
// number of SHAPES these things take. This file matches those shapes, and it
// contains no proper noun at all — which is why, unlike the word-list check, it
// can live in the public repository and run in CI. A checker that lists what it
// forbids publishes the list; a checker that describes a shape publishes only
// the shape.
//
//   node scripts/check-disclosure-shape.mjs              # scan tracked files
//   node scripts/check-disclosure-shape.mjs --self-test  # prove the needles fire
//   node scripts/check-disclosure-shape.mjs --paths a b  # scan specific files
//   node scripts/check-disclosure-shape.mjs --verbose    # list what was skipped
//
// Exit 0 when the tracked surface is clean, 1 when a shape matches, and 3 when
// the run was VACUOUS — nothing scanned, or a needle that failed to fire against
// its own positive control. A check that cannot demonstrate it still works must
// not be allowed to report zero: reporting a confident zero from a broken needle
// is precisely how the label above survived in two files through several audits.
//
// ── ON THE LITERALS ────────────────────────────────────────────────────────
//
// Every pattern below is written in \u escapes rather than as literal
// characters, and every positive control is assembled from fragments at runtime.
// Both follow the precedent in scripts/check-packaging-invariants.mjs:244. Here
// the reason is sharper: this file is itself a tracked file, so it is scanned by
// its own run. Written literally, the needles would match themselves and the
// check would fail on a repository that is clean. Do not "tidy" them into
// literal characters.
import { readFileSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, basename } from 'node:path';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Files larger than this are reported as skipped rather than scanned. */
const MAX_BYTES = 4 * 1024 * 1024;

// ── Shapes ──────────────────────────────────────────────────────────────────
//
// `scope` limits a shape to files whose basename matches, for shapes that would
// be meaningless (or unbearably noisy) everywhere else.
//
// ⚠ `scope` is a LOAD-BEARING BLIND SPOT and the reason IGNORE-RATIONALE no
//   longer has one. That shape was scoped to ignore-file basenames, on the
//   reasoning that only an ignore file annotates a withheld path. It does not
//   hold: the same annotation — this directory is withheld, and here is what it
//   contains — was found in a `//` comment in a build script, where neither the
//   basename scope nor the `#`-comment filter could see it. A shape scoped to
//   the file where it was first noticed catches that file and nothing else.
//   Before adding `scope` to a shape, ask whether the shape is really about the
//   file, or only about where you happened to find it first.
const SHAPES = [
  {
    id: 'PLAN-LABEL-ENCLOSED',
    why:
      'An ideograph immediately followed by an enclosed or fullwidth alphanumeric. ' +
      'Ordinary prose does not glue those together; internal section labels do.',
    // CJK ideograph + { enclosed alphanumeric | fullwidth digit | fullwidth capital }
    re: /[㐀-鿿][①-⓿０-９Ａ-Ｚ]/gu,
    control: () => String.fromCodePoint(0x5c71) + String.fromCodePoint(0x2462),
  },
  {
    id: 'PLAN-LABEL-LATIN',
    why:
      'An ideograph immediately followed by a lone Latin capital. Same shape as ' +
      'the above in the spelling the word-list check already covered; kept so the ' +
      'two forms are enforced by one rule rather than by one rule and a memory.',
    re: /[㐀-鿿][A-Z](?![A-Za-z])/gu,
    control: () => String.fromCodePoint(0x5c71) + 'C',
  },
  // ⚠ A SHAPE THAT WAS TRIED AND WITHDRAWN, so the next person does not spend
  //   the afternoon rediscovering why. `\b[A-Za-z]{3,} [①-⓿]` — an English word,
  //   a space, an enclosed alphanumeric — was written to catch the internal item
  //   label in its ENGLISH spelling. The two shapes above require the label to be
  //   glued to an ideograph, which is how it is written in Japanese, and both
  //   walk straight past the spaced English form; one such phrase was printing
  //   into the public job summary of every CI run while this file called the tree
  //   clean.
  //
  //   Measured on this tree: 62 hits, and they are not one thing. Most are the
  //   internal sense. But a cross-file rule documents its own three-part
  //   predicate as `Condition ①/②/③`, which is ordinary technical writing that
  //   discloses nothing, and no regex separates "the item ① of a document you
  //   cannot see" from "the first of the three conditions defined ten lines
  //   above" — the difference is whether the referent is nearby, which is not a
  //   property of the spelling.
  //
  //   Shipping it would have meant either rewriting legitimate documentation or
  //   carrying an exemption list, and an exemption list is the word list this
  //   file exists to avoid. The English-spelled instances that named a document
  //   were fixed at the source instead. If this comes back, it needs a rule about
  //   REFERENTS, not about characters.
  {
    id: 'ACRONYM-YEAR',
    why:
      'A short all-caps token glued to a 20xx year, where the year is the ' +
      'current one or later. That is how an UNDECIDED submission target is ' +
      'written. The year bound is what separates it from a citation: a past ' +
      'year next to an acronym is someone else\'s published paper, which is ' +
      'public by definition, while a future one names where unpublished work is ' +
      'being sent — and, from the commit that deletes it, whether it was ' +
      'rejected. The bound moves on its own each January, which is correct: ' +
      'last year\'s target stops being a secret once the work is out.',
    re: /(?<![A-Za-z0-9])[A-Z]{2,6}[ \-_]?(20\d\d)(?![\d])/g,
    // Standards and language editions are written this way too and are not
    // disclosures. Matched against the letters only.
    allow: new Set(['ES', 'ECMA', 'ISO', 'IEC', 'RFC', 'ANSI', 'IEEE', 'UTC', 'GMT', 'NIST', 'OWASP', 'CWE', 'CVE', 'SI', 'W3C', 'IETF']),
    // Split further than the others, and the year built arithmetically. A two-
    // fragment split leaves the acronym and the year contiguous INSIDE the
    // second fragment, which this file's own run then matches — it became a
    // scanned file the moment it was tracked. It caught that, and then it caught
    // the comment that had quoted the offending fragment while explaining it.
    // Both are the behaviour wanted; neither is a spelling anyone would guess to
    // check by hand.
    control: () => 'AB' + 'CD' + ' ' + String(2000 + 99),
  },
  {
    id: 'HOME-DIRECTORY',
    why:
      'An absolute path through a per-user home directory. The segment after it ' +
      'is an account name, which no word list can contain and which is published ' +
      'the moment such a path is committed.',
    re: /(?:\/mnt\/[a-z]\/[Uu]sers|[A-Za-z]:[\\/]{1,2}[Uu]sers|\/[Hh]ome)[\\/]+([^\\/\s"'`<>${}%*?,;:)\]]+)/g,
    // Placeholders, CI accounts and well-known system users are not account
    // names of a person. Compared case-insensitively against the captured segment.
    allow: new Set([
      'user', 'users', 'username', 'name', 'you', 'me', 'someone', 'somebody', 'example',
      'runner', 'root', 'ubuntu', 'node', 'vscode', 'test', 'tester', 'ci', 'build', 'builder',
      'linuxbrew', 'admin', 'administrator', 'default', 'public', 'your-name', 'yourname',
    ]),
    control: () => '/mnt/' + 'x/Users/' + 'somebody/work',
  },
  {
    id: 'IGNORE-RATIONALE',
    why:
      'A comment — in ANY tracked file, not only an ignore file — that names a ' +
      'withheld path and then says what it CONTAINS. The path name alone is ' +
      'unavoidable, because the ignore rule has to spell it; an annotation ' +
      'saying it is worth having is a strictly worse disclosure than the name, ' +
      'and is the opposite of the reason it was withheld.',
    // Two conditions, not one. The word list below is noise on its own — this
    // repository is about attacks and says so on hundreds of lines — so a hit
    // counts only on a comment line that also names a path .gitignore excludes.
    // That pairing is the shape; either half alone is ordinary.
    requiresWithheldPath: true,
    // Only comment lines are examined, in every comment style, not just `#`; see scanOne().
    re: new RegExp(
      [
        'attack', 'exploit', 'evasion', 'bypass', 'vulnerab', 'payload', 'adversar',
        'red[ -]?team', 'threat model', 'unpublished', 'unannounced', 'until .{0,24}ship',
        '攻撃', '回避', '脆弱', '悪用', '未公開', '未発表',
      ].join('|'),
      'gi',
    ),
    control: () => '# holds the ' + 'attack corpus',
  },
];

// ── Scanning ────────────────────────────────────────────────────────────────

/**
 * Everything a push could carry: non-binary, small enough, and either already
 * tracked or sitting un-ignored in the working tree.
 *
 * `git ls-files -z` alone was wrong here, and wrong in the direction that does
 * not announce itself. It lists TRACKED files only, so a branch that has just
 * written two hundred new files gets a clean report about the two hundred that
 * were already there. Caught by planting `/home/<name>/...` inside one of the
 * new files and watching this checker report `hits: 0` with the scanned count
 * unchanged — the instrument was not broken, it was pointed somewhere else.
 *
 * `--cached --others --exclude-standard` is exactly the set `git add .` would
 * stage, which is the question the push is about to ask. Ignored files stay out,
 * as they should: they are not going anywhere.
 */
function collectTargets(explicit) {
  const rel = explicit ?? execFileSync(
    'git',
    ['ls-files', '-z', '--cached', '--others', '--exclude-standard'],
    { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  ).split('\0').filter(Boolean);
  const files = [];
  const skipped = [];
  for (const r of rel) {
    const abs = join(REPO_ROOT, r);
    let size;
    try {
      size = statSync(abs).size;
    } catch {
      skipped.push([r, 'unreadable']);
      continue;
    }
    if (size > MAX_BYTES) {
      skipped.push([r, `too large (${size} B)`]);
      continue;
    }
    let text;
    try {
      const buf = readFileSync(abs);
      if (buf.includes(0)) {
        skipped.push([r, 'binary']);
        continue;
      }
      text = buf.toString('utf8');
    } catch {
      skipped.push([r, 'unreadable']);
      continue;
    }
    files.push([r, text]);
  }
  return { files, skipped };
}

/** The first year that counts as "not yet published". See ACRONYM-YEAR's `why`. */
const CURRENT_YEAR = new Date().getFullYear();

/** Whether a match is exempt under the shape's allow-list. */
function exempt(shape, match) {
  if (shape.id === 'ACRONYM-YEAR') {
    const year = Number.parseInt(match[1], 10);
    if (Number.isFinite(year) && year < CURRENT_YEAR) return true; // a citation, not a target
    const letters = /^[A-Z]+/.exec(match[0]);
    return letters !== null && shape.allow.has(letters[0]);
  }
  if (shape.id === 'HOME-DIRECTORY') {
    const raw = match[1] ?? '';
    const seg = raw.toLowerCase();
    // An elision or a single letter is a worked example, not an account: the
    // point of the shape is the NAME, and these carry none.
    if (raw.includes('…') || raw.includes('...') || raw.length <= 1) return true;
    if (raw.includes('<') || raw.includes('>')) return true;
    return shape.allow.has(seg) || seg.startsWith('$') || seg.startsWith('%') || seg.startsWith('{');
  }
  return false;
}

/**
 * The concrete path names .gitignore withholds — the half of IGNORE-RATIONALE
 * that keeps it from firing on ordinary security prose.
 *
 * Read from .gitignore rather than listed here, so this file still contains no
 * proper noun: it describes the shape, and the repository supplies the names.
 * Globs are skipped (a pattern is not a name), and so is anything shorter than
 * eight characters — `out`, `dist`, `nul` and friends are words before they are
 * paths, and matching them would put the noise straight back.
 */
function withheldPathTokens() {
  let text;
  try {
    text = readFileSync(join(REPO_ROOT, '.gitignore'), 'utf8');
  } catch {
    return [];
  }
  const out = new Set();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#') || line.startsWith('!')) continue;
    if (line.includes('*') || line.includes('?')) continue;
    const token = line.replace(/^\/+/, '').replace(/\/+$/, '');
    if (token.length >= 8) out.add(token);
  }
  return [...out];
}

const WITHHELD = withheldPathTokens();

/**
 * Does this line name a withheld path AS A PATH?
 *
 * The distinction is not pedantry, it is the whole false-positive budget. Some
 * of what .gitignore withholds is spelled with an ordinary English word —
 * measured on this tree, a bare substring test flagged two lines that say
 * "adversarial coverage" and "reduce coverage", neither of which is about a
 * directory at all. A directory is written with a separator after it, and a
 * withheld FILE carries an extension; a word carries neither.
 */
function namesWithheldPath(line) {
  return WITHHELD.some((t) => (t.includes('.') ? line.includes(t) : line.includes(`${t}/`) || line.includes(`${t}\\`)));
}

/** Is this line a comment, in any of the styles the tracked surface uses? */
function isCommentLine(line) {
  return /^\s*(#|\/\/|\*|<!--|--|;|%)/.test(line) || /\S\s+(\/\/|#)\s/.test(line);
}

function scanOne(relPath, text) {
  const hits = [];
  const base = basename(relPath);
  const lines = text.split(/\r?\n/);
  for (const shape of SHAPES) {
    if (shape.scope && !shape.scope.test(base)) continue;
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      // IGNORE-RATIONALE reads comment lines only, and only those that name a
      // withheld path: an ignore RULE may legitimately name a path containing
      // any of these words, and the words alone appear all over a repository
      // whose subject is attacks. The pair is the disclosure; neither half is.
      if (shape.requiresWithheldPath) {
        if (!isCommentLine(line)) continue;
        if (!namesWithheldPath(line)) continue;
      }
      shape.re.lastIndex = 0;
      let m;
      while ((m = shape.re.exec(line)) !== null) {
        if (!exempt(shape, m)) hits.push({ file: relPath, line: i + 1, shape: shape.id, text: line.trim().slice(0, 160), match: m[0] });
        if (m[0].length === 0) shape.re.lastIndex += 1;
      }
    }
  }
  return hits;
}

// ── Self-test ───────────────────────────────────────────────────────────────
//
// Every needle is fired against its own positive control before any zero is
// reported. A needle that has stopped matching — a mangled escape, a lost
// unicode flag, an editor that normalised a character — otherwise reports the
// same clean zero as a repository that really is clean.
function selfTest() {
  const failures = [];
  for (const shape of SHAPES) {
    const ctl = shape.control();
    shape.re.lastIndex = 0;
    if (!shape.re.test(ctl)) failures.push(`${shape.id}: needle did not match its own positive control`);
    shape.re.lastIndex = 0;
  }
  // A negative control for the noisiest shape: an ordinary ideograph pair must
  // NOT match, or PLAN-LABEL-* would flag every line of Japanese prose.
  const ordinary = String.fromCodePoint(0x767b) + String.fromCodePoint(0x5c71); // two ideographs
  for (const shape of SHAPES.filter((s) => s.id.startsWith('PLAN-LABEL'))) {
    shape.re.lastIndex = 0;
    if (shape.re.test(ordinary)) failures.push(`${shape.id}: matched an ordinary ideograph pair (would flag prose)`);
    shape.re.lastIndex = 0;
  }

  // The paired shapes need their PAIRING controlled, not just their needle. A
  // needle that matches its control while the second condition can never be
  // satisfied reports the same clean zero as a clean tree — which is the exact
  // failure this whole file exists to refuse.
  for (const shape of SHAPES.filter((s) => s.requiresWithheldPath)) {
    if (WITHHELD.length === 0) {
      failures.push(`${shape.id}: no withheld path names could be read, so this shape can never fire`);
      continue;
    }
    const word = 'attack' + ' corpus';
    const dir = WITHHELD.find((t) => !t.includes('.')) ?? WITHHELD[0];
    const positive = `// ${dir}/ holds the ${word}`;
    const negativeNoPath = `// this rule mitigates the ${word}`;
    const negativeBareWord = `// ${dir} is a word here, and this mentions an ${word}`;
    const negativeNotComment = `const x = '${dir}/ holds the ${word}';`;
    if (scanOne('control.mjs', positive).length === 0) {
      failures.push(`${shape.id}: a comment naming a withheld path and saying what it holds did not match`);
    }
    if (scanOne('control.mjs', negativeNoPath).length > 0) {
      failures.push(`${shape.id}: matched a comment that names no withheld path (would flag ordinary prose)`);
    }
    if (scanOne('control.mjs', negativeBareWord).length > 0) {
      failures.push(`${shape.id}: matched a withheld name used as a word rather than a path (would flag prose)`);
    }
    if (scanOne('control.mjs', negativeNotComment).length > 0) {
      failures.push(`${shape.id}: matched a non-comment line (would flag code and ignore rules)`);
    }
  }
  return failures;
}

// ── Main ────────────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
const verbose = argv.includes('--verbose');
const selfTestOnly = argv.includes('--self-test');
const pathsIdx = argv.indexOf('--paths');
const explicit = pathsIdx === -1 ? null : argv.slice(pathsIdx + 1).filter((a) => !a.startsWith('--'));

const ctlFailures = selfTest();
if (ctlFailures.length > 0) {
  for (const f of ctlFailures) console.error(`SELF-TEST FAILED  ${f}`);
  console.error('\nRefusing to report a result: a needle that cannot match its own control');
  console.error('cannot distinguish a clean tree from a broken check.');
  process.exit(3);
}
if (selfTestOnly) {
  console.log(`self-test: ${SHAPES.length} shape(s) matched their positive controls; the ideograph-pair negative control did not match.`);
  process.exit(0);
}

const { files, skipped } = collectTargets(explicit && explicit.length > 0 ? explicit : null);
const hits = files.flatMap(([r, t]) => scanOne(r, t));

for (const h of hits) console.log(`${h.file}:${h.line}: ${h.shape} (${JSON.stringify(h.match)}) | ${h.text}`);

console.log('');
console.log(`shapes:   ${SHAPES.length}`);
console.log(`scanned:  ${files.length} file(s)`);
console.log(`hits:     ${hits.length}`);
console.log(`skipped:  ${skipped.length} (binary / too large / unreadable)`);
if (verbose) for (const [r, why] of skipped) console.log(`  skip ${r} — ${why}`);

if (files.length === 0) {
  console.error('\nVACUOUS: nothing was scanned. Reporting "clean" here would be a lie about');
  console.error('an empty set, which is the failure mode this exit code exists for.');
  process.exit(3);
}
if (hits.length > 0) {
  console.error(`\n${hits.length} disclosure-shaped string(s) found. Each is either a real leak or a`);
  console.error('shape this check should learn to exempt — decide which, and record the decision.');
  process.exit(1);
}
process.exit(0);
