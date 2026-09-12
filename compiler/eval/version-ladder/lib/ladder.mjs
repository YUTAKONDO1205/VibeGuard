/**
 * The ladder itself: which versions exist, whether a binary is the version it
 * was asked for, and at which version a disappearance first appears.
 *
 * All pure. No compiler is run here and nothing is read from disk, so the one
 * rule this lane can get wrong -- the first-appearance rule -- is decidable on a
 * table and is tested on one (../test/ladder.test.mjs).
 *
 * The shape is not new. Simon, Chisnall and Anderson (EuroS&P 2018) put three
 * clang versions side by side on constant-time selection and reported that as
 * "compiler version increases (Clang 3.0, 3.3 and 3.9), more [implementations
 * become insecure]". That was three versions, hand-inspected. What is different
 * here is the oracle, not the idea: the verdict at each rung comes from
 * differential compilation with a positive control co-resident (the find step's
 * own verdictOf), so "the detector stopped working" and "the defence was
 * removed" are separable at every rung rather than at none.
 */

/**
 * The declared ladder, per vendor, lowest first.
 *
 * Declared, not discovered: the difference between "version 15 kept the wipe"
 * and "version 15 was never installed here" is the whole of the first-appearance
 * rule, and it can only be drawn against a list written down in advance. A
 * version absent from the machine still appears in this list, and the run says
 * it was not obtained.
 */
export const LADDER = Object.freeze({
  clang: Object.freeze([15, 16, 17, 18, 19, 20]),
  gcc: Object.freeze([10, 11, 12, 13, 14]),
});

/** The two compilers whose rows the tracked r2 data can anchor. */
export const ANCHOR_CC = Object.freeze({ clang: 'clang-18', gcc: 'gcc-13' });

/** The levels the find step measured, in its order. */
export const ALL_OPTS = Object.freeze(['-O0', '-O1', '-O2', '-O3', '-Os']);

/**
 * The verdicts that are an answer about the wipe. Everything else -- a compile
 * that failed, an ablation that did not build, a body the extractor could not
 * find, a control that did not hold -- is a cell with no reading, and a rung
 * with no reading cannot be passed over on the way to a first appearance.
 */
export const SCORABLE = Object.freeze(new Set(['WIPE_SURVIVED', 'WIPE_ELIMINATED']));

/** The `N` in `clang-N` / `gcc-N`, or null for any other spelling. */
export function spelledMajor(cc) {
  if (typeof cc !== 'string') return null;
  const base = cc.split(/[\\/]/).pop();
  const m = /^(?:clang|gcc)-(\d+)$/.exec(base);
  return m ? Number(m[1]) : null;
}

/** The leading integer of a `-dumpversion` string ('13', '18.1.3'), or null. */
export function parseMajor(text) {
  if (typeof text !== 'string') return null;
  const m = /^\s*(\d+)(?:\.|\s|$)/.exec(text);
  return m ? Number(m[1]) : null;
}

/**
 * The version a `--version` banner claims, per vendor: `{full, major}` or null.
 * clang says "Ubuntu clang version 18.1.3 (1ubuntu1)"; gcc says
 * "gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0" and the trailing triple is
 * the one that means the compiler rather than the package.
 */
export function versionFromBanner(vendor, text) {
  if (typeof text !== 'string') return null;
  const first = text.split('\n')[0].replace(/\r$/, '');
  if (vendor === 'clang') {
    const m = /clang version (\d+(?:\.\d+)*)/i.exec(first);
    return m ? { full: m[1], major: parseMajor(m[1]) } : null;
  }
  if (vendor === 'gcc') {
    const m = /(\d+(?:\.\d+)+)\s*$/.exec(first.trim());
    return m ? { full: m[1], major: parseMajor(m[1]) } : null;
  }
  return null;
}

/**
 * Is this binary the version its name claims? null when it is, otherwise the
 * refusal, in full.
 *
 * This is the lane's own false-first-appearance guard, and it is the reason the
 * lane records a digest at all. `clang` on a PATH can be a symlink to any
 * version; so can `/usr/local/bin/clang-17` on a machine where somebody was
 * testing something. A rung that is secretly another rung does not fail
 * anywhere -- it compiles, it produces a verdict, and the verdict is filed
 * under the wrong version. The lane would then report a first appearance one or
 * more rungs away from the truth and there would be nothing in the output to
 * see it by. So: an unversioned spelling is refused outright (it names no rung),
 * and a versioned one must agree with both the banner and `-dumpversion`.
 */
export function identityProblem({ cc, vendor, banner, dumpversion }) {
  if (!vendor) return `--cc ${cc}: the basename names neither clang nor gcc, so there is no ladder to put it on`;
  const spelled = spelledMajor(cc);
  if (spelled === null) {
    return `--cc ${cc}: this lane needs a versioned spelling (clang-N or gcc-N). `
      + 'An unversioned name does not say which rung of the ladder it is, and the whole output is indexed by rung';
  }
  const b = versionFromBanner(vendor, banner);
  if (!b || b.major === null) return `--cc ${cc}: could not read a version out of its --version banner`;
  const d = parseMajor(dumpversion);
  if (d === null) return `--cc ${cc}: could not read a version out of its -dumpversion`;
  if (b.major !== spelled) {
    return `--cc ${cc}: the binary reports version ${b.full}, whose major is ${b.major}, not ${spelled}. `
      + 'A name that is a link to another version would file every one of its verdicts under the wrong rung';
  }
  if (d !== spelled) {
    return `--cc ${cc}: -dumpversion says ${String(dumpversion).trim()}, whose major is ${d}, not ${spelled}`;
  }
  if (!LADDER[vendor].includes(spelled)) {
    return `--cc ${cc}: ${spelled} is not a rung of the declared ${vendor} ladder (${LADDER[vendor].join(', ')})`;
  }
  return null;
}

/**
 * At which version does the elimination first appear, for one (file, level,
 * vendor)?
 *
 * `cells` maps a major version number to a verdict; a version that was not
 * obtained is simply absent from it. The rule, which is the one thing in this
 * lane that would make it wrong rather than incomplete:
 *
 *   FIRST_AT v        v is the lowest rung showing WIPE_ELIMINATED, AND every
 *                     rung below v in the DECLARED ladder was obtained and
 *                     scorable. Only then does "first" mean anything.
 *   NEVER_ELIMINATED  every declared rung was obtained and scorable and none
 *                     eliminated.
 *   UNDETERMINED      otherwise, with `gaps` naming each rung that stopped the
 *                     question being answerable and why.
 *
 * A rung that was not obtained is `not-obtained`. It is never NOT_OBSERVED --
 * that word is for a reading that was attempted and did not come back -- and
 * never UNSUPPORTED, which in this project's vocabulary
 * (compiler/schema/interfaces.md section 3.1) means the toolchain refused an
 * invocation it was given. Neither is true of a compiler that is not installed.
 *
 * FIRST_AT carries a second word, `transition`, because the status alone is two
 * different observations under one name and a machine reading these records
 * cannot tell them apart otherwise:
 *
 *   transition: 'observed'    at least one declared rung BELOW v was obtained,
 *                             was scorable and kept the wipe. The elimination
 *                             appears between two measured rungs, which is the
 *                             only shape that says a version introduced it.
 *   transition: 'none-below'  v is the LOWEST rung of the declared ladder. The
 *                             `below` set is empty, so "every lower rung was
 *                             obtained and kept the wipe" is true of nothing:
 *                             the wipe was already gone at the bottom of the
 *                             ladder and NO transition was observed anywhere.
 *                             This is not evidence that version v introduced
 *                             the elimination, and the ladder cannot say which
 *                             earlier version would have.
 *
 * It is null for the other two statuses, where no first appearance was stated.
 *
 * A vendor with no declared ladder throws rather than answering. With
 * `rungs = []` every set below is empty and the function would return a clean
 * NEVER_ELIMINATED -- a negative result over a ladder with no rungs, which is
 * the shape the sibling rule forbids for a valid vendor.
 */
export function firstAppearance({ vendor, cells }) {
  const rungs = LADDER[vendor];
  if (!rungs) {
    throw new TypeError(`firstAppearance: ${JSON.stringify(vendor)} has no declared ladder `
      + `(${Object.keys(LADDER).join(', ')}). An empty ladder would answer NEVER_ELIMINATED over no rungs`);
  }
  const gapOf = (v) => {
    if (!Object.prototype.hasOwnProperty.call(cells, v)) return { version: v, why: 'not-obtained' };
    if (!SCORABLE.has(cells[v])) return { version: v, why: cells[v] };
    return null;
  };
  const firstElim = rungs.find((v) => cells[v] === 'WIPE_ELIMINATED');
  const below = firstElim === undefined ? rungs : rungs.filter((v) => v < firstElim);
  const gaps = below.map(gapOf).filter(Boolean);
  if (gaps.length) return { status: 'UNDETERMINED', version: null, transition: null, gaps };
  if (firstElim === undefined) return { status: 'NEVER_ELIMINATED', version: null, transition: null, gaps: [] };
  return { status: 'FIRST_AT', version: firstElim, transition: below.length ? 'observed' : 'none-below', gaps: [] };
}

/** Why a rung produced no cells. Both are "not obtained"; neither is a verdict. */
export const SKIP_REASONS = Object.freeze(['not-installed', 'not-requested']);

/**
 * The counting line for the versions half of the run.
 *
 * `obtained + skipped` is every rung of both declared ladders, ALWAYS -- the run
 * carries an entry for a rung it never asked for as well as for one it asked for
 * and did not find, so that the denominator a reader sees is the ladder and not
 * the subset this invocation happened to name. `accountedFor` is false if that
 * ever stops being true, and the report prints it.
 *
 * `skipped` is split by reason because the two are different facts about the
 * run and only one of them is about the machine:
 *   not-installed  the rung was asked for and is not on this machine
 *   not-requested  this invocation did not ask for the rung
 * Neither is UNSUPPORTED (interfaces.md 3.1: the toolchain refused an
 * invocation) and neither is NOT_OBSERVED (a reading that did not come back).
 */
export function versionCounting(versions) {
  const declared = Object.values(LADDER).reduce((n, l) => n + l.length, 0);
  const obtained = versions.filter((v) => v.obtained).length;
  const notInstalled = versions.filter((v) => !v.obtained && v.reason === 'not-installed').length;
  const notRequested = versions.filter((v) => !v.obtained && v.reason === 'not-requested').length;
  const skipped = versions.filter((v) => !v.obtained).length;
  return {
    declared, obtained, skipped, notInstalled, notRequested,
    accountedFor: obtained + skipped === declared && notInstalled + notRequested === skipped,
  };
}

/**
 * The counting line for the cells half: every (file, level, vendor) question
 * asked, split by what came back. `asked` is the sum of the rest.
 */
export function appearanceCounting(appearances) {
  const by = (s) => appearances.filter((a) => a.status === s).length;
  const firstAt = by('FIRST_AT');
  const never = by('NEVER_ELIMINATED');
  const undetermined = by('UNDETERMINED');
  // The first-appearance count is split by `transition` and the split is
  // printed, because "38 first appearances" and "38 files already eliminated at
  // the bottom rung, no transition seen anywhere" are the same number and
  // opposite findings. A FIRST_AT that carries neither word is a broken record
  // and breaks the accounting rather than being filed under the kinder one.
  const t = (w) => appearances.filter((a) => a.status === 'FIRST_AT' && a.transition === w).length;
  const firstAtObserved = t('observed');
  const firstAtNoneBelow = t('none-below');
  return {
    asked: appearances.length,
    firstAt,
    firstAtObserved,
    firstAtNoneBelow,
    never,
    undetermined,
    accountedFor: firstAt + never + undetermined === appearances.length
      && firstAtObserved + firstAtNoneBelow === firstAt,
  };
}

/** How a rung prints on its own: its verdict, or the not-obtained mark. */
export function cellMark(cells, v) {
  if (!Object.prototype.hasOwnProperty.call(cells, v)) return '-(not obtained)';
  return cells[v];
}

/** Short marks for the wide per-file table: E eliminated, S survived, ? unscorable, - not obtained. */
export function shortMark(cells, v) {
  if (!Object.prototype.hasOwnProperty.call(cells, v)) return '-';
  const s = cells[v];
  if (s === 'WIPE_ELIMINATED') return 'E';
  if (s === 'WIPE_SURVIVED') return 'S';
  return '?';
}

/**
 * The sentence that says what a first appearance rests on, or why there is not
 * one. Written out rather than left to the reader, because an UNDETERMINED with
 * a gap list beside it reads as "nothing was found" to people who are not being
 * careless.
 *
 * The FIRST_AT sentence has two forms and the difference between them is the
 * whole reading. Where `v` is the lowest declared rung the old single form said
 * "every lower rung (none) was obtained and kept the wipe" -- a universal over
 * the empty set, which is true of nothing observed and reads as a transition
 * that was never seen. The lower set is taken from the DECLARED ladder here, not
 * from the record, so the sentence stays correct for a record written before
 * `transition` existed.
 */
export function appearanceSentence(a) {
  const rungs = LADDER[a.vendor].join(', ');
  if (a.status === 'FIRST_AT') {
    const lower = LADDER[a.vendor].filter((v) => v < a.version);
    if (!lower.length) {
      return `eliminated already at ${a.vendor}-${a.version}, the LOWEST rung of the declared ${a.vendor} ladder `
        + `(${rungs}): there is no rung below it, so no transition was observed and this is not evidence that `
        + `${a.vendor}-${a.version} introduced the elimination -- an earlier release might have done it too, and this `
        + 'ladder does not reach one';
    }
    return `first eliminated at ${a.vendor}-${a.version}; every lower rung (${lower.join(', ')}) was obtained and `
      + `kept the wipe, so the elimination appears between ${a.vendor}-${lower[lower.length - 1]} and ${a.vendor}-${a.version}`;
  }
  if (a.status === 'NEVER_ELIMINATED') {
    return `not eliminated at any rung; all of ${rungs} were obtained and scorable`;
  }
  const g = a.gaps.map((x) => `${a.vendor}-${x.version} ${x.why}`).join(', ');
  return `no first appearance can be stated: ${g}. That is a gap in the ladder, not a finding about the wipe`;
}
