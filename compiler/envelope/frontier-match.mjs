#!/usr/bin/env node
/**
 * Frontier comparison — the one place two ladder frontiers are compared.
 *
 * A FRONTIER is the graded response of the ladder: one small synthetic
 * specimen, compiled on its own under one exact command line, read through the
 * three implemented IR extractors as `rung -> one word`. It is a measurement of
 * the LADDER and of nothing else. Comparing two of them says whether this exact
 * invocation's optimiser treats property-shaped code the way the invocation the
 * cell was measured under did.
 *
 * WHY THE COMPARISON LIVES HERE AND NOT IN ITS CALLER
 *
 * The driver's fallback lookup is the first caller and will not be the only one;
 * the sidecar deriver beside this file is the second. A second implementation of
 * "are these two readings the same reading" is a second definition of a
 * measurement that already has one home, and the two copies drift on exactly the
 * case that matters: a rung that could not be read. So the rule is written once,
 * here, and each caller decides what to do about the answer. The comparison
 * itself opens no file; only the CLI at the foot of this file reads anything.
 *
 * WHY IT EXISTS AT ALL
 *
 * The driver keys a measured envelope by a NOMINAL six-axis config key, and that
 * key cannot see `-D_FORTIFY_SOURCE=3`, `-fno-builtin-memset`, `-ffast-math` or
 * `-fstack-protector-strong`. Measured on the driver's own `normalise()` +
 * `driverConfigAxes()`, the key for `-O2` is byte-identical to the key for
 * `-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3`. Two builds whose nominal keys
 * agree but whose frontiers differ are different exposures, and quoting one's
 * cell for the other is refused.
 *
 * ★ GUARD ONLY, PERMANENTLY. A frontier may refuse a cell. It may never fill
 *   one, choose one, or stand in for a missing measurement. A ladder rung is a
 *   (ladder-subject, config) measurement and says nothing whatever about the
 *   user's subject. `derive-fallback-table.mjs` names keying by propertyId
 *   instead of by (subject, config) as its documented mistake #1; feeding a
 *   ladder frontier into a cell is that same mistake one level up, where the
 *   subject is not merely the wrong program but a synthetic one.
 *
 * THE THREE WORDS, AND WHY NONE OF THEM IS "VERIFIED"
 *
 *   exposure-mismatch      the frontier measured for this build differs from the
 *                          frontier recorded for the cell being quoted. Evidence
 *                          that at least one probed mechanism differs.
 *   exposure-consistent    no probed mechanism separated the two. NECESSARY,
 *                          NEVER SUFFICIENT — not "matched", not "the same
 *                          exposure", not "verified".
 *   exposure-incomparable  ladder version, generator version or health do not
 *                          line up, so no comparison was made. Never collapsed
 *                          into mismatch: "the two differ" and "I could not
 *                          look" send a reader to two different places, and only
 *                          one of them is a finding.
 *
 * This is the instrument's own vocabulary and it is NOT added to the driver's
 * three-word resolution vocabulary (fallback | no-safe-target | not-observed),
 * which answers a different question from a different evidence base.
 *
 * FAILURE DIRECTION
 *
 * Fails towards exposure-consistent. The ladder is a single-TU synthetic
 * specimen: cross-translation-unit inlining, profile data, -march code
 * generation, stack-protector variants and everything downstream of the IR
 * optimiser are invisible to its three extractors, so two genuinely different
 * exposures can present identical frontiers. A consistent reading is necessary,
 * never sufficient. The opposite direction is clean: with a deterministic
 * compiler a differing frontier under an identical ladder is evidence of a
 * differing exposure, and refusing to quote the cell is the correct reading.
 * Measured limits, clang 18.1.3 on 2026-08-17: -O2, -O3 and -Os are
 * indistinguishable to this rung set, and so are _FORTIFY_SOURCE=2 and =3. Any
 * command line carrying an LTO token is refused at measurement time rather than
 * measured.
 *
 * WHAT A FRONTIER BINDS, AND WHAT IT LEAVES UNBOUND
 *
 * A frontier binds the FLAG SEQUENCE and the COMPILER, and it does not bind the
 * HEADER SET. `_FORTIFY_SOURCE` is a header rewrite — the six rungs it moves
 * move because glibc's headers redirect `memcpy` to `__memcpy_chk`, not because
 * the optimiser was told anything new — so a build whose image ships different
 * headers while argv and clang stay identical presents the same frontier and is
 * not caught. The honest contract is therefore an operational one, and it is
 * the caller's to keep: THE LADDER IS RUN IN THE SAME IMAGE AND THE SAME JOB AS
 * THE BUILD IT GUARDS. A frontier measured six weeks ago in another container
 * is a reading of another exposure, and this module cannot tell.
 *
 * And a command line carrying a path-bearing flag — `-I/usr/local/include`,
 * `--sysroot=/opt/vendor` — cannot have a frontier ASSEMBLED at all, because
 * interfaces.md section 5 keeps host paths out of a digested document and the
 * assembler refuses rather than redacting the line it measured. Vendor-sysroot
 * and cross builds are thus outside this guard's coverage; that is disclosed
 * here rather than fixed by widening the fence, because a digest over a
 * redacted command line would name an invocation nobody ran.
 *
 * A BROKEN RUNG IS INCOMPARABLE, NOT A DIFFERENCE
 *
 * interfaces.md section 4: a measurement whose control also fell to zero is a
 * broken measurement, not a finding. A frontier renders such a rung as `BROKEN`
 * rather than as whatever state the verdict happened to carry, and one BROKEN
 * rung on either side makes the whole comparison incomparable — a rung nobody
 * successfully measured cannot be evidence that the two sides are the same, and
 * differenced against a real state it would read as a difference, so a broken
 * instrument would start refusing builds. That direction is deliberate:
 * incomparable declines to quote the cell, which is safe, while folding the rung
 * into "equal anyway" would manufacture consistency out of an apparatus failure.
 * `NOT_OBSERVED` is treated identically and for the identical reason —
 * interfaces.md section 3 keeps "we did not see it" apart from "it is not
 * there", and this is that distinction one layer out.
 *
 * WHAT THIS MODULE READS
 *
 * Five things, out of a `vibeguard.ladder-frontier/1` document that carries
 * considerably more:
 *
 *   ladder.sourceSha256       identity of the specimen that was compiled
 *   ladder.generatorVersion   identity of the harness that graded it
 *   health.broken             whether the run that produced it was usable at all
 *   health.{twinsHeld,chainMonotone,spellingExclusive}
 *                             whether the specimen still behaved like a ladder
 *   frontier                  { <rung>: <one word> }, flat
 *
 * Everything else — `config`, `toolchain`, `context`, per-rung evidence — is
 * carried past this module untouched. A document that spells these four
 * differently is REFUSED by name rather than read approximately: comparing the
 * wrong fields by accident is worse than not comparing.
 *
 * `toolchain` is RECORDED but is deliberately NOT part of the equality test. The
 * nominal key already carries `cc`, so the compiler's identity is checked where
 * cell lookup happens; and the principle here is "did the reference specimen
 * respond the same way", not "is the label the same". Two clang builds with
 * different package digests that produce an identical frontier have, on every
 * mechanism this ladder probes, behaved identically, and that is the whole claim
 * being made. Putting the digest into the equality test would turn every
 * toolchain refresh into a wall of mismatches that say nothing about the
 * optimiser, and a guard that cries wolf on every upgrade is one that gets
 * switched off.
 *
 * EXIT CODES (interfaces.md section 7)
 *   0  exposure-consistent
 *   2  exposure-mismatch — the thing this guard looks for was found
 *   3  exposure-incomparable, or a document that could not be read at all.
 *      Never conflated with 0.
 */

// The property-state words are fixed in interfaces.md section 3, and fragility.mjs
// already binds them for this directory. Imported rather than listed a third
// time: a vocabulary each consumer re-types is one any consumer can widen alone.
import { KNOWN_STATES } from './fragility.mjs';

export const COMPONENT = 'FrontierMatch';

/** The document version this module knows how to compare. */
export const LADDER_FRONTIER_SCHEMA_VERSION = 'vibeguard.ladder-frontier/1';

export const RESULT_CONSISTENT = 'exposure-consistent';
export const RESULT_MISMATCH = 'exposure-mismatch';
export const RESULT_INCOMPARABLE = 'exposure-incomparable';

/** The whole vocabulary. Not added to the three-word resolution vocabulary. */
export const EXPOSURE_RESULTS = Object.freeze([
  RESULT_CONSISTENT,
  RESULT_INCOMPARABLE,
  RESULT_MISMATCH,
]);

/**
 * The word a frontier uses for a rung whose own measurement broke — the
 * co-resident control did not hold, or the subject did not resolve in the
 * pre-optimisation IR.
 *
 * It is not a seventh property state and must not become one. interfaces.md
 * section 3.1 keeps the apparatus column apart from the state column for exactly
 * this reason. A frontier collapses the two into one cell per rung because the
 * frontier is compared as a unit, and there is only one useful thing to say
 * about a rung whose apparatus failed: it is not data.
 */
export const BROKEN_RUNG = 'BROKEN';

/** Every word a rung may carry. */
export const KNOWN_RUNG_READINGS = Object.freeze([...KNOWN_STATES, BROKEN_RUNG]);

/**
 * Readings that make the whole comparison incomparable rather than contributing
 * to equality. Both mean "this rung was not successfully measured here".
 */
export const UNCOMPARABLE_RUNG_READINGS = Object.freeze([BROKEN_RUNG, 'NOT_OBSERVED']);

/**
 * The instrument's failure direction, for the header of the sidecar and for
 * anything else that quotes a frontier at a reader. One unbroken string, so that
 * two producers cannot disagree about where the line breaks fall.
 *
 * `build-ladder-frontier.py` writes its own copy into each document it
 * assembles, and the two are deliberately NOT checked against each other. The
 * document's copy is inside the document's digest (interfaces.md section 5), so
 * tying that digest to a sentence this file may extend would turn every
 * improvement to a disclosure into a re-measurement. What keeps them honest is
 * that they say the same things about the same instrument, and this one says one
 * thing more: the operational contract, which is about how the guard is RUN
 * rather than about what the measurement covers, and which only the side that
 * clears builds is in a position to state.
 */
export const FAILURE_DIRECTION =
  'Fails towards exposure-consistent. The ladder is a single-TU synthetic specimen: '
  + 'cross-translation-unit inlining, profile data, -march code generation, stack-protector '
  + 'variants and everything downstream of the IR optimiser are invisible to its three '
  + 'extractors, so two genuinely different exposures can present identical frontiers. A '
  + 'consistent reading is necessary, never sufficient. The opposite direction is clean: with a '
  + 'deterministic compiler a differing frontier under an identical ladder is evidence of a '
  + 'differing exposure, and refusing to quote the cell is the correct reading. Measured limits, '
  + 'clang 18.1.3 on 2026-08-17: -O2, -O3 and -Os are indistinguishable to this rung set, and so '
  + 'are _FORTIFY_SOURCE=2 and =3. Any command line carrying an LTO token is refused at '
  + 'measurement time rather than measured. '
  + 'What is bound is the flag sequence and the compiler, not the header set: no rung reads a '
  + 'header, and _FORTIFY_SOURCE is a header rewrite, so two builds whose flags and compiler '
  + 'agree present one exposure even where their include paths resolve to different headers. The '
  + 'contract that closes that gap is operational and belongs to whoever runs the guard: THE '
  + 'LADDER IS MEASURED IN THE SAME IMAGE AND THE SAME JOB AS THE BUILD IT GUARDS. A frontier '
  + 'measured earlier, or elsewhere, is a reading of another exposure, and no comparison made '
  + 'here can tell. And a command line carrying a path-bearing flag -- -I/usr/local/include, '
  + '--sysroot=/opt/vendor -- cannot have a frontier assembled at all, because section 5 will not '
  + 'let a host path into a digested document; vendor-sysroot and cross builds are therefore '
  + 'outside the coverage of this guard rather than quietly inside it.';

/** interfaces.md section 5 rule 5: sha-256, lowercase hex. */
const SHA256_HEX = /^[0-9a-f]{64}$/;

/** Base class so a caller can branch on "this component could not answer". */
export class FrontierError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FrontierError';
    /** interfaces.md section 7: a check that could not be completed. Never 0. */
    this.exitCode = 3;
  }
}

/** A document was not the shape this module is documented to take. */
export class FrontierInputError extends FrontierError {
  constructor(message) {
    super(message);
    this.name = 'FrontierInputError';
  }
}

const isPlainObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

const short = (s) => (typeof s === 'string' && s.length > 12 ? `${s.slice(0, 12)}…` : String(s ?? 'none'));

/**
 * Whether a document declares its own measurement unusable.
 *
 * Read before anything else, and demanded as a boolean. A missing `health.broken`
 * is refused rather than read as `false`: "the producer did not say" and "the
 * producer said the run was fine" are different sentences, and picking the second
 * for a document that stated neither is how a broken run gets quoted.
 */
export function declaresBroken(doc, where = 'document') {
  if (!isPlainObject(doc)) {
    throw new FrontierInputError(`${where}: a frontier document is a JSON object; got ${JSON.stringify(doc)}`);
  }
  if (!isPlainObject(doc.health) || typeof doc.health.broken !== 'boolean') {
    throw new FrontierInputError(
      `${where}.health.broken must be a boolean. It is the field that says whether this reading `
      + 'is usable at all, and this module will not choose the permissive reading for a producer '
      + 'that did not state one.',
    );
  }
  return doc.health.broken;
}

/**
 * The invariants a ladder document states about its own run, over and above
 * `health.broken`. All three are computed by the assembler and re-derived from
 * the same observations by `check-ladder.py`, which exits 2 when a document's
 * stated value disagrees with what its own rungs say — so by the time one
 * arrives here the word is as good as the measurement behind it.
 *
 *   chainMonotone      a property lost at one rung stays lost at the ones above
 *                      it; a ladder that recovers a property going up is not
 *                      ordered, and an unordered ladder grades nothing
 *   spellingExclusive  exactly one spelling of each wipe/guard survived, so a
 *                      rung's reading names one mechanism rather than a sum
 *   twinsHeld          every rung's co-resident control was still there
 *                      (interfaces.md section 4)
 *
 * Alphabetical, and emitted in this order wherever they are named.
 */
export const HEALTH_INVARIANTS = Object.freeze(['chainMonotone', 'spellingExclusive', 'twinsHeld']);

/**
 * Which of those invariants a document declares FALSE — `null` when it declares
 * none of them false.
 *
 * `null` rather than an empty array, and the choice is load-bearing rather than
 * stylistic. This answer is read at the point a build is cleared or refused,
 * `if (declaresUnhealthy(doc))` is what that reads like at every call site, and
 * an empty array is truthy in JavaScript. A guard whose safe path depends on
 * every caller remembering `.length` is a guard with a silent off switch.
 *
 * An ABSENT invariant is not read as false. That is the opposite treatment from
 * `health.broken`, which is demanded, and the asymmetry is deliberate:
 * `health.broken` is the field that says whether the reading is usable at all,
 * so a document that omits it has not answered the question, while these three
 * arrived after documents that do not carry them and an omission is honestly
 * "this producer does not state it". What may never happen is the other
 * direction — a document that says `twinsHeld: false` and is compared anyway.
 *
 * @param {object} doc a parsed frontier document, sidecar entry, or anything
 *        else claiming to be one; a non-object is not a document that declares
 *        anything, and is answered `null` rather than thrown at
 * @returns {string[]|null} the failing invariant names, in HEALTH_INVARIANTS order
 */
export function declaresUnhealthy(doc) {
  if (!isPlainObject(doc) || !isPlainObject(doc.health)) return null;
  const failed = HEALTH_INVARIANTS.filter((k) => doc.health[k] === false);
  return failed.length > 0 ? failed : null;
}

/**
 * Validate the parts of a healthy document that a comparison reads, and return
 * them.
 *
 * Throwing rather than returning incomparable is deliberate, and the line is
 * worth stating. `exposure-incomparable` is a MEASURED reading: both sides were
 * well formed and something about them did not line up. A document that is not
 * the documented shape has produced no reading at all, and reporting it as
 * incomparable would put a producer bug and an ordinary ladder-version skew in
 * one bucket — the first needs fixing, the second is normal. Both leave the CLI
 * at exit 3, so nothing is quoted either way.
 */
export function readHealthyDocument(doc, where) {
  if (!isPlainObject(doc.ladder)) {
    throw new FrontierInputError(
      `${where}.ladder must be an object carrying sourceSha256 and generatorVersion. Those two `
      + 'names are the contract; a document that spells them otherwise is refused rather than '
      + 'searched for near-matches.',
    );
  }
  const { sourceSha256, generatorVersion } = doc.ladder;
  if (typeof sourceSha256 !== 'string' || !SHA256_HEX.test(sourceSha256)) {
    throw new FrontierInputError(
      `${where}.ladder.sourceSha256 must be 64 lowercase hex characters (interfaces.md section 5 `
      + `rule 5); got ${JSON.stringify(sourceSha256)}. The format is checked rather than compared `
      + 'as an opaque string because an uppercase or truncated digest would make two identical '
      + 'ladders read as different — a silent incomparable, which is the one failure this module '
      + 'cannot detect from the inside.',
    );
  }
  // An integer or a non-empty string. Both spellings are in the tree: the
  // assembler writes an integer, because interfaces.md section 5 rule 4 makes
  // every number in a record an integer, and the driver-side documents write a
  // string, as `derive-fallback-table.mjs`'s own GENERATOR_VERSION does. Either
  // is a fine identity label. What is NOT done is coercing between them: 1 and
  // "1" compare unequal here and the pair is reported incomparable, which sends
  // a reader to the producer that changed the field's type instead of hiding it.
  const versionOk = Number.isInteger(generatorVersion)
    || (typeof generatorVersion === 'string' && generatorVersion.length > 0);
  if (!versionOk) {
    throw new FrontierInputError(
      `${where}.ladder.generatorVersion must be an integer or a non-empty string; got `
      + `${JSON.stringify(generatorVersion)}. A float is refused outright: interfaces.md section 5 `
      + 'rule 4 admits no non-integer number into a record.',
    );
  }
  if (!isPlainObject(doc.frontier) || Object.keys(doc.frontier).length === 0) {
    throw new FrontierInputError(
      `${where}.frontier must be a non-empty object mapping each rung to one word. A document `
      + 'that declares itself healthy and carries no frontier is refused rather than treated as '
      + 'an empty reading: two empty frontiers compare equal, which would report '
      + `${JSON.stringify(RESULT_CONSISTENT)} for two builds nothing was measured on.`,
    );
  }
  for (const [rung, reading] of Object.entries(doc.frontier)) {
    if (rung.length === 0) throw new FrontierInputError(`${where}.frontier has an empty rung name`);
    if (!KNOWN_RUNG_READINGS.includes(reading)) {
      throw new FrontierInputError(
        `${where}.frontier.${rung} is ${JSON.stringify(reading)}, which is not one of `
        + `${KNOWN_RUNG_READINGS.join('/')}. An unrecognised word is refused rather than compared `
        + 'as an opaque string: comparing it would happen to work, and then the day one producer '
        + 'spells it differently the guard reports a mismatch nobody can explain.',
      );
    }
  }
  return { sourceSha256, generatorVersion, frontier: doc.frontier };
}

/** The rungs a document did not successfully measure. Sorted, for messages. */
export function brokenRungsOf(doc) {
  if (!isPlainObject(doc) || !isPlainObject(doc.frontier)) return [];
  return Object.keys(doc.frontier)
    .filter((r) => UNCOMPARABLE_RUNG_READINGS.includes(doc.frontier[r]))
    .sort();
}

/**
 * Compare two ladder frontiers.
 *
 * Both arguments are parsed documents — this function does no I/O, so a caller
 * holding a path opens it, and a caller holding a document embedded in a larger
 * one hands the sub-object straight in.
 *
 * @param {object} a the frontier measured for the build in hand
 * @param {object} b the frontier recorded for the cell being quoted
 * @param {{whereA?: string, whereB?: string}} [labels] names used in messages
 * @returns {{result: string, differingRungs: string[], reason: string}}
 *          `differingRungs` is sorted and is empty unless the result is a
 *          mismatch; `reason` is always a sentence, including on success.
 * @throws {FrontierInputError} a document was not the documented shape
 */
export function compareFrontiers(a, b, labels = {}) {
  const whereA = labels.whereA ?? 'a';
  const whereB = labels.whereB ?? 'b';

  // Health first, and it short-circuits. A document that declares its own
  // measurement broken is not asked to carry a well-formed frontier at all — the
  // sidecar deriver writes exactly such a document for a config key it refused
  // to resolve — so demanding one before reading `health.broken` would turn a
  // correctly self-reported refusal into a shape error.
  const brokenA = declaresBroken(a, whereA);
  const brokenB = declaresBroken(b, whereB);
  if (brokenA || brokenB) {
    const sides = [brokenA ? whereA : null, brokenB ? whereB : null].filter(Boolean);
    const why = [a, b]
      .map((d) => (isPlainObject(d.health) ? d.health.reason : null))
      .filter((r) => typeof r === 'string' && r.length > 0);
    return {
      result: RESULT_INCOMPARABLE,
      differingRungs: [],
      reason:
        `health.broken is true on ${sides.join(' and ')}`
        + `${why.length > 0 ? ` (${why.join('; ')})` : ''}`
        + ', so no comparison was made. A run that reported itself broken is not evidence of '
        + 'sameness and is not evidence of difference.',
    };
  }

  // Then the three invariants, read here for the same reason `health.broken` is
  // read here: this is the one place on the path that clears a build which both
  // documents pass through. `check-ladder.py` already refuses a document whose
  // invariants are false, and `check-ladder.py` is never invoked by the driver —
  // a guard that only holds when someone remembers to run a second tool is not
  // a guard. A ladder that has measurably stopped being a ladder must not clear
  // anything: `health.broken` is one rung's apparatus failing, while these are
  // the specimen itself no longer behaving like the graded object the whole
  // comparison assumes, and its rungs are then not evidence of anything.
  //
  // Returned alone rather than collected into `blockers` below, and reported for
  // both sides at once, so the reader is sent to the instrument rather than to
  // whichever ordinary gate happened to fire alongside it.
  const unhealthy = [[whereA, declaresUnhealthy(a)], [whereB, declaresUnhealthy(b)]]
    .filter(([, failing]) => failing !== null);
  if (unhealthy.length > 0) {
    return {
      result: RESULT_INCOMPARABLE,
      differingRungs: [],
      reason:
        `${unhealthy.map(([w, failing]) => `${w} declares ${failing.join(' and ')} false`).join('; ')}`
        + ', so the specimen was no longer the graded ladder this comparison assumes and no '
        + 'comparison was made. An invariant of the instrument is not a rung: it says the reading '
        + 'itself is not data, in the same way a control that fell to zero does.',
    };
  }

  // The schema version is not one of the four fields the comparison reads, and
  // it is checked only when a document states one. It is here because a document
  // of another vintage may spell those four fields differently, and comparing
  // the wrong fields by accident is worse than declining to compare.
  for (const [where, doc] of [[whereA, a], [whereB, b]]) {
    if (doc.schemaVersion !== undefined && doc.schemaVersion !== LADDER_FRONTIER_SCHEMA_VERSION) {
      return {
        result: RESULT_INCOMPARABLE,
        differingRungs: [],
        reason:
          `${where} declares schemaVersion ${JSON.stringify(doc.schemaVersion)}, not `
          + `${JSON.stringify(LADDER_FRONTIER_SCHEMA_VERSION)}. A document of another vintage may `
          + 'spell the compared fields differently, so it is not read.',
      };
    }
  }

  const ra = readHealthyDocument(a, whereA);
  const rb = readHealthyDocument(b, whereB);

  // Every gate below produces the same word, so they are collected rather than
  // short-circuited: when the ladder was regenerated AND a rung is broken, a
  // reason naming only whichever test ran first sends the reader to fix the
  // wrong thing.
  const blockers = [];

  if (ra.sourceSha256 !== rb.sourceSha256) {
    blockers.push(
      `ladder.sourceSha256 differs (${whereA}=${short(ra.sourceSha256)} ${whereB}=`
      + `${short(rb.sourceSha256)}): the two readings are of different specimens, so a differing `
      + 'rung would be a difference between the specimens rather than between the exposures',
    );
  }
  if (ra.generatorVersion !== rb.generatorVersion) {
    blockers.push(
      `ladder.generatorVersion differs (${whereA}=${JSON.stringify(ra.generatorVersion)} `
      + `${whereB}=${JSON.stringify(rb.generatorVersion)}): the rung set, the symbol lists and the `
      + 'grading rule belong to the generator, so the same specimen graded by two of them is not '
      + 'one measurement repeated',
    );
  }

  // Deep equality of a flat map is its key set plus the value at each key. The
  // key set is checked first, so a rung missing from one side is reported as
  // never measured rather than as a difference in how it responded.
  const rungsA = Object.keys(ra.frontier).sort();
  const onlyA = rungsA.filter((r) => !(r in rb.frontier));
  const onlyB = Object.keys(rb.frontier).sort().filter((r) => !(r in ra.frontier));
  if (onlyA.length > 0 || onlyB.length > 0) {
    blockers.push(
      'the two readings do not cover the same rungs ('
      + `${whereA}-only=${JSON.stringify(onlyA)} ${whereB}-only=${JSON.stringify(onlyB)}`
      + '): a rung one side never measured cannot be evidence that the two sides agree',
    );
  }

  const brokenRungs = [...new Set([...brokenRungsOf(a), ...brokenRungsOf(b)])].sort();
  if (brokenRungs.length > 0) {
    blockers.push(
      `${brokenRungs.length} rung(s) were not successfully measured on one or both sides `
      + `(${brokenRungs.join(', ')}): interfaces.md section 4 makes such a rung a broken `
      + 'measurement rather than a finding, and it would difference against a state as though it '
      + 'were one. Refusing to compare is the safe direction; folding it into "equal anyway" '
      + 'would manufacture consistency out of an apparatus failure',
    );
  }

  if (blockers.length > 0) {
    return { result: RESULT_INCOMPARABLE, differingRungs: [], reason: blockers.join('; ') };
  }

  const differingRungs = rungsA.filter((r) => ra.frontier[r] !== rb.frontier[r]);
  if (differingRungs.length > 0) {
    return {
      result: RESULT_MISMATCH,
      differingRungs,
      reason:
        `${differingRungs.length} of ${rungsA.length} rungs responded differently (`
        + differingRungs.map((r) => `${r}: ${ra.frontier[r]} on ${whereA}, ${rb.frontier[r]} on ${whereB}`).join('; ')
        + '). At least one probed mechanism differs between these two invocations, so the cell '
        + 'recorded for one must not be quoted for the other.',
    };
  }

  // Deliberately not "matched" and not "verified". Every rung this ladder
  // carries answered the same way in both builds; the ladder does not probe
  // everything a build can differ in, and this word says only that.
  return {
    result: RESULT_CONSISTENT,
    differingRungs: [],
    reason:
      `all ${rungsA.length} rungs responded identically. No probed mechanism separated the two `
      + 'invocations. Necessary, never sufficient — two genuinely different exposures can present '
      + 'identical frontiers.',
  };
}

/** Exit code for a comparison, per interfaces.md section 7. */
export function exitCodeFor(result) {
  if (result === RESULT_CONSISTENT) return 0;
  if (result === RESULT_MISMATCH) return 2;
  if (result === RESULT_INCOMPARABLE) return 3;
  throw new FrontierInputError(`${JSON.stringify(result)} is not one of ${EXPOSURE_RESULTS.join('/')}`);
}

/** Human-readable form. Always prints the word and the reason together. */
export function formatComparison(cmp) {
  const lines = [cmp.result];
  if (cmp.differingRungs.length > 0) lines.push(`  differing rungs: ${cmp.differingRungs.join(', ')}`);
  lines.push(`  ${cmp.reason}`);
  // Printed on the one outcome a reader is tempted to over-read, and nowhere
  // else. A caller that saw "exposure-consistent" and stopped reading is exactly
  // the reader this paragraph is for.
  if (cmp.result === RESULT_CONSISTENT) lines.push(`  ${FAILURE_DIRECTION}`);
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE = `usage: node frontier-match.mjs <measured.json> <recorded.json> [--json]

  <measured.json>  the frontier measured for the build in hand
  <recorded.json>  the frontier recorded for the cell being quoted

exit codes (compiler/schema/interfaces.md section 7)
  0  ${RESULT_CONSISTENT}
  2  ${RESULT_MISMATCH}
  3  ${RESULT_INCOMPARABLE}, or a document that could not be read

There is deliberately no flag that turns a mismatch into a warning.`;

async function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    process.stdout.write(`${USAGE}\n`);
    return args.length === 0 ? 3 : 0;
  }

  let asJson = false;
  const files = [];
  for (const a of args) {
    if (a === '--json') asJson = true;
    else if (a.startsWith('-')) throw new FrontierInputError(`unknown option ${a}`);
    else files.push(a);
  }
  if (files.length !== 2) {
    throw new FrontierInputError(`two frontier documents are required; got ${files.length}`);
  }

  const { readFile } = await import('node:fs/promises');
  const docs = [];
  for (const f of files) {
    let raw;
    try {
      raw = await readFile(f, 'utf8');
    } catch (err) {
      throw new FrontierError(`could not read ${f}: ${err.message}`);
    }
    try {
      docs.push(JSON.parse(raw));
    } catch (err) {
      throw new FrontierInputError(`${f} is not JSON: ${err.message}`);
    }
  }

  const cmp = compareFrontiers(docs[0], docs[1], { whereA: 'measured', whereB: 'recorded' });
  process.stdout.write(
    `${asJson
      ? JSON.stringify({ component: COMPONENT, ...cmp, failureDirection: FAILURE_DIRECTION }, null, 2)
      : formatComparison(cmp)}\n`,
  );
  return exitCodeFor(cmp.result);
}

// Matched on the entry path rather than by comparing `import.meta.url` to a file
// URL: the URL forms disagree across platforms on drive-letter case, and a
// mismatch there leaves the CLI silently inert instead of loudly broken.
if (process.argv[1] && /(^|[/\\])frontier-match\.mjs$/.test(process.argv[1].replace(/\\/g, '/'))) {
  main(process.argv)
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      process.stderr.write(`${err.message}\n`);
      process.exitCode = err instanceof FrontierError ? err.exitCode : 3;
    });
}
