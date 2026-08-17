#!/usr/bin/env node
/**
 * derive-frontier-sidecar — many per-exposure ladder frontier documents into one
 * `vibeguard.ladder-frontiers/1` sidecar, mapping a nominal six-axis config key
 * to the frontier that was measured at it.
 *
 *   node derive-frontier-sidecar.mjs --out <path> <frontier.json> [...]
 *   node derive-frontier-sidecar.mjs --out <path> --dir <dir-of-frontiers>
 *
 * The sidecar sits beside the fallback table and is consulted before a cell is
 * quoted: the driver measures the ladder under the build in hand, looks the
 * build's config key up here, and hands both frontiers to `frontier-match.mjs`.
 * A mismatch refuses the quote.
 *
 * ★ THE COLLISION RULE — the single most important decision in this file.
 *
 * Two frontier documents can map to the same config key and still disagree. That
 * is not a defect in the inputs and it is not noise to be smoothed: IT IS THE
 * PHENOMENON THE GUARD EXISTS TO DETECT. The nominal key carries six axes — cc,
 * freestanding, lto, ndebug, opt, target — and measured on the driver's own
 * `normalise()` + `driverConfigAxes()`, the key for `-O2` is byte-identical to
 * the key for `-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3`, for
 * `-O2 -fno-builtin-memset`, for `-O2 -ffast-math` and for
 * `-O2 -fstack-protector-strong -fPIC -march=native`. When two such builds
 * respond differently to the ladder, the key has been shown to be unable to tell
 * two exposures apart. So a collision is NEVER merged, NEVER averaged and NEVER
 * resolved last-one-wins:
 *
 *   * the key is written out as unusable, carrying `health.broken: true` and no
 *     frontier, so that a consumer running it through `compareFrontiers` gets
 *     `exposure-incomparable` rather than an arbitrary winner;
 *   * the collision is recorded in `anomalies`, naming both sources and every
 *     rung they differ on. The precedent is `derive-fallback-table.mjs`'s
 *     `anomalies` array: excluded, but never silently.
 *
 * Picking a winner would be strictly worse than having no sidecar at all. The
 * guard would then answer `exposure-consistent` for whichever of the two builds
 * happened to lose the coin toss — a confident wrong answer produced by the very
 * component that was added to stop confident wrong answers.
 *
 * ★ GUARD ONLY, PERMANENTLY. Nothing here may be merged into a
 *   `vibeguard.fallback-table/1` row or into an envelope cell. A ladder frontier
 *   is a (ladder-subject, config) measurement of a synthetic specimen and says
 *   nothing about the user's subject. `derive-fallback-table.mjs` documents
 *   keying by propertyId rather than by (subject, config) as its mistake #1;
 *   letting a frontier fill or select a cell is that mistake one level up.
 *
 * THE KEY DISCIPLINE
 *
 * The six axis names and their order are the ones `derive-fallback-table.mjs`
 * fixes in its `CONFIG_KEYS`, and a config is canonicalised the same way: exactly
 * those keys, in that order, missing ones written `null`. They are restated here
 * rather than imported, and the duplication is deliberate on both counts. The
 * two files must AGREE, because a sidecar keyed differently from the table it
 * guards would silently guard nothing — so a test pins the list. And they must
 * not SHARE code, because the one thing this sidecar must never become is an
 * input to that table, and a shared module is the first step of exactly that
 * merge.
 *
 * ★ WHERE THE VALUES COME FROM, WHICH IS NOT THE DOCUMENT
 *
 * A frontier document states no `config`, and it is right not to. What it
 * records is the invocation it measured — `exposure.opt` and
 * `exposure.extraArgs`, the line that was actually compiled — plus the compiler
 * that compiled it at `toolchain.cc`. Turning that line into six axes is a
 * READING of a command line, and this tree has exactly one: `normalise()` in
 * `compiler/driver/lib/cmdline.mjs` followed by `driverConfigAxes()` in
 * `compiler/driver/lib/config-axes.mjs`. Both are imported here and the reading
 * is not re-implemented, in bash, in Python or in this file.
 *
 * That import does not contradict the paragraph above. What must not be shared
 * with `derive-fallback-table.mjs` is the axis vocabulary, and it still is not;
 * what IS shared is the driver's reading of an argument list, and sharing it is
 * the whole point — the driver looks this sidecar up by the key its own reader
 * produced, so a second reading here would not disagree visibly, it would MISS,
 * and a sidecar that silently has nothing to say about any build looks from the
 * driver's side exactly like a clean run. Nothing flows from this file into the
 * table in either direction.
 *
 * A `null` axis is recorded as an anomaly rather than accepted quietly. A key
 * with a null axis is a key that under-specifies the build even more than the
 * six axes already do, so two more genuinely different builds land on it.
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
 * A frontier binds the flag sequence and the compiler and NOT the header set:
 * `_FORTIFY_SOURCE` is a header rewrite, so two builds whose argv and clang are
 * identical but whose images ship different headers key the same, frontier the
 * same, and are not told apart here. The contract that closes that gap is
 * operational and belongs to whoever runs the sweep — THE LADDER IS MEASURED IN
 * THE SAME IMAGE AND THE SAME JOB AS THE BUILD IT GUARDS — and a sidecar
 * assembled from documents measured in some earlier container is a lookup table
 * of other exposures. Relatedly, a build whose command line carries a
 * path-bearing flag (`-I/usr/local/include`, `--sysroot=/opt/vendor`) never
 * reaches this file at all: interfaces.md section 5 keeps host paths out of a
 * digested document, so the assembler refuses instead of redacting, and
 * vendor-sysroot and cross builds are outside this guard's coverage rather than
 * loosely inside it.
 *
 * The paragraph is emitted into the sidecar itself, at
 * `instrument.failureDirection`, so that a reader who has only the artefact is
 * told what a consistent reading is worth.
 *
 * EXIT CODES (interfaces.md section 7)
 *   0  a sidecar was written. NOT a claim that every key is usable — a run in
 *      which every key collided exits 0, because the collisions are the finding
 *      and destroying the report of them would be the worse outcome. The stderr
 *      summary always states how many keys came out usable.
 *   1  the command line is wrong
 *   2  an invariant failed: the entries do not account for every input document,
 *      or an entry contradicts itself. No sidecar is written, because a sidecar
 *      that quietly dropped an exposure is worse than none
 *   3  nothing to derive from: no input was named, or one of the inputs could
 *      not be read or was not the documented shape. One unreadable document
 *      fails the whole run rather than being skipped — skipping it would drop an
 *      exposure from the collision search, which is the one thing this file is
 *      for
 */

import { readdirSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { normalise } from '../driver/lib/cmdline.mjs';
import { driverConfigAxes } from '../driver/lib/config-axes.mjs';
import {
  EXPOSURE_RESULTS,
  FAILURE_DIRECTION,
  FrontierError,
  HEALTH_INVARIANTS,
  RESULT_INCOMPARABLE,
  RESULT_MISMATCH,
  compareFrontiers,
  declaresBroken,
  declaresUnhealthy,
  readHealthyDocument,
} from './frontier-match.mjs';

export const EXIT_OK = 0;
export const EXIT_USAGE = 1;
export const EXIT_INVARIANT = 2;
export const EXIT_INCOMPLETE = 3;

export const SIDECAR_SCHEMA_VERSION = 'vibeguard.ladder-frontiers/1';
export const GENERATOR_NAME = 'derive-frontier-sidecar';
export const GENERATOR_VERSION = '1';

/**
 * The six axes of the nominal key, in the order
 * `derive-fallback-table.mjs`'s `CONFIG_KEYS` fixes. Emitted in this order
 * everywhere, so that two runs over the same inputs produce identical bytes.
 */
export const CONFIG_KEYS = Object.freeze(['cc', 'freestanding', 'lto', 'ndebug', 'opt', 'target']);

/** Why a config key was written out as unusable. */
export const UNUSABLE = Object.freeze({
  COLLISION: 'config-key-collision',
  INCOMPARABLE: 'config-key-incomparable',
  BROKEN: 'broken-measurement',
  // Kept apart from BROKEN on purpose. `health.broken` is a rung whose apparatus
  // failed; a false invariant is the specimen no longer behaving like a ladder
  // at all, and the two send a reader to different places — one to the rung's
  // fixture, one to the generator.
  INVARIANT: 'health-invariant-false',
});

const isPlainObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

/** A config object with exactly CONFIG_KEYS, in CONFIG_KEYS order. */
export function canonConfig(config) {
  const out = {};
  for (const k of CONFIG_KEYS) out[k] = config?.[k] ?? null;
  return out;
}

/** Stable identity string for a config. Used for keys and for sorting. */
export function configKey(config) {
  return JSON.stringify(canonConfig(config));
}

/** Deterministic serialisation for comparing two recorded objects. */
function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

const byString = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The nominal six-axis config a document was measured at, derived from the
 * invocation the document records.
 *
 * Five of the six come off the command line, read by the driver's own
 * `normalise()` + `driverConfigAxes()` over `exposure.opt` followed by
 * `exposure.extraArgs` — the same two calls, in the same order, that the driver
 * will run over the build in hand when it looks this sidecar up. Deriving them
 * here in any other way, including a three-line reimplementation that happens to
 * agree today, would put a second definition of the key on the two ends of one
 * lookup; see the header.
 *
 * `cc` is the sixth and is not on any command line. It comes from
 * `toolchain.cc`, which `build-ladder-frontier.py` takes from the manifest the
 * runner wrote and cross-checks against the compiler the observer actually saw.
 * A document that states none is REFUSED rather than filed under `cc: null`:
 * `cc` is the axis that separates readings taken by different compilers, and an
 * all-`cc: null` key would collect them into one collision that says nothing
 * about the exposures and everything about the missing field.
 *
 * @returns {{config: object|null, problem: string|null}}
 */
export function configFromDocument(doc, id) {
  const bad = (why) => ({ config: null, problem: `${id}: ${why}` });

  const exposure = doc.exposure;
  if (!isPlainObject(exposure)) {
    return bad(
      'the document states no `exposure` object, so there is no invocation to read the nominal '
      + `key off. The six axes are ${CONFIG_KEYS.join(', ')}; five of them are read from `
      + '`exposure.opt` + `exposure.extraArgs` and none of them is guessed',
    );
  }
  if (typeof exposure.opt !== 'string') {
    return bad(
      `exposure.opt is ${JSON.stringify(exposure.opt)}, not a string. It is the one axis the `
      + 'ladder varies deliberately, and a document that does not say which level it was measured '
      + 'at is not filed at a level',
    );
  }
  const extraArgs = exposure.extraArgs ?? [];
  if (!Array.isArray(extraArgs) || extraArgs.some((a) => typeof a !== 'string')) {
    return bad('exposure.extraArgs must be an array of strings; the rest of the command line is what carries FORTIFY');
  }
  const cc = doc.toolchain?.cc;
  if (typeof cc !== 'string' || cc.length === 0) {
    return bad(
      'the document states no `toolchain.cc`, and `cc` is one of the six axes. It is not on any '
      + 'command line and it is not guessed from `toolchain.clang`: the axis names the driver the '
      + 'sweep invoked, and inventing one would file this reading under a compiler nobody used',
    );
  }

  // `opt` first and `extraArgs` after, which is the order the runner passes
  // them to the compiler. It matters: clang takes the LAST `-O`, so an
  // `extraArgs` carrying its own level must win here as it wins there.
  const argv = [...(exposure.opt.length > 0 ? [exposure.opt] : []), ...extraArgs];
  return { config: { cc, ...driverConfigAxes(normalise(argv)) }, problem: null };
}

/**
 * interfaces.md section 5: absolute paths must not appear anywhere in a record.
 * The sidecar echoes document ids, toolchain records and — through the derived
 * key — values read straight off the measured command line, so a producer that
 * let a lab directory into any of them would launder it through here into a
 * committable file. `build-ladder-frontier.py` refuses a path-bearing argument
 * at assembly time, which is the reason a `--sysroot=` build has no frontier at
 * all; this is the backstop for the day something reaches here another way.
 * Checked on the way out: the inputs are somebody else's to fix, but what this
 * file emits is this file's problem.
 */
/**
 * The forms a path takes when it is not at the front of the string. A leading
 * `/` is only the shape a bare path has; the shape that actually turns up here
 * is a path inside a token — `clang --sysroot=/home/…`, `-I/home/…` — and a
 * leading-character test walks straight past both. Measured 2026-08-17: a
 * document whose `toolchain.cc` read `clang --sysroot=/home/<name>/sysroot`
 * derived at exit 0 with no problems, and the account name came out in
 * `entries[0].config.cc` AND, verbatim, in `entries[0].configKey`.
 *
 * Kept the same shape as the predicates either side of this one -- see
 * `looks_absolute` in build-ladder-frontier.py and `findAbsolutePaths` in
 * compiler/driver/lib/paths.mjs. A backstop weaker than the check it backs up
 * is not a backstop.
 *
 * Narrower than `findAbsolutePaths` in one direction, and deliberately: this
 * file's own `failureDirection` prose names `-I/usr/local/include` and
 * `--sysroot=/opt/vendor` as the shapes that cannot be measured, so a predicate
 * that took every system prefix refused the sidecar over its own disclosure.
 * What is left is the set that can carry an account or a machine name.
 */
const EMBEDDED_PATH = /(^|[^A-Za-z0-9_])(\/(home|root|Users|mnt)\/|[A-Za-z]:[\\/])/;

function absolutePathsIn(value, path, found) {
  if (typeof value === 'string') {
    if (value.startsWith('/') || EMBEDDED_PATH.test(value)) {
      found.push(`${path}: ${JSON.stringify(value)}`);
    }
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => absolutePathsIn(v, `${path}/${i}`, found));
  } else if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) absolutePathsIn(v, `${path}/${k}`, found);
  }
  return found;
}

/**
 * The invariants EVERY source of a key states as `true`.
 *
 * Carried onto the entry so that a consumer holding only the sidecar can ask
 * `declaresUnhealthy` and get the same answer the sources would give — the
 * entries are shaped to BE frontier documents, and an entry that dropped the
 * three fields would answer "nothing stated" for a key whose sources all
 * measured them. An invariant one source states and another does not is left
 * off, because absent means "this producer does not state it" and writing
 * `true` over that would put a claim on the entry that no single reading makes.
 */
function agreedInvariants(docs) {
  const out = {};
  for (const k of HEALTH_INVARIANTS) {
    if (docs.every(({ doc }) => doc.health?.[k] === true)) out[k] = true;
  }
  return out;
}

/**
 * Derive the sidecar from already-parsed documents.
 *
 * @param {Array<{id: string, doc: object}>} documents id is the file's basename
 * @returns {{sidecar: object|null, exitCode: number, summary: string, problems: string[]}}
 */
export function deriveSidecar(documents) {
  const anomalies = [];
  const problems = [];

  if (!Array.isArray(documents) || documents.length === 0) {
    return {
      sidecar: null,
      exitCode: EXIT_INCOMPLETE,
      summary: 'documents=0',
      problems: ['no frontier documents were given; there is nothing to derive a sidecar from'],
    };
  }

  // ── 1. group by the nominal key, and say when the key is under-specified ───
  const groups = new Map();
  for (const { id, doc } of [...documents].sort((a, b) => byString(a.id, b.id))) {
    if (!isPlainObject(doc)) {
      problems.push(`${id}: a frontier document is a JSON object`);
      continue;
    }
    if (doc.schemaVersion !== undefined && doc.schemaVersion !== 'vibeguard.ladder-frontier/1') {
      anomalies.push(
        `schema-version-unexpected: ${id} declares schemaVersion=${JSON.stringify(doc.schemaVersion)}, `
        + 'which is not the shape this deriver reads. It is still read, and this line is here so a '
        + 'reader can tell whether the sidecar was built from documents of one vintage',
      );
    }
    // `exposure.id`, which is where the assembler writes it. This check used to
    // read `doc.exposureId`, a field no producer in this tree has ever written,
    // so it could not fire — a check that cannot fire is worse than no check,
    // because the file reads as though the case is covered.
    if (typeof doc.exposure?.id === 'string' && doc.exposure.id !== id) {
      anomalies.push(
        `document-id-mismatch: file ${id} carries exposure.id=${JSON.stringify(doc.exposure.id)}. `
        + 'The sidecar names sources by file name, because a file name is the one identifier that '
        + 'cannot disagree with itself; the two are listed apart rather than reconciled',
      );
    }
    // A stated `config` is recorded and not read. The key is derived from the
    // invocation with the driver's own reader (see the header), and honouring a
    // second one that arrived in the document would put two definitions of the
    // key on the two ends of one lookup. Named rather than dropped quietly: a
    // producer that went to the trouble of computing six axes is entitled to
    // find out that they were not used.
    if (doc.config !== undefined) {
      const stated = isPlainObject(doc.config) ? configKey(doc.config) : JSON.stringify(doc.config);
      anomalies.push(
        `config-stated-not-read: ${id} carries its own \`config\` (${stated}). The nominal key is `
        + 'derived from `exposure` with the driver\'s normalise() + driverConfigAxes(), because the '
        + 'driver looks this sidecar up by the key its own reader produces and a second reading '
        + 'would not disagree visibly, it would miss',
      );
    }
    const derived = configFromDocument(doc, id);
    if (derived.problem !== null) {
      problems.push(derived.problem);
      continue;
    }
    // The shape is checked as the document ENTERS, not only when two of them are
    // compared. A key with one document is never compared against anything, so
    // until this ran a lone document carrying `frontier: {}` was written out
    // `usable: true` and quoted at a build — while `compareFrontiers`, handed
    // the same document, refuses an empty frontier by name. The validator is
    // `frontier-match.mjs`'s own, imported: a second opinion here about what a
    // well-formed reading is would be the drift this whole file guards against.
    // A document that declares itself broken is exempt for the reason the
    // comparator exempts it — it is not asked to carry a frontier at all.
    try {
      if (!declaresBroken(doc, id)) readHealthyDocument(doc, id);
    } catch (err) {
      if (!(err instanceof FrontierError)) throw err;
      problems.push(err.message);
      continue;
    }
    const key = configKey(derived.config);
    if (!groups.has(key)) groups.set(key, { key, config: canonConfig(derived.config), docs: [] });
    groups.get(key).docs.push({ id, doc });
  }
  if (problems.length > 0) {
    return {
      sidecar: null,
      exitCode: EXIT_INCOMPLETE,
      summary: `documents=${documents.length} unreadable=${problems.length}`,
      problems,
    };
  }

  for (const key of [...groups.keys()].sort()) {
    const g = groups.get(key);
    for (const axis of CONFIG_KEYS) {
      if (g.config[axis] === null) {
        anomalies.push(
          `underspecified-axis: key=${key} axis=${axis} is null (sources `
          + `${JSON.stringify(g.docs.map((d) => d.id))}). The nominal key already fails to see `
          + 'FORTIFY, -fno-builtin and -ffast-math; an axis nobody recorded widens the set of '
          + 'genuinely different builds that land on this one key further still',
        );
      }
    }
  }

  // ── 2. resolve each key, never by picking a winner ────────────────────────
  const entries = [];
  const counts = {
    documents: documents.length,
    keys: groups.size,
    usableKeys: 0,
    unusableKeys: 0,
    collisions: 0,
    brokenDocuments: 0,
    unhealthyDocuments: 0,
  };

  for (const key of [...groups.keys()].sort()) {
    const g = groups.get(key);
    const sources = g.docs.map((d) => d.id).sort();

    // `health.broken` was demanded of every document as it entered, so it is a
    // boolean here and this cannot throw.
    const broken = g.docs.filter(({ id, doc }) => declaresBroken(doc, id));
    counts.brokenDocuments += broken.length;
    for (const b of broken) {
      anomalies.push(
        `broken-measurement: ${b.id} at key=${key} declares health.broken, so its reading is not `
        + 'data. It is counted as a source of this key and named here rather than dropped: a key '
        + 'whose only measurement was broken must not look like a key nobody measured',
      );
    }

    // The three invariants, on the path that clears builds. A pair of documents
    // under one key would be caught by `compareFrontiers`, which now refuses an
    // unhealthy document — but a key with ONE document is never compared against
    // anything, and that is precisely the key a driver would quote. So each
    // document is asked directly.
    const unhealthy = g.docs
      .map(({ id, doc }) => ({ id, failing: declaresUnhealthy(doc) }))
      .filter((u) => u.failing !== null);
    counts.unhealthyDocuments += unhealthy.length;
    for (const u of unhealthy) {
      anomalies.push(
        `health-invariant-false: ${u.id} at key=${key} declares ${u.failing.join(' and ')} false, `
        + 'so the specimen stopped behaving like a ladder during the run that produced it. Its '
        + 'rungs are not graded readings and the key is written out unusable rather than quoted',
      );
    }

    // Every pair, not each against the first. `exposure-incomparable` is not
    // transitive — b may be comparable with a and with c while a and c are not —
    // so a first-against-rest sweep can miss the pair that actually disagrees.
    const pairs = [];
    for (let i = 0; i < g.docs.length; i += 1) {
      for (let j = i + 1; j < g.docs.length; j += 1) {
        const A = g.docs[i];
        const B = g.docs[j];
        let cmp;
        try {
          cmp = compareFrontiers(A.doc, B.doc, { whereA: A.id, whereB: B.id });
        } catch (err) {
          problems.push(`${A.id} vs ${B.id}: ${err.message}`);
          continue;
        }
        pairs.push({ a: A.id, b: B.id, ...cmp });
      }
    }

    const mismatched = pairs.filter((p) => p.result === RESULT_MISMATCH);
    const incomparable = pairs.filter((p) => p.result === RESULT_INCOMPARABLE);

    let unusableReason = null;
    if (mismatched.length > 0) {
      unusableReason = UNUSABLE.COLLISION;
      counts.collisions += 1;
      for (const p of mismatched) {
        anomalies.push(
          `config-key-collision: key=${key} sources=${JSON.stringify([p.a, p.b])} `
          + `differingRungs=${JSON.stringify(p.differingRungs)} — two builds the nominal key `
          + 'cannot tell apart responded differently to the same ladder, so the key is written '
          + 'out unusable. Not merged, not averaged, not last-one-wins: a winner here would let '
          + 'the guard answer exposure-consistent for whichever build lost the coin toss',
        );
      }
    } else if (broken.length > 0) {
      unusableReason = UNUSABLE.BROKEN;
    } else if (unhealthy.length > 0) {
      // Ahead of `incomparable`, which is what an unhealthy document makes every
      // pair it appears in: the invariant is the cause and the incomparability
      // is the symptom, and a key reported under the symptom sends a reader
      // looking for a version skew that is not there.
      unusableReason = UNUSABLE.INVARIANT;
    } else if (incomparable.length > 0) {
      unusableReason = UNUSABLE.INCOMPARABLE;
      for (const p of incomparable) {
        anomalies.push(
          `config-key-incomparable: key=${key} sources=${JSON.stringify([p.a, p.b])} — ${p.reason} `
          + 'The key is unusable, and this is kept apart from a collision on purpose: nothing was '
          + 'shown to differ here, so calling it a collision would report a measurement that was '
          + 'never made',
        );
      }
    }

    const usable = unusableReason === null;
    const first = g.docs[0];

    // `toolchain` is recorded, never compared — see frontier-match.mjs. This is
    // the one place worth saying out loud when two of them produced the same
    // frontier, because that agreement is the evidence for not comparing them.
    const toolchains = [...new Set(g.docs.map((d) => stableStringify(d.doc.toolchain ?? null)))];
    if (usable && toolchains.length > 1) {
      anomalies.push(
        `toolchain-differs-under-one-key: key=${key} sources=${JSON.stringify(sources)} were `
        + 'measured under different toolchain records and produced the same frontier. Recorded, '
        + 'not refused: the comparison asks whether the specimen responded the same way, not '
        + 'whether the label is the same, and the nominal key already carries cc',
      );
    }

    entries.push({
      configKey: key,
      config: g.config,
      usable,
      unusableReason,
      // Shaped so that an entry IS a frontier document as far as
      // `compareFrontiers` is concerned. An unusable key therefore reads as
      // `health.broken`, and any consumer that hands it to the comparator gets
      // exposure-incomparable without having to know this file's vocabulary.
      ladder: usable ? { ...first.doc.ladder } : null,
      toolchain: usable ? (first.doc.toolchain ?? null) : null,
      health: usable
        ? { broken: false, ...agreedInvariants(g.docs) }
        : { broken: true, reason: unusableReason },
      frontier: usable ? { ...first.doc.frontier } : null,
      sources,
    });

    if (usable) counts.usableKeys += 1;
    else counts.unusableKeys += 1;
  }

  if (problems.length > 0) {
    return {
      sidecar: null,
      exitCode: EXIT_INCOMPLETE,
      summary: `documents=${documents.length} keys=${groups.size} unreadable=${problems.length}`,
      problems,
    };
  }

  // ── 3. the invariant: every input document is accounted for exactly once ──
  //
  // A sidecar that quietly dropped an exposure is worse than no sidecar: the
  // dropped one is precisely the exposure that would have collided.
  const accounted = new Map();
  for (const e of entries) for (const s of e.sources) accounted.set(s, (accounted.get(s) ?? 0) + 1);
  for (const { id } of documents) {
    const n = accounted.get(id) ?? 0;
    if (n !== 1) problems.push(`document ${id} appears in ${n} entries; it must appear in exactly one`);
  }
  for (const s of accounted.keys()) {
    if (!documents.some((d) => d.id === s)) problems.push(`entry names source ${s}, which was not an input`);
  }
  for (const e of entries) {
    if (e.usable === (e.frontier === null)) {
      problems.push(`entry ${e.configKey} is usable=${e.usable} with frontier=${e.frontier === null ? 'null' : 'set'}`);
    }
    if (e.usable === e.health.broken) {
      problems.push(`entry ${e.configKey} is usable=${e.usable} with health.broken=${e.health.broken}`);
    }
  }
  if (problems.length > 0) {
    return {
      sidecar: null,
      exitCode: EXIT_INVARIANT,
      summary: `documents=${documents.length} keys=${counts.keys} entries=${entries.length} problems=${problems.length}`,
      problems,
    };
  }

  const sidecar = {
    schemaVersion: SIDECAR_SCHEMA_VERSION,
    generator: { name: GENERATOR_NAME, version: GENERATOR_VERSION },
    instrument: {
      use: 'guard-only: a frontier may refuse a cell, and may never fill one or choose one',
      resultVocabulary: [...EXPOSURE_RESULTS],
      failureDirection: FAILURE_DIRECTION,
    },
    configKeys: [...CONFIG_KEYS],
    counts,
    entries,
    anomalies,
  };

  const offenders = absolutePathsIn(sidecar, '', []);
  if (offenders.length > 0) {
    return {
      sidecar: null,
      exitCode: EXIT_INVARIANT,
      summary: `absolutePaths=${offenders.length}`,
      problems: [
        `the sidecar would carry ${offenders.length} absolute path(s), which interfaces.md `
        + `section 5 forbids in a record: ${offenders.slice(0, 5).join('; ')}`,
      ],
    };
  }

  return {
    sidecar,
    exitCode: EXIT_OK,
    summary:
      `documents=${counts.documents} keys=${counts.keys} usable=${counts.usableKeys} `
      + `unusable=${counts.unusableKeys} collisions=${counts.collisions} anomalies=${anomalies.length}`,
    problems,
  };
}

// ── CLI ─────────────────────────────────────────────────────────────────────

export function parseArgs(argv) {
  const out = { out: null, files: [], dirs: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--out') out.out = argv[++i];
    else if (a === '--dir') out.dirs.push(argv[++i]);
    else if (a.startsWith('-')) throw new Error(`unknown argument ${a}`);
    else out.files.push(a);
  }
  if (!out.out) throw new Error('--out <path> is required');
  if (out.files.length === 0 && out.dirs.length === 0) {
    throw new Error('at least one frontier document, or a --dir holding some, is required');
  }
  return out;
}

/** Read every named document, refusing the whole run if one cannot be read. */
export function loadDocuments({ files, dirs }) {
  const paths = [...files];
  for (const d of dirs) {
    for (const name of readdirSync(d).filter((n) => n.endsWith('.json')).sort()) {
      paths.push(join(d, name));
    }
  }

  const documents = [];
  const seen = new Set();
  for (const p of paths) {
    // The file's basename, never its path: interfaces.md section 5 keeps
    // absolute paths out of records, and the lab lives outside the repository.
    const id = basename(p).replace(/\.json$/, '');
    if (seen.has(id)) {
      const err = new Error(
        `two inputs are both named ${JSON.stringify(id)}. The sidecar names its sources by file `
        + 'name, so a duplicate would make an anomaly line ambiguous about which exposure it is '
        + 'talking about',
      );
      err.exitCode = EXIT_USAGE;
      throw err;
    }
    seen.add(id);
    let raw;
    try {
      raw = readFileSync(p, 'utf8');
    } catch (cause) {
      throw new FrontierError(`could not read ${basename(p)}: ${cause.message}`);
    }
    try {
      documents.push({ id, doc: JSON.parse(raw) });
    } catch (cause) {
      throw new FrontierError(`${basename(p)} is not JSON: ${cause.message}`);
    }
  }
  return documents;
}

export function main(argv, { stdout = process.stdout, stderr = process.stderr } = {}) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (err) {
    stderr.write(`${GENERATOR_NAME}: ${err.message}\n`);
    stderr.write(`usage: ${GENERATOR_NAME}.mjs --out <path> <frontier.json> [...] [--dir <dir>]\n`);
    return EXIT_USAGE;
  }

  let documents;
  try {
    documents = loadDocuments(args);
  } catch (err) {
    stderr.write(`${GENERATOR_NAME}: ${err.message}\n`);
    return err.exitCode ?? EXIT_INCOMPLETE;
  }

  const { sidecar, exitCode, summary, problems } = deriveSidecar(documents);
  for (const p of problems) stderr.write(`${GENERATOR_NAME}: ${p}\n`);

  if (exitCode !== EXIT_OK) {
    stderr.write(`${GENERATOR_NAME}: no sidecar written (exit ${exitCode})\n`);
    stderr.write(`${summary}\n`);
    return exitCode;
  }

  const outPath = resolve(args.out);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify(sidecar, null, 2)}\n`, 'utf8');
  stdout.write(`${String(args.out).split('\\').join('/')}\n`);
  // Always the last thing on stderr: a run that finished quietly would let a
  // sidecar in which nothing is usable read like a sidecar in which everything is.
  stderr.write(`${summary}\n`);
  return EXIT_OK;
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) process.exit(main(process.argv.slice(2)));
