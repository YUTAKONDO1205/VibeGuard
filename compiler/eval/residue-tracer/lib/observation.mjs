/**
 * The consumer for compiler/schema/emit-observation.mjs.
 *
 * WHY THIS FILE EXISTS
 *
 * emit-observation.mjs is the reference writer for observation.schema.json and
 * until this file existed nothing outside compiler/schema/ imported it: its only
 * callers were its own test and a glob in scripts/check-doc-drift.mjs. Its own
 * header says a fake consumer would be worse than the hole, so this is not a
 * stub in some other package -- it is the lane that actually observes a running
 * process, writing what it observed through the reference writer.
 *
 * compiler/schema/properties.json says of checkpointOwners.process:
 *
 *   "NOTHING IN THIS REPOSITORY HAS EVER EMITTED AN OBSERVATION AT THIS
 *    CHECKPOINT ... compiler/eval/residue-tracer writes plain rows like every
 *    other compiler/eval lane, and no observation record here carries checkpoint
 *    process."
 *
 * That is the sentence this file is for. It does not replace the rows: the rows
 * are still what `--write-data` writes and what README.md is held to. A record is
 * emitted only when `--emit-observation` is passed, and only into the lab
 * directory outside the repository.
 *
 * WHAT IS PURE AND WHAT IS NOT
 *
 * `draftForCell` reads no clock, no environment and no file, for the same reason
 * buildObservation does: the caller decides what time it is. `emitForRows` takes
 * a schema object rather than loading one. The runner is the only place here that
 * touches the disk.
 *
 * THE THREE THINGS THE SCHEMA CANNOT HOLD, AND WHAT HAPPENS INSTEAD
 *
 * Each of these is a REFUSAL with a code, never a record with a field bent to
 * fit. They are counted and printed, and the request for the missing vocabulary
 * belongs in compiler/schema/properties.json -> interfaceExtensionsRequested,
 * which this lane does not edit while implementing against it.
 *
 *   toolchain-vendor-not-expressible
 *       observation.schema.json's `toolchain` requires the key `clang` and sets
 *       additionalProperties:false, and buildToolchainBlock in
 *       emit-observation.mjs mirrors that. Measured: a draft carrying
 *       `toolchain.gcc` is refused ("toolchain.clang must be a string, got
 *       undefined"), and a draft carrying `toolchain.vendor` or `toolchain.cc`
 *       BESIDE `clang` is accepted while the extra keys are silently dropped --
 *       buildToolchainBlock returns a three-key literal and never fails on a key
 *       it does not know. So the only way to emit a gcc-side record is to file a
 *       gcc version string under a field named `clang`. This lane runs on both
 *       vendors and refuses rather than do that. See README, "The vendor half of
 *       the toolchain block".
 *
 *   residue-present-has-no-finding-location
 *       A cell whose secret was still readable is a measured failure. Saying so
 *       in a record needs a findings[] entry, and findings[].where.kind is the
 *       six words interfaces.md section 2 fixes -- invocation, source, ir,
 *       object, link, artifact -- none of which names a running process. That gap
 *       is already OPEN in properties.json ->
 *       interfaceExtensionsRequested.checkpoints["where.kind"]. Filing it under
 *       `artifact` would be the one-thing-said-another-meant that entry exists to
 *       refuse, so the cell is refused instead. THIS BIASES WHICH CELLS BECOME
 *       RECORDS -- the interesting ones do not -- which is why the refusal is
 *       counted and printed rather than logged and forgotten.
 *
 *   control-effect-not-a-call-site
 *       effectCount.oracle is a `const` of "call-site" in the schema, on purpose.
 *       The find step's control survives either as a call or, at higher levels,
 *       as an inline `rep stos` (CONTROL_EFFECT.allowInlineZeroStore). A cell
 *       whose control was found by the rep-stos fallback has a control that is
 *       present and has zero call sites, and callSites:0 is how the emitter
 *       spells "the control died". Recording 1 there would be counting an inline
 *       store as a call. Eight of the eighty-two tracked rows are this case.
 *
 * WHY NO RECORD FROM THIS LANE IS EVER VERIFIED_CLEAN
 *
 * verdict.unobserved is documented in the schema as "Everything this run could
 * not observe, by name. A non-empty list here forbids VERIFIED_CLEAN." This lane
 * names seven such things in every row -- the heap, other threads, both sides of
 * the window, kernel-saved state, and the ymm/zmm upper halves -- plus the
 * strings half of the catalogue property it only half answers. They go in the
 * list, so the honest verdict is VERIFICATION_INCOMPLETE and the record says so.
 * That is the README's "a NONE reading is residency, not secrecy", enforced by
 * the emitter rather than repeated in prose.
 *
 * THE WORD APPEARS TWICE AND ONLY ONE OF THEM IS OURS. The emitter derives
 * properties[0].verdict VERIFIED_CLEAN for a cell whose history ends ABSENT,
 * because that derivation looks at the property's own evidence and not at
 * verdict.unobserved. A reader of properties[0].verdict alone sees a clean
 * property under an incomplete record. Asked which of the two is wrong, the
 * schema answers: verdict.unobserved exists at the record level and nowhere else
 * (propertyObservation has no such field), buildProperties ends `q.verdict =
 * verdict` and overwrites whatever a draft supplies, and the record verdict is
 * then gated ON the property verdicts -- a property that is not clean is itself
 * a cleanBlocker. Property-clean is necessary and not sufficient for
 * record-clean, by design. So the emitted verdicts stand and the TEST changed:
 * it now asserts both levels rather than the record level under a name that
 * claimed both. The property's `note` says which half of the oracle was
 * answered, and the test holds it to that too.
 *
 * TWO MORE THINGS THIS FILE WILL NOT DO
 *
 *   It does not compute toolchain.digest. There is one derivation of that number
 *   in this tree -- evidenceDigest(pinnedSet(pin, verifyPin(pin))), in
 *   compiler/driver/lib/run.mjs -- and emit-observation's own driver adapter
 *   refuses to invent one ("this adapter will not invent a digest for it"). A
 *   digest built here out of a version string was well formed, matched nothing,
 *   and could not be recomputed by a reader holding the compiler. The provenance
 *   is now a run fact (toolchainDigestSource) and a draft without it is refused.
 *   See lib/toolchain-digest.mjs.
 *
 *   It does not file an apparatus failure as a refusal. The three codes above
 *   are named, deliberate and expected; an emitter that rejects a draft this
 *   lane built is the lane not working. emitForRows returns the two separately
 *   and observationOutcome gives them different exits.
 */
import { UNOBSERVED, vendorOf } from './manifest.mjs';
import { CONTROLS, gradeControl } from './grade.mjs';
import { emitObservation } from '../../../schema/emit-observation.mjs';
import { DIGEST_SOURCE, DIGEST_DERIVATION } from './toolchain-digest.mjs';

/** The catalogue entry this lane answers half of. compiler/schema/properties.json. */
export const PROPERTY_ID = 'unobservable.secret-buffer-residue';
export const PROPERTY_KIND = 'must-remain-unobservable';

/** The function whose frame holds the secret; the observer stops at its return. */
export const SUBJECT_FN = 'handle_request';

/** The find step's own positive control, appended to the very listing that ran. */
export const COMPILE_CONTROL_UNIT = 'vgctl_control';

/** The point ids a record from this lane declares. Lowercase, for the schema's POINT_ID pattern. */
export const POINT_IDS = Object.freeze({
  subject: 'subject',
  'control-retain': 'control.retain',
  'control-nosecret': 'control.nosecret',
  'control-o0-wiped': 'control.o0-wiped',
});

/**
 * The half of the catalogue oracle this lane does not touch, named so that it
 * lands in verdict.unobserved rather than being inferred from silence. The
 * catalogue's oracle for this property is "strings, then residency"; the strings
 * half is an artefact byte scan and no fixture here carries one.
 */
export const STRINGS_HALF_UNOBSERVED =
  'the strings half of unobservable.secret-buffer-residue (an artefact byte scan for the secret) '
  + 'is not measured by this lane; only the residency half is';

const HEX64 = /^[0-9a-f]{64}$/;
const OPT_LEVELS = new Set(['-O0', '-O1', '-O2', '-O3', '-Os', '-Oz']);

const refuse = (code, message) => ({ ok: false, refusal: { code, message } });

/**
 * Would writing here put a record inside the repository?
 *
 * Records are lab output. One that landed in the tree would be a measurement
 * committed without review, and the whole point of the lab directory is that
 * nothing in it is tracked. Written as a predicate rather than inline in the
 * runner so that the refusal has a test; both arguments are absolute paths.
 */
export function wouldWriteInsideRepo(dir, repoRoot, pathApi) {
  const { relative, isAbsolute, sep } = pathApi;
  const rel = relative(repoRoot, dir);
  if (rel === '') return true;
  return !!rel && !isAbsolute(rel) && !rel.split(sep).includes('..');
}

/** A cell id, flattened to something a file name can carry. */
export function recordSlug(cellId) {
  return String(cellId).replace(/[^A-Za-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

/**
 * The property state a residency reading means.
 *
 * NONE is ABSENT and nothing stronger: the property's own note and the record's
 * verdict.unobserved carry what ABSENT does not cover. A cell that did not
 * measure is NOT_OBSERVED and never ABSENT -- that collapse is the one this whole
 * directory exists to refuse.
 */
export function propertyStateFor(row) {
  if (!row || row.measurement !== 'OK') return 'NOT_OBSERVED';
  const s = row.residue && row.residue.stack;
  if (s === 'NONE') return 'ABSENT';
  if (s === 'PARTIAL' || s === 'FULL') return 'PRESENT';
  return 'NOT_OBSERVED';
}

/**
 * The optimisation level a control has to have been taken at to qualify a cell
 * at `opt`. A control that pins a level is a control at THAT level only --
 * control-o0-wiped is the -O0 memset that no optimiser removes -- and every
 * other control qualifies a cell at the level the cell was compiled at.
 */
export function controlLevelFor(name, opt) {
  const spec = CONTROLS[name];
  if (!spec) return null;
  return spec.opt ? spec.opt : opt;
}

/**
 * The run-level control cell that qualifies a subject cell, or nothing.
 *
 * Same vendor AND the level from controlLevelFor. There is no fallback to
 * "whatever control of that name was run": this function used to end
 *
 *     return list.find((r) => r.opt === wanted) ?? list[0] ?? null;
 *
 * and the `?? list[0]` handed back a control measured at a DIFFERENT level, so a
 * -O2 cell was qualified by a -O0 instrument check and pointsFor reported the
 * point reached. An instrument check taken at another level says nothing about
 * this one: -O0 is the level at which nothing is optimised away, which is why
 * control-o0-wiped is pinned there in the first place, and a control-retain read
 * at -O0 does not establish that the window and the reader work on the -O2
 * layout. Deleting the fallback was the fix; the caller reports the point
 * unreached, naming the level it wanted, which is a measured gap rather than a
 * borrowed pass.
 */
export function findControlRow(rows, name, cc, opt) {
  const wanted = controlLevelFor(name, opt);
  if (wanted === null) return null;
  return (Array.isArray(rows) ? rows : []).find(
    (r) => r && r.kind === 'control' && r.control === name && r.cc === cc && r.opt === wanted,
  ) ?? null;
}

/**
 * Every observation point a record for this cell declares: the cell itself, and
 * the three run-level controls that qualify the instrument for it.
 *
 * A control that was never run, that did not measure, or that read something
 * other than what it exists to read is `reached: false` with the reason in the
 * grader's own words. gradeControl already treats "did not run" and "read the
 * wrong thing" as one failure -- either way the run is unqualified -- and this
 * follows it rather than inventing a third answer.
 */
export function pointsFor(row, rows) {
  const points = [{
    id: POINT_IDS.subject,
    checkpoint: 'process',
    stage: 'run',
    reached: row.measurement === 'OK',
    unreachedReason: row.measurement === 'OK' ? null
      : `residue-tracer graded this cell ${row.measurement}: ${row.reason ?? 'unstated'}`,
    optLevel: OPT_LEVELS.has(row.opt) ? row.opt : null,
    tool: row.cc,
  }];
  for (const name of Object.keys(CONTROLS)) {
    const wanted = controlLevelFor(name, row.opt);
    const c = findControlRow(rows, name, row.cc, row.opt);
    const g = c ? gradeControl(name, c) : null;
    // Three different answers, and the third is the one the missing fallback
    // used to hide: the control was run on this vendor, but not at the level
    // this cell needs it at, so it qualifies some other cell and not this one.
    const elsewhere = c ? [] : (Array.isArray(rows) ? rows : []).filter(
      (r) => r && r.kind === 'control' && r.control === name && r.cc === row.cc,
    );
    points.push({
      id: POINT_IDS[name],
      checkpoint: 'process',
      stage: 'run',
      reached: !!(g && g.held),
      unreachedReason: g && g.held ? null
        : (c ? `run-level control ${name} did not hold: ${g.why}`
          : (elsewhere.length
            ? `run-level control ${name} was not run on ${row.cc} at ${wanted}, only at `
              + `${[...new Set(elsewhere.map((r) => r.opt))].join(', ')}; a control taken at another optimisation `
              + 'level does not qualify the instrument for this cell'
            : `run-level control ${name} was not run on ${row.cc} at ${wanted}, so nothing qualified the `
              + 'instrument for this cell')),
      optLevel: c && OPT_LEVELS.has(c.opt) ? c.opt : (OPT_LEVELS.has(wanted) ? wanted : null),
      tool: row.cc,
    });
  }
  return points;
}

/**
 * Everything this record could not observe, by name.
 *
 * Three sources, concatenated rather than one replacing another: the lane's own
 * seven, the half of the catalogue oracle this lane does not answer, and every
 * point that was not reached. The last matters because buildObservation lets a
 * supplied verdict.unobserved REPLACE the list it would have derived -- supply a
 * short list and the record stops naming the point that was missed, while the
 * verdict still accounts for it. So the derived lines are put back by hand.
 */
export function unobservedFor(row, points) {
  const out = [];
  for (const p of points) if (!p.reached) out.push(`observation point ${p.id} was not reached`);
  out.push(STRINGS_HALF_UNOBSERVED);
  const lane = Array.isArray(row.unobserved) && row.unobserved.length ? row.unobserved : [...UNOBSERVED];
  for (const u of lane) out.push(u);
  return out;
}

/**
 * One subject cell, as a draft for emit-observation.mjs -- or a refusal.
 *
 * @param {object} row     a subject row from this lane
 * @param {object[]} rows  every row of the run, for the run-level controls
 * @param {object} run     {generatedAt, timeSource, sourceDateEpoch?, toolchainDigest,
 *                          ccVersion, observerSha256?}
 */
export function draftForCell(row, rows, run) {
  if (!row || typeof row !== 'object') return refuse('not-a-row', 'a row must be an object');
  if (row.kind !== 'subject') {
    return refuse('cell-not-a-subject',
      `${row.cell} is a ${row.kind} cell. A run-level control is a point inside a record about a subject cell, `
      + 'not a record of its own: it qualifies the instrument and carries no property.');
  }
  if (vendorOf(row.cc) !== 'clang') {
    return refuse('toolchain-vendor-not-expressible',
      `${row.cell} was compiled with ${row.cc}. The toolchain block of observation.schema.json requires the key `
      + 'clang and sets additionalProperties:false, and buildToolchainBlock in compiler/schema/emit-observation.mjs '
      + 'mirrors it: a draft with toolchain.gcc is refused, and a vendor or cc key beside clang is silently dropped. '
      + 'Emitting this cell would mean writing a gcc version string into a field named clang. The vocabulary need is '
      + 'reported, not worked around.');
  }
  if (row.confirmControlVia === 'rep-stos-fallback') {
    return refuse('control-effect-not-a-call-site',
      `${row.cell}: the find step control ${COMPILE_CONTROL_UNIT} survived as an inline zero store, not as a call. `
      + 'effectCount.oracle is a const of "call-site" in observation.schema.json, and callSites:0 is how the emitter '
      + 'spells a control that died, so there is no honest pair of numbers for this cell.');
  }
  if (!Number.isInteger(row.nSpans)) {
    return refuse('no-span-count',
      `${row.cell} carries no nSpans, so the history entry has no call-site count to record.`);
  }

  const state = propertyStateFor(row);
  if (state === 'PRESENT') {
    return refuse('residue-present-has-no-finding-location',
      `${row.cell} left the secret readable (residue ${row.residue.stack}, longest run `
      + `${row.longestRunBytes}/${row.needleLen} bytes). A record may not carry a measured failure with nothing `
      + 'naming it, and a findings[] entry needs a where.kind, whose six words (invocation, source, ir, object, link, '
      + 'artifact) have no word for a running process -- the request recorded in compiler/schema/properties.json -> '
      + 'interfaceExtensionsRequested.checkpoints["where.kind"], not granted. Refused rather than filed under '
      + 'artifact.');
  }

  const bad = checkRun(run);
  if (bad) return refuse(bad.code, bad.message);

  const points = pointsFor(row, rows);
  const reached = points.filter((p) => p.reached).length;
  const controlPresent = row.confirmControl === 'PRESENT';

  const packages = [{ name: row.cc, version: run.ccVersion }];
  if (run.observerSha256) {
    packages.push({ name: 'residue-observer', version: 'built-by-gcc-13', sha256: run.observerSha256 });
  }

  const draft = {
    context: {
      generatedAt: run.generatedAt,
      timeSource: run.timeSource,
      ...(run.sourceDateEpoch === undefined ? {} : { sourceDateEpoch: run.sourceDateEpoch }),
    },
    toolchain: { digest: run.toolchainDigest, clang: run.ccVersion, packages },
    counts: {
      inputs: points.length,
      checked: reached,
      skipped: points.length - reached,
      skippedNames: points.filter((p) => !p.reached).map((p) => p.id),
    },
    observationPoints: points,
    properties: [{
      id: PROPERTY_ID,
      kind: PROPERTY_KIND,
      scope: { functions: [SUBJECT_FN], files: [`fixtures/target-${row.subject}.c`] },
      // The find step's own control, on the very listing that was assembled and
      // run, counted by the call-site oracle it is counted by there. It is a
      // control on the COMPILE; the control on the READING is the co-resident
      // needle, and that one is folded into the subject point's `reached`
      // because gradeCell already refuses to produce a reading without it.
      control: {
        unit: COMPILE_CONTROL_UNIT,
        state: controlPresent ? 'PRESENT' : 'ABSENT',
        count: { callSites: controlPresent ? 1 : 0, oracle: 'call-site', naiveSymbolMatches: null },
      },
      history: [{
        point: POINT_IDS.subject,
        phase: 'after',
        state,
        // No pass ran here. The artefact is finished and is being executed, and
        // the unit is the function whose frame held the secret -- null for the
        // pass is "not applicable", which is what the attribution block's own
        // description reserves null for.
        attribution: { pass: null, unit: SUBJECT_FN, unitKind: 'function', lineage: SUBJECT_FN, seq: null },
        count: { callSites: row.nSpans, oracle: 'call-site', naiveSymbolMatches: null },
      }],
      historyComplete: true,
      fate: 'LIVE',
      note: noteFor(row),
    }],
    layers: layersFor(row),
    findings: [],
    // The reason is supplied rather than left to defaultReason, because
    // defaultReason builds the VERIFICATION_INCOMPLETE sentence out of
    // `unobservedBlockers` alone and never looks at a SUPPLIED
    // verdict.unobserved. A record of this lane's normal shape -- every point
    // reached, incomplete only because seven things were never in the window --
    // came out reading "the run did not finish looking: a checkpoint was not
    // reached", which names a failure that did not happen. The sentence below
    // states facts rather than a verdict, so it stays true whichever state the
    // emitter derives. The defect is reported; emit-observation is not edited
    // from here.
    verdict: {
      unobserved: unobservedFor(row, points),
      reason: `residue-tracer read a running process at the return of ${SUBJECT_FN}: ${reached} of ${points.length} `
        + `observation points were reached, the property ended ${state}, and `
        + `${unobservedFor(row, points).length} thing(s) this run could not observe are named in verdict.unobserved`,
    },
  };
  return { ok: true, draft };
}

function noteFor(row) {
  const above = (row.window && Number.isInteger(row.window.hi) && row.stop && Number.isInteger(row.stop.rsp))
    ? row.window.hi - row.stop.rsp : null;
  return `${DIGEST_DERIVATION}. `
    + 'Residency at one instant, not secrecy. The observer stopped the process at the return of '
    + `${SUBJECT_FN}, read the stack window reaching ${row.window?.belowReached ?? 'an unrecorded number of'} bytes `
    + `below the stop rsp and ${above ?? 'an unrecorded number of'} above it, the general-purpose registers and `
    + `xmm0-15, and graded the longest contiguous run of a per-run random ${row.needleLen}-byte tracer: `
    + `${row.longestRunBytes} bytes for the secret and ${row.controlRunBytes} for the co-resident control held `
    + `unwiped in the same frame. residue stack=${row.residue.stack} gpr=${row.residue.gpr} xmm=${row.residue.xmm}. `
    + `The find step own code judged the same listing ${row.confirmVerdict}. history[0].count counts the wipe call `
    + 'sites the find step located in the source, because effectCount.oracle is a const of "call-site" and a byte-run '
    + 'reading has no word there; the byte counts above are the reading. This record answers the residency half of '
    + 'the catalogue oracle "strings, then residency" and no part of the strings half, which is named in '
    + 'verdict.unobserved.';
}

/**
 * The three layers, each answered from what THIS ROW carries.
 *
 * It used to return `observed: true` three times for every cell, which is true
 * of the 82 tracked rows -- all of them measurement OK -- and not true of the
 * lane. A cell can stop at any of the three stages, and the row says where,
 * because each stage leaves a digest behind:
 *
 * compile: the find step compiled the target to assembly, found the wipe spans,
 *   ablated them, compiled again and judged the two bodies -- and THAT listing is
 *   the one that was assembled, so `asmSha256` and `objSha256` are both there. A
 *   cell that did not compile (`compile-failed`) or did not assemble carries
 *   neither, and the layer is unobserved with the row's own reason.
 * link: the lane linked it -no-pie; `exe.sha256Before` is the executable that was
 *   about to run. A `link-failed` cell has none.
 * artifact: the same binary was disassembled with objdump for the subject frame
 *   (`frame.parsed`) and hashed again after execution (`exe.sha256After`). A cell
 *   whose objdump failed has `frame.parsed: false` and did not observe this
 *   layer, which is also why such a cell is BROKEN_MEASUREMENT. No artefact
 *   REQUIREMENT was checked, so `checks` is an empty array rather than absent.
 *
 * The schema's own rule is the one being obeyed here: "layers.<name>.observed
 * must be a boolean; a layer that was never looked at must not read as a layer
 * that was clean", and `observed: false` requires an unobservedReason.
 */
function layersFor(row) {
  const why = row && typeof row.reason === 'string' && row.reason.trim() ? row.reason.trim() : 'unstated';
  const compiled = typeof row.asmSha256 === 'string' && typeof row.objSha256 === 'string';
  const linked = !!(row.exe && typeof row.exe.sha256Before === 'string');
  const artifactRead = !!(row.frame && row.frame.parsed === true
    && row.exe && typeof row.exe.sha256After === 'string');

  const compile = compiled
    ? { observed: true, unobservedReason: null, optLevel: OPT_LEVELS.has(row.opt) ? row.opt : null }
    : {
      observed: false,
      unobservedReason: 'this cell carries no assembly or object digest, so no listing of it was compiled and '
        + `assembled here (the row is ${row.measurement}: ${why})`,
      optLevel: OPT_LEVELS.has(row.opt) ? row.opt : null,
    };

  const link = {
    observed: linked,
    unobservedReason: linked ? null
      : 'this cell carries no linked executable digest, so nothing was linked to run '
        + `(the row is ${row.measurement}: ${why})`,
    ...(linked ? { linker: `${row.cc} driver` } : {}),
    ltoMode: 'none',
    // There was no LTO backend, so there was no backend pipeline to watch.
    // `false` with ltoMode none is not a blocker and is not the same claim as
    // `true`, which would say a backend was observed.
    backendObserved: false,
    backendUnobservedReason: 'ltoMode is none: no LTO backend ran, so there was no backend pipeline to observe',
    inputs: [],
  };

  const artifact = artifactRead
    ? { observed: true, unobservedReason: null, format: 'elf', checks: [] }
    : {
      observed: false,
      unobservedReason: 'the artefact was not read for this cell: frame.parsed is '
        + `${JSON.stringify(row.frame ? row.frame.parsed : null)}`
        + `${row.frame && typeof row.frame.why === 'string' && row.frame.why ? ` (${row.frame.why})` : ''}`
        + ` and exe.sha256After is ${row.exe && typeof row.exe.sha256After === 'string' ? 'present' : 'absent'}`,
      checks: [],
    };

  return { compile, link, artifact };
}

/**
 * The run facts, and where the digest in them came from.
 *
 * Returns {code, message} so that the two failures stay apart. Missing run facts
 * are `run-facts-missing`. A digest that is well formed but was not derived the
 * way this tree derives one is `toolchain-digest-not-derivable`, which is its own
 * code because it is its own mistake: this lane used to compute
 * sha256(JSON.stringify({cc, version, observer})) and write the result into a
 * field the rest of the tree fills from evidenceDigest(pinnedSet(...)). The
 * number was well formed, matched nothing, and could not be recomputed by a
 * reader holding the toolchain. See lib/toolchain-digest.mjs.
 */
function checkRun(run) {
  const missing = (message) => ({ code: 'run-facts-missing', message });
  if (!run || typeof run !== 'object') return missing('run facts must be an object');
  if (typeof run.generatedAt !== 'string' || !run.generatedAt.trim()) return missing('run.generatedAt must be a non-empty string');
  if (run.timeSource !== 'SOURCE_DATE_EPOCH' && run.timeSource !== 'wall-clock') {
    return missing('run.timeSource must be SOURCE_DATE_EPOCH or wall-clock');
  }
  if (typeof run.toolchainDigest !== 'string' || !HEX64.test(run.toolchainDigest)) {
    return missing('run.toolchainDigest must be 64 lowercase hex characters');
  }
  if (run.toolchainDigestSource !== DIGEST_SOURCE) {
    return {
      code: 'toolchain-digest-not-derivable',
      message: `run.toolchainDigestSource is ${JSON.stringify(run.toolchainDigestSource ?? null)}, and the only `
        + `digest a record from this lane may carry is ${JSON.stringify(DIGEST_SOURCE)}: ${DIGEST_DERIVATION}. `
        + 'A digest computed here out of a version string would match no other value in this tree and could not be '
        + 'recomputed from the toolchain, and emit-observation own driver adapter refuses to invent one for the '
        + 'same reason. Run with --toolchain-pin.',
    };
  }
  if (typeof run.ccVersion !== 'string' || !run.ccVersion.trim()) return missing('run.ccVersion must be a non-empty string');
  if (run.observerSha256 !== undefined && run.observerSha256 !== null && !HEX64.test(String(run.observerSha256))) {
    return missing('run.observerSha256, when given, must be 64 lowercase hex characters');
  }
  return null;
}

/**
 * THE THREE CODES A CELL MAY BE REFUSED WITH, AND NOTHING ELSE.
 *
 * Each is a hole in the schema's vocabulary, named in this file's header, decided
 * before the run and expected during it. A run in which every gcc cell is refused
 * `toolchain-vendor-not-expressible` is a run that went exactly as designed.
 *
 * Anything else that stops a cell becoming a record is an APPARATUS FAILURE: the
 * emitter rejected a draft this lane built, the run facts could not identify the
 * toolchain, a row carries no span count because it never compiled. Those are not
 * outcomes of the experiment, they are the experiment not working, and until this
 * wave they went into the same `refusals` array and the same exit code -- so a
 * run whose emitter rejected fifty-nine of sixty drafts printed "refused 59
 * cell(s)" and exited 0.
 */
export const EXPECTED_REFUSAL_CODES = Object.freeze([
  'toolchain-vendor-not-expressible',
  'residue-present-has-no-finding-location',
  'control-effect-not-a-call-site',
]);

/** Is this a cell the schema has no honest shape for, or is it the apparatus? */
export function isExpectedRefusal(code) {
  return EXPECTED_REFUSAL_CODES.includes(code);
}

/**
 * Every subject row, through the reference writer.
 *
 * Returns three lists, not two. Nothing is written here; the runner decides where
 * records go and refuses to put them inside the repository.
 *
 *   records   a cell that became a record
 *   refusals  a cell the schema has no honest shape for -- one of the three codes
 *             above, deliberate, named and expected
 *   failures  everything else: the apparatus did not work on this cell
 */
export function emitForRows(schema, rows, run) {
  const records = [];
  const refusals = [];
  const failures = [];
  const file = (cell, code, message) => {
    (isExpectedRefusal(code) ? refusals : failures).push({ cell, code, message });
  };
  for (const row of (Array.isArray(rows) ? rows : [])) {
    if (!row || row.kind !== 'subject') continue;
    const d = draftForCell(row, rows, run);
    if (!d.ok) { file(row.cell, d.refusal.code, d.refusal.message); continue; }
    const e = emitObservation(schema, d.draft);
    if (!e.ok) {
      file(row.cell, `emitter-${e.stage}`, e.errors.join(' | '));
      continue;
    }
    records.push({ cell: row.cell, slug: recordSlug(row.cell), record: e.record, text: e.text });
  }
  return { records, refusals, failures };
}

/**
 * What the run does about it. Pure, so the exit code is a unit rather than a
 * thing that only happens on a box with two compilers on it.
 *
 * A deliberate refusal and an apparatus failure do not share an exit:
 *
 *   - one or more failures     -> exit 5, whatever else succeeded. "Some cells
 *                                 emitted" is not a reason to call a broken
 *                                 emitter a pass; the cells that failed are the
 *                                 ones nobody would ever look at again.
 *   - no failures, no records  -> exit 5. A consumer that emitted nothing has
 *                                 not consumed anything.
 *   - no failures, some records-> exit 0, with the refusals printed and written.
 */
export function observationOutcome({ records = [], refusals = [], failures = [] } = {}) {
  if (failures.length) {
    return {
      ok: false,
      exitCode: 5,
      why: `${failures.length} cell(s) could not be expressed at all, which is this lane failing rather than the `
        + `schema refusing: ${failures.slice(0, 4).map((f) => `${f.cell}: ${f.code}`).join('; ')}`
        + `${failures.length > 4 ? ` (+${failures.length - 4} more)` : ''}. `
        + `${records.length} record(s) were written anyway, and observations/failures.json carries every reason; a `
        + 'failure here is not one of the three named refusals and must not be read as one.',
    };
  }
  if (records.length === 0) {
    return {
      ok: false,
      exitCode: 5,
      why: 'no observation record was produced. A consumer that emitted nothing has not consumed anything: every '
        + `subject cell was refused (${refusals.map((r) => r.code).join(', ') || 'no cells at all'}).`,
    };
  }
  return { ok: true, exitCode: 0, why: null };
}

/**
 * THE GATE, MEASURED IN BOTH DIRECTIONS.
 *
 * emit-observation refuses VERIFIED_CLEAN when anything at all was unobserved. A
 * consumer that can only ever succeed has not tested that, and neither has one
 * that can only ever fail -- so this asks the emitter the same question twice,
 * once with every run-level control present and once with one deliberately
 * removed, and reports both answers.
 *
 *   positive  every control cell present, verdict.unobserved emptied, claim
 *             VERIFIED_CLEAN  ->  a record IS produced. Without this the negative
 *             below would also pass against an emitter that refuses everything.
 *   negative  the SAME draft with one run-level control cell deleted from the
 *             rows  ->  its point is reached:false, the claim is refused, and NO
 *             record comes back.
 *
 * Neither draft is ever written to disk: the positive one has its
 * verdict.unobserved emptied to isolate the control cell as the only variable,
 * and a record with an empty unobserved list would overstate what this lane saw.
 * The production path in emitForRows never empties it and never claims clean.
 *
 * @param {string} [omit] which run-level control to delete; default the one that
 *                        catches a stop point placed before the wipe.
 */
export function gateSelfCheck(schema, rows, run, omit = 'control-o0-wiped') {
  if (!CONTROLS[omit]) {
    return { ok: false, why: `${omit} is not one of the run-level controls: ${Object.keys(CONTROLS).join(', ')}` };
  }
  const candidate = (Array.isArray(rows) ? rows : []).find((r) => {
    if (!r || r.kind !== 'subject') return false;
    if (!draftForCell(r, rows, run).ok) return false;
    return pointsFor(r, rows).every((p) => p.reached);
  });
  if (!candidate) {
    return {
      ok: false,
      why: 'no subject cell in these rows is emittable with every run-level control reached, so the gate cannot be '
        + 'shown to pass in the positive direction. A gate that was only ever shown refusing has not been measured.',
    };
  }

  const claimClean = (rs) => {
    const d = draftForCell(candidate, rs, run);
    if (!d.ok) return { emitted: false, errors: [`${d.refusal.code}: ${d.refusal.message}`] };
    // The only two edits, and they are the experiment: empty the list of things
    // this lane never observes (so the control cell is the sole variable), and
    // claim the verdict the gate exists to refuse.
    const draft = { ...d.draft, verdict: { state: 'VERIFIED_CLEAN', unobserved: [] } };
    const e = emitObservation(schema, draft);
    return e.ok ? { emitted: true, record: e.record } : { emitted: false, errors: e.errors };
  };

  const positive = claimClean(rows);
  const without = rows.filter((r) => !(r && r.kind === 'control' && r.control === omit && r.cc === candidate.cc));
  const negative = claimClean(without);

  const ok = positive.emitted === true && negative.emitted === false;
  return {
    ok,
    cell: candidate.cell,
    omitted: omit,
    positive,
    negative,
    why: ok ? null
      : (positive.emitted
        ? `the gate did not refuse VERIFIED_CLEAN with ${omit} absent; a control cell can go missing and a clean `
          + 'record still be written'
        : `the gate refused VERIFIED_CLEAN even with every control present (${(positive.errors || []).join(' | ')}); `
          + 'the negative result therefore proves nothing'),
  };
}
