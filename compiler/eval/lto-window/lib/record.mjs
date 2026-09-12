/**
 * What a run writes down about itself, and what it exits with.
 *
 * Four decisions live here: what a skipped check leaves behind in the record,
 * which guard figures a cell publishes, what the provenance scan refuses, and
 * what the whole run's exit code is. All four used to be inline in
 * `../run-lto-window.mjs`, where no test could reach them -- and all four were
 * wrong in the same direction, which is the direction that reads as "fine":
 *
 *   - `--skip-negative-control` and `--skip-gcc` left NO record at all. The
 *     README said the result records the skip; the field was simply left `{}`.
 *   - a run with the lane's only mechanical demonstration that guard 1 can fire
 *     turned off exited 0 with a clean all-OK table. `../../schema/interfaces.md`
 *     section 7 reserves 0 for "everything asked for was checked and nothing was
 *     found", and 3 for "a check could not be completed -- **never conflated
 *     with 0**".
 *   - `lineKinds` was computed by parseLldPassLog, carried as far as the cell,
 *     and dropped before the record was written, so per-kind linker line counts
 *     quoted in prose could not be reconciled against the artifact by anyone.
 *
 * Pure functions over plain objects. Nothing here runs or reads anything.
 */

import { MEASUREMENT, STATE } from './cell.mjs';

/* ------------------------------------------------------------- skipping -- */

/** The flags that turn a check off, spelled once. */
export const SKIP_FLAG = Object.freeze({
  negativeControl: '--skip-negative-control',
  gcc: '--skip-gcc',
  thinltoEvidence: '--skip-thinlto-evidence',
});

/**
 * What a check that did not run leaves in the record.
 *
 * The shape `--skip-thinlto-evidence` already used -- `attempted: false` plus a
 * note saying the word below is not earned here -- generalised to the other two,
 * because a skip that leaves no trace turns into a clean row when someone reads
 * the JSON later. `ran: false` is carried as well so that a consumer looking for
 * either spelling finds it.
 */
export function skippedRecord(what, why) {
  const flag = SKIP_FLAG[what];
  if (!flag) throw new Error(`no skip flag known for ${what}`);
  return { attempted: false, ran: false, skipped: true, flag, note: `not run in this run (${flag}): ${why}` };
}

export const SKIP_WHY = Object.freeze({
  negativeControl:
    'guard 1 was not shown to fire, so nothing in this run distinguishes a link-time reading from a compile-time one',
  gcc: 'gcc was not probed, so no UNSUPPORTED row is earned here',
  thinltoEvidence: 'the ThinLTO link that earns the BROKEN_MEASUREMENT word was not run; the word is not earned here',
});

/**
 * The lines the run prints about itself under the table.
 *
 * A skip is stated in the report's own summary, not only buried in the JSON:
 * the table a reader looks at is the table that has to say that the
 * demonstration behind it was turned off.
 */
export function skipSummaryLines(skipped = {}) {
  const lines = [];
  for (const [what, flag] of Object.entries(SKIP_FLAG)) {
    if (skipped[what]) lines.push(`${what}: SKIPPED (${flag}) -- ${SKIP_WHY[what]}`);
  }
  return lines;
}

/* --------------------------------------------------------------- guards -- */

/**
 * The guard figures a link cell publishes.
 *
 * `lldLineKinds` is here because a number that is measured, quoted and then not
 * recorded cannot be checked: the linker's per-kind line counts (`Running
 * pass:`, `Running analysis:`, `Invalidating analysis:`, ...) were computed on
 * every run and thrown away at exactly this point.
 */
export function linkGuardRecord({ inputs, linkerPipeline, agreement = null, byteIdentical = null, debugFlagChangedBytes = null } = {}) {
  return {
    inputsOk: inputs?.ok ?? null,
    inputProblems: inputs?.problems ?? [],
    lldRunningPassLines: linkerPipeline?.runs ?? null,
    lldLineKinds: linkerPipeline?.lineKinds ?? null,
    passAgreement: agreement,
    byteIdentical,
    debugFlagChangedBytes,
  };
}

/* -------------------------------------------------- the intervention pair -- */

/**
 * What a cell from the family WITHOUT the fixture intervention is a reading of.
 *
 * `tools/make-lto-fixtures.sh` emits `xtu` with `__attribute__((noinline))` on
 * the subject and the control, and `xtu-inline` with those two lines deleted and
 * nothing else changed. The second family is NOT the first one repaired and it
 * is NOT a second sample of the same measurement: it is the measurement of what
 * the intervention costs, and its expected outcome is a WORSE reading than the
 * intervened family's.
 *
 * Three things can come back from it, and they say three different things:
 *
 *   the unit was ABSORBED        the observer has no SUMMARY row for the
 *                                subject, the instrument was otherwise
 *                                established (log intact, evidence records, a
 *                                control that HELD), so the cell is `OK` with
 *                                `NOT_OBSERVED` -- interfaces.md 3.1's third
 *                                situation. This is the expected outcome and it
 *                                is the pair's point: WITHOUT the attribute
 *                                there is no (pass, unit) pair to attribute the
 *                                elimination TO.
 *
 *   the unit SURVIVED anyway     a row exists under the subject's own name, with
 *                                or without a loss. Then the attribute was not
 *                                what made the attribution possible here, and
 *                                the pair's claim about it is contradicted at
 *                                this optimisation level. A real result, and the
 *                                one a reader should be told about loudest.
 *
 *   the INSTRUMENT FAULTED       measurement is not OK -- a shredded log, guard
 *                                1 refusing the link, a control that fell, two
 *                                pass readings that disagree. This cell is not a
 *                                reading of the intervention AT ALL, and
 *                                reporting it as "see, without noinline the
 *                                attribution becomes impossible" would be taking
 *                                a broken instrument for evidence about the
 *                                program. `usable` is false; the run says so and
 *                                cannot exit 0 (a non-OK cell already forces 3).
 *
 * That third branch is the whole reason this function exists rather than a
 * reader eyeballing the table: `BROKEN_MEASUREMENT` and "the attribution became
 * impossible" LOOK the same in a results table, and only one of them is about
 * the fixture.
 */
export const INTERVENTION = Object.freeze({
  ABSORBED: 'unit-absorbed-no-attribution-possible',
  UNIT_SURVIVED: 'unit-survived-attribution-still-possible',
  INSTRUMENT_FAULT: 'instrument-fault-this-cell-is-not-a-reading-of-the-intervention',
});

export function interventionAbsentReading(cell = {}) {
  if (cell.measurement !== MEASUREMENT.OK) {
    return {
      reading: INTERVENTION.INSTRUMENT_FAULT,
      usable: false,
      why: `the cell is ${cell.measurement} (${(cell.reasons ?? []).join('; ') || 'no reason given'}): `
        + 'the instrument did not complete here, so this cell says nothing about whether the elimination '
        + 'needs the intervention. It is NOT the family\'s result.',
    };
  }
  if (cell.state === STATE.NOT_OBSERVED) {
    return {
      reading: INTERVENTION.ABSORBED,
      usable: true,
      why: 'the instrument was established and there is no reading of the subject at this point: without the '
        + 'intervention no unit under the subject\'s name survives for a (pass, unit) pair to name. The '
        + 'ATTRIBUTION is out of reach; whether the store is in the linked program is a question for the '
        + 'artifact reader, not for this cell.',
    };
  }
  return {
    reading: INTERVENTION.UNIT_SURVIVED,
    usable: true,
    why: `the subject still has a unit of its own (state ${cell.state}${cell.attribution ? `, attributed to ${cell.attribution.pass}` : ''}): `
      + 'at this optimisation level the intervention was not what made the attribution possible, which '
      + 'contradicts the pair\'s expectation and is a result in its own right.',
  };
}

/**
 * What the artifact says once BOTH wipes live in one function.
 *
 * When the subject and the control are absorbed into `main`, the disassembly
 * reader can no longer name which function a zero fill belongs to -- both
 * readings resolve to the same body, so the verdict WORD (`PRESENT`/`ABSENT`)
 * stops discriminating. The quantity that still does is how many bytes of zero
 * fill that one body contains: one wipe's worth, or two.
 *
 * This is a NECESSARY reading, not a sufficient one, and it is spelled that way
 * in every outcome below: byte counting cannot say WHICH buffer the surviving
 * fill covers. It can say that only one wipe's worth of fill is left where the
 * source asks for two, which is what the elimination claim needs and is all this
 * function claims.
 *
 * `bytes` and `memsetCalls` come from gcc-repair's objdump oracle by way of
 * tools/read-wipe.py; `bufferBytes` is the fixture's own buffer size, taken from
 * the generator rather than from the reading.
 */
export const ABSORBED_FILL = Object.freeze({
  ONE: 'one-wipe-of-fill-left-consistent-with-the-subject-store-being-gone',
  TWO: 'two-wipes-of-fill-left-the-subject-store-was-not-removed',
  NONE: 'no-fill-at-all-the-control-did-not-survive-either-so-this-reading-is-blind',
  MEMSET_CALL: 'a-memset-call-remains-byte-counting-cannot-separate-the-two-wipes',
  INCONCLUSIVE: 'fill-bytes-match-neither-one-wipe-nor-two',
});

export function absorbedFillReading({ bytes = null, memsetCalls = 0, bufferBytes = null } = {}) {
  if (typeof bytes !== 'number' || typeof bufferBytes !== 'number' || bufferBytes <= 0) {
    return { reading: ABSORBED_FILL.INCONCLUSIVE, discriminating: false, why: 'no byte count was read' };
  }
  // A call is opaque to byte counting: one `memset` call could be either wipe,
  // and two could be both. Checked BEFORE the byte comparison, because a call
  // plus one wipe's worth of inline fill would otherwise read as ONE.
  if (memsetCalls > 0) {
    return {
      reading: ABSORBED_FILL.MEMSET_CALL,
      discriminating: false,
      why: `${memsetCalls} memset call(s) remain: a call covers a length this reading cannot see, so the `
        + 'byte count cannot say whether one wipe or two are left',
    };
  }
  if (bytes === 0) {
    return {
      reading: ABSORBED_FILL.NONE,
      discriminating: false,
      why: 'no zero fill at all: the control did not survive either, so "the subject\'s store is gone" and '
        + '"this executable has no fill to read" are the same reading',
    };
  }
  if (bytes === bufferBytes) {
    return {
      reading: ABSORBED_FILL.ONE,
      discriminating: true,
      why: `${bytes}B of zero fill where the source asks for two ${bufferBytes}B wipes: one of them is gone. `
        + 'Byte counting cannot say WHICH, so this is consistent with the subject\'s store having been '
        + 'removed and is not on its own proof of it.',
    };
  }
  if (bytes >= 2 * bufferBytes) {
    return {
      reading: ABSORBED_FILL.TWO,
      discriminating: true,
      why: `${bytes}B of zero fill: both ${bufferBytes}B wipes are still in the program, so nothing was `
        + 'eliminated here',
    };
  }
  return {
    reading: ABSORBED_FILL.INCONCLUSIVE,
    discriminating: false,
    why: `${bytes}B of zero fill is neither one ${bufferBytes}B wipe nor two`,
  };
}

/**
 * What the PAIR establishes, from the two cells and the artifact reading.
 *
 * The claim under test is one sentence:
 *
 *     the elimination does not depend on the intervention; the intervention is
 *     required only to have a (pass, unit) to attribute the elimination TO.
 *
 * It has two halves and they are read from two different instruments. The
 * ATTRIBUTION half is read from the observer: present in the intervened family,
 * out of reach in the family without the intervention. The ELIMINATION half is
 * read from the linked bytes by the disassembly oracle, which does not care
 * whether a unit survived. A verdict that took both halves from the observer
 * would be circular -- the observer is the thing the intervention exists to
 * serve.
 *
 * `supported: null` is not a weak `false`. It is "this run did not put the
 * question", and the two ways to get there are the two ways this pair can be
 * mis-read: an instrument fault in the un-intervened family (which LOOKS like
 * the attribution becoming impossible) and an artifact reading that could not
 * separate the two wipes.
 */
export function interventionPairVerdict({ intervenedCell = null, plainReading = null, plainFill = null } = {}) {
  if (!intervenedCell || !plainReading) {
    return { supported: null, why: 'one half of the pair was not measured in this run' };
  }
  if (!plainReading.usable) {
    return {
      supported: null,
      why: 'not established: the cell from the family WITHOUT the intervention is an instrument fault, not a '
        + `reading of the intervention (${plainReading.why}). A BROKEN_MEASUREMENT here must not be reported `
        + 'as "the attribution became impossible": the two look identical in a results table and only one of '
        + 'them is about the fixture.',
    };
  }
  if (!intervenedCell.attribution) {
    return {
      supported: null,
      why: 'the intervened family produced no (pass, unit) attribution in this run, so there is nothing for '
        + 'the pair to be about',
    };
  }
  if (plainReading.reading === INTERVENTION.UNIT_SURVIVED) {
    return {
      supported: false,
      why: 'the subject kept a unit of its own without the intervention, so at this level the intervention '
        + 'was not what made the attribution possible. The claim\'s second half is contradicted here; its '
        + 'first half is untouched.',
    };
  }
  if (!plainFill || plainFill.discriminating !== true) {
    return {
      supported: null,
      why: `the attribution is out of reach without the intervention, as expected, but the artifact reading `
        + `does not settle whether the store is gone (${plainFill?.why ?? 'no artifact reading'}). Half a `
        + 'pair is not a pair: without the elimination half this says only that removing the attribute '
        + 'blinded the observer.',
    };
  }
  if (plainFill.reading === ABSORBED_FILL.ONE) {
    return {
      supported: true,
      why: 'the attribution is out of reach without the intervention (no unit to name) AND one wipe\'s worth '
        + 'of zero fill is missing from the linked program anyway. The elimination did not need the '
        + 'attribute; the attribution did.',
    };
  }
  return {
    supported: false,
    why: `without the intervention the artifact reads ${plainFill.reading}: the elimination this lane `
      + 'attributes in the intervened family did not happen here, so it is not independent of the '
      + 'intervention in the way the claim says.',
  };
}

/* ----------------------------------------------------------- provenance -- */

/**
 * No record leaves here carrying a machine path.
 *
 * The pattern used to be a seven-root whitelist -- `/(home|root|mnt|Users|tmp|
 * var|usr)/` -- which is a check for "a path under the roots this machine
 * happens to use", not for an absolute path. `/opt/vg-lab/...`,
 * `/srv/...`, `/data/<name>/...` and `/workspace/...` all went straight
 * through. What is actually refused now is any rooted, multi-segment path
 * token: a leading `/` followed by at least two path segments, or a Windows
 * drive letter. The preceding-character class keeps `5/10` and
 * `PassManager<...>` out of it, and this pattern was run over the lane's real
 * 10-cell result before being adopted: 0 hits, the same as the old one.
 */
export const ABSOLUTE_PATH_RE = /(^|["'\s:=(,[])(\/[\w.+@~-]+(?:\/[\w.+@~-]*)+|[A-Za-z]:[\\/])/;

export function scrubbed(json) {
  const hits = [];
  for (const line of String(json).split('\n')) {
    if (ABSOLUTE_PATH_RE.test(line)) hits.push(line.trim().slice(0, 160));
  }
  return hits;
}

/* ------------------------------------------------------------ exit code -- */

/**
 * The exit code for a whole run, from what the run actually established.
 *
 * `../../schema/interfaces.md` section 7 is the vocabulary: 0 "everything asked
 * for was checked and nothing was found", 1 the underlying tool failed, 2
 * findings at threshold, 3 "a check could not be completed -- never conflated
 * with 0", 4 a policy/integrity refusal (handled at the call sites, before
 * anything is measured).
 *
 * Two of these codes are decided here rather than by counting OK cells:
 *
 *   - A run whose NEGATIVE CONTROL was skipped cannot be 0. Guard 1's only
 *     mechanical demonstration is the thing that was turned off, so that run has
 *     not established the claim its whole table rests on -- that a compile-time
 *     reading would have been refused. It is 3, and the reason is printed. The
 *     same holds for `--skip-gcc` and `--skip-thinlto-evidence`: each removes a
 *     cell or a piece of evidence the lane otherwise reports, so each is a check
 *     that did not complete.
 *
 *   - A cell that is `OK` with state `NOT_OBSERVED` is 3 as well. The instrument
 *     worked and there was no reading of that property, which interfaces.md 3.1
 *     calls ungradeable either way -- a completed run, not a completed check.
 *
 *   - A family that was measured and has NO negative-control record, and a
 *     full-LTO clang link cell whose non-invasiveness was never established, are
 *     both code 2. Neither is a check that failed; each is a check that silently
 *     did not happen for one family while the table for that family reads clean.
 *     It is the shape the adversarial review caught in `../../spike/` -- a
 *     configuration that kept its ESTABLISHED word while the thing establishing
 *     it had gone quiet -- and a new fixture family is where it comes back,
 *     because a family is added by editing a table and every per-family check
 *     has to be reached from that table on its own. `families` is the list the
 *     run was ASKED for, so a
 *     family that never reached the negative control is detected by its absence
 *     rather than by a field it did not write.
 */
export function exitDecision({
  cells = [],
  skipped = {},
  toolFailure = null,
  byteFinding = null,
  negativeControls = {},
  families = [],
} = {}) {
  if (toolFailure) return { code: 1, messages: [toolFailure] };
  if (byteFinding) {
    return {
      code: 2,
      messages: ['the linked executable differed with the plugin loaded: the observer is not non-invasive here'],
    };
  }
  for (const [name, nc] of Object.entries(negativeControls)) {
    if (nc && nc.ran && !nc.fired) {
      return {
        code: 2,
        messages: [`the negative control for ${name} was NOT refused: guard 1 did not fire on a non-LTO link, `
          + 'so nothing in this lane distinguishes a link-time reading from a compile-time one'],
      };
    }
  }
  // A family that was asked for and has no negative-control record at all. Not
  // the same as one that was skipped by flag (that record exists and says so) or
  // one whose control did not fire (above). This is the check not being reached
  // for that family, which is invisible in the family's own table.
  for (const name of families) {
    if (!negativeControls[name]) {
      return {
        code: 2,
        messages: [`the family ${name} was measured with NO negative-control record: guard 1 was never shown `
          + 'to fire for it, so its cells do not distinguish a link-time reading from a compile-time one. '
          + 'A new family that reaches the cells but not the per-family checks reads exactly like a clean one.'],
      };
    }
  }
  // Non-invasiveness, per cell rather than per run. `false` is the finding
  // `byteFinding` already carries; `null` is the check never having run on this
  // cell, which is the same silent omission as the one above and is refused with
  // the same code. Scoped to the cells the check is defined for: the plugin is
  // only loaded on a clang full-LTO link.
  //
  // DEFENSIVE, AND NOT YET REACHED. An adversarial review pointed out that the
  // runner cannot currently produce an input for this branch, and measuring the
  // 2026-09-12 -O2 run agrees: all three clang/full/link cells came back
  // `byteIdentical: true` (including `erasure.full.link`, which is
  // BROKEN_MEASUREMENT for an unrelated reason but did link and was compared),
  // because `linkWindowCell` assigns a boolean before returning and the `false`
  // case is caught earlier by `byteFinding`. So this is a guard against a future
  // shape, not a defect it has caught. Saying so here rather than letting the
  // test suite's synthetic inputs read as evidence that a real class of silent
  // omission was closed.
  for (const c of cells) {
    if (c.window !== 'link' || c.vendor !== 'clang' || c.form !== 'full') continue;
    // A cell that was not measured has nothing to compare, and saying its
    // equality check "did not establish non-invasiveness" asserts a check ran.
    // UNSUPPORTED means no lld; BROKEN_MEASUREMENT means the observed link
    // produced nothing readable. Either way there was no observed executable, so
    // `byteIdentical` is null for the same reason the cell is incomplete -- and
    // incomplete is code 3, below, which is the code interfaces.md section 7
    // fixes to keep "we did not look" out of "it is not clean". Without this
    // line the loop ran before the incomplete tally and answered 2 for both,
    // measured against HEAD: BROKEN and UNSUPPORTED were 3 there and 2 here.
    if (c.measurement !== MEASUREMENT.OK) continue;
    if (c.guards && c.guards.byteIdentical === true) continue;
    return {
      code: 2,
      messages: [`${c.id}: the sha256 equality check (stock executable vs observed) did not establish `
        + `non-invasiveness here (byteIdentical ${JSON.stringify(c.guards?.byteIdentical ?? null)}). `
        + 'An observed link whose bytes were never compared is not known to be an observation of the same '
        + 'program the build produces.'],
    };
  }

  const messages = [];
  const incomplete = cells.filter((c) => c.measurement !== MEASUREMENT.OK);
  const unread = cells.filter((c) => c.measurement === MEASUREMENT.OK && c.state === STATE.NOT_OBSERVED);
  if (incomplete.length) {
    messages.push(`${incomplete.length} of ${cells.length} cells could not be completed; see \`reasons\` in the result`);
  }
  if (unread.length) {
    messages.push(`${unread.length} cell(s) measured OK with nothing to read (state NOT_OBSERVED); see \`reasons\``);
  }
  for (const line of skipSummaryLines(skipped)) messages.push(line);
  return { code: messages.length ? 3 : 0, messages };
}

/* ---------------------------------------------------------------------------
 * WHICH of the two absorbed wipes is gone -- by deletion, not by byte counting
 *
 * absorbedFillReading() above stops one step short on purpose and says so: with
 * both wipes in one body, "32B of fill where the source asks for two 32B wipes"
 * establishes that ONE of them is gone and explicitly cannot say which. That
 * caveat is the whole weight a reviewer puts on this family, because the claim
 * being defended is about the SUBJECT's store specifically.
 *
 * The missing step does not need a better reader. It needs the question asked
 * differently: build the same family three times -- as written, with the
 * subject's wipe deleted from the source, and with the control's wipe deleted --
 * and read the fill in the absorbed body each time. This is the find step's own
 * move (ablate, rebuild, compare) applied at the link instead of at the compile,
 * and it does not depend on a function name surviving, on the observer resolving
 * a unit, or on being able to tell two stack buffers apart in a disassembly.
 *
 *   deleting the SUBJECT's wipe changes nothing   -> it contributed nothing to
 *                                                    the program: already gone
 *   deleting the SUBJECT's wipe removes fill      -> it was still there
 *   deleting the CONTROL's wipe removes the fill  -> the fill that IS there is
 *                                                    the control's
 *
 * The last one is the positive control of this reading and is required: without
 * it, "deleting the subject changed nothing" is equally consistent with a build
 * whose fill is not responsive to the source at all.
 */
export const WHICH_WIPE = Object.freeze({
  SUBJECT_GONE: 'subject-store-already-gone-deleting-it-from-the-source-changes-nothing',
  SUBJECT_PRESENT: 'subject-store-still-there-deleting-it-from-the-source-removes-fill',
  BLIND: 'the-control-deletion-did-not-move-the-fill-so-this-reading-is-not-responsive-to-the-source',
  INCONCLUSIVE: 'the-three-builds-do-not-form-a-readable-pattern',
});

/**
 * @param asWritten   fill bytes in the absorbed body, source unmodified
 * @param subjectCut  fill bytes with the subject's wipe deleted from the source
 * @param controlCut  fill bytes with the control's wipe deleted from the source
 */
export function whichWipeSurvived({ asWritten = null, subjectCut = null, controlCut = null } = {}) {
  const nums = [asWritten, subjectCut, controlCut];
  if (nums.some((n) => typeof n !== 'number' || n < 0)) {
    return { reading: WHICH_WIPE.INCONCLUSIVE, proves: null, why: 'one of the three builds produced no byte count' };
  }
  // The positive control first. If removing a wipe that MUST survive does not
  // change the fill, the instrument is not reading the source and no comparison
  // below it means anything -- the same rule the other lanes apply when a
  // control goes missing.
  if (controlCut >= asWritten) {
    return {
      reading: WHICH_WIPE.BLIND,
      proves: null,
      why: `deleting the control's wipe left ${controlCut}B where the unmodified source gives ${asWritten}B: `
        + 'the fill did not respond to a deletion that must change it, so nothing is being read here',
    };
  }
  if (subjectCut === asWritten) {
    return {
      reading: WHICH_WIPE.SUBJECT_GONE,
      proves: 'the elimination does not depend on the intervention',
      why: `deleting the subject's wipe from the source left the fill at ${asWritten}B, unchanged, while `
        + `deleting the control's dropped it to ${controlCut}B. The subject's store contributes nothing to the `
        + 'linked program, so it was already eliminated -- without the intervention, and without needing a '
        + 'unit name to say so.',
    };
  }
  if (subjectCut < asWritten) {
    return {
      reading: WHICH_WIPE.SUBJECT_PRESENT,
      proves: 'the elimination DID depend on the intervention at this level',
      why: `deleting the subject's wipe dropped the fill from ${asWritten}B to ${subjectCut}B, so the subject's `
        + 'store was still in the program. Whatever the intervened family showed, it is not reproduced here.',
    };
  }
  return {
    reading: WHICH_WIPE.INCONCLUSIVE,
    proves: null,
    why: `deleting the subject's wipe RAISED the fill from ${asWritten}B to ${subjectCut}B, which no `
      + 'reading of this instrument explains; it is reported rather than rounded to one of the other words',
  };
}
