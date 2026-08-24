// Cross-examining claims about protections.
//
// ── THE RULE ────────────────────────────────────────────────────────────────
//
// A claim that a protection exists is an accusation, not evidence. Whoever made
// it — a rule reading the source, a fixer reporting its own edit, a coding
// assistant describing what it wrote — has created something that must be
// proven and has proven nothing. So a claim is born `NOT_OBSERVED`, and only an
// observation at a layer OTHER than the claimant's may move it.
//
// The consequence that shapes every function here: a claim can only ever ADD
// something to prove. It cannot turn a screen green. That is not a stylistic
// preference. The obvious alternative design — let the assistant annotate its
// output and believe the annotation — makes the party under examination the
// examiner, and the whole reason this product exists is that its user cannot
// check the assistant's word. A green tick sourced from that word hands the
// user back precisely the question they could not answer.
//
// ── WHAT THE LAYERS ARE ─────────────────────────────────────────────────────
//
//   assistant  the prose a coding assistant wrote next to the code
//   source     the source text, as read by a rule
//   fixer      a fixer's record of what it inserted
//   artifact   the bytes the project ships
//   sidecar    a file shipped alongside — a source map
//
// The first three make claims. The last two settle them. Nothing settles a
// claim made at its own layer, and `illegalClaimTransition` in
// `@vibeguard/findings-schema` is the single place that rule is written down.

import { normaliseText } from './bundle.mjs';
import {
  SPAN_ATTRIBUTION_CAP,
  coarseWidthAt,
  regionSourceAt,
  sourceIndexesCarrying,
} from './source-map-regions.mjs';

/**
 * Shortest witness this adjudicator will look for.
 *
 * ── THE ONE REAL FAILURE MODE OF `String.includes` ──────────────────────────
 *
 * `haystack.includes('')` is true for every haystack, so a degenerate needle
 * turns this whole channel into a machine that reports PRESENT for everything
 * — the single direction the doctrine says nothing here may ever fail in. Four
 * characters, matching the admissibility floor inside `identifierWitness`.
 *
 * ── WHY IT IS CHECKED HERE WHEN THE PRODUCER ALREADY CHECKS IT ──────────────
 *
 * `identifierWitness` in `@vibeguard/findings-schema` refuses to return a
 * token shorter than four characters, so today every witness that reaches this
 * function already clears the floor. That is a guarantee of the PRODUCER, not
 * a defence of the ADJUDICATOR, and the difference is about to matter: this
 * function's falsiness test is `!claim.witness`, which admits `'  '`, `'ab'`
 * and anything else a future claim source hands it. The claim sources today
 * are two pure functions in this repository. The next one is a fixer ledger
 * read off disk, and the check has to be here BEFORE that exists rather than
 * after, because afterwards it is a fix and before it is a floor.
 */
const MIN_WITNESS_CHARS = 4;

/**
 * Shortest source text that may be used to identify an artefact.
 *
 * A one-word probe would be found in every chunk and would hand jurisdiction
 * to all of them, which is the failure this whole mechanism replaces. Twenty
 * characters is roughly one meaningful line of code and is deliberately
 * conservative: below it the answer is NOT_OBSERVED, not a guess.
 */
const MIN_PROBE_CHARS = 20;

/**
 * How many artefacts a probe may match before it is treated as saying nothing.
 *
 * ── LENGTH IS NOT IDENTITY, AND THE FLOOR ABOVE ONLY BUYS LENGTH ────────────
 *
 * Measured on this repository's own corpus: VG-AUTH-009's probe is
 * `if (process.env.NODE_ENV !== 'production') {`. That is 44 characters, so it
 * clears the floor comfortably, and it is also one of the most common lines in
 * the JavaScript ecosystem — a React vendor chunk carries it. A probe like that
 * hands jurisdiction to whichever chunk happens to contain it, and jurisdiction
 * was the entire mechanism keeping an unrelated chunk from settling a claim.
 *
 * So a probe that matches more artefacts than this is not identifying anything
 * and the claim goes back to NOT_OBSERVED. Three rather than one, because code
 * splitting legitimately duplicates a module across entry points; beyond that
 * the probe is describing the ecosystem rather than the file.
 */
const MAX_JURISDICTION_ARTEFACTS = 3;

// ── WHERE THE REST OF THE LEDGER IS ─────────────────────────────────────────
//
// `CLAIM_BEARING_RULES`, `identifierWitness`, `claimsFromFindings` and
// `claimsFromAssistantProse` are pure functions of a finding, and they live in
// `@vibeguard/findings-schema` — not here — so the editor, the browser panel
// and the generation-time guard can build a ledger too. None of them can import
// this package: it reads directories off disk, and the packaging invariants
// forbid it three ways.
//
// They are NOT re-exported from here, and the reason is a test two directories
// away: `test/boundary.test.mjs` asserts this package declares no dependencies
// at all, so that it cannot acquire one by drift. A re-export would need one.
// The split that avoids it is also the better one — this file adjudicates, and
// adjudication is the only half that needs a filesystem.
//
// A caller wanting both imports each from its owner. `apps/cli/src/index.ts`
// does exactly that.

/**
 * Can this occurrence of the witness be attributed to the claim's own source?
 *
 * ── WHY PRESENCE NEEDS THIS AND ABSENCE DOES NOT ────────────────────────────
 *
 * Absence over the whole chunk is sound as absence over the part: a token that
 * is nowhere in the file is nowhere in the claim's own module either. So the
 * LOST and REINTRODUCED paths ask nothing of this function and are unchanged.
 * Only PRESENT needs it, and it needs it because jurisdiction stops one level
 * too high — it establishes that the right FILE is being read and says nothing
 * about which of that file's hundreds of modules the hit is in.
 *
 * Returns `{ ok: true }` or `{ ok: false, why }`. There is no third answer and
 * no default: every path that cannot attribute returns a reason, and the
 * caller turns a reason into NOT_OBSERVED.
 *
 * ── NO CAP ON HOW MANY OCCURRENCES ARE EXAMINED, AND WHY THAT IS SAFE ───────
 *
 * The witness can occur many times — measured on this repository's own bundles
 * the most frequent identifier-shaped token of four characters or more occurs
 * 985 times in 375 KB — and every occurrence must be examined, because ONE of
 * them landing in the claim's own region is what PRESENT means. There is no
 * occurrence cap because the work is already bounded: the scan is linear in
 * the artefact, which `MAX_ARTEFACT_BYTES` bounds, and each lookup is a binary
 * search over a region list measured at 187 entries for that same bundle. A
 * cap here would only add a way to answer NOT_OBSERVED about a witness that is
 * genuinely, attributably there.
 */
function attributeWitness(record, witness, probe) {
  if (!Array.isArray(record.regions)) {
    return { ok: false, why: record.regionsWhy ?? 'its source map was not decoded into regions' };
  }
  const mine = new Set(sourceIndexesCarrying(record.contents ?? [], probe));
  if (!mine.size) {
    // Reachable, and not the same thing as having no jurisdiction. Jurisdiction
    // tests the JOIN of every `sourcesContent` entry, so a probe straddling the
    // newline between two of them puts the artefact in scope while belonging to
    // no single source in it.
    return { ok: false, why: 'no single source in its map carries this claim\'s source text' };
  }
  let widestCoarse = 0;
  const coarse = Array.isArray(record.coarse) ? record.coarse : [];
  for (let at = record.code.indexOf(witness); at >= 0; at = record.code.indexOf(witness, at + 1)) {
    if (mine.has(regionSourceAt(record.regions, at))) return { ok: true };
    const w = coarseWidthAt(coarse, at);
    if (w > widestCoarse) widestCoarse = w;
  }
  if (widestCoarse) {
    return { ok: false,
      why: `the widest mapping covering an occurrence spans ${widestCoarse} generated characters, above the ${SPAN_ATTRIBUTION_CAP} at which a mapping stops attributing anything` };
  }
  return { ok: false,
    why: 'every occurrence sits in a region its map gives to a different source, or in generated text the map attributes to none' };
}

/**
 * Settle claims against an artefact observation.
 *
 * ── JURISDICTION: THE STEP THAT WAS MISSING ─────────────────────────────────
 *
 * The first version searched every artefact in the directory for the witness
 * token and called the first hit a PRESENT. That is not cross-examination, it
 * is a substring search: `isAdmin` and `hasPermission` are ordinary property
 * names, a vendor chunk is full of other people's code, and a hit in one of
 * them would have overwritten the disappearance of the user's own guard with a
 * green line. The witness heuristic was later changed to prefer property names
 * — which makes the witness survive minification, and makes a collision with a
 * vendor chunk MORE likely, not less.
 *
 * So a claim is now settled only by an artefact that is demonstrably about the
 * same source. The test is that the artefact's `sourcesContent` CONTAINS the
 * text the rule actually matched (`sourceProbe`, newline-normalised). That one
 * predicate does three jobs:
 *
 *   * it kills the vendor-chunk false PRESENT, because a chunk that does not
 *     carry this source is not consulted about this claim;
 *   * it is the per-claim positive control the global `control: 'function'`
 *     could never be — that only said "some source was mapped";
 *   * it retires a stale map by content rather than by timestamp, since a map
 *     from an earlier build does not contain a line the rule matched today.
 *
 * ── AND WHAT IT MEANS TO FIND NO JURISDICTION ───────────────────────────────
 *
 * `NOT_OBSERVED`, never LOST. No artefact under the build output declares that
 * it contains this source: the file may be tree-shaken, may belong to a
 * different entry point, may not be part of this build at all. Reporting that
 * as a removed defence would be exactly the over-claim this channel exists to
 * prevent.
 *
 * ── AND THE HALF JURISDICTION DOES NOT REACH ────────────────────────────────
 *
 * Jurisdiction is a statement about a FILE. A chunk holds hundreds of modules,
 * so a witness found anywhere in a chunk that legitimately holds jurisdiction
 * is still only evidence that SOMEBODY in that chunk spells `isAdmin`. That is
 * the within-chunk false PRESENT, and `attributeWitness` above is what closes
 * it: presence must be attributed to the claim's own region of the generated
 * text, and a presence that cannot be attributed is NOT_OBSERVED with the
 * broken link named — never PRESENT, and never LOST either, because the token
 * is demonstrably still in the bytes.
 */
export function crossExamine(claims, observation, illegal) {
  const usable = observation.records.filter((r) => r.measured);
  return claims.map((claim) => {
    if (!claim.witness) {
      return { ...claim, state: 'NOT_OBSERVED',
        note: 'the claim names nothing that can be looked for in the shipped bytes' };
    }
    if (String(claim.witness).trim().length < MIN_WITNESS_CHARS) {
      return { ...claim, state: 'NOT_OBSERVED',
        note: `the claim's witness is ${JSON.stringify(claim.witness)}, under the ${MIN_WITNESS_CHARS} characters a token needs before it can be looked for` };
    }
    if (!usable.length) {
      return { ...claim, state: 'NOT_OBSERVED',
        note: `no artefact under the build output could be measured (${observation.records.length} read, none passed its controls)` };
    }
    if (!claim.sourceProbe) {
      return { ...claim, state: 'NOT_OBSERVED',
        note: 'the claim carries no source text, so no artefact can be shown to be about it' };
    }
    const probe = normaliseText(claim.sourceProbe).trim();
    // Too short a probe would match everywhere and hand jurisdiction to any
    // artefact. Below the floor the honest answer is that we cannot tell.
    if (probe.length < MIN_PROBE_CHARS) {
      return { ...claim, state: 'NOT_OBSERVED',
        note: `the source text for this claim is ${probe.length} characters, below the ${MIN_PROBE_CHARS} needed to identify an artefact` };
    }
    let jurisdiction = usable.filter((r) => r.sidecar && r.sidecar.includes(probe));
    if (!jurisdiction.length) {
      return { ...claim, state: 'NOT_OBSERVED',
        note: `no artefact under the build output carries this source (${usable.length} measured), so none of them is about this claim` };
    }
    // Narrow by the file the claim came from, when the map says which sources
    // it holds. Bundlers rewrite these paths (`webpack:///./src/x.ts`, absolute,
    // relative), so this is a TIE-BREAK on the basename and never the primary
    // test — a miss leaves the wider set rather than emptying it.
    if (jurisdiction.length > 1 && claim.filePath) {
      const base = String(claim.filePath).split(/[\\/]/).pop();
      const narrowed = jurisdiction.filter((r) =>
        Array.isArray(r.sources) && r.sources.some((src) => String(src).endsWith(base)),
      );
      if (narrowed.length) jurisdiction = narrowed;
    }
    if (jurisdiction.length > MAX_JURISDICTION_ARTEFACTS) {
      return { ...claim, state: 'NOT_OBSERVED',
        note: `this claim's source text appears in ${jurisdiction.length} of the ${usable.length} measured artefacts, so it does not identify one of them` };
    }
    // ── PRESENCE IS ATTRIBUTED; ABSENCE IS NOT ────────────────────────────
    //
    // `inCode` is now set only where the witness could be tied to the claim's
    // own region of the generated text. `sawWitness` records the weaker fact —
    // the token is in the bytes somewhere — because the two lead to different
    // verdicts and collapsing them is the bug being fixed. The sidecar half is
    // untouched: a source map republishes whole files, so a hit in it needs no
    // region and gets none.
    let inCode = null;
    let inSidecar = false;
    let sawWitness = false;
    let unattributed = null;
    for (const r of jurisdiction) {
      if (r.sidecar && r.sidecar.includes(claim.witness)) inSidecar = true;
      if (!r.code || !r.code.includes(claim.witness)) continue;
      sawWitness = true;
      if (inCode) continue;
      const attribution = attributeWitness(r, claim.witness, probe);
      if (attribution.ok) inCode = r.artefact;
      else if (!unattributed) unattributed = `${r.artefact}: ${attribution.why}`;
    }
    if (!inCode && sawWitness) {
      // NOT_OBSERVED and not LOST. The witness IS in the shipped bytes; what
      // is missing is the evidence that this claim's copy of it is the one
      // there. Calling that a removed defence would be a false accusation
      // pointing the other way, and it is no more allowed than a false pass.
      return { ...claim, state: 'NOT_OBSERVED',
        note: `the witness occurs in the shipped bytes but could not be attributed to the source this claim came from (${unattributed})` };
    }
    const where = inCode ?? jurisdiction[0].artefact;
    const observedAt = inCode ? 'artifact' : 'sidecar';
    const reason = illegal(claim, observedAt, inCode ? 'PRESENT' : 'LOST');
    if (reason) return { ...claim, state: 'NOT_OBSERVED', note: reason };

    // ── HISTORY, BECAUSE REINTRODUCED REQUIRES A PRECEDING LOSS ─────────────
    //
    // `evidence-bundle/src/states.mjs` fixes the rule: REINTRODUCED means
    // "PRESENT again after being LOST", and a record that asserts it with no
    // loss in front of it is malformed. So the loss is written down rather than
    // skipped over: absent from the code that runs is a LOST, and finding it in
    // the sidecar afterwards is the REINTRODUCED that follows it.
    const history = [];
    if (inCode) {
      history.push({ checkpoint: 'deployed', state: 'PRESENT', where });
    } else {
      history.push({ checkpoint: 'deployed', state: 'LOST', where });
      if (inSidecar) history.push({ checkpoint: 'sidecar', state: 'REINTRODUCED', where });
    }
    const state = history[history.length - 1].state;
    const note = inCode
      ? `found in ${where}`
      : inSidecar
        ? `absent from the code that runs, still published in the source map next to ${where}`
        : `not in ${where}, which is the artefact that carries this source`;
    const unmeasured = observation.records.length - usable.length;
    return {
      ...claim,
      state,
      crossExaminedAt: observedAt,
      history,
      note: unmeasured > 0 ? `${note} (${unmeasured} artefact(s) could not be measured)` : note,
    };
  });
}
