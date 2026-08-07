// The verdict: an observation of one link, plus `policy.link`, in; findings,
// a count, and an exit code out. Pure — no filesystem, no child process, no
// clock — which is why it is the part that is always tested, on any machine,
// with or without a toolchain.
//
// THREE THINGS THIS FILE REFUSES TO DO
//
// 1. It refuses to produce a verdict from a map it was not told the wrapper
//    made. Not "warns"; refuses, with exit 4. An attacker who can hand the
//    checker a map can describe a link that never happened, and the resulting
//    "clean" carries the authority of a check.
//
// 2. It refuses to treat an absent policy list as an authorisation. An absent
//    `allowedObjects` means object authorisation was not checked, and that is
//    exit 3. Every input it could not check is named in the output, because a
//    count of skipped cases without their names is a number nobody can act on.
//
// 3. It refuses to report on zero inputs. A link with no observed inputs is a
//    broken observation, not a clean link, and `--allow-empty` has to be asked
//    for explicitly before that reports anything other than exit 3.

import { EXIT_OK, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_INTEGRITY } from './exit.mjs';
import { LINK, makeFinding, atOrAboveThreshold } from './findings.mjs';
import { matchRef } from './refs.mjs';
import { forbidLinkerScripts } from './policy-link.mjs';
import { PRODUCED_BY_WRAPPER } from './observe.mjs';

function authorise(input, link) {
  const objects = link?.allowedObjects;
  const libraries = link?.allowedLibraries;

  if (input.kind === 'linker-generated') {
    return { checked: false, why: 'linker-generated; it is not a file and no policy list names it', allowed: true };
  }

  if (input.kind === 'shared-library') {
    if (!Array.isArray(libraries)) {
      return { checked: false, why: 'policy.link.allowedLibraries is absent, so shared-library authorisation was not checked', allowed: null };
    }
    const m = matchRef(input.ref, libraries, input.base);
    return { checked: true, allowed: m.allowed, by: m.by, pattern: m.pattern, list: 'allowedLibraries' };
  }

  if (input.kind === 'archive-member') {
    // An archive member is an object that arrived inside a static library, so
    // either list may authorise it: `allowedObjects` naming the member, or
    // `allowedLibraries` naming the archive it came out of. Both spellings are
    // reported so the record shows which one was relied on.
    const haveObjects = Array.isArray(objects);
    const haveLibraries = Array.isArray(libraries);
    if (!haveObjects && !haveLibraries) {
      return { checked: false, why: 'neither policy.link.allowedObjects nor allowedLibraries is present, so archive members were not checked', allowed: null };
    }
    if (haveObjects) {
      const m = matchRef(input.ref, objects, input.base);
      if (m.allowed) return { checked: true, allowed: true, by: m.by, pattern: m.pattern, list: 'allowedObjects' };
    }
    if (haveLibraries && input.archive) {
      const archiveBase = input.archive.replace(/^.*\//, '');
      const m = matchRef(input.archive, libraries, archiveBase);
      if (m.allowed) return { checked: true, allowed: true, by: m.by, pattern: m.pattern, list: 'allowedLibraries' };
    }
    return { checked: true, allowed: false, by: null, pattern: null, list: haveObjects ? 'allowedObjects' : 'allowedLibraries' };
  }

  if (!Array.isArray(objects)) {
    return { checked: false, why: 'policy.link.allowedObjects is absent, so object authorisation was not checked', allowed: null };
  }
  const m = matchRef(input.ref, objects, input.base);
  return { checked: true, allowed: m.allowed, by: m.by, pattern: m.pattern, list: 'allowedObjects' };
}

const FINDING_FOR_KIND = {
  object: LINK.UNAUTHORISED_OBJECT,
  'archive-member': LINK.UNAUTHORISED_ARCHIVE_MEMBER,
  'shared-library': LINK.UNAUTHORISED_LIBRARY,
};

/**
 * @param {object} a
 * @param {object} a.observation      from buildObservation()
 * @param {object} a.policyResult     from readLinkPolicy()
 * @param {{allowEmpty?: boolean, failOnIncomplete?: boolean}} [a.options]
 */
export function verdict({ observation, policyResult, options = {} }) {
  const allowEmpty = options.allowEmpty === true;
  const failOnIncomplete = options.failOnIncomplete !== false;

  const findings = [];
  const incomplete = [];
  const decisions = [];
  const skippedNames = [];

  // ---- 0. the policy itself -------------------------------------------------
  if (!policyResult || policyResult.ok !== true) {
    return {
      exitCode: EXIT_INTEGRITY,
      findings: [],
      incomplete: [{ what: 'policy', why: policyResult?.detail ?? 'the policy could not be read' }],
      decisions: [],
      counts: { inputs: 0, checked: 0, skipped: 0 },
      skipped: [],
      integrity: policyResult?.detail ?? 'the policy could not be read',
    };
  }
  const link = policyResult.link;
  const failOn = policyResult.failOn ?? 'high';

  // ---- 1. provenance of the observation ------------------------------------
  const producedBy = observation?.provenance?.map?.producedBy;
  const integrityFindings = [];
  if (producedBy !== PRODUCED_BY_WRAPPER) {
    integrityFindings.push(makeFinding({
      id: LINK.MAP_NOT_PRODUCED_HERE,
      detail: `the map's provenance is ${JSON.stringify(producedBy ?? null)}, not ${JSON.stringify(PRODUCED_BY_WRAPPER)}. A map supplied from outside the wrapper is the caller's account of the link, not an observation of it, so no verdict is computed from it.`,
      where: { kind: 'link', path: null },
    }));
  }
  for (const r of observation?.command?.refusals ?? []) {
    integrityFindings.push(makeFinding({
      id: LINK.MAP_NOT_PRODUCED_HERE,
      detail: `the link command line carries ${JSON.stringify(r.what)}: ${r.why}`,
      where: { kind: 'invocation', path: null },
    }));
  }
  if (integrityFindings.length > 0) {
    return {
      exitCode: EXIT_INTEGRITY,
      findings: integrityFindings,
      incomplete: [{ what: 'observation', why: 'the map was not produced by this wrapper' }],
      decisions: [],
      counts: { inputs: 0, checked: 0, skipped: 0 },
      skipped: [],
      integrity: integrityFindings[0].detail,
    };
  }

  // ---- 2. the command line could not be fully read --------------------------
  for (const o of observation.command.opaque ?? []) {
    findings.push(makeFinding({
      id: LINK.COMMAND_LINE_NOT_FULLY_OBSERVED,
      detail: `${JSON.stringify(o.what)}: ${o.why}`,
      where: { kind: 'invocation', path: null },
    }));
    incomplete.push({ what: 'command-line', why: o.why });
  }

  // ---- 3. the linker ---------------------------------------------------------
  const linker = observation.command.linker;
  if (Array.isArray(link?.allowedLinkers)) {
    if (linker === null) {
      incomplete.push({ what: 'linker', why: 'the command line does not name a linker (no -fuse-ld=, and the program is not a linker), so it could not be compared with policy.link.allowedLinkers' });
    } else {
      const m = matchRef(linker, link.allowedLinkers, linker);
      if (!m.allowed) {
        findings.push(makeFinding({
          id: LINK.UNAUTHORISED_LINKER,
          detail: `the link used ${JSON.stringify(linker)}, which is not in policy.link.allowedLinkers (${JSON.stringify(link.allowedLinkers)}).`,
          where: { kind: 'invocation', path: null },
        }));
      }
    }
  } else {
    incomplete.push({ what: 'linker', why: 'policy.link.allowedLinkers is absent, so the linker was not checked' });
    skippedNames.push(`linker:${linker ?? 'unnamed'}`);
  }

  // ---- 4. linker scripts -----------------------------------------------------
  const scriptsForbidden = forbidLinkerScripts(link);
  for (const s of observation.command.scripts ?? []) {
    if (scriptsForbidden) {
      findings.push(makeFinding({
        id: LINK.LINKER_SCRIPT_USED,
        detail: `the link used the linker script ${JSON.stringify(s.ref)}. policy.link.forbidLinkerScripts is ${link?.forbidLinkerScripts === undefined ? 'absent, which the schema defaults to true' : 'true'}; a linker script can place, rename, wrap or discard any section, so a build that uses one is not described by the rest of this policy.`,
        where: { kind: 'link', path: s.ref },
      }));
    } else {
      decisions.push({ ref: s.ref, kind: 'linker-script', checked: true, allowed: true, by: 'policy.link.forbidLinkerScripts=false' });
    }
  }

  // ---- 5. the inputs ---------------------------------------------------------
  const inputs = observation.inputs ?? [];
  let checked = 0;
  const authorisedRefs = new Set();

  for (const input of inputs) {
    const a = authorise(input, link);
    decisions.push({
      ref: input.ref,
      kind: input.kind,
      sources: input.sources.slice(),
      checked: a.checked,
      allowed: a.allowed,
      by: a.by ?? null,
      pattern: a.pattern ?? null,
      list: a.list ?? null,
      why: a.why ?? null,
    });
    if (a.checked) {
      checked += 1;
      if (a.allowed) authorisedRefs.add(input.ref);
      else {
        findings.push(makeFinding({
          id: FINDING_FOR_KIND[input.kind] ?? LINK.UNAUTHORISED_OBJECT,
          detail: `${input.ref} was linked in (seen by: ${input.sources.join(', ')}) and is not authorised by policy.link.${a.list}.`,
          where: { kind: input.kind === 'shared-library' ? 'link' : 'object', path: input.ref },
        }));
      }
    } else {
      if (a.allowed === true) {
        // linker-generated: not a file, nothing to authorise. Named anyway.
        authorisedRefs.add(input.ref);
      } else {
        incomplete.push({ what: `input:${input.ref}`, why: a.why });
      }
      skippedNames.push(input.ref);
    }
  }

  // ---- 6. the two observations of the input set ------------------------------
  for (const input of inputs) {
    if (input.kind === 'linker-generated') continue;
    if (input.sources.includes('map') && !input.sources.includes('trace')) {
      findings.push(makeFinding({
        id: LINK.OBSERVATIONS_DISAGREE,
        detail: `${input.ref} contributed bytes according to the map but the linker's own input trace never lists it. Everything that contributed bytes was opened, so the two observations of this link do not describe the same link.`,
        where: { kind: 'link', path: input.ref },
      }));
    }
  }

  // ---- 7. .init_array --------------------------------------------------------
  // Recorded whether or not it is empty: an .init_array that gained an entry is
  // the difference between a build that runs the code you wrote and one that
  // runs something else first, and "no .init_array" is a fact worth having.
  for (const c of observation.initArray?.contributions ?? []) {
    const decision = decisions.find((d) => d.ref === c.input);
    if (!decision || decision.checked !== true) {
      incomplete.push({ what: `init_array:${c.input}`, why: 'the input contributing to .init_array was not itself authorised, so its contribution could not be judged' });
      continue;
    }
    if (!decision.allowed) {
      findings.push(makeFinding({
        id: LINK.INIT_ARRAY_FROM_UNAUTHORISED_INPUT,
        detail: `${c.input} contributes ${c.size} byte(s) to .init_array${c.symbols.length ? ` (${c.symbols.join(', ')})` : ''} and is not authorised. Code reached through .init_array runs before main.`,
        where: { kind: 'link', path: c.input },
      }));
    }
  }

  // ---- 8. the entry point ----------------------------------------------------
  const entry = observation.entry ?? { resolved: 'NOT_OBSERVED' };
  if (entry.resolved === 'PRESENT') {
    const decision = decisions.find((d) => d.ref === entry.input);
    if (!decision || decision.checked !== true) {
      incomplete.push({ what: 'entry-point', why: `the entry point is defined by ${entry.input}, whose authorisation was not checked` });
    } else if (!decision.allowed) {
      findings.push(makeFinding({
        id: LINK.ENTRY_POINT_FROM_UNAUTHORISED_INPUT,
        detail: `the entry point 0x${(entry.address ?? 0).toString(16)} is ${entry.symbol}, defined by ${entry.input}, which is not authorised.`,
        where: { kind: 'artifact', path: entry.input },
      }));
    }
  } else {
    incomplete.push({ what: 'entry-point', why: `the entry point was ${entry.resolved}: no symbol in the map sits at the artefact's entry address` });
  }

  // ---- 9. counting -----------------------------------------------------------
  const counts = { inputs: inputs.length, checked, skipped: skippedNames.length };

  if (inputs.length === 0 && !allowEmpty) {
    incomplete.push({ what: 'inputs', why: 'no link inputs were observed. A link with no inputs is a broken observation, not a clean link; pass --allow-empty to say otherwise deliberately.' });
    return { exitCode: EXIT_INCOMPLETE, findings, incomplete, decisions, counts, skipped: skippedNames };
  }

  const firing = atOrAboveThreshold(findings, failOn);
  let exitCode = EXIT_OK;
  if (firing.length > 0) exitCode = EXIT_FINDINGS;
  else if (incomplete.length > 0 && failOnIncomplete) exitCode = EXIT_INCOMPLETE;

  return { exitCode, findings, firing, incomplete, decisions, counts, skipped: skippedNames };
}

/**
 * Was the artefact modified after the link?
 *
 * Compares the bytes on disk now with the digest the link recorded. Separate
 * from `verdict` because it answers a question about a DIFFERENT MOMENT: the
 * link's verdict was true when the link finished, and this is the only check
 * that says anything about the time since.
 *
 * @param {{artifact: {path: string|null, sha256: string, size: number}}} record
 * @param {{sha256: string, size: number}|null} now  null when the artefact is gone
 */
export function recheckArtifact(record, now) {
  const want = record?.observation?.artifact ?? record?.artifact ?? null;
  if (!want || typeof want.sha256 !== 'string') {
    return {
      ok: false,
      incomplete: { what: 'artifact', why: 'the record carries no artefact digest, so there is nothing to compare against' },
      finding: null,
    };
  }
  if (now === null) {
    return {
      ok: false,
      incomplete: { what: 'artifact', why: `the artefact ${want.path ?? '(unnamed)'} recorded by this link is not there now` },
      finding: null,
    };
  }
  if (now.sha256 === want.sha256 && now.size === want.size) {
    return { ok: true, incomplete: null, finding: null };
  }
  return {
    ok: false,
    incomplete: null,
    finding: makeFinding({
      id: LINK.ARTIFACT_CHANGED_AFTER_LINK,
      detail:
        `${want.path ?? '(unnamed artefact)'} is ${now.size} byte(s) with sha256 ${now.sha256}; the link recorded ` +
        `${want.size} byte(s) with sha256 ${want.sha256}. The bytes on disk are not the ones this link produced.`,
      where: { kind: 'artifact', path: want.path ?? null },
    }),
  };
}
