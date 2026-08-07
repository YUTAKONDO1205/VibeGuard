// The VG-LINK-0NN namespace. interfaces.md §2 fixes the shape of a finding and
// assigns this namespace to the link wrapper; the numbers below are allocated
// here and nowhere else.
//
// Every id names a thing that was OBSERVED, never a thing that was assumed. The
// difference matters most for the three that are easy to conflate:
//
//   VG-LINK-006  the bytes on disk are not the bytes this link produced
//   VG-LINK-007  the map this verdict would have been computed from did not
//                come from this wrapper — so there is no observation at all
//   VG-LINK-008  the two independent observations of the input set disagree
//
// 007 is an integrity failure rather than a finding about the build, which is
// why it exits 4: a map handed in from outside is an attacker-chosen account of
// what was linked, and a verdict computed from one is worse than no verdict,
// because it carries the authority of a check that never happened.

export const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const RANK = new Map(SEVERITIES.map((s, i) => [s, i]));

export const WHERE_KINDS = new Set(['invocation', 'source', 'ir', 'object', 'link', 'artifact']);

export const LINK = {
  UNAUTHORISED_OBJECT: 'VG-LINK-001',
  UNAUTHORISED_ARCHIVE_MEMBER: 'VG-LINK-002',
  UNAUTHORISED_LIBRARY: 'VG-LINK-003',
  LINKER_SCRIPT_USED: 'VG-LINK-004',
  UNAUTHORISED_LINKER: 'VG-LINK-005',
  ARTIFACT_CHANGED_AFTER_LINK: 'VG-LINK-006',
  MAP_NOT_PRODUCED_HERE: 'VG-LINK-007',
  OBSERVATIONS_DISAGREE: 'VG-LINK-008',
  INIT_ARRAY_FROM_UNAUTHORISED_INPUT: 'VG-LINK-009',
  ENTRY_POINT_FROM_UNAUTHORISED_INPUT: 'VG-LINK-010',
  COMMAND_LINE_NOT_FULLY_OBSERVED: 'VG-LINK-011',
};

export const TITLES = {
  [LINK.UNAUTHORISED_OBJECT]: 'An object file was linked in that the policy does not authorise',
  [LINK.UNAUTHORISED_ARCHIVE_MEMBER]: 'An archive member was pulled into the link that the policy does not authorise',
  [LINK.UNAUTHORISED_LIBRARY]: 'A shared library was linked against that the policy does not authorise',
  [LINK.LINKER_SCRIPT_USED]: 'A linker script was used and the policy forbids linker scripts',
  [LINK.UNAUTHORISED_LINKER]: 'The link was performed by a linker the policy does not authorise',
  [LINK.ARTIFACT_CHANGED_AFTER_LINK]: 'The artefact on disk is not the one this link produced',
  [LINK.MAP_NOT_PRODUCED_HERE]: 'The link map was not produced by this wrapper',
  [LINK.OBSERVATIONS_DISAGREE]: 'The map and the linker input trace do not describe the same link',
  [LINK.INIT_ARRAY_FROM_UNAUTHORISED_INPUT]: '.init_array carries a contribution from an input the policy does not authorise',
  [LINK.ENTRY_POINT_FROM_UNAUTHORISED_INPUT]: 'The entry point is defined by an input the policy does not authorise',
  [LINK.COMMAND_LINE_NOT_FULLY_OBSERVED]: 'The link command line could not be fully observed',
};

export const DEFAULT_SEVERITY = {
  [LINK.UNAUTHORISED_OBJECT]: 'high',
  [LINK.UNAUTHORISED_ARCHIVE_MEMBER]: 'high',
  [LINK.UNAUTHORISED_LIBRARY]: 'high',
  [LINK.LINKER_SCRIPT_USED]: 'high',
  [LINK.UNAUTHORISED_LINKER]: 'high',
  [LINK.ARTIFACT_CHANGED_AFTER_LINK]: 'critical',
  [LINK.MAP_NOT_PRODUCED_HERE]: 'critical',
  [LINK.OBSERVATIONS_DISAGREE]: 'high',
  [LINK.INIT_ARRAY_FROM_UNAUTHORISED_INPUT]: 'high',
  [LINK.ENTRY_POINT_FROM_UNAUTHORISED_INPUT]: 'high',
  [LINK.COMMAND_LINE_NOT_FULLY_OBSERVED]: 'high',
};

/**
 * Build a finding in the shape interfaces.md §2 fixes. `unit` and `pass` are
 * null because a link has neither — null here means "not applicable", never
 * "not looked at", and there is no third value that would mean the latter.
 */
export function makeFinding({ id, severity, title, detail, where }) {
  const sev = severity ?? DEFAULT_SEVERITY[id];
  if (!RANK.has(sev)) {
    throw new TypeError(`severity must be one of ${SEVERITIES.join(', ')}, got ${sev}`);
  }
  const w = where ?? {};
  const kind = w.kind ?? 'link';
  if (!WHERE_KINDS.has(kind)) {
    throw new TypeError(`where.kind must be one of ${[...WHERE_KINDS].join(', ')}, got ${kind}`);
  }
  return {
    id,
    severity: sev,
    title: title ?? TITLES[id] ?? id,
    detail,
    where: { kind, path: w.path ?? null, unit: w.unit ?? null, pass: w.pass ?? null },
  };
}

export function severityRank(severity) {
  const r = RANK.get(severity);
  return r === undefined ? -1 : r;
}

export function atOrAboveThreshold(findings, failOn) {
  const floor = severityRank(failOn);
  if (floor < 0) return [];
  return findings.filter((f) => severityRank(f.severity) >= floor);
}
