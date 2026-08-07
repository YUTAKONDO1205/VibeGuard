// Findings. interfaces.md §2 — one shape, produced by every component that can
// complain. The driver owns the VG-CFG-0NN namespace and nothing else.

export const SEVERITIES = ['low', 'medium', 'high', 'critical'];

const RANK = new Map(SEVERITIES.map((s, i) => [s, i]));

export const WHERE_KINDS = new Set([
  'invocation',
  'source',
  'ir',
  'object',
  'link',
  'artifact',
]);

/**
 * Build a finding. `unit` and `pass` are null when the question does not apply
 * to this finding — never when it applies but was not looked at.
 */
export function makeFinding({ id, severity, title, detail, where }) {
  if (!RANK.has(severity)) {
    throw new TypeError(`severity must be one of ${SEVERITIES.join(', ')}, got ${severity}`);
  }
  const w = where ?? {};
  if (!WHERE_KINDS.has(w.kind)) {
    throw new TypeError(`where.kind must be one of ${[...WHERE_KINDS].join(', ')}, got ${w.kind}`);
  }
  return {
    id,
    severity,
    title,
    detail,
    where: {
      kind: w.kind,
      path: w.path ?? null,
      unit: w.unit ?? null,
      pass: w.pass ?? null,
    },
  };
}

export function severityRank(severity) {
  const r = RANK.get(severity);
  return r === undefined ? -1 : r;
}

/** Findings at or above the policy's failure threshold. */
export function atOrAboveThreshold(findings, failOn) {
  const floor = severityRank(failOn);
  if (floor < 0) return [];
  return findings.filter((f) => severityRank(f.severity) >= floor);
}

/**
 * A finding whose shape came from another component. Checked rather than
 * trusted: a malformed finding from a peer must not become a silent pass, and
 * must not corrupt the evidence record either.
 */
export function isWellFormedFinding(f) {
  return (
    !!f &&
    typeof f === 'object' &&
    typeof f.id === 'string' &&
    RANK.has(f.severity) &&
    typeof f.title === 'string' &&
    typeof f.detail === 'string' &&
    !!f.where &&
    typeof f.where === 'object' &&
    WHERE_KINDS.has(f.where.kind)
  );
}

/** Normalise a peer's finding into the recorded shape, filling absent keys with null. */
export function normaliseFinding(f) {
  return {
    id: f.id,
    severity: f.severity,
    title: f.title,
    detail: f.detail,
    where: {
      kind: f.where.kind,
      path: f.where.path ?? null,
      unit: f.where.unit ?? null,
      pass: f.where.pass ?? null,
    },
  };
}

// The driver's own identifiers. VG-CFG-001..003 are fixed by interfaces.md and
// policy.schema.json; 004 upward are allocated here.
export const CFG = {
  DIGEST_MISMATCH: 'VG-CFG-001',
  FORBIDDEN_FLAG: 'VG-CFG-002',
  OPT_LEVEL_NOT_EVALUATED: 'VG-CFG-003',
  REQUIRED_FLAG_MISSING: 'VG-CFG-004',
  EVIDENCE_OUT_INSIDE_COMPILER: 'VG-CFG-005',
  RESPONSE_FILE_UNREADABLE: 'VG-CFG-006',
  ABSOLUTE_PATH_IN_RECORD: 'VG-CFG-007',
  PLUGIN_CHECK_UNAVAILABLE: 'VG-CFG-008',
  EVIDENCE_WRITER_UNAVAILABLE: 'VG-CFG-009',
  PIN_UNREADABLE: 'VG-CFG-010',
  COMMAND_LINE_UNRECOVERABLE: 'VG-CFG-011',
};
