// Did the run observe the subject at all?
//
// The observer is configured by name. `OBS_TARGET_FN=handle_requestX` is a
// perfectly valid configuration of a subject that does not exist, and the log it
// produces is not empty and not obviously wrong: the control is PRESENT, the
// summary is well formed, STATS counts hundreds of passes, and the compiler
// exits 0 with nothing on stderr. Two of the observer's silent failures are
// already fenced -- the wrong plugin writes no log, and a missing environment
// variable prints `refusing to install` -- and neither fence touches this one,
// because the run looks healthy from every angle except the one nobody was
// checking: the subject's rows are simply not there, and "no rows" is what a
// subject whose property was never observed and a subject that was erased
// before the first boundary both look like.
//
// The plugin now records the fact per module (`SUBJECTRES`, History.cpp). It
// deliberately does not draw the conclusion, and this file is why. In a
// whole-project build the plugin is loaded once per translation unit; a subject
// defined in one file is legitimately absent from every other, so
// `not-in-module` is the normal reading for most logs of a healthy run. The
// question that has an answer is about the run, not the module:
//
//     did ANY module in this run resolve the name?
//
// That is a claim about a set of logs, so it is made here, where the set exists.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

/** The record type the plugin writes. */
export const RECORD = 'SUBJECTRES';

/**
 * The four words the plugin may write in the resolution column.
 *
 * None of them is one of the six property states (PRESENT, ABSENT, LOST,
 * REINTRODUCED, NOT_APPLICABLE, NOT_OBSERVED) or one of the three unit fates
 * (LIVE, BODY_REMOVED, ERASED). They answer a different question -- whether the
 * configured name had a referent in this module -- and a word shared between two
 * questions is a word that can no longer answer either.
 */
export const RESOLUTIONS = Object.freeze({
  /** A definition of that lineage is in the module. The only good answer. */
  RESOLVED: 'resolved',
  /** The name is in the module, but only as a declaration: nothing to count. */
  DECLARATION_ONLY: 'declaration-only',
  /** No function of that lineage in this module. Innocent on its own. */
  NOT_IN_MODULE: 'not-in-module',
  /** No module was ever walked, so the question was never put. */
  NOT_SCANNED: 'not-scanned',
});

const KNOWN = new Set(Object.values(RESOLUTIONS));

export const ROLES = Object.freeze(['subject', 'control']);

/**
 * Verdict statuses. `ok` is the only passing one; the rest are split into
 * "the run is broken" and "the run cannot be judged from what is here", because
 * a harness that collapses those two has re-invented the failure this file
 * exists to end.
 */
export const STATUS = Object.freeze({
  OK: 'ok',
  UNRESOLVED: 'unresolved',
  DECLARATION_ONLY: 'declaration-only',
  INCONSISTENT_NAME: 'inconsistent-name',
  UNKNOWN_WORD: 'unknown-word',
  NOT_SCANNED: 'not-scanned',
  NO_RECORD: 'no-record',
  NO_LOGS: 'no-logs',
});

/** Statuses that mean "this run is broken". */
const BROKEN = new Set([
  STATUS.UNRESOLVED, STATUS.DECLARATION_ONLY, STATUS.INCONSISTENT_NAME,
  STATUS.UNKNOWN_WORD,
]);

/**
 * Read the SUBJECTRES records out of one log.
 *
 * Every other record type is ignored rather than rejected: this reads a log
 * written by a plugin that may be newer than this file, and a reader that fails
 * on a record it does not know turns every future addition into a broken tool.
 *
 * `hasRecord` is reported separately from `records.length` so that "this log
 * predates the check" is distinguishable from "this log has the check and it
 * said nothing" -- which cannot happen today, and would be a plugin bug worth
 * seeing rather than reading as an absence.
 *
 * @param {string} text  contents of an OBS_OUT log (the main one; the
 *   `.summary.tsv` side file deliberately does not carry these records)
 * @param {string} [source]  where the text came from, for the reason strings
 */
export function parseResolutionRecords(text, source = '<text>') {
  const records = [];
  let nonEmptyLines = 0;
  for (const raw of String(text).split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (!line) continue;
    nonEmptyLines++;
    const f = line.split('\t');
    if (f[0] !== RECORD) continue;
    records.push({
      source,
      seq: Number(f[1]),
      moduleId: f[2] ?? '',
      role: f[3] ?? '',
      name: f[4] ?? '',
      resolution: f[5] ?? '',
    });
  }
  return { source, records, nonEmptyLines, hasRecord: records.length > 0 };
}

function roleVerdict(role, records) {
  const mine = records.filter((r) => r.role === role);
  const counts = Object.create(null);
  const resolvedIn = [];
  const names = [];
  const unknown = [];
  for (const r of mine) {
    counts[r.resolution] = (counts[r.resolution] ?? 0) + 1;
    if (!names.includes(r.name)) names.push(r.name);
    if (!KNOWN.has(r.resolution)) unknown.push(r);
    if (r.resolution === RESOLUTIONS.RESOLVED) resolvedIn.push(r.moduleId);
  }

  const base = { role, names, name: names.length === 1 ? names[0] : null, counts, resolvedIn, records: mine };
  const fail = (status, reason) => ({ ...base, ok: false, status, reason });

  if (mine.length === 0) {
    return fail(STATUS.NO_RECORD, `no ${RECORD} record names the ${role}: nothing here says whether the ${role} name had a referent`);
  }
  // Checked before the good news. A run whose logs disagree about which name
  // was configured is not one run, and "some module resolved something" is not
  // a statement about the subject anybody asked for.
  if (names.length > 1) {
    return fail(
      STATUS.INCONSISTENT_NAME,
      `the logs disagree about the ${role} name (${names.map((n) => `'${n}'`).join(', ')}): `
      + 'these are not observations of one run, so no aggregate over them means anything',
    );
  }
  if (unknown.length > 0) {
    const words = [...new Set(unknown.map((r) => r.resolution))].map((w) => `'${w}'`).join(', ');
    return fail(
      STATUS.UNKNOWN_WORD,
      `the ${role} resolution column holds ${words}, which this checker does not know. `
      + 'Refusing rather than guessing: a word invented by a newer plugin might mean the '
      + 'opposite of what a permissive reading would assume',
    );
  }
  if (resolvedIn.length > 0) {
    return { ...base, ok: true, status: STATUS.OK,
      reason: `the ${role} '${base.name}' resolved to a defined function in ${resolvedIn.length} of ${mine.length} module(s)` };
  }
  if (counts[RESOLUTIONS.DECLARATION_ONLY] > 0) {
    return fail(
      STATUS.DECLARATION_ONLY,
      `the ${role} '${base.name}' appears in ${counts[RESOLUTIONS.DECLARATION_ONLY]} module(s) only as a declaration `
      + 'and is defined in none of them, so there was never a body to count anything in',
    );
  }
  if (counts[RESOLUTIONS.NOT_IN_MODULE] > 0) {
    return fail(
      STATUS.UNRESOLVED,
      `the ${role} '${base.name}' resolved in none of the ${mine.length} module(s) this run walked. `
      + `Either the name is wrong, or the plugin was never loaded for the translation unit that defines it. `
      + `Nothing in this run is an observation of the ${role}`,
    );
  }
  return fail(
    STATUS.NOT_SCANNED,
    `no module boundary was reached in this run, so whether the ${role} '${base.name}' resolves `
    + 'was never determined. This is not a report that it is missing; it is a report that nobody asked',
  );
}

/**
 * The run-level verdict, over every log the run produced.
 *
 * @param {{source?: string, text: string}[]} logs  one entry per OBS_OUT log
 * @param {{roles?: string[]}} [opts]  which roles must resolve; both by default,
 *   because a control that resolves nowhere breaks the measurement exactly as
 *   completely as a subject that does, and the existing "the control held"
 *   invariant is the one that cannot notice it
 */
export function aggregateResolution(logs, opts = {}) {
  const roles = opts.roles ?? ROLES;
  const parsed = (logs ?? []).map((l) => parseResolutionRecords(l.text, l.source ?? '<text>'));
  const records = parsed.flatMap((p) => p.records);
  const moduleIds = [...new Set(records.map((r) => r.moduleId).filter((m) => m && m !== '-'))];

  const shell = {
    logsRead: parsed.length,
    logsWithRecord: parsed.filter((p) => p.hasRecord).length,
    modulesSeen: moduleIds.length,
    moduleIds,
    roles: {},
  };

  if (parsed.length === 0) {
    return { ...shell, ok: false, status: STATUS.NO_LOGS, judged: false,
      reason: 'no logs were given, so there is nothing to judge. An empty set of logs is not a clean run' };
  }
  if (records.length === 0) {
    return { ...shell, ok: false, status: STATUS.NO_RECORD, judged: false,
      reason: `none of the ${parsed.length} log(s) carries a ${RECORD} record. Either they were written by a `
        + 'plugin from before this check existed, or the plugin never installed. Whether the subject was '
        + 'observed cannot be decided from them, and it must not be assumed' };
  }

  for (const role of ROLES) shell.roles[role] = roleVerdict(role, records);

  const judged = roles.map((r) => shell.roles[r]);
  const failed = judged.filter((v) => !v.ok);
  if (failed.length === 0) {
    return { ...shell, ok: true, status: STATUS.OK, judged: true,
      reason: judged.map((v) => v.reason).join('; ') };
  }
  // The most decisive failure leads: a broken run outranks an unjudgeable one,
  // and the subject outranks the control.
  const lead = failed.find((v) => v.role === 'subject' && BROKEN.has(v.status))
    ?? failed.find((v) => BROKEN.has(v.status))
    ?? failed.find((v) => v.role === 'subject')
    ?? failed[0];
  return { ...shell, ok: false, status: lead.status, judged: BROKEN.has(lead.status),
    reason: failed.map((v) => v.reason).join('; ') };
}

/**
 * Exit code for a verdict, in the convention the observer's other checkers use:
 * 0 it holds, 2 it does not, 3 it could not be established. Three codes and not
 * two, because "the run is broken" and "this cannot be judged" call for
 * different things from whoever reads them -- and neither of them is 0.
 */
export function exitCodeFor(verdict) {
  if (verdict.ok) return 0;
  return BROKEN.has(verdict.status) ? 2 : 3;
}

/** A human-readable report; the CLI prints this. */
export function formatResolutionReport(verdict) {
  const lines = [];
  lines.push(`${verdict.ok ? 'PASS' : 'FAIL'}  subject-resolution  status=${verdict.status}`);
  lines.push(`  logs read      : ${verdict.logsRead} (${verdict.logsWithRecord} carrying ${RECORD})`);
  lines.push(`  modules walked : ${verdict.modulesSeen}`);
  for (const role of ROLES) {
    const v = verdict.roles[role];
    if (!v) continue;
    const counts = Object.entries(v.counts).map(([k, n]) => `${k}=${n}`).join(' ') || '(none)';
    const shown = v.name ?? (v.names.join('|') || '(none)');
    lines.push(`  ${role.padEnd(8)}: ${shown}  ${counts}`);
  }
  lines.push(`  reason         : ${verdict.reason}`);
  return lines.join('\n');
}
