// The ensemble merger: three tools' findings -> one list, each row labelled with
// how much of the ensemble agreed.
//
// ★★ THE CLAIM BEING OPERATIONALISED, AND THE PART OF IT THAT CANNOT BE
//
// "A finding only one tool reports needs investigation; a weakness ALL tools miss
// is the highest risk." The first half is computable from reports and is what
// `Agreement` labels. The second half is NOT computable from reports and never
// will be: a weakness every tool missed produces no row in any report, so it
// produces no row here. There is no bucket for it, `EnsembleResult.unobservable`
// says so in prose on every run, and README.md repeats it. An empty bucket would
// have been read as a count of zero, which would be this package asserting the
// strongest possible security claim — "nothing was missed" — on no evidence at
// all.
//
// ★★ AGREEMENT NEEDS TWO NORMALISATIONS AND BOTH ARE PARTIAL
//
// LOCATION. `location.ts` canonicalises separators and segments and clusters
// within `DEFAULT_LINE_TOLERANCE` lines, a tolerance taken from the two existing
// comparison scripts rather than chosen here. Partial because two tools can
// anchor the same weakness in genuinely different places (a dataflow tool at the
// sink, a lexical tool at the literal), and no tolerance small enough to be safe
// catches all of those.
//
// WEAKNESS CLASS. `weakness-class.ts` maps Semgrep check_ids and CodeQL query ids
// onto nine families copied from the two sec-transfer scripts. Partial, and
// measurably so: on the 20 recorded Semgrep results in this package's fixture, 9
// classify and 11 do not. The unmapped ones are labelled `unclassified` and are
// never labelled `unique-to-tool`, because "only Semgrep found it" is a claim
// about what the other tools did, and an unmapped finding does not license any
// claim about anyone.
//
// ★★ WHY CLUSTERING IS ANCHOR-BASED AND NOT SINGLE-LINKAGE
//
// The obvious clustering — "join any two findings within the tolerance, then take
// connected components" — is single-linkage, and it CHAINS. Findings at lines 4,
// 6, 8, 10, 12 are each within 2 of the next, so they collapse into one cluster
// spanning 8 lines; a dense file of similar findings collapses into one row
// spanning the whole function. The reported `startLine` would then name a place
// most members are nowhere near, and a row claiming three tools agree would be
// summarising three tools that pointed at three different statements.
//
// So: sort by line, take the lowest unassigned finding as the ANCHOR, absorb
// everything within the tolerance OF THE ANCHOR, start again. Every cluster spans
// at most `tolerance` lines by construction, and the reported line is a line some
// tool really reported. The cost is a boundary artifact — findings at 4 and 6
// cluster, 6 and 8 do not, so a pair straddling the boundary is reported as two
// rows — and that is the right cost to pay: a missed join is two visible rows a
// reader can reconcile, a false join destroys information no downstream consumer
// can recover.
//
// DETERMINISM. Two merges of the same inputs must produce byte-identical output,
// because a baseline diff over two runs has to be empty. Every sort key here is
// total (line, then tool order, then rule id, then finding id — no two members
// can tie on all four), every output array is sorted, and nothing consults a
// clock, a random source, or a Map iteration order that depends on insertion.

import type { Confidence, Finding, Severity } from '@vibeguard/findings-schema';
import { DEFAULT_LINE_TOLERANCE, normalizePath } from './location.js';
import type {
  Agreement,
  EnsembleMember,
  EnsembleResult,
  EnsembleToolId,
  ExternalReport,
  MappingCoverage,
  MergedFinding,
  ToolParticipation,
  ToolProvenance,
  ToolSide,
} from './types.js';
import { AGREEMENT_ORDER, ENSEMBLE_TOOL_ORDER } from './types.js';
import type { WeaknessClass } from './weakness-class.js';
import { classifyVibeguardRuleId, toolHasDetectorFor } from './weakness-class.js';

/**
 * VibeGuard's own side of the ensemble.
 *
 * `engineVersion` is the version of the engine that produced `findings` IN THIS
 * PROCESS. It is the one version in the whole result that is not read out of a
 * file, and its provenance says so (`obtainedBy: 'vibeguard-in-process'`).
 */
export interface VibeguardSide {
  findings: readonly Finding[];
  engineVersion: string | null;
}

/**
 * One ensemble run's inputs.
 *
 * ★ EVERY FIELD IS REQUIRED. Not `semgrep?: …` — required, so that "Semgrep was
 * not supplied" is something a caller has to WRITE (`notSupplied()`) rather than
 * something it produces by forgetting a key. The whole participation model is
 * defeated if the not-supplied state is the one you get by accident, because the
 * accident is silent and the consequence is a report that reads as if two engines
 * had looked.
 */
export interface EnsembleInput {
  vibeguard: ToolSide<VibeguardSide>;
  semgrep: ToolSide<ExternalReport>;
  codeql: ToolSide<ExternalReport>;
  /** Defaults to `DEFAULT_LINE_TOLERANCE`. Recorded in the result so a clustering can be reproduced. */
  lineTolerance?: number;
}

/** The standing caveat, emitted verbatim on every run. See the header. */
const UNOBSERVABLE_NOTE =
  'This merge can only classify weaknesses at least one tool REPORTED. A weakness every tool missed '
  + 'produces no row in any report and therefore no row here — it is unobservable from reports alone, '
  + 'and the absence of such rows is not evidence that there are none. The closest observable proxy is '
  + 'the unique-to-tool bucket: a weakness one engine saw and another engine, which was looking for that '
  + 'class, did not.';

/** Internal working shape: one finding from one tool, ready to cluster. */
interface Candidate {
  tool: EnsembleToolId;
  weaknessClass: WeaknessClass | null;
  filePath: string;
  startLine: number;
  member: EnsembleMember;
  /** Stable tiebreak so the sort is total. */
  sortKey: string;
}

/**
 * Merge whatever participated into one labelled list.
 *
 * Pure: no I/O, no clock, no randomness. The same `EnsembleInput` always produces
 * the same `EnsembleResult`.
 */
export function mergeEnsemble(input: EnsembleInput): EnsembleResult {
  const lineTolerance = input.lineTolerance ?? DEFAULT_LINE_TOLERANCE;

  const participation: ToolParticipation[] = [];
  const candidates: Candidate[] = [];
  const participatingTools: EnsembleToolId[] = [];

  // ---- VibeGuard side -----------------------------------------------------
  {
    const side = input.vibeguard;
    if (side.kind === 'report') {
      const provenance: ToolProvenance = {
        tool: 'vibeguard',
        // The field is named for the common case (a version read out of a
        // report). On this side it is the engine version of the process that
        // produced the findings, and `obtainedBy` is what tells the two apart.
        // One shape for all three tools is worth the slightly odd field name;
        // two shapes would mean every consumer branches before it can print a
        // version.
        versionFromReport: side.report.engineVersion,
        reportPath: null,
        obtainedBy: 'vibeguard-in-process',
      };
      let refusedCount = 0;
      for (const finding of side.report.findings) {
        // Same refusal as the adapters, for the same reason: a finding with no
        // file or no line cannot be clustered, and giving it line 1 would make it
        // a peer of whatever really is on line 1. Snippet scans (`targetType:
        // 'snippet'`) legitimately produce findings with no `filePath`, so this
        // is a real population, not a defensive branch.
        if (finding.filePath === undefined || finding.startLine === undefined) {
          refusedCount += 1;
          continue;
        }
        const filePath = normalizePath(finding.filePath);
        candidates.push({
          tool: 'vibeguard',
          weaknessClass: classifyVibeguardRuleId(finding.ruleId),
          filePath,
          startLine: finding.startLine,
          member: {
            tool: 'vibeguard',
            toolRuleId: finding.ruleId,
            severity: finding.severity,
            confidence: finding.confidence,
            filePath,
            startLine: finding.startLine,
            message: finding.title,
            provenance,
          },
          sortKey: finding.findingId,
        });
      }
      participatingTools.push('vibeguard');
      participation.push({
        tool: 'vibeguard',
        status: 'participated',
        detail: `VibeGuard ran in this process${side.report.engineVersion === null ? '' : ` (engine ${side.report.engineVersion})`}.`,
        provenance,
        findingCount: side.report.findings.length - refusedCount,
        refusedCount,
        toolReportedErrors: [],
      });
    } else {
      participation.push(absentParticipation('vibeguard', side));
    }
  }

  // ---- External sides -----------------------------------------------------
  for (const tool of ['semgrep', 'codeql'] as const) {
    const side = tool === 'semgrep' ? input.semgrep : input.codeql;
    if (side.kind !== 'report') {
      participation.push(absentParticipation(tool, side));
      continue;
    }
    const report = side.report;
    for (const finding of report.findings) {
      candidates.push({
        tool,
        weaknessClass: finding.weaknessClass,
        filePath: finding.filePath ?? '',
        startLine: finding.startLine ?? 0,
        member: {
          tool,
          toolRuleId: finding.toolRuleId,
          severity: finding.severity,
          confidence: finding.confidence,
          filePath: finding.filePath ?? '',
          startLine: finding.startLine ?? 0,
          message: finding.title,
          provenance: finding.provenance,
        },
        sortKey: finding.findingId,
      });
    }
    participatingTools.push(tool);
    participation.push({
      tool,
      status: 'participated',
      detail:
        `${toolLabel(tool)} report supplied by the user at ${report.provenance.reportPath ?? '<unknown path>'}`
        + `${report.provenance.versionFromReport === null ? ' (report states no version)' : ` (report states version ${report.provenance.versionFromReport})`}`
        + `. VibeGuard did NOT run ${toolLabel(tool)}; these findings are read from that file.`,
      provenance: report.provenance,
      findingCount: report.findings.length,
      refusedCount: report.refused.length,
      toolReportedErrors: report.toolReportedErrors,
    });
  }

  // ---- Participation gate -------------------------------------------------
  // ★ EVERY AGREEMENT LABEL IS GATED ON THIS. With one participant, "unique to
  // VibeGuard" is true of every single finding and means nothing at all — it is a
  // restatement of the input, dressed as a comparison. Emitting it would be the
  // most misleading output this package could produce, because it looks exactly
  // like the output of a real three-tool run.
  const agreementComputable = participatingTools.length >= 2;
  const agreementNotComputableReason = agreementComputable
    ? null
    : participatingTools.length === 0
      ? 'no tool participated: there is nothing to compare.'
      : `only ${toolLabel(participatingTools[0] as EnsembleToolId)} participated. Agreement is a statement about `
        + 'two or more engines; with one engine every finding would be trivially "unique to" it, which says '
        + 'nothing about the code and everything about the ensemble being empty.';

  const absent = participation.filter((p) => p.status !== 'participated');
  const degraded = absent.length > 0;
  const degradedNotice = degraded ? buildDegradedNotice(absent, participatingTools) : null;

  // ---- Cluster ------------------------------------------------------------
  const merged = clusterCandidates(candidates, lineTolerance, participatingTools, agreementComputable);

  const byAgreement = Object.fromEntries(AGREEMENT_ORDER.map((a) => [a, 0])) as Record<Agreement, number>;
  for (const row of merged) byAgreement[row.agreement] += 1;

  return {
    participation,
    participatingTools: sortTools(participatingTools),
    degraded,
    degradedNotice,
    agreementComputable,
    agreementNotComputableReason,
    merged,
    byAgreement,
    mappingCoverage: buildMappingCoverage(candidates),
    unobservable: UNOBSERVABLE_NOTE,
    lineTolerance,
  };
}

/**
 * The printable one-liner the CLI is required to emit when the ensemble is short
 * a tool.
 *
 * Written to be quoted verbatim rather than summarised, and written to name the
 * DIFFERENCE explicitly ("no findings" vs "never ran") because that difference is
 * the whole reason the notice exists. A notice that said only "running in
 * degraded mode" would be technically true and would not stop a reader from
 * treating the absent tool's silence as agreement.
 */
function buildDegradedNotice(absent: ToolParticipation[], participating: EnsembleToolId[]): string {
  const clauses = absent.map((p) =>
    p.status === 'not-supplied'
      ? `${toolLabel(p.tool)} was NOT run (no report supplied)`
      : `${toolLabel(p.tool)} was NOT usable (${p.detail})`,
  );
  const ran =
    participating.length === 0
      ? 'No tool participated'
      : `Only ${sortTools(participating).map(toolLabel).join(' and ')} participated`;
  return (
    `ENSEMBLE DEGRADED — ${clauses.join('; ')}. ${ran}. `
    + 'Absent tools reported nothing because they were never asked, not because they found nothing: '
    + '"no findings from this tool" and "this tool was never run" are different facts, and only the first '
    + 'is evidence. Nothing below may be read as corroborated or contradicted by an absent tool.'
  );
}

function absentParticipation<R>(tool: EnsembleToolId, side: ToolSide<R>): ToolParticipation {
  if (side.kind === 'unreadable') {
    return {
      tool,
      status: 'report-unreadable',
      detail: `a ${toolLabel(tool)} report was supplied at ${side.reportPath} but could not be read: ${side.reason}`,
      provenance: null,
      findingCount: null,
      refusedCount: null,
      toolReportedErrors: [],
    };
  }
  return {
    tool,
    status: 'not-supplied',
    detail:
      tool === 'vibeguard'
        ? 'VibeGuard findings were not supplied to this merge.'
        : `no ${toolLabel(tool)} report was supplied. ${toolLabel(tool)} was not run and its silence is not evidence.`,
    provenance: null,
    findingCount: null,
    refusedCount: null,
    toolReportedErrors: [],
  };
}

/**
 * Group candidates into merged rows.
 *
 * Classified and unclassified candidates take different paths, and they must.
 * Two unclassified findings at the same line might be the same weakness or might
 * be two of the six different things Semgrep says about
 * `samples/vulnerable/express_session.js:14` in this package's real fixture
 * (a missing HttpOnly flag, a missing Secure flag, a missing domain, a missing
 * expiry, a default name, and a hardcoded secret — six rules, at least three
 * genuinely distinct weaknesses, all on one line). Clustering them by location
 * alone would collapse those six into one row and present it as six findings
 * agreeing about a line where they agree about nothing. So an unclassified
 * candidate is always its own row.
 */
function clusterCandidates(
  candidates: readonly Candidate[],
  lineTolerance: number,
  participatingTools: readonly EnsembleToolId[],
  agreementComputable: boolean,
): MergedFinding[] {
  const rows: MergedFinding[] = [];

  // -- unclassified: one row each, no agreement claim -----------------------
  for (const candidate of candidates) {
    if (candidate.weaknessClass !== null) continue;
    rows.push({
      weaknessClass: null,
      filePath: candidate.filePath,
      startLine: candidate.startLine,
      agreement: agreementComputable ? 'unclassified' : 'not-computable',
      reportedBy: [candidate.tool],
      // Empty, not "every tool": with no class there is no family record, so
      // there is no set of tools that could have been looking for this.
      couldHaveBeenReportedBy: [],
      silentTools: [],
      members: [candidate.member],
    });
  }

  // -- classified: anchor-clustered within (class, file) --------------------
  const groups = new Map<string, Candidate[]>();
  for (const candidate of candidates) {
    if (candidate.weaknessClass === null) continue;
    // NUL is the separator because it cannot occur in a weakness class (a closed
    // union of kebab-case literals) or in a normalised path. A `:` or `#` would
    // be ambiguous against a Windows drive letter or a path containing one.
    const key = `${candidate.weaknessClass}\u0000${candidate.filePath}`;
    const bucket = groups.get(key);
    if (bucket === undefined) groups.set(key, [candidate]);
    else bucket.push(candidate);
  }

  for (const key of [...groups.keys()].sort()) {
    const bucket = groups.get(key) as Candidate[];
    // Total order: line, then tool position, then rule id, then finding id. No
    // two candidates can tie on all four (the last is unique per tool per
    // report), so the sort is stable without relying on the engine's stability.
    bucket.sort(
      (a, b) =>
        a.startLine - b.startLine
        || toolIndex(a.tool) - toolIndex(b.tool)
        || a.member.toolRuleId.localeCompare(b.member.toolRuleId)
        || a.sortKey.localeCompare(b.sortKey),
    );

    let i = 0;
    while (i < bucket.length) {
      const anchor = bucket[i] as Candidate;
      const members: Candidate[] = [anchor];
      let j = i + 1;
      // Absorb against the ANCHOR's line, never against the last absorbed line.
      // That is the whole anti-chaining property; see the header.
      while (j < bucket.length && (bucket[j] as Candidate).startLine - anchor.startLine <= lineTolerance) {
        members.push(bucket[j] as Candidate);
        j += 1;
      }
      i = j;

      const weaknessClass = anchor.weaknessClass as WeaknessClass;
      const reportedBy = sortTools([...new Set(members.map((m) => m.tool))]);
      const couldHaveBeenReportedBy = sortTools(
        participatingTools.filter((t) => toolHasDetectorFor(t, weaknessClass)),
      );
      const silentTools = couldHaveBeenReportedBy.filter((t) => !reportedBy.includes(t));

      rows.push({
        weaknessClass,
        filePath: anchor.filePath,
        startLine: anchor.startLine,
        agreement: agreementComputable
          ? classifyAgreement(reportedBy.length, couldHaveBeenReportedBy.length)
          : 'not-computable',
        reportedBy,
        couldHaveBeenReportedBy,
        silentTools,
        members: members.map((m) => m.member),
      });
    }
  }

  // Output order is a total order over the rows themselves, so two merges of the
  // same inputs emit the same list: file, then line, then class (`''` for
  // unclassified sorts first), then the first rule id in the row.
  rows.sort(
    (a, b) =>
      a.filePath.localeCompare(b.filePath)
      || a.startLine - b.startLine
      || (a.weaknessClass ?? '').localeCompare(b.weaknessClass ?? '')
      || (a.members[0]?.toolRuleId ?? '').localeCompare(b.members[0]?.toolRuleId ?? ''),
  );
  return rows;
}

/**
 * The label, from two counts.
 *
 * ★ THE ORDER OF THESE BRANCHES IS THE ARGUMENT. `sole-detector` is tested
 * FIRST, before `unanimous`, because a class only one participating tool has a
 * detector for satisfies `reported === could` trivially — one tool reported it,
 * one tool could have — and would otherwise be labelled `unanimous`. "All tools
 * agreed" about a weakness only one tool can even see is the most overstated
 * output this package could emit, and it is one `if` away at all times.
 */
function classifyAgreement(reportedCount: number, couldCount: number): Agreement {
  if (couldCount < 2) return 'sole-detector';
  if (reportedCount >= couldCount) return 'unanimous';
  if (reportedCount >= 2) return 'corroborated';
  return 'unique-to-tool';
}

function buildMappingCoverage(candidates: readonly Candidate[]): MappingCoverage {
  const byTool: Record<string, { classified: number; unclassified: number }> = {};
  const unmapped = new Set<string>();
  let classified = 0;
  for (const candidate of candidates) {
    const bucket = (byTool[candidate.tool] ??= { classified: 0, unclassified: 0 });
    if (candidate.weaknessClass === null) {
      bucket.unclassified += 1;
      unmapped.add(`${candidate.tool}:${candidate.member.toolRuleId}`);
    } else {
      bucket.classified += 1;
      classified += 1;
    }
  }
  return {
    totalFindings: candidates.length,
    classified,
    unclassified: candidates.length - classified,
    byTool,
    unmappedRuleIds: [...unmapped].sort(),
  };
}

function toolIndex(tool: EnsembleToolId): number {
  const i = ENSEMBLE_TOOL_ORDER.indexOf(tool);
  return i === -1 ? ENSEMBLE_TOOL_ORDER.length : i;
}

function sortTools(tools: readonly EnsembleToolId[]): EnsembleToolId[] {
  return [...tools].sort((a, b) => toolIndex(a) - toolIndex(b));
}

function toolLabel(tool: EnsembleToolId): string {
  return tool === 'vibeguard' ? 'VibeGuard' : tool === 'semgrep' ? 'Semgrep' : 'CodeQL';
}

/**
 * Severity and confidence of a merged row, for a renderer that needs one of each.
 *
 * ★ THE MAXIMUM, NOT AN AVERAGE OR THE FIRST TOOL'S. An average of an ordinal
 * scale is meaningless (there is no severity halfway between `high` and `low`
 * that any rule assigned), and taking the first tool's would make the answer
 * depend on `ENSEMBLE_TOOL_ORDER`, i.e. on a display constant. The maximum is the
 * only choice that cannot be gamed by adding a tool: a second opinion can raise
 * the alarm, never lower it, which is the correct direction for a security
 * artifact.
 *
 * Not a field on `MergedFinding` because it is a rendering decision, and baking
 * it into the data would let a renderer that disagrees have no way to recompute
 * it — the per-tool values are all still on `members`.
 */
export function mergedSeverity(row: MergedFinding): Severity {
  const order: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
  let best = 0;
  for (const member of row.members) best = Math.max(best, order.indexOf(member.severity));
  return order[best] as Severity;
}

/** Companion to `mergedSeverity`, same maximum argument. */
export function mergedConfidence(row: MergedFinding): Confidence {
  const order: Confidence[] = ['low', 'medium', 'high'];
  let best = 0;
  for (const member of row.members) best = Math.max(best, order.indexOf(member.confidence));
  return order[best] as Confidence;
}
