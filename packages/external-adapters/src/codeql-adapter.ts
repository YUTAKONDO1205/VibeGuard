// CodeQL SARIF 2.1.0 report -> ExternalFinding[].
//
// ★★ THIS ADAPTER IS WRITTEN AGAINST A SPECIFICATION, NOT AGAINST A TOOL, AND
//    THAT IS A WEAKER FORM OF EVIDENCE THAN THE SEMGREP ADAPTER HAS
//
// There is no recorded CodeQL output anywhere in this repository. Checked:
// paper_data/ (which holds recorded Semgrep and Bandit artifacts) and
// security-experiment/_results/ (which holds transfer-semgrep.json but no
// transfer-codeql.json with results). The CodeQL CLI is not installed on the
// machine this was written on. `scripts/sec-transfer-codeql.mjs` is in the same
// position and says so in its own header at length: its query-id patterns are
// "correct-by-construction from CodeQL's PUBLISHED query ids (github/codeql), NOT
// yet confirmed on this corpus".
//
// So the fixture beside this file is marked SCHEMA-DERIVED, NOT TOOL-RECORDED,
// and the two fixtures in this package are not equal evidence:
//
//   semgrep-samples-vulnerable.json   bytes a real Semgrep 1.165.0 produced
//   codeql-schema-derived.sarif       bytes a human wrote from the SARIF spec
//
// A test proves the Semgrep adapter agrees with the shipped Semgrep parser on
// real output. No such test can exist here, and pretending otherwise by writing a
// fixture that LOOKS recorded would be the single most damaging thing this
// package could do — it would make an unverified parser indistinguishable from a
// verified one for every future reader.
//
// ★★ WHY SARIF IS PARSED PROPERLY INSTEAD OF SHALLOWLY
//
// `sec-transfer-codeql.mjs` reads SARIF in six lines:
//
//     const loc = r.locations?.[0]?.physicalLocation;
//     const uri = loc?.artifactLocation?.uri ?? '';
//     const line = Number(loc?.region?.startLine ?? 0);
//     const ruleId = String(r.ruleId ?? r.rule?.id ?? '');
//
// That is correct for the one thing it needs (a rule id and a place) and it is
// not enough here, because this package has to produce a `Finding`, which needs a
// severity, and severity in SARIF is not a field on the result. It is a chain:
//
//   result.level                                          (SARIF 3.27.10)
//     -> the rule's defaultConfiguration.level            (SARIF 3.27.10, 3.49.14)
//       -> "warning"                                      (SARIF 3.27.10 default)
//
// and the rule descriptor is not necessarily in `tool.driver.rules` — CodeQL puts
// query rules in `tool.extensions[].rules`, one component per query pack, and
// results point at them with `rule.toolComponent.index` (SARIF 3.19.31, 3.52.3).
// A parser that only looked in `driver.rules` would find no descriptor for any
// CodeQL result, fall through to "warning", and silently render every CodeQL
// finding as `medium` — including `py/command-line-injection`, whose published
// security-severity is 9.8. That failure is invisible: nothing crashes, every
// finding is present, and the severities are all quietly wrong. The fixture
// exercises all three levels of the chain for exactly this reason.
//
// ★ WHAT IS REFUSED, AND WHY REFUSAL IS THE SAFE DIRECTION HERE
//
// A result whose `physicalLocation` carries no `region.startLine` is dropped into
// `refused` rather than placed at line 1. SARIF permits a file-level result and
// CodeQL emits them for some queries. Placing one at line 1 would make it a
// cluster peer of whatever really is on line 1, so a file-level advisory could be
// merged with a real finding and reported as corroborating it. The merged row
// would then claim two tools agree about a line only one of them named.

import type { Confidence, Severity } from '@vibeguard/findings-schema';
import { normalizeReportPath } from './location.js';
import type { AdapterOptions, ExternalFinding, ExternalReport, RefusedResult, ToolProvenance } from './types.js';
import { ExternalReportError } from './types.js';
import { classifyCodeqlRuleId } from './weakness-class.js';

/**
 * SARIF `level` -> VibeGuard severity. SARIF 2.1.0 3.27.10 fixes the value set
 * at exactly these four, so unlike the Semgrep table this one is total over the
 * specification and an unknown value means the report is not conformant.
 *
 * ★ `error` MAPS TO `high`, NOT `critical`, for the same reason Semgrep's ERROR
 * does: `critical` is reserved for a VibeGuard rule's own judgement, and
 * promoting another tool's top band into it would systematically out-rank the
 * engine that actually ran here.
 */
const SARIF_LEVEL_TO_SEVERITY: Record<string, Severity> = {
  error: 'high',
  warning: 'medium',
  note: 'low',
  none: 'info',
};

/** SARIF 2.1.0 3.27.10: when neither the result nor the rule states a level, it is `warning`. */
const SARIF_DEFAULT_LEVEL = 'warning';

/** Where a non-conformant `level` string lands. Same neutral-middle argument as the Semgrep adapter. */
const UNKNOWN_SEVERITY: Severity = 'medium';

/**
 * CodeQL rule `properties.precision` -> VibeGuard confidence.
 *
 * ★ THIS IS THE INVERSE OF A MAPPING THIS REPOSITORY ALREADY WRITES.
 * `packages/sarif-adapter/src/index.ts` emits `properties.precision` derived from
 * a finding's confidence (`CONFIDENCE_TO_PRECISION`), with the note "VibeGuard is
 * a regex-first scanner, so nothing here claims very-high". Reading the field
 * back with the inverse mapping means a VibeGuard SARIF file round-trips through
 * this adapter without changing confidence, which is a property worth having and
 * would have been lost had this invented its own scale.
 *
 * `very-high` has no VibeGuard counterpart above `high`, so it maps to `high`.
 * That is a ceiling, not an equivalence, and it is the only direction available:
 * `Confidence` has three bands.
 */
const PRECISION_TO_CONFIDENCE: Record<string, Confidence> = {
  'very-high': 'high',
  high: 'high',
  medium: 'medium',
  low: 'low',
};

/**
 * Confidence for a result whose rule declared no precision.
 *
 * `medium` for the reason the Semgrep adapter's default is `medium`: precision is
 * rule metadata, its absence is a statement about the query pack rather than
 * about this match, and letting a missing property push findings below the
 * project's confidence filters would turn someone else's metadata gap into
 * deleted findings.
 */
const UNKNOWN_CONFIDENCE: Confidence = 'medium';

/** A rule descriptor as this adapter needs it, flattened out of driver + extensions. */
interface RuleDescriptor {
  id: string;
  name: string | null;
  shortDescription: string | null;
  defaultLevel: string | null;
  precision: string | null;
  securitySeverity: string | null;
  cweIds: string[];
}

/**
 * Parse a SARIF 2.1.0 log produced by CodeQL.
 *
 * Same contract as `parseSemgrepReport`: takes text, never touches the
 * filesystem, throws `ExternalReportError` on a document that is not a SARIF log
 * rather than returning an empty one.
 *
 * ★ NOT NAMED `parseSarifReport`, THOUGH IT IS A GENERIC SARIF PARSER.
 * Every other tool in the ecosystem emits SARIF too — Semgrep does, with
 * `--sarif` — and a generic name would invite feeding it their output. It would
 * mostly work, and the weakness classification would be silently wrong for all of
 * it, because `classifyCodeqlRuleId` matches CodeQL query-id shapes (`py/...`,
 * `js/...`) and nothing else. A merged report would then show every Semgrep-via-
 * SARIF finding as `unclassified` with no indication why. The narrow name is the
 * warning.
 */
export function parseCodeqlSarifReport(reportText: string, options: AdapterOptions): ExternalReport {
  const { reportPath, rootDir } = options;

  let root: unknown;
  try {
    root = JSON.parse(reportText);
  } catch (err) {
    throw new ExternalReportError(
      'codeql',
      reportPath,
      `not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (root === null || typeof root !== 'object' || Array.isArray(root)) {
    throw new ExternalReportError('codeql', reportPath, 'top level is not a JSON object');
  }
  const doc = root as Record<string, unknown>;

  const runs = doc['runs'];
  if (!Array.isArray(runs)) {
    throw new ExternalReportError(
      'codeql',
      reportPath,
      'no "runs" array — this does not look like a SARIF 2.1.0 log '
        + '(a `semgrep --json` file needs the Semgrep adapter instead)',
    );
  }
  // The version is checked and reported but NOT enforced. SARIF 2.1.0 is the only
  // version CodeQL emits and the only one this parser was written against, so a
  // different value is worth surfacing; refusing outright would break on a future
  // 2.2 whose result shape is unchanged, and a parser that refuses a document it
  // would have read correctly is its own kind of wrong answer.
  const sarifVersion = typeof doc['version'] === 'string' ? doc['version'] : null;

  const findings: ExternalFinding[] = [];
  const refused: RefusedResult[] = [];
  const toolReportedErrors: string[] = [];
  const idCounts = new Map<string, number>();
  let driverVersion: string | null = null;
  // Result indices are reported per-run in `refused`, so a multi-run log stays
  // navigable. CodeQL emits one run per database; a repository analysed for three
  // languages produces three runs in one file, and collapsing their indices would
  // make `refused[].index` unusable for finding the offending result.
  let globalIndex = 0;

  for (const runValue of runs) {
    if (runValue === null || typeof runValue !== 'object') continue;
    const run = runValue as Record<string, unknown>;

    const components = collectToolComponents(run['tool']);
    if (driverVersion === null) driverVersion = readDriverVersion(run['tool']);
    toolReportedErrors.push(...readInvocationNotifications(run['invocations']));

    const results = run['results'];
    if (!Array.isArray(results)) continue;

    for (const resultValue of results) {
      const index = globalIndex;
      globalIndex += 1;
      if (resultValue === null || typeof resultValue !== 'object') {
        refused.push({ index, toolRuleId: '', reason: 'result is not an object' });
        continue;
      }
      const result = resultValue as Record<string, unknown>;

      const ruleRef = result['rule'] as { id?: unknown; index?: unknown; toolComponent?: { index?: unknown } } | undefined;
      // `r.ruleId ?? r.rule?.id` is sec-transfer-codeql.mjs's order and is kept.
      const codeqlRuleId =
        typeof result['ruleId'] === 'string'
          ? result['ruleId']
          : typeof ruleRef?.id === 'string'
            ? ruleRef.id
            : '';
      if (codeqlRuleId === '') {
        refused.push({ index, toolRuleId: '', reason: 'no ruleId and no rule.id — the finding cannot be attributed to a query' });
        continue;
      }

      const descriptor = resolveDescriptor(components, codeqlRuleId, ruleRef);

      const location = Array.isArray(result['locations']) ? (result['locations'] as unknown[])[0] : undefined;
      const physical = readPhysicalLocation(location);
      if (physical === null) {
        refused.push({ index, toolRuleId: codeqlRuleId, reason: 'no physicalLocation on the first location — the finding cannot be located, so it is not merged' });
        continue;
      }
      if (physical.startLine === null) {
        refused.push({
          index,
          toolRuleId: codeqlRuleId,
          reason: 'physicalLocation carries no region.startLine (a SARIF file-level result) — placing it at line 1 would let it merge with whatever is on line 1, so it is not merged',
        });
        continue;
      }
      if (physical.uri === '') {
        refused.push({ index, toolRuleId: codeqlRuleId, reason: 'artifactLocation has no uri — the finding cannot be located, so it is not merged' });
        continue;
      }

      const filePath = normalizeReportPath(physical.uri, rootDir);
      const rawLevel = typeof result['level'] === 'string' ? result['level'] : null;
      // The full SARIF 3.27.10 defaulting chain. `effectiveLevel` is what the
      // severity is mapped from; `rawSeverity` records the level the RESULT
      // itself stated, which is `null` when it stated none — the two are kept
      // apart so a reader can see that a `medium` came from a rule default rather
      // than from the result.
      const effectiveLevel = rawLevel ?? descriptor?.defaultLevel ?? SARIF_DEFAULT_LEVEL;
      const precision = descriptor?.precision ?? null;
      const cweIds = descriptor?.cweIds ?? [];
      const message = readMessageText(result['message']);
      const weaknessClass = classifyCodeqlRuleId(codeqlRuleId);

      const ruleId = `codeql:${codeqlRuleId}`;
      const idKey = `${filePath}:${physical.startLine}:${ruleId}`;
      const seen = idCounts.get(idKey) ?? 0;
      idCounts.set(idKey, seen + 1);

      findings.push({
        findingId: seen === 0 ? idKey : `${idKey}#${seen + 1}`,
        ruleId,
        title: descriptor?.shortDescription ?? descriptor?.name ?? codeqlRuleId,
        description: message,
        severity: SARIF_LEVEL_TO_SEVERITY[effectiveLevel] ?? UNKNOWN_SEVERITY,
        confidence: precision !== null ? PRECISION_TO_CONFIDENCE[precision] ?? UNKNOWN_CONFIDENCE : UNKNOWN_CONFIDENCE,
        category: 'external-codeql',
        filePath,
        startLine: physical.startLine,
        endLine: physical.endLine ?? undefined,
        startColumn: physical.startColumn ?? undefined,
        endColumn: physical.endColumn ?? undefined,
        evidence: [
          `codeql.ruleId=${codeqlRuleId}`,
          `sarif.result.level=${rawLevel ?? '<absent>'}`,
          `sarif.rule.defaultConfiguration.level=${descriptor?.defaultLevel ?? '<absent>'}`,
          `sarif.level.effective=${effectiveLevel}`,
          `codeql.precision=${precision ?? '<absent>'}`,
          // Carried verbatim and NOT converted into a severity band. GitHub's
          // documented thresholds (9.0+ critical, 7.0+ high, …) would let this
          // number override `level`, and that is a second unverified layer on top
          // of an adapter no CodeQL run has ever exercised. One unverified layer
          // is the cost of the environment; two would be a choice.
          `codeql.security-severity=${descriptor?.securitySeverity ?? '<absent>'}`,
          ...(cweIds.length > 0 ? [`codeql.cwe=${cweIds.join(',')}`] : []),
        ],
        // `'external'` rather than `'semgrep'`: the schema's `SourceEngine` union
        // has exactly one slot for a non-Semgrep external tool and this is it.
        sourceEngine: 'external',
        provenance: {
          tool: 'codeql',
          versionFromReport: driverVersion,
          reportPath,
          obtainedBy: 'user-supplied-report',
        },
        weaknessClass,
        toolRuleId: codeqlRuleId,
        rawSeverity: rawLevel,
        cweIds,
      });
    }
  }

  const provenance: ToolProvenance = {
    tool: 'codeql',
    versionFromReport: driverVersion,
    reportPath,
    obtainedBy: 'user-supplied-report',
  };
  // Provenance is built once at the end so every finding and the report share one
  // object identity — but the findings above were built inside the loop, before
  // `driverVersion` was necessarily known for a later run. Re-point them, so a
  // reader never sees two different version strings inside one report.
  for (const finding of findings) finding.provenance = provenance;

  if (sarifVersion !== null && sarifVersion !== '2.1.0') {
    toolReportedErrors.push(
      `SARIF version is "${sarifVersion}"; this adapter was written against 2.1.0. Parsed anyway — verify the result shapes.`,
    );
  }

  return {
    tool: 'codeql',
    provenance,
    findings,
    refused,
    toolReportedErrors,
    // ★ ALWAYS EMPTY, AND THE EMPTINESS MEANS "UNKNOWN", NOT "NOTHING".
    // SARIF can express the analysed file set (`runs[].artifacts[]`), but CodeQL
    // populates it with the artifacts its RESULTS reference, not with everything
    // the extractor read — so treating it as coverage would understate the scan
    // by exactly the files that were clean, which is the population the
    // "both tools looked and agreed" claim rests on. Reporting nothing is
    // honest; reporting the results' own files as the scanned set is not.
    scannedPaths: [],
  };
}

/**
 * Every rule descriptor in the run, from `tool.driver` and every
 * `tool.extensions[]`, in component order.
 *
 * Returned as a list of components rather than one flat map because SARIF
 * addresses a rule by (component index, rule index) and two components may
 * legitimately hold the same rule id — `codeql/python-queries` and
 * `codeql/javascript-queries` both ship rules whose ids differ only by language
 * prefix, but a customer query pack can ship a rule id that collides with a
 * standard one. Flattening first would resolve such a pair by whichever came
 * last.
 */
function collectToolComponents(toolValue: unknown): RuleDescriptor[][] {
  if (toolValue === null || typeof toolValue !== 'object') return [];
  const tool = toolValue as Record<string, unknown>;
  const components: RuleDescriptor[][] = [];

  // SARIF 3.19.31: toolComponent index 0 is the driver; extensions are indexed
  // from 0 in their own array. CodeQL's results reference extensions, and a
  // result with no `rule.toolComponent` refers to the driver. Both are kept, in
  // that order, and `resolveDescriptor` knows which array an index belongs to.
  const driver = tool['driver'];
  components.push(readRuleArray(driver));
  const extensions = tool['extensions'];
  if (Array.isArray(extensions)) {
    for (const ext of extensions) components.push(readRuleArray(ext));
  }
  return components;
}

function readRuleArray(componentValue: unknown): RuleDescriptor[] {
  if (componentValue === null || typeof componentValue !== 'object') return [];
  const rules = (componentValue as Record<string, unknown>)['rules'];
  if (!Array.isArray(rules)) return [];
  const out: RuleDescriptor[] = [];
  for (const ruleValue of rules) {
    if (ruleValue === null || typeof ruleValue !== 'object') continue;
    const rule = ruleValue as Record<string, unknown>;
    const id = typeof rule['id'] === 'string' ? rule['id'] : '';
    if (id === '') continue;
    const properties = (rule['properties'] ?? null) as Record<string, unknown> | null;
    const defaultConfiguration = (rule['defaultConfiguration'] ?? null) as Record<string, unknown> | null;
    out.push({
      id,
      name: typeof rule['name'] === 'string' ? rule['name'] : null,
      shortDescription: readMessageTextOrNull(rule['shortDescription']),
      defaultLevel: typeof defaultConfiguration?.['level'] === 'string' ? (defaultConfiguration['level'] as string) : null,
      precision: typeof properties?.['precision'] === 'string' ? (properties['precision'] as string) : null,
      securitySeverity:
        typeof properties?.['security-severity'] === 'string' ? (properties['security-severity'] as string) : null,
      cweIds: readCwesFromTags(properties?.['tags']),
    });
  }
  return out;
}

/**
 * Find the descriptor for a result.
 *
 * Order: the (component, index) pair the result gives, then a search by id
 * across every component. The index path is first because it is what SARIF
 * defines and what CodeQL emits; the id search exists because a result may carry
 * only `ruleId` (the fixture has one such result), and because an index that
 * points outside its component's array is a malformed report from which the id is
 * still recoverable.
 *
 * ★ AN UNRESOLVED DESCRIPTOR IS `undefined`, NOT A SYNTHESISED DEFAULT.
 * A fabricated descriptor with `defaultLevel: 'warning'` would be
 * indistinguishable at the call site from a real rule that really does default to
 * warning, and the evidence line `sarif.rule.defaultConfiguration.level=<absent>`
 * — which is how a reader spots a report whose rules failed to resolve — would
 * become a lie.
 */
function resolveDescriptor(
  components: RuleDescriptor[][],
  ruleId: string,
  ruleRef: { index?: unknown; toolComponent?: { index?: unknown } } | undefined,
): RuleDescriptor | undefined {
  const ruleIndex = typeof ruleRef?.index === 'number' ? ruleRef.index : null;
  const componentIndex = typeof ruleRef?.toolComponent?.index === 'number' ? ruleRef.toolComponent.index : null;
  if (ruleIndex !== null) {
    // `toolComponent.index` indexes the EXTENSIONS array; components[0] is the
    // driver, so an extension index of n lives at components[n + 1]. A result
    // with no toolComponent refers to the driver, i.e. components[0].
    const component = components[componentIndex === null ? 0 : componentIndex + 1];
    const byIndex = component?.[ruleIndex];
    if (byIndex !== undefined && byIndex.id === ruleId) return byIndex;
  }
  for (const component of components) {
    for (const descriptor of component) {
      if (descriptor.id === ruleId) return descriptor;
    }
  }
  return undefined;
}

interface PhysicalLocation {
  uri: string;
  startLine: number | null;
  endLine: number | null;
  startColumn: number | null;
  endColumn: number | null;
}

/**
 * The first location's physical location.
 *
 * ★ ONLY THE FIRST, matching `r.locations?.[0]?.physicalLocation` in
 * sec-transfer-codeql.mjs. A CodeQL result carries its sink as `locations[0]` and
 * everything else — the source, the intermediate steps — as `relatedLocations`
 * and `codeFlows`. Merging on any location other than the first would anchor a
 * dataflow finding at the point where untrusted data ENTERED rather than where it
 * was used, and the tools this is merged against all report the use site.
 * `relatedLocations` are deliberately not carried: `Finding` has no field for
 * them (that is `DesignSmellFinding.relatedLocations`, a different partition),
 * and inventing one here would put a second kind of finding in the same channel.
 */
function readPhysicalLocation(locationValue: unknown): PhysicalLocation | null {
  if (locationValue === null || typeof locationValue !== 'object') return null;
  const physical = (locationValue as Record<string, unknown>)['physicalLocation'];
  if (physical === null || typeof physical !== 'object') return null;
  const phys = physical as Record<string, unknown>;
  const artifact = (phys['artifactLocation'] ?? null) as Record<string, unknown> | null;
  const region = (phys['region'] ?? null) as Record<string, unknown> | null;
  const rawUri = typeof artifact?.['uri'] === 'string' ? (artifact['uri'] as string) : '';
  return {
    uri: decodeArtifactUri(rawUri),
    startLine: readInt(region?.['startLine']),
    endLine: readInt(region?.['endLine']),
    startColumn: readInt(region?.['startColumn']),
    endColumn: readInt(region?.['endColumn']),
  };
}

/**
 * `artifactLocation.uri` is a URI reference (SARIF 3.4.1), so a space in a path
 * arrives as `%20`.
 *
 * ★ DECODED, WITH A FALLBACK, AND THE FALLBACK IS THE INTERESTING HALF.
 * Not decoding would mean `samples/legacy%20client/x.js` never joins with
 * VibeGuard's `samples/legacy client/x.js`, so every finding in any path
 * containing a space would silently fail to corroborate — a whole class of files
 * quietly excluded from the ensemble.
 *
 * `decodeURIComponent` throws on a malformed escape, and a literal `%` in a
 * filename is legal on every filesystem this runs on. So a failure falls back to
 * the raw string rather than dropping the finding: a path that fails to decode is
 * still a path, and the worst case is the non-decoding behaviour, which is where
 * this started.
 *
 * A `file://` scheme is left alone deliberately — `normalizeReportPath` will see
 * `file:///home/...` as a non-absolute string with a `file:` first segment and
 * leave it whole, which is visibly wrong to a reader and therefore reportable,
 * whereas stripping the scheme would produce a plausible-looking absolute path
 * that silently fails to match anything.
 */
function decodeArtifactUri(uri: string): string {
  if (!uri.includes('%')) return uri;
  try {
    return decodeURIComponent(uri);
  } catch {
    return uri;
  }
}

function readInt(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? Math.trunc(value) : null;
}

/** SARIF message objects are `{ text }`, sometimes with `markdown`. Text only — markdown is for renderers. */
function readMessageText(value: unknown): string {
  return readMessageTextOrNull(value) ?? '';
}

function readMessageTextOrNull(value: unknown): string | null {
  if (value === null || typeof value !== 'object') return null;
  const text = (value as Record<string, unknown>)['text'];
  return typeof text === 'string' ? text : null;
}

/** `semanticVersion` first — it is the one CodeQL populates with a real version — then `version`. */
function readDriverVersion(toolValue: unknown): string | null {
  if (toolValue === null || typeof toolValue !== 'object') return null;
  const driver = (toolValue as Record<string, unknown>)['driver'];
  if (driver === null || typeof driver !== 'object') return null;
  const d = driver as Record<string, unknown>;
  if (typeof d['semanticVersion'] === 'string') return d['semanticVersion'];
  if (typeof d['version'] === 'string') return d['version'];
  return null;
}

/**
 * `external/cwe/cwe-089` -> `CWE-89`.
 *
 * The leading zeros are stripped so the id matches the `CWE-89` Semgrep emits;
 * keeping `CWE-089` would make the same weakness compare unequal between the two
 * tools on a formatting difference. CWE ids are not a join key here (see
 * weakness-class.ts), but they are printed side by side, and a report showing
 * `CWE-089` next to `CWE-89` invites the reader to conclude the tools disagree.
 */
function readCwesFromTags(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const tag of value) {
    if (typeof tag !== 'string') continue;
    const match = /^external\/cwe\/cwe-([0-9]{1,7})$/i.exec(tag.trim());
    if (match?.[1] !== undefined) out.push(`CWE-${Number(match[1])}`);
  }
  return [...new Set(out)].sort();
}

/**
 * `runs[].invocations[].toolExecutionNotifications` at level error/warning —
 * the SARIF channel for "the tool itself had a problem".
 *
 * Surfaced for the same reason Semgrep's `errors[]` is: a run that failed to
 * build part of its database analysed less than it appears to have, and a merger
 * that reads its silence as coverage is wrong in the direction that flatters the
 * result. This repository's own SARIF writer emits the same field for the same
 * purpose (see `SarifInvocation` in packages/sarif-adapter), so reading it back
 * is symmetric.
 */
function readInvocationNotifications(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const invocation of value) {
    if (invocation === null || typeof invocation !== 'object') continue;
    const notifications = (invocation as Record<string, unknown>)['toolExecutionNotifications'];
    if (!Array.isArray(notifications)) continue;
    for (const notification of notifications) {
      if (notification === null || typeof notification !== 'object') continue;
      const n = notification as Record<string, unknown>;
      const level = typeof n['level'] === 'string' ? n['level'] : 'warning';
      if (level !== 'error' && level !== 'warning') continue;
      const text = readMessageTextOrNull(n['message']);
      if (text !== null) out.push(`${level}: ${text}`);
    }
  }
  return out;
}
