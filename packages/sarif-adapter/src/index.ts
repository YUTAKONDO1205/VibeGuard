import {
  isDesignSmellFinding,
  type ConfidenceAudit,
  type DesignMetrics,
  type Finding,
  type ScanResponse,
  type SecurityContext,
  type Severity,
} from '@vibeguard/findings-schema';
import type { AiProvenanceObservation } from './provenance.js';

// The provenance vocabulary is re-exported from the package root so a consumer
// gets the types without reaching for a subpath. The COLLECTOR that reads a
// repository is deliberately not re-exported here — it lives behind
// `@vibeguard/sarif-adapter/node`, because it imports `node:child_process` and
// this entry point must stay importable in a browser bundle. See the header of
// `./provenance-node.ts`.
export {
  AI_PROVENANCE_CLAIM_LIMIT,
  KNOWN_AI_ASSISTANT_IDS,
  collectAiProvenance,
  parseGitLogRecords,
  type AiAuthorshipMarker,
  type AiMarkerChannel,
  type AiMarkerMatchedOn,
  type AiProvenanceInput,
  type AiProvenanceInspection,
  type AiProvenanceObservation,
} from './provenance.js';

export interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri?: string;
      rules: SarifRuleDescriptor[];
    };
  };
  results: SarifResult[];
  invocations?: SarifInvocation[];
  /**
   * Run-scoped property bag. SARIF 2.1.0 §3.14.35.
   *
   * `provenance` sits here rather than on a result because it is a statement
   * about the REPOSITORY, not about any finding. Attaching it to results would
   * put an authorship marker next to a vulnerability in the code-scanning UI,
   * which is exactly the "AI-written therefore dangerous" reading the collector
   * is built to refuse: nothing in the marker set is evidence about the finding
   * beside it, and no rendering should be able to imply that it is.
   */
  properties?: {
    provenance?: AiProvenanceObservation;
  };
}

/**
 * SARIF 2.1.0 §3.20. Carries rules that threw and were skipped as
 * `toolExecutionNotifications` (level "error"). Without it, a rule crash silently
 * drops its findings and the CI scan passes green — an undeclared suppression
 * channel. `executionSuccessful` is false when any rule was skipped this way.
 */
export interface SarifInvocation {
  executionSuccessful: boolean;
  toolExecutionNotifications: SarifNotification[];
}

export interface SarifNotification {
  level: SarifLevel;
  message: { text: string };
  associatedRule?: { id: string };
}

export interface SarifRuleDescriptor {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help?: { text: string; markdown?: string };
  defaultConfiguration: { level: SarifLevel };
  properties?: {
    tags?: string[];
    category?: string;
    /** GitHub code scanning severity band. See SEVERITY_TO_SECURITY_SEVERITY. */
    'security-severity'?: string;
    /** GitHub code scanning precision hint, derived from confidence. */
    precision?: string;
  };
}

export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: {
        startLine: number;
        endLine?: number;
        startColumn?: number;
        endColumn?: number;
        snippet?: { text: string };
      };
    };
  }>;
  /**
   * The other places a finding implicates — SARIF's own field for exactly this,
   * rendered by GitHub code scanning as linked secondary locations.
   *
   * Present only for design smells that carry `relatedLocations`. It matters
   * more than it looks: a cross-file finding's entire claim is the RELATIONSHIP
   * between sites ("this authorization check is duplicated in five handlers
   * across four files"), and `locations` can hold exactly one. Emitting only
   * that collapses the claim to a single line and silently discards the
   * evidence, in the format the GitHub Action produces BY DEFAULT — so the
   * channel most users see would have been the one that could not show what was
   * found.
   */
  relatedLocations?: Array<{
    id: number;
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; endLine?: number; startColumn?: number; endColumn?: number };
    };
    message?: { text: string };
  }>;
  properties?: {
    confidence?: string;
    severity?: string;
    tags?: string[];
    confidenceAudit?: ConfidenceAudit;
    /** Design-smell scope (`file`, `project`, …). Absent for ordinary findings. */
    scope?: string;
    /** The measurements behind a design smell's verdict. */
    metrics?: DesignMetrics;
    securityContext?: SecurityContext;
  };
}

export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

const SEVERITY_TO_LEVEL: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

// The OASIS publication location for the 2.1.0 Errata 01 schema. The previous
// value pointed into the sarif-spec repo's `master` branch, which no longer
// serves that path (404) — a `$schema` nobody can fetch is worse than none,
// because validators report a load failure rather than a schema violation.
// This URI is a published standard artefact, so it does not move with a branch.
const SCHEMA_URI =
  'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json';

/** The repository this tool actually lives in. Used as the SARIF `informationUri`. */
const DEFAULT_INFORMATION_URI = 'https://github.com/YUTAKONDO1205/VibeGuard';

/**
 * GitHub code scanning reads `security-severity` off the rule descriptor to
 * place an alert in its own Critical/High/Medium/Low buckets; without it every
 * alert lands in the same bucket regardless of what VibeGuard said. The numbers
 * are GitHub's documented bands (critical >= 9.0, high >= 7.0, medium >= 4.0,
 * low > 0.0), expressed as strings because that is what the property expects.
 *
 * This matters because `level` alone cannot carry the distinction: SARIF has
 * four levels and VibeGuard has five severities, so `critical` and `high` both
 * map to `error`. `security-severity` is where that collapse is undone.
 */
const SEVERITY_TO_SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.0',
  high: '7.0',
  medium: '5.0',
  low: '3.0',
  info: '1.0',
};

/**
 * GitHub's `precision` hint, derived from the finding's confidence. VibeGuard is
 * a regex-first scanner, so nothing here claims `very-high`.
 */
const CONFIDENCE_TO_PRECISION: Record<string, string> = {
  high: 'high',
  medium: 'medium',
  low: 'low',
};

function buildRuleDescriptors(findings: Finding[]): SarifRuleDescriptor[] {
  const byId = new Map<string, SarifRuleDescriptor>();
  for (const f of findings) {
    if (byId.has(f.ruleId)) continue;
    byId.set(f.ruleId, {
      id: f.ruleId,
      name: f.title,
      shortDescription: { text: f.title },
      fullDescription: { text: f.description },
      help: f.remediation
        ? {
            text: `${f.remediation.why}\n\n${f.remediation.how}`,
          }
        : undefined,
      defaultConfiguration: { level: SEVERITY_TO_LEVEL[f.severity] },
      properties: {
        tags: f.tags,
        category: f.category,
        'security-severity': SEVERITY_TO_SECURITY_SEVERITY[f.severity],
        precision: CONFIDENCE_TO_PRECISION[f.confidence],
      },
    });
  }
  return Array.from(byId.values());
}

/**
 * `uri` for a path, lifted out of the target's basis into the repository's.
 *
 * The prefix is applied only to RELATIVE paths. An absolute path (a snippet
 * scan carries the fsPath; `<inline>` carries no path at all) is left alone,
 * because prefixing it would produce something that is neither.
 */
function toUri(filePath: string | undefined, prefix: string): string {
  const p = filePath ?? '<inline>';
  if (!prefix || p === '<inline>') return p;
  // Already absolute, or already carrying the prefix — leave it.
  if (/^([a-zA-Z]:[\\/]|\/)/.test(p) || p.startsWith(prefix)) return p;
  return `${prefix}${p}`;
}

function findingToResult(f: Finding, uriPrefix = ''): SarifResult {
  const startLine = f.startLine ?? 1;
  return {
    ruleId: f.ruleId,
    level: SEVERITY_TO_LEVEL[f.severity],
    message: { text: f.description },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toUri(f.filePath, uriPrefix) },
          region: {
            startLine,
            endLine: f.endLine,
            startColumn: f.startColumn,
            endColumn: f.endColumn,
            snippet: f.snippet ? { text: f.snippet } : undefined,
          },
        },
      },
    ],
    // Conditional spread throughout, for the reason spelled out on the
    // properties bag below: an absent key and a key holding `undefined` are the
    // same thing in JSON and different things to a consumer enumerating them.
    ...(isDesignSmellFinding(f) && (f.relatedLocations?.length ?? 0) > 0
      ? {
          relatedLocations: f.relatedLocations!.map((loc, i) => ({
            // SARIF requires related locations to be identified so a message can
            // reference them. 1-based to match how the spec's examples number
            // them, and stable because `relatedLocations` is emitted in the
            // producer's deterministic order.
            id: i + 1,
            physicalLocation: {
              artifactLocation: { uri: toUri(loc.filePath, uriPrefix) },
              region: {
                startLine: loc.startLine,
                endLine: loc.endLine,
                startColumn: loc.startColumn,
                endColumn: loc.endColumn,
              },
            },
            ...(loc.evidence ? { message: { text: loc.evidence } } : {}),
          })),
        }
      : {}),
    properties: {
      confidence: f.confidence,
      severity: f.severity,
      tags: f.tags,
      // Spread rather than assigned: SARIF property bags are open, but a key
      // present with an undefined value still shows up to consumers that
      // enumerate them, and "this finding was never context-evaluated" must not
      // look like "it was evaluated and found nothing".
      ...(f.confidenceAudit ? { confidenceAudit: f.confidenceAudit } : {}),
      ...(isDesignSmellFinding(f)
        ? {
            scope: f.scope,
            ...(f.metrics ? { metrics: f.metrics } : {}),
            ...(f.securityContext ? { securityContext: f.securityContext } : {}),
          }
        : {}),
    },
  };
}

export interface ToSarifOptions {
  toolName?: string;
  toolVersion?: string;
  informationUri?: string;
  /**
   * Prepended to every artifact URI, `/`-terminated. Use it to lift
   * target-relative finding paths to repository-root-relative ones.
   *
   * A finding's `filePath` is relative to the SCAN TARGET, which is the right
   * basis for the CLI's own output and for `--fix`. It is the wrong basis for
   * SARIF: GitHub code scanning resolves `artifactLocation.uri` from the
   * repository root, so `vibeguard packages/api --format sarif` emitted
   * `routes.ts` for a file that lives at `packages/api/routes.ts`. Every alert
   * then pointed at a path that does not exist, or — worse — at a different
   * file that happens to share the name.
   *
   * Applied here rather than by changing `filePath` itself, because that field
   * has three other consumers (`fix.ts` reads a finding back as
   * `join(target, filePath)`, config `suppress[].paths` globs are written
   * against it, and the CLI prints it) and moving its basis would break all of
   * them to fix one.
   */
  uriPrefix?: string;
  /**
   * AI-authorship markers observed in the repository under scan, from
   * `readAiProvenance` in `@vibeguard/sarif-adapter/node` (or hand-built).
   *
   * Emitted as `run.properties.provenance` — and ONLY when it carries at least
   * one marker. See the emission rule inside `toSarif`.
   */
  provenance?: AiProvenanceObservation;
}

/**
 * ★ THE EMISSION RULE, AND WHY AN EMPTY OBSERVATION IS DROPPED ENTIRELY.
 *
 * The file's standing discipline is that an absent key and a key holding
 * `undefined` are the same thing in JSON and different things to a consumer
 * enumerating them — hence conditional spread everywhere above. Provenance adds
 * a case that discipline does not settle on its own: an observation that was
 * MADE and found nothing.
 *
 * It is dropped, and the argument is epistemic rather than cosmetic. The
 * collector's claim limit says outright that most AI-assisted work carries no
 * marker, so "we read 500 commits and found no declaration" tells a reader
 * exactly as much about whether an assistant wrote this code as "we never
 * looked" does: nothing. The two states are informationally identical, so
 * giving them two different JSON shapes would invite a consumer to treat one of
 * them as a negative result — an `observedAuthorshipMarkers: []` rendered as "no
 * AI involvement detected" is the single most likely misreading of this whole
 * feature, and it becomes possible the moment the empty array is emitted.
 *
 * This is the one place where the "absent ≠ empty" rule points the other way,
 * and it points that way because here the two really do mean the same thing.
 *
 * The check is on the marker list rather than on `provenance` being supplied,
 * because `ToSarifOptions` is public: a caller can hand in an observation it
 * built itself, and the guarantee has to hold for that caller too.
 */
function provenanceProperties(
  provenance: AiProvenanceObservation | undefined,
): Pick<SarifRun, 'properties'> {
  if (!provenance || provenance.observedAuthorshipMarkers.length === 0) return {};
  return { properties: { provenance } };
}

export function toSarif(scan: ScanResponse, options: ToSarifOptions = {}): SarifLog {
  const rules = buildRuleDescriptors(scan.findings);
  // Normalised to a single trailing slash so callers may pass either form.
  const uriPrefix = options.uriPrefix ? options.uriPrefix.replace(/\/*$/, '/') : '';
  const results = scan.findings.map((f) => findingToResult(f, uriPrefix));
  const run: SarifRun = {
    tool: {
      driver: {
        name: options.toolName ?? 'VibeGuard',
        version: options.toolVersion ?? scan.engineVersions.core ?? '0.3.1',
        informationUri: options.informationUri ?? DEFAULT_INFORMATION_URI,
        rules,
      },
    },
    results,
    ...provenanceProperties(options.provenance),
  };
  const ruleErrors = scan.ruleErrors ?? [];
  const degradations = scan.degradations ?? [];
  const suppressions = scan.suppressions ?? [];
  const vetoes = scan.declaredPackageVetoes ?? [];
  if (ruleErrors.length || degradations.length || suppressions.length || vetoes.length) {
    const notifications: SarifNotification[] = [
      // Rule crashes are errors: the rule produced nothing.
      ...ruleErrors.map((e) => ({
        level: 'error' as SarifLevel,
        message: {
          text: `Rule ${e.ruleId} threw and was skipped; its findings are not reported: ${e.message}`,
        },
        associatedRule: { id: e.ruleId },
      })),
      // Degradations are WARNINGS, not errors: the rule ran and reported
      // findings, it just did not finish. Level 'error' here (as an earlier
      // version emitted, via ruleErrors) would fail the whole run for any file
      // over the cap — overstating a partial scan as a total failure.
      ...degradations.map((d) => ({
        level: 'warning' as SarifLevel,
        message: {
          text: `${d.detail}${d.filePath ? ` (${d.filePath})` : ''}`,
        },
        associatedRule: { id: d.ruleId },
      })),
      // Suppressions are NOTES: nothing went wrong, and a suppression is usually
      // a deliberate, legitimate decision. They are here at all because SARIF is
      // the format the GitHub Action emits BY DEFAULT (`action.yml`, `format:
      // sarif`), so leaving them out meant the suppression tally existed in the
      // JSON and human output and vanished on the one path most projects
      // actually run. A trace that disappears in the flagship configuration is
      // not a trace.
      //
      // Granularity matches the tally itself — rule, channel, scope, file, count
      // — and deliberately carries no line number. Emitting one would rebuild the
      // finding the author asked to suppress, in the artifact a reviewer reads,
      // which is the thing `SuppressionRecord` declines to do.
      //
      // Not modelled as SARIF `result.suppressions[]`. That is the schema's
      // first-class spelling for this concept, but it requires emitting the
      // result — location included — and marking it suppressed, which is exactly
      // the line-number exposure above. The trade is deliberate: less idiomatic
      // SARIF, no reconstruction of a suppressed finding.
      ...suppressions.map((s) => ({
        level: 'note' as SarifLevel,
        message: {
          text:
            `${s.count} finding(s) of ${s.ruleId} were suppressed by a ${s.channel} ` +
            `${s.scope} suppression${s.filePath ? ` (${s.filePath})` : ''} and are not reported above.`,
        },
        associatedRule: { id: s.ruleId },
      })),
      // The declared-package veto, on the same channel and for the same reason.
      // It DELETES findings, and until this existed it reported itself only on
      // the CLI's stderr — so the artifact the GitHub Action uploads, which is
      // the one most projects actually read, could not tell "nothing was found"
      // from "something was found and removed".
      //
      // The wording states what was OBSERVED. Nothing here contacted a registry
      // and neither `resolved` nor `integrity` was checked, so a hand-written
      // entry naming a package that was never published looks exactly like a
      // real one. Saying "the package exists" would assert what the tool did not
      // establish.
      ...vetoes.map((v) => ({
        level: 'note' as SarifLevel,
        message: {
          text:
            `${v.count} finding(s) of ${v.ruleId} for package "${v.packageName}" ` +
            `${v.filePath ? `in ${v.filePath} ` : ''}were not reported because ` +
            `${v.source ?? 'a project manifest'} declares that package. ` +
            'The manifest was read as written and not verified against a registry, ' +
            'so this is a statement about the manifest, not evidence that the package exists or is safe.',
        },
        associatedRule: { id: v.ruleId },
      })),
    ];
    run.invocations = [
      {
        // A partial scan alone does not fail the run; a rule CRASH does. Callers
        // who want CI to fail on partial results gate on `degradations` length.
        executionSuccessful: ruleErrors.length === 0,
        toolExecutionNotifications: notifications,
      },
    ];
  }
  return { $schema: SCHEMA_URI, version: '2.1.0', runs: [run] };
}
