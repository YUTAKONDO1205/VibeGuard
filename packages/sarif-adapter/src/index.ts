import {
  isDesignSmellFinding,
  type ConfidenceAudit,
  type DesignMetrics,
  type Finding,
  type ScanResponse,
  type SecurityContext,
  type Severity,
} from '@vibeguard/findings-schema';

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
  properties?: { tags?: string[]; category?: string };
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

const SCHEMA_URI =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

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
      },
    });
  }
  return Array.from(byId.values());
}

function findingToResult(f: Finding): SarifResult {
  const startLine = f.startLine ?? 1;
  return {
    ruleId: f.ruleId,
    level: SEVERITY_TO_LEVEL[f.severity],
    message: { text: f.description },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.filePath ?? '<inline>' },
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
              artifactLocation: { uri: loc.filePath },
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
}

export function toSarif(scan: ScanResponse, options: ToSarifOptions = {}): SarifLog {
  const rules = buildRuleDescriptors(scan.findings);
  const results = scan.findings.map(findingToResult);
  const run: SarifRun = {
    tool: {
      driver: {
        name: options.toolName ?? 'VibeGuard',
        version: options.toolVersion ?? scan.engineVersions.core ?? '0.3.0',
        informationUri: options.informationUri ?? 'https://github.com/vibeguard/vibeguard',
        rules,
      },
    },
    results,
  };
  const ruleErrors = scan.ruleErrors ?? [];
  const degradations = scan.degradations ?? [];
  const suppressions = scan.suppressions ?? [];
  if (ruleErrors.length || degradations.length || suppressions.length) {
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
