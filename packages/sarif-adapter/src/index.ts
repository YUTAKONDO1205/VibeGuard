import type {
  ConfidenceAudit,
  Finding,
  ScanResponse,
  Severity,
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
  properties?: {
    confidence?: string;
    severity?: string;
    tags?: string[];
    confidenceAudit?: ConfidenceAudit;
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
    properties: {
      confidence: f.confidence,
      severity: f.severity,
      tags: f.tags,
      // Spread rather than assigned: SARIF property bags are open, but a key
      // present with an undefined value still shows up to consumers that
      // enumerate them, and "this finding was never context-evaluated" must not
      // look like "it was evaluated and found nothing".
      ...(f.confidenceAudit ? { confidenceAudit: f.confidenceAudit } : {}),
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
        version: options.toolVersion ?? scan.engineVersions.core ?? '0.1.0',
        informationUri: options.informationUri ?? 'https://github.com/vibeguard/vibeguard',
        rules,
      },
    },
    results,
  };
  const ruleErrors = scan.ruleErrors ?? [];
  if (ruleErrors.length) {
    run.invocations = [
      {
        executionSuccessful: false,
        toolExecutionNotifications: ruleErrors.map((e) => ({
          level: 'error' as SarifLevel,
          message: {
            text: `Rule ${e.ruleId} threw and was skipped; its findings are not reported: ${e.message}`,
          },
          associatedRule: { id: e.ruleId },
        })),
      },
    ];
  }
  return { $schema: SCHEMA_URI, version: '2.1.0', runs: [run] };
}
