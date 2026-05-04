export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type SourceEngine = 'core-rule' | 'semgrep' | 'external';
export type ScanMode = 'fast' | 'standard' | 'deep';
export type TargetType = 'file' | 'snippet' | 'diff' | 'repo';

export interface Remediation {
  why: string;
  how: string;
  exampleFix?: string;
  references?: string[];
}

export interface Finding {
  findingId: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  language?: string;
  filePath?: string;
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
  snippet?: string;
  evidence?: string[];
  remediation?: Remediation;
  references?: string[];
  sourceEngine: SourceEngine;
  tags?: string[];
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface ScanContext {
  workingDirectory?: string;
  projectName?: string;
  isAIGenerated?: boolean;
  framework?: string;
}

export interface ScanRequest {
  targetType: TargetType;
  content?: string;
  filePath?: string;
  language?: string;
  mode: ScanMode;
  includeExternalScanners?: boolean;
  includeRemediation?: boolean;
  context?: ScanContext;
}

export interface ScanResponse {
  summary: ScanSummary;
  findings: Finding[];
  executionTimeMs: number;
  engineVersions: Record<string, string>;
  generatedAt: string;
}

export function emptySummary(): ScanSummary {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
}

export function summarize(findings: Finding[]): ScanSummary {
  const summary = emptySummary();
  for (const f of findings) {
    summary[f.severity] += 1;
    summary.total += 1;
  }
  return summary;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[b] - SEVERITY_ORDER[a];
}
