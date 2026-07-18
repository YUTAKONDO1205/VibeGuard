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

/** A reason the context layer lowered (or tried to lower) a match's confidence. */
export type DowngradeSignal = 'comment' | 'docstring' | 'test-path';

/**
 * Why a finding ended up with the confidence it has, when the surrounding
 * context argued for something lower.
 *
 * The field that carries the weight is `floored`. Read naively, the interesting
 * audit event would be "a finding was downgraded" — but the severity gate
 * (`SEVERITY_CONFIDENCE_FLOOR`) means a critical/high finding is *never*
 * downgraded, so a `downgraded` flag would be dead on arrival for exactly the
 * findings worth auditing. The observable event is the inverse: the context
 * signals asked for a downgrade and the gate refused. That is what someone
 * wrapping a real vulnerability in a comment or a `tests/` path looks like from
 * the inside, so `floored: true` marks an attempted-and-neutralised hiding
 * attempt rather than a mere scoring detail.
 *
 * Present only when at least one signal fired, so a clean finding carries no
 * extra bytes and the key's presence is itself the "context argued about this
 * one" bit. Absent entirely for findings whose rule supplied a per-match
 * confidence: those bypass the context layer, and inventing an audit trail for
 * an evaluation that never ran would be a fabrication.
 */
export interface ConfidenceAudit {
  /** Signals that fired. Non-empty by construction. */
  signals: DowngradeSignal[];
  /** What the signals alone would have produced, with no severity gate. */
  ungated: Confidence;
  /** Whether the gate held the downgrade back (`confidence !== ungated`). */
  floored: boolean;
}

export interface Finding {
  findingId: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  /** Context-downgrade audit trail; present only when a signal fired. */
  confidenceAudit?: ConfidenceAudit;
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

/**
 * A rule whose `match` threw and was skipped during a scan. The analyzer catches
 * a throwing rule so one broken rule cannot crash the whole scan — but skipping
 * it silently drops every finding it would have produced, an undeclared
 * suppression channel (crash the rule, lose the findings, no signal anywhere).
 * Carrying the crash on the response makes it observable rather than silent: the
 * CLI surfaces it in every format (human, markdown, JSON, SARIF). The VS Code and
 * Chrome extensions receive it on the response but do not yet render it in their
 * UI — surfacing it there is tracked separately.
 */
export interface RuleError {
  ruleId: string;
  message: string;
}

export interface ScanResponse {
  summary: ScanSummary;
  findings: Finding[];
  executionTimeMs: number;
  engineVersions: Record<string, string>;
  generatedAt: string;
  /** Rules that threw during `match` and were skipped. Present only when non-empty. */
  ruleErrors?: RuleError[];
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
