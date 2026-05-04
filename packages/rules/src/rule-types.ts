import type { Confidence, Severity } from '@vibeguard/findings-schema';

export interface RuleMatch {
  startLine: number;
  endLine: number;
  startColumn: number;
  endColumn: number;
  evidence: string;
  /** Optional confidence override per match (for context-aware rules). */
  confidence?: Confidence;
  /** Free-form variables a remediation template may interpolate. */
  variables?: Record<string, string>;
}

export interface RuleContext {
  filePath?: string;
  language?: string;
  content: string;
  /** Pre-split lines for convenience (no trailing newline). */
  lines: string[];
}

export interface RuleDefinition {
  ruleId: string;
  name: string;
  description: string;
  /** Languages this rule applies to. Use ['*'] for any language. */
  languages: string[];
  category: string;
  severity: Severity;
  defaultConfidence: Confidence;
  cwe?: string[];
  owasp?: string[];
  references?: string[];
  tags?: string[];
  remediation?: {
    why: string;
    how: string;
    exampleFix?: string;
  };
  /** Pure function returning matches. Implementations must not mutate context. */
  match: (ctx: RuleContext) => RuleMatch[];
}
