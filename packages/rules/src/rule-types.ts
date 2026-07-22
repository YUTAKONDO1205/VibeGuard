import type { Confidence, Severity } from '@vibeguard/findings-schema';

export interface RuleMatch {
  startLine: number;
  endLine: number;
  startColumn: number;
  endColumn: number;
  evidence: string;
  /** Optional confidence override per match (for context-aware rules). */
  confidence?: Confidence;
  /**
   * Optional severity override per match. Mirrors `confidence` above: a rule
   * whose severity escalates on the CONTENT of a specific match (VG-SMELL-012
   * hitting an `admin`/`root` literal, VG-SMELL-003 covering an authorization
   * method) sets it here, and the analyzer takes `m.severity ?? rule.severity`
   * both when assembling the finding and when applying the suppression severity
   * gate, so an escalated match is gated at its real severity. Omitted, the
   * rule's static `severity` stands. It never LOWERS below the rule default in
   * practice — rules only set it to escalate — but the analyzer imposes no such
   * rule; it is a straight override.
   */
  severity?: Severity;
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
  /**
   * Context-window confidence policy (paper item ①). 'auto' (the default when
   * omitted) lets the analyzer down-rank this rule's matches that sit in a
   * comment, docstring/block comment, or test fixture. Set 'off' for rules
   * where the comment itself is the detection signal (e.g. VG-AUTH-002,
   * VG-QUAL-009) so a comment must not lower their confidence.
   */
  contextConfidence?: 'auto' | 'off';
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
