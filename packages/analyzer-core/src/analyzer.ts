import {
  emptySummary,
  summarize,
  compareSeverity,
  type Finding,
  type RuleError,
  type ScanMode,
  type ScanRequest,
  type ScanResponse,
} from '@vibeguard/findings-schema';
import {
  allRules,
  contextConfidence,
  getRulesForLanguage,
  languageMatches,
  type RuleContext,
  type RuleDefinition,
} from '@vibeguard/rules';
import { buildRemediation } from '@vibeguard/remediation-engine';
import { detectLanguageFromContent, detectLanguageFromPath } from './language-detect.js';
import { extractSnippet, maskSecret } from './snippet.js';
import { parseSuppressions, isSuppressed } from './suppress.js';

/**
 * Detection-engine version, embedded in every scan result and SARIF report
 * (`engineVersions.core`). This is a SEPARATE axis from the released tool /
 * package version (package.json): bump it only when detection behavior changes
 * (rules, analysis, finding schema) — not for packaging, UX, or docs releases.
 * It deliberately stayed at 0.1.0 across tool releases 0.1.1–0.1.3, which did
 * not alter what VibeGuard detects.
 *
 * KNOWN HAZARD — this value currently understates the engine. The severity gate
 * on context-window confidence (`SEVERITY_CONFIDENCE_FLOOR` in @vibeguard/rules)
 * DID change detection behavior: critical/high findings now keep their default
 * confidence in contexts where they were previously down-ranked. The bump to
 * 0.2.0 is deliberately deferred until the current round of detection changes is
 * finished, so that 0.2.0 names ONE settled engine rather than several
 * successive ones. The cost of deferring is real and is accepted knowingly:
 * until that bump lands, `engineVersions.core: 0.1.0` does NOT satisfy the "same
 * engine ⇒ identical verdicts" contract in README.md. To compare against the
 * pre-gate engine, use the `paper-ses-v0.1.3` tag rather than this field.
 */
export const ENGINE_VERSION = '0.1.0';

let counter = 0;
function findingId(): string {
  counter += 1;
  return `vg-${Date.now().toString(36)}-${counter.toString(36)}`;
}

function shouldMaskCategory(category: string): boolean {
  return category === 'secrets';
}

function filterRulesByMode(rules: RuleDefinition[], mode: ScanMode): RuleDefinition[] {
  if (mode === 'fast') {
    return rules.filter((r) => r.severity === 'critical' || r.severity === 'high');
  }
  // 'standard' and 'deep' run all rules. Future: 'deep' will also dispatch to
  // external scanners when request.includeExternalScanners is true.
  return rules;
}

function buildRuleContext(content: string, language: string | undefined, filePath: string | undefined): RuleContext {
  return {
    content,
    lines: content.split('\n'),
    language,
    filePath,
  };
}

export interface AnalyzerOptions {
  /** Override which rules participate. Defaults to allRules. */
  rules?: RuleDefinition[];
  /** Skip remediation generation (CI-light scans). */
  skipRemediation?: boolean;
}

export class Analyzer {
  private readonly rules: RuleDefinition[];

  constructor(options: AnalyzerOptions = {}) {
    this.rules = options.rules ?? allRules;
  }

  scan(request: ScanRequest): ScanResponse {
    const start = Date.now();
    const findings: Finding[] = [];
    const ruleErrors: RuleError[] = [];

    if (!request.content) {
      return {
        summary: emptySummary(),
        findings,
        executionTimeMs: 0,
        engineVersions: { core: ENGINE_VERSION, rules: String(this.rules.length) },
        generatedAt: new Date().toISOString(),
      };
    }

    const language =
      request.language ??
      (request.filePath ? detectLanguageFromPath(request.filePath) : undefined) ??
      detectLanguageFromContent(request.content);

    const baseRules = language ? getRulesForLanguage(language) : this.rules;
    const mode: ScanMode = request.mode ?? 'standard';
    const candidateRules = filterRulesByMode(baseRules, mode);
    const ctx = buildRuleContext(request.content, language, request.filePath);
    const suppressions = parseSuppressions(request.content);

    for (const rule of candidateRules) {
      if (!languageMatches(rule.languages, language)) continue;
      let matches;
      try {
        matches = rule.match(ctx);
      } catch (err) {
        // A broken rule should never crash the scan; skip it and continue. But
        // skipping silently drops every finding it would have produced, so record
        // the crash in `ruleErrors` — otherwise this is an undeclared suppression
        // channel (the stderr line below is invisible on the browser/extension path).
        // eslint-disable-next-line no-console
        console.error(`[vibeguard] rule ${rule.ruleId} threw:`, err);
        ruleErrors.push({
          ruleId: rule.ruleId,
          message: err instanceof Error ? err.message : String(err),
        });
        continue;
      }
      const includeRemediation = request.includeRemediation !== false;
      for (const m of matches) {
        if (isSuppressed(suppressions, rule.ruleId, m.startLine)) continue;
        const rawSnippet = extractSnippet(ctx.lines, m.startLine, m.endLine, 0);
        const snippet = shouldMaskCategory(rule.category) ? maskSecret(rawSnippet) : rawSnippet;
        const evidence = shouldMaskCategory(rule.category) ? maskSecret(m.evidence) : m.evidence;

        findings.push({
          findingId: findingId(),
          ruleId: rule.ruleId,
          title: rule.name,
          description: rule.description,
          severity: rule.severity,
          confidence:
            m.confidence ??
            contextConfidence(
              rule.defaultConfidence,
              rule.severity,
              ctx,
              m,
              rule.contextConfidence ?? 'auto',
            ),
          category: rule.category,
          language,
          filePath: request.filePath,
          startLine: m.startLine,
          endLine: m.endLine,
          startColumn: m.startColumn,
          endColumn: m.endColumn,
          snippet,
          evidence: [evidence],
          remediation: includeRemediation ? buildRemediation(rule, m) : undefined,
          references: rule.references,
          sourceEngine: 'core-rule',
          tags: rule.tags,
        });
      }
    }

    findings.sort((a, b) => {
      const sev = compareSeverity(a.severity, b.severity);
      if (sev !== 0) return sev;
      const lineA = a.startLine ?? 0;
      const lineB = b.startLine ?? 0;
      return lineA - lineB;
    });

    return {
      summary: summarize(findings),
      findings,
      executionTimeMs: Date.now() - start,
      engineVersions: { core: ENGINE_VERSION, rules: String(this.rules.length) },
      generatedAt: new Date().toISOString(),
      ...(ruleErrors.length ? { ruleErrors } : {}),
    };
  }
}

export function scan(request: ScanRequest, options?: AnalyzerOptions): ScanResponse {
  return new Analyzer(options).scan(request);
}
