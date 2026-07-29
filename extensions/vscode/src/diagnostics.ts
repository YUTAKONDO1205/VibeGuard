import * as vscode from 'vscode';
import type { Finding, RuleError, ScanDegradation } from '@vibeguard/findings-schema';

function severityToVscode(sev: Finding['severity']): vscode.DiagnosticSeverity {
  if (sev === 'critical' || sev === 'high') return vscode.DiagnosticSeverity.Error;
  if (sev === 'medium') return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

export function toDiagnostic(f: Finding, doc: vscode.TextDocument): vscode.Diagnostic {
  const startLine = Math.max(0, (f.startLine ?? 1) - 1);
  const endLine = Math.max(startLine, (f.endLine ?? f.startLine ?? 1) - 1);
  const startCol = Math.max(0, (f.startColumn ?? 1) - 1);
  const lineLen = doc.lineAt(Math.min(endLine, doc.lineCount - 1)).text.length;
  const endCol = Math.max(startCol, (f.endColumn ?? lineLen + 1) - 1);

  const range = new vscode.Range(startLine, startCol, endLine, endCol);
  // Confidence goes at the end so the Problems panel still leads with the title.
  // The field is required by the schema and the analyzer runs in-process, so the
  // guard is only for findings that arrive from outside that path (imported
  // JSON): "(confidence: undefined)" would be worse than saying nothing.
  const message = f.confidence
    ? `${f.title}: ${f.description} (confidence: ${f.confidence})`
    : `${f.title}: ${f.description}`;
  const d = new vscode.Diagnostic(range, message, severityToVscode(f.severity));
  d.code = f.ruleId;
  d.source = 'VibeGuard';
  return d;
}

/**
 * A degradation becomes a Warning diagnostic on line 1, so a PARTIAL scan is
 * visible in the Problems panel instead of being silently dropped — a bounded
 * scan must never look like a clean one. Warning, not Error: the file WAS
 * scanned, the result is just incomplete.
 *
 * The message is `d.detail` verbatim, deliberately. There are now several kinds
 * of bound (a ReDoS time/length guard that stopped mid-input, and `match-limit`,
 * where the input was read to the end but one rule reported only its first
 * REGEX_MATCH_LIMIT matches), and they fail in different ways. Naming a single
 * cause here — as this comment itself used to, and as the CLI and Chrome banners
 * both did until 2026-07-20 — makes the panel state a reason that is false for
 * every other kind. Only the producer of the degradation knows why it fired, so
 * only `detail` gets to say it.
 */
export function degradationToDiagnostic(d: ScanDegradation): vscode.Diagnostic {
  const range = new vscode.Range(0, 0, 0, 0);
  const diag = new vscode.Diagnostic(range, `VibeGuard: ${d.detail}`, vscode.DiagnosticSeverity.Warning);
  diag.code = d.ruleId;
  diag.source = 'VibeGuard';
  return diag;
}

/**
 * A rule that CRASHED, surfaced the same way a degradation is, for the same
 * reason: an incomplete scan must not look like a clean one.
 *
 * `Analyzer.scan` catches a throwing rule, records it in `ruleErrors` and lets
 * the rest of the scan finish — the right call, since a partial report beats
 * none. But nothing here read that field, so a rule that died contributed zero
 * findings and the file went green in the Problems panel. The distinction
 * between "this rule found nothing" and "this rule never ran" was not
 * observable from the editor at all.
 *
 * Warning rather than Error, matching `degradationToDiagnostic`: the file was
 * scanned and most rules did run. What is missing is one rule's verdict.
 */
export function ruleErrorToDiagnostic(e: RuleError): vscode.Diagnostic {
  const range = new vscode.Range(0, 0, 0, 0);
  const diag = new vscode.Diagnostic(
    range,
    `VibeGuard: rule ${e.ruleId} errored and was skipped — findings from it may be missing (${e.message})`,
    vscode.DiagnosticSeverity.Warning,
  );
  diag.code = e.ruleId;
  diag.source = 'VibeGuard';
  return diag;
}
