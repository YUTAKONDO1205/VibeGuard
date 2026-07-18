import * as vscode from 'vscode';
import type { Finding } from '@vibeguard/findings-schema';

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
