import * as vscode from 'vscode';
import type { Finding } from '@vibeguard/findings-schema';
import type { ScanRunner } from './runner.js';
import { suppressionComment } from './comment-syntax.js';

export class VibeGuardCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedKinds = [vscode.CodeActionKind.QuickFix];

  constructor(private readonly runner: ScanRunner) {}

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const ours = context.diagnostics.filter((d) => d.source === 'VibeGuard');
    if (ours.length === 0) return [];

    const findings = this.runner.getFindings(document.uri);
    const actions: vscode.CodeAction[] = [];

    for (const diag of ours) {
      const ruleId = typeof diag.code === 'string' ? diag.code : String(diag.code ?? '');
      // Match by rule ID + line; multiple findings on the same line for the
      // same rule are rare but not impossible — surface one action per match.
      const targetLine = diag.range.start.line;
      const matched = findings.filter(
        (f) => f.ruleId === ruleId && (f.startLine ?? 1) - 1 === targetLine,
      );
      const finding: Finding | undefined = matched[0];

      // `null` when the language has no comment syntax that survives a
      // re-parse (strict JSON). Offering nothing beats offering a fix that
      // silences the finding by corrupting the file.
      const suppress = this.suppressLineAction(document, diag, ruleId);
      if (suppress) actions.push(suppress);

      if (finding?.remediation) {
        actions.push(this.showRemediationAction(finding));
      }
    }

    return actions;
  }

  private suppressLineAction(
    document: vscode.TextDocument,
    diag: vscode.Diagnostic,
    ruleId: string,
  ): vscode.CodeAction | null {
    const comment = suppressionComment(document.languageId, ruleId);
    if (comment === null) return null;

    const action = new vscode.CodeAction(
      `VibeGuard: suppress ${ruleId} on this line`,
      vscode.CodeActionKind.QuickFix,
    );
    action.diagnostics = [diag];
    action.isPreferred = false;

    const targetLine = diag.range.start.line;
    const lineText = document.lineAt(targetLine).text;
    const indentMatch = /^[ \t]*/.exec(lineText);
    const indent = indentMatch ? indentMatch[0] : '';
    const insertion = `${indent}${comment}\n`;

    const edit = new vscode.WorkspaceEdit();
    edit.insert(document.uri, new vscode.Position(targetLine, 0), insertion);
    action.edit = edit;
    return action;
  }

  private showRemediationAction(finding: Finding): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `VibeGuard: show remediation for ${finding.ruleId}`,
      vscode.CodeActionKind.QuickFix,
    );
    action.command = {
      command: 'vibeguard.showRemediation',
      title: 'Show remediation',
      arguments: [finding],
    };
    return action;
  }
}

/** Renders why/how/exampleFix into the shared output channel. */
export function showRemediation(channel: vscode.OutputChannel, finding: Finding): void {
  channel.clear();
  channel.appendLine(`${finding.ruleId} — ${finding.title}`);
  channel.appendLine('');
  channel.appendLine(finding.description);
  channel.appendLine('');
  if (finding.remediation) {
    channel.appendLine('Why:');
    channel.appendLine(`  ${finding.remediation.why}`);
    channel.appendLine('');
    channel.appendLine('How:');
    channel.appendLine(`  ${finding.remediation.how}`);
    if (finding.remediation.exampleFix) {
      channel.appendLine('');
      channel.appendLine('Example fix:');
      channel.appendLine(`  ${finding.remediation.exampleFix}`);
    }
  }
  channel.show(true);
}
