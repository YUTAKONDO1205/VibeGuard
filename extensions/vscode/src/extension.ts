import * as vscode from 'vscode';
import type { Finding, ScanMode } from '@vibeguard/findings-schema';
import { ScanRunner } from './runner.js';
import { FindingsTreeProvider } from './findings-tree.js';
import { VibeGuardCodeActionProvider, showRemediation } from './code-actions.js';
import { exportFindings } from './export.js';

export function activate(context: vscode.ExtensionContext): void {
  const collection = vscode.languages.createDiagnosticCollection('vibeguard');
  context.subscriptions.push(collection);

  const runner = new ScanRunner(collection);
  context.subscriptions.push({ dispose: () => runner.dispose() });

  const channel = vscode.window.createOutputChannel('VibeGuard');
  context.subscriptions.push(channel);

  // C7: Findings TreeView in the Explorer panel.
  const treeProvider = new FindingsTreeProvider(runner);
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider('vibeguard.findings', treeProvider),
  );

  // C6: Quick Fix / Code Action provider for VibeGuard diagnostics.
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      new VibeGuardCodeActionProvider(runner),
      { providedCodeActionKinds: VibeGuardCodeActionProvider.providedKinds },
    ),
  );

  // Save → scan
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration('vibeguard');
      if (!config.get<boolean>('scanOnSave', true)) return;
      const mode = (config.get<string>('scanOnSaveMode', 'fast') as ScanMode) ?? 'fast';
      runner.scanDocument(doc, mode);
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      runner.clear(doc.uri);
    }),
  );

  // Manual full-file scan
  context.subscriptions.push(
    vscode.commands.registerCommand('vibeguard.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage('VibeGuard: no active editor.');
        return;
      }
      runner.scanDocument(editor.document, 'standard');
    }),
  );

  // C4: scan only the current selection (full file scanned, results filtered
  // by the selection range so regex context is preserved).
  context.subscriptions.push(
    vscode.commands.registerCommand('vibeguard.scanSelection', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage('VibeGuard: no active editor.');
        return;
      }
      if (editor.selection.isEmpty) {
        vscode.window.showInformationMessage('VibeGuard: select code first.');
        return;
      }
      const count = runner.scanSelection(editor.document, editor.selection, 'standard');
      vscode.window.showInformationMessage(
        count === 0
          ? 'VibeGuard: no findings in selection.'
          : `VibeGuard: ${count} finding${count === 1 ? '' : 's'} in selection.`,
      );
    }),
  );

  // Helper command surfaced from Code Actions to display full remediation.
  context.subscriptions.push(
    vscode.commands.registerCommand('vibeguard.showRemediation', (finding: Finding) => {
      showRemediation(channel, finding);
    }),
  );

  // C9: export the workspace's accumulated findings as SARIF v2.1.0 or JSON.
  context.subscriptions.push(
    vscode.commands.registerCommand('vibeguard.exportFindings', () => exportFindings(runner)),
  );
}

export function deactivate(): void {
  // Resources are disposed via context.subscriptions.
}
