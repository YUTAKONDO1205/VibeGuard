import * as vscode from 'vscode';
import type { Finding, ScanMode } from '@vibeguard/findings-schema';
import { ScanRunner } from './runner.js';
import { FindingsTreeProvider } from './findings-tree.js';
import { VibeGuardCodeActionProvider, showRemediation } from './code-actions.js';
import { exportFindings } from './export.js';
import { StatusBarManager } from './status-bar.js';

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

  // Status-bar indicator so a clean file produces a visible "✓" instead of
  // a silent blank panel.
  context.subscriptions.push(new StatusBarManager(runner));

  // C6: Quick Fix / Code Action provider for VibeGuard diagnostics.
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      new VibeGuardCodeActionProvider(runner),
      { providedCodeActionKinds: VibeGuardCodeActionProvider.providedKinds },
    ),
  );

  // Save → scan
  //
  // `scanDocument` became async when the declared-package veto was wired in:
  // the lockfile that refutes a hallucinated-dependency finding is read from
  // disk, and it has to be read BEFORE the scan it applies to. The event
  // handler cannot await, so the rejection is handled explicitly — an unhandled
  // one in an extension host surfaces as a bare stack trace with no indication
  // of which extension produced it.
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration('vibeguard');
      if (!config.get<boolean>('scanOnSave', true)) return;
      const mode = (config.get<string>('scanOnSaveMode', 'fast') as ScanMode) ?? 'fast';
      void runner.scanDocument(doc, mode).catch((err: unknown) => {
        channel.appendLine(
          `[vibeguard] scan on save failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      });
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      runner.clear(doc.uri);
    }),
  );

  // Manual full-file scan
  context.subscriptions.push(
    vscode.commands.registerCommand('vibeguard.scanFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage('VibeGuard: no active editor.');
        return;
      }
      await runner.scanDocument(editor.document, 'standard');
      const count = runner.getFindings(editor.document.uri).length;
      vscode.window.showInformationMessage(
        count === 0
          ? 'VibeGuard: ✓ no issues found.'
          : `VibeGuard: ${count} finding${count === 1 ? '' : 's'}.`,
      );
    }),
  );

  // C4: scan only the current selection (full file scanned, results filtered
  // by the selection range so regex context is preserved).
  context.subscriptions.push(
    vscode.commands.registerCommand('vibeguard.scanSelection', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage('VibeGuard: no active editor.');
        return;
      }
      if (editor.selection.isEmpty) {
        vscode.window.showInformationMessage('VibeGuard: select code first.');
        return;
      }
      const count = await runner.scanSelection(editor.document, editor.selection, 'standard');
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
