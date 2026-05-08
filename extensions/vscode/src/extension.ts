import * as vscode from 'vscode';
import type { ScanMode } from '@vibeguard/findings-schema';
import { ScanRunner } from './runner.js';

export function activate(context: vscode.ExtensionContext): void {
  const collection = vscode.languages.createDiagnosticCollection('vibeguard');
  context.subscriptions.push(collection);

  const runner = new ScanRunner(collection);

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
}

export function deactivate(): void {
  // DiagnosticCollection is disposed via context.subscriptions.
}
