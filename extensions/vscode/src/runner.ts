import * as vscode from 'vscode';
import { Analyzer } from '@vibeguard/analyzer-core';
import type { ScanMode } from '@vibeguard/findings-schema';
import { toDiagnostic } from './diagnostics.js';

export class ScanRunner {
  private readonly analyzer = new Analyzer();

  constructor(private readonly collection: vscode.DiagnosticCollection) {}

  scanDocument(doc: vscode.TextDocument, mode: ScanMode): void {
    if (doc.uri.scheme !== 'file') return;
    const response = this.analyzer.scan({
      targetType: 'file',
      content: doc.getText(),
      filePath: doc.uri.fsPath,
      mode,
    });
    const diagnostics = response.findings.map((f) => toDiagnostic(f, doc));
    this.collection.set(doc.uri, diagnostics);
  }

  clear(uri: vscode.Uri): void {
    this.collection.delete(uri);
  }
}
