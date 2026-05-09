import * as vscode from 'vscode';
import { Analyzer } from '@vibeguard/analyzer-core';
import type { Finding, ScanMode } from '@vibeguard/findings-schema';
import { toDiagnostic } from './diagnostics.js';

/**
 * ScanRunner wraps the analyzer and manages two pieces of per-document state:
 *
 * 1. The DiagnosticCollection (squiggles in the editor)
 * 2. A findings cache keyed by URI string, so the TreeView and Code Action
 *    provider can look up the live result without re-running the analyzer.
 *
 * Anything that changes the cache fires `onDidChangeFindings`, which the
 * TreeView subscribes to.
 */
export class ScanRunner {
  private readonly analyzer = new Analyzer();
  private readonly findingsByUri = new Map<string, Finding[]>();
  private readonly emitter = new vscode.EventEmitter<vscode.Uri | undefined>();

  /** Fires with the URI that changed, or `undefined` for "everything". */
  readonly onDidChangeFindings = this.emitter.event;

  constructor(private readonly collection: vscode.DiagnosticCollection) {}

  scanDocument(doc: vscode.TextDocument, mode: ScanMode): void {
    if (doc.uri.scheme !== 'file') return;
    const response = this.analyzer.scan({
      targetType: 'file',
      content: doc.getText(),
      filePath: doc.uri.fsPath,
      mode,
    });
    this.applyFindings(doc, response.findings);
  }

  /**
   * Scan the *whole* document but report only findings whose start-line
   * falls inside the selection. Scanning the whole file (instead of just the
   * selected text) preserves regex context for rules that look at
   * surrounding lines.
   */
  scanSelection(doc: vscode.TextDocument, selection: vscode.Range, mode: ScanMode): number {
    if (doc.uri.scheme !== 'file') return 0;
    const response = this.analyzer.scan({
      targetType: 'snippet',
      content: doc.getText(),
      filePath: doc.uri.fsPath,
      mode,
    });
    const startLine1 = selection.start.line + 1;
    const endLine1 = selection.end.line + 1;
    const filtered = response.findings.filter((f) => {
      const fStart = f.startLine ?? 0;
      const fEnd = f.endLine ?? fStart;
      return fStart && fEnd >= startLine1 && fStart <= endLine1;
    });
    this.applyFindings(doc, filtered);
    return filtered.length;
  }

  private applyFindings(doc: vscode.TextDocument, findings: Finding[]): void {
    const diagnostics = findings.map((f) => toDiagnostic(f, doc));
    this.collection.set(doc.uri, diagnostics);
    this.findingsByUri.set(doc.uri.toString(), findings);
    this.emitter.fire(doc.uri);
  }

  getFindings(uri: vscode.Uri): Finding[] {
    return this.findingsByUri.get(uri.toString()) ?? [];
  }

  getAllFindings(): ReadonlyMap<string, Finding[]> {
    return this.findingsByUri;
  }

  clear(uri: vscode.Uri): void {
    this.collection.delete(uri);
    this.findingsByUri.delete(uri.toString());
    this.emitter.fire(uri);
  }

  dispose(): void {
    this.emitter.dispose();
  }
}
