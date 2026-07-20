import * as vscode from 'vscode';
import { Analyzer } from '@vibeguard/analyzer-core';
import type {
  Finding,
  ScanDegradation,
  ScanMode,
  SuppressionRecord,
} from '@vibeguard/findings-schema';
import { toDiagnostic, degradationToDiagnostic } from './diagnostics.js';

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
  // Cached alongside the findings so the SARIF/JSON export can say the scan was
  // partial. Without this the export rebuilds a ScanResponse from findings
  // alone, and a truncated scan is written out as a clean report.
  private readonly degradationsByUri = new Map<string, ScanDegradation[]>();
  // Same reasoning as the degradations above, for the same reason it applies
  // more strongly: a suppressed finding is not in `findings` either, so an
  // export rebuilt from findings alone cannot distinguish "nothing was found"
  // from "something was found and silenced". The tally is the only thing that
  // makes those two states different, and dropping it here puts them back
  // together in the artefact that outlives the session.
  private readonly suppressionsByUri = new Map<string, SuppressionRecord[]>();
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
    this.applyFindings(doc, response.findings, response.degradations, response.suppressions);
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
    // Degradations passed through here too: a selection scan runs the rules over
    // the WHOLE document, so an oversized file is just as partial as it is on a
    // full scan, and the user needs to know before trusting an empty result.
    this.applyFindings(doc, filtered, response.degradations, response.suppressions);
    return filtered.length;
  }

  private applyFindings(
    doc: vscode.TextDocument,
    findings: Finding[],
    degradations?: ScanDegradation[],
    suppressions?: SuppressionRecord[],
  ): void {
    const diagnostics = findings.map((f) => toDiagnostic(f, doc));
    // A partial scan must be visible, not silently dropped. Dedup by kind so one
    // oversized file adds a single line-1 warning, not one per bounded rule.
    if (degradations?.length) {
      const seen = new Set<string>();
      for (const d of degradations) {
        if (seen.has(d.kind)) continue;
        seen.add(d.kind);
        diagnostics.push(degradationToDiagnostic(d));
      }
    }
    this.collection.set(doc.uri, diagnostics);
    this.findingsByUri.set(doc.uri.toString(), findings);
    if (degradations?.length) this.degradationsByUri.set(doc.uri.toString(), degradations);
    else this.degradationsByUri.delete(doc.uri.toString());
    if (suppressions?.length) this.suppressionsByUri.set(doc.uri.toString(), suppressions);
    else this.suppressionsByUri.delete(doc.uri.toString());
    this.emitter.fire(doc.uri);
  }

  getFindings(uri: vscode.Uri): Finding[] {
    return this.findingsByUri.get(uri.toString()) ?? [];
  }

  /** Degradations for one document, for the export path. */
  getDegradations(uri: vscode.Uri): ScanDegradation[] {
    return this.degradationsByUri.get(uri.toString()) ?? [];
  }

  /** Every degradation currently cached, for a whole-workspace export. */
  getAllDegradations(): ScanDegradation[] {
    return [...this.degradationsByUri.values()].flat();
  }

  /** Every suppression currently cached, for a whole-workspace export. */
  getAllSuppressions(): SuppressionRecord[] {
    return [...this.suppressionsByUri.values()].flat();
  }

  getAllFindings(): ReadonlyMap<string, Finding[]> {
    return this.findingsByUri;
  }

  clear(uri: vscode.Uri): void {
    this.collection.delete(uri);
    this.findingsByUri.delete(uri.toString());
    this.degradationsByUri.delete(uri.toString());
    this.suppressionsByUri.delete(uri.toString());
    this.emitter.fire(uri);
  }

  dispose(): void {
    this.emitter.dispose();
  }
}
