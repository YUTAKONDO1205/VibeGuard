import { dirname } from 'node:path';
import * as vscode from 'vscode';
import { Analyzer } from '@vibeguard/analyzer-core';
// The Node-only door of an otherwise browser-safe package. Importing it here is
// correct and importing it from `extensions/chrome/src` would not be: this
// extension is bundled with `--platform=node`, so `node:fs` is available to it,
// and it is the ONE way the editor can answer the declared-package question the
// same way the CLI does. See `packages/analyzer-core/src/node.ts`.
import {
  lockfileStamp,
  readDeclaredPackages,
  type DeclaredPackagesResult,
} from '@vibeguard/analyzer-core/node';
import type {
  DeclaredPackageVetoRecord,
  Finding,
  RuleError,
  ScanDegradation,
  ScanMode,
  SuppressionRecord,
} from '@vibeguard/findings-schema';
import { toDiagnostic, degradationToDiagnostic, ruleErrorToDiagnostic } from './diagnostics.js';

/**
 * ScanRunner wraps the analyzer and manages two pieces of per-document state:
 *
 * 1. The DiagnosticCollection (squiggles in the editor)
 * 2. A findings cache keyed by URI string, so the TreeView and Code Action
 *    provider can look up the live result without re-running the analyzer.
 *
 * Anything that changes the cache fires `onDidChangeFindings`, which the
 * TreeView subscribes to.
 *
 * ── THE DECLARED-PACKAGE VETO IS WIRED IN HERE (§17z-b) ───────────────────
 *
 * VG-AISC-001 flags an import whose name is a near miss of a popular package —
 * the shape a model produces when it invents a dependency. The other half of
 * that sentence is "AND THE PROJECT DID NOT RESOLVE IT", and the evidence for
 * that half is the lockfile. Without it the rule fires on `psycopg`, `merge2`,
 * `preact`, `enquirer` and every other legitimately-installed near miss.
 *
 * This runner used to construct `new Analyzer()` with no arguments and pass no
 * `declaredPackages` on the request, so the veto never ran in the editor. The
 * consequence was not "a missing feature" but a DISAGREEMENT: one project, one
 * engine, two answers depending on whether you looked at it through the CLI or
 * through VS Code, with the editor showing findings the command line had
 * already refuted using a file sitting next to the code. Parity across the four
 * channels is a property this codebase asserts (E1); an input wired into one
 * channel and not another breaks it just as thoroughly as a divergent rule.
 *
 * The fix shares the CLI's reader rather than reimplementing it —
 * `@vibeguard/analyzer-core/node` is the same module `apps/cli` calls, so
 * "identical algorithm" is a fact about the code and not a promise in a
 * comment. A reimplementation would agree on the day it was written and drift
 * on the first lockfile-format change.
 */
export class ScanRunner {
  /**
   * One Analyzer per `declaredPackageSource` string.
   *
   * `declaredPackageSource` (which lockfile the names came from) is an
   * Analyzer-construction option, not a request field, and it is stamped onto
   * every veto record so a reviewer can weigh the claim. A single long-lived
   * Analyzer could therefore only ever report one source — wrong the moment a
   * multi-root workspace has a `package-lock.json` in one folder and a
   * `poetry.lock` in another, and wrong in a way that misattributes evidence
   * rather than merely losing it. Constructing an Analyzer is a field
   * assignment plus a shared rule array, so the cache is small and cheap; it is
   * keyed rather than rebuilt per scan only so the rule list is not re-read on
   * every keystroke-adjacent save.
   */
  private readonly analyzers = new Map<string, Analyzer>();
  /**
   * Declared packages per scan root, with the lockfile fingerprint they were
   * read at.
   *
   * The stamp is what keeps the cache honest: after `npm uninstall`, a cached
   * set would keep vetoing a package the project no longer resolves, which is a
   * FALSE NEGATIVE invented by a cache — the one direction this feature is not
   * allowed to fail in. Re-reading a multi-megabyte lockfile on every save is
   * the cost this avoids; six `stat` calls is the cost it pays.
   */
  private readonly declaredByRoot = new Map<string, { stamp: string; declared: DeclaredPackagesResult }>();
  /** Roots whose lockfile warnings have already been reported, by stamp. */
  private readonly warnedRoots = new Map<string, string>();
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
  // And the veto, which is the third way a finding can be absent — and the only
  // one of the three the editor could not previously report at all, because it
  // never ran. Cached with the same shape so the export can carry it.
  private readonly vetoesByUri = new Map<string, DeclaredPackageVetoRecord[]>();
  private readonly emitter = new vscode.EventEmitter<vscode.Uri | undefined>();
  private readonly warn: (message: string) => void;

  /** Fires with the URI that changed, or `undefined` for "everything". */
  readonly onDidChangeFindings = this.emitter.event;

  /**
   * `warn` receives lockfile problems — a lockfile that is present and could
   * not be read or parsed, which means the veto is INCOMPLETE and findings the
   * project can refute will be reported anyway. The CLI writes the same strings
   * to stderr. Injectable so a test can assert they are emitted; defaults to
   * `console.warn`, which reaches the Extension Host log.
   *
   * Deliberately NOT a diagnostic: a diagnostic would repeat on every file in
   * the workspace for one broken lockfile, and a warning nobody can dismiss is
   * a warning everybody turns off.
   */
  constructor(
    private readonly collection: vscode.DiagnosticCollection,
    options: { warn?: (message: string) => void } = {},
  ) {
    this.warn = options.warn ?? ((message: string) => console.warn(`[vibeguard] ${message}`));
  }

  /**
   * The directory whose lockfile applies to `uri`.
   *
   * The CLI searches the directory the user named (or the file's own directory
   * when a single file was named). The editor's analogue of "what the user
   * named" is the workspace folder they opened — that is the thing a VS Code
   * user points at, and it is where `npm install` writes. A document outside
   * every workspace folder falls back to its own directory, which is exactly
   * `vibeguard path/to/that/file`.
   *
   * REJECTED: always using the document's directory. It is the more literal
   * reading of "same algorithm as the CLI", and it makes the veto useless in
   * the layout every real project has — `src/app.ts` with the lockfile at the
   * root — which would leave the editor reporting refuted findings and the
   * parity gap unclosed in practice while looking closed in a diff.
   *
   * REJECTED: walking up from the document until a lockfile appears. That is
   * the behaviour the reader's own docstring rejects for the CLI, and adopting
   * it here would put the two channels back into disagreement over which file
   * counts as evidence.
   */
  private scanRootFor(uri: vscode.Uri): string {
    const folder = vscode.workspace.getWorkspaceFolder?.(uri);
    if (folder && folder.uri.scheme === 'file') return folder.uri.fsPath;
    return dirname(uri.fsPath);
  }

  /**
   * Declared packages for a document, read at most once per lockfile state.
   *
   * Returns the SAME array instance for repeated scans of an unchanged
   * lockfile, which matters beyond allocation: `buildDeclaredPackageIndex`
   * memoizes on array identity, so a stable instance indexes a thousand-entry
   * lockfile once instead of once per save.
   */
  private async declaredFor(uri: vscode.Uri): Promise<DeclaredPackagesResult> {
    const root = this.scanRootFor(uri);
    const stamp = await lockfileStamp(root);
    const cached = this.declaredByRoot.get(root);
    if (cached && cached.stamp === stamp) return cached.declared;

    const declared = await readDeclaredPackages(root);
    this.declaredByRoot.set(root, { stamp, declared });
    // Reported once per lockfile state, not once per scan: a broken lockfile
    // must be visible, and must not print on every keystroke-adjacent save.
    if (declared.warnings.length && this.warnedRoots.get(root) !== stamp) {
      this.warnedRoots.set(root, stamp);
      for (const w of declared.warnings) this.warn(w);
    }
    return declared;
  }

  /**
   * The Analyzer to use for a declared set — one per source string, built on
   * first use. `source` is the comma-joined list of lockfiles the names came
   * from, formed exactly as `apps/cli/src/index.ts` forms it so the two
   * channels stamp veto records identically.
   */
  private analyzerFor(declared: DeclaredPackagesResult): Analyzer {
    const source = declared.sources.map((s) => s.file).join(', ');
    let analyzer = this.analyzers.get(source);
    if (!analyzer) {
      analyzer = new Analyzer(source ? { declaredPackageSource: source } : {});
      this.analyzers.set(source, analyzer);
    }
    return analyzer;
  }

  /**
   * Scan one document.
   *
   * ASYNC because reading the lockfile is I/O and the veto must be applied to
   * THIS scan, not the next one. A synchronous version that used whatever
   * happened to be cached would report refuted findings on the first save after
   * opening a project and then quietly stop — an intermittent disagreement with
   * the CLI, which is worse than a consistent one because nobody can reproduce
   * it.
   */
  async scanDocument(doc: vscode.TextDocument, mode: ScanMode): Promise<void> {
    if (doc.uri.scheme !== 'file') return;
    const declared = await this.declaredFor(doc.uri);
    const response = this.analyzerFor(declared).scan({
      targetType: 'file',
      content: doc.getText(),
      filePath: doc.uri.fsPath,
      mode,
      // Passed unconditionally, empty list included — the same shape the CLI
      // puts on the request. An empty list arms nothing and changes no answer;
      // sending it anyway keeps the two channels' requests identical instead of
      // identical-except-when-there-is-no-lockfile.
      declaredPackages: declared.packages,
    });
    this.applyFindings(
      doc,
      response.findings,
      response.degradations,
      response.suppressions,
      response.ruleErrors,
      response.declaredPackageVetoes,
    );
  }

  /**
   * Scan the *whole* document but report only findings whose start-line
   * falls inside the selection. Scanning the whole file (instead of just the
   * selected text) preserves regex context for rules that look at
   * surrounding lines.
   */
  async scanSelection(
    doc: vscode.TextDocument,
    selection: vscode.Range,
    mode: ScanMode,
  ): Promise<number> {
    if (doc.uri.scheme !== 'file') return 0;
    const declared = await this.declaredFor(doc.uri);
    const response = this.analyzerFor(declared).scan({
      targetType: 'snippet',
      content: doc.getText(),
      filePath: doc.uri.fsPath,
      mode,
      declaredPackages: declared.packages,
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
    //
    // The veto records are passed through UNFILTERED, and deliberately: they
    // carry no line number (by design — a record that could rebuild the finding
    // is the thing `DeclaredPackageVetoRecord` declines to be), so there is
    // nothing to intersect with the selection. Dropping them instead would make
    // a selection scan the one place the veto is invisible again.
    this.applyFindings(
      doc,
      filtered,
      response.degradations,
      response.suppressions,
      response.ruleErrors,
      response.declaredPackageVetoes,
    );
    return filtered.length;
  }

  private applyFindings(
    doc: vscode.TextDocument,
    findings: Finding[],
    degradations?: ScanDegradation[],
    suppressions?: SuppressionRecord[],
    ruleErrors?: RuleError[],
    vetoes?: DeclaredPackageVetoRecord[],
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
    // A rule that CRASHED is the other way a scan can be incomplete, and it was
    // the invisible one: its findings are simply absent, so the file goes green.
    // Deduped by rule id — one broken rule is one line-1 warning, however many
    // times it threw.
    if (ruleErrors?.length) {
      const seenRules = new Set<string>();
      for (const e of ruleErrors) {
        if (seenRules.has(e.ruleId)) continue;
        seenRules.add(e.ruleId);
        diagnostics.push(ruleErrorToDiagnostic(e));
      }
    }
    this.collection.set(doc.uri, diagnostics);
    this.findingsByUri.set(doc.uri.toString(), findings);
    if (degradations?.length) this.degradationsByUri.set(doc.uri.toString(), degradations);
    else this.degradationsByUri.delete(doc.uri.toString());
    if (suppressions?.length) this.suppressionsByUri.set(doc.uri.toString(), suppressions);
    else this.suppressionsByUri.delete(doc.uri.toString());
    // NOT a diagnostic. The veto's whole claim is that the finding was WRONG —
    // refuted by a resolved lockfile entry, not silenced — so surfacing it as a
    // squiggle would re-report what it just removed. It goes to the export,
    // where the CLI's JSON and SARIF carry the same record.
    //
    // An EMPTY array is stored, not discarded. `undefined` and `[]` are
    // different facts on the response — the veto did not run, versus it ran and
    // removed nothing — and the export is the artefact that outlives the
    // session, so this is the last place to flatten them together.
    if (vetoes !== undefined) this.vetoesByUri.set(doc.uri.toString(), vetoes);
    else this.vetoesByUri.delete(doc.uri.toString());
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

  /**
   * Every declared-package veto currently cached, for a whole-workspace export.
   *
   * Aggregated exactly like the suppression tally: one entry per
   * rule+package+file, no line numbers.
   */
  getAllDeclaredPackageVetoes(): DeclaredPackageVetoRecord[] {
    return [...this.vetoesByUri.values()].flat();
  }

  /**
   * True when at least one cached scan ARMED the veto — i.e. was handed a
   * non-empty declared set — whether or not it removed anything.
   *
   * The export needs this to tell `declaredPackageVetoes: []` ("we read your
   * lockfile and it refuted nothing") from an absent field ("nobody read a
   * lockfile"). Without it every clean workspace exports the second document
   * while half of them mean the first.
   */
  declaredPackageVetoRan(): boolean {
    return this.vetoesByUri.size > 0;
  }

  getAllFindings(): ReadonlyMap<string, Finding[]> {
    return this.findingsByUri;
  }

  clear(uri: vscode.Uri): void {
    this.collection.delete(uri);
    this.findingsByUri.delete(uri.toString());
    this.degradationsByUri.delete(uri.toString());
    this.suppressionsByUri.delete(uri.toString());
    this.vetoesByUri.delete(uri.toString());
    this.emitter.fire(uri);
  }

  dispose(): void {
    this.emitter.dispose();
  }
}
