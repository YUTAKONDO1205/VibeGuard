import * as vscode from 'vscode';
import { claimsFromFindings, summariseClaims, type Finding } from '@vibeguard/findings-schema';
import type { ScanRunner } from './runner.js';

const HIGH_SEVERITIES = new Set<Finding['severity']>(['critical', 'high']);

export class StatusBarManager implements vscode.Disposable {
  private readonly item: vscode.StatusBarItem;
  private readonly disposables: vscode.Disposable[] = [];

  constructor(private readonly runner: ScanRunner) {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    this.item.name = 'VibeGuard';
    this.item.command = 'vibeguard.findings.focus';
    this.disposables.push(this.item);

    this.disposables.push(runner.onDidChangeFindings(() => this.update()));
    this.disposables.push(vscode.window.onDidChangeActiveTextEditor(() => this.update()));

    this.update();
  }

  private update(): void {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.uri.scheme !== 'file') {
      this.item.hide();
      return;
    }

    const uri = editor.document.uri;
    const all = this.runner.getAllFindings();
    if (!all.has(uri.toString())) {
      // Not scanned yet — say so explicitly so the bar is never silently blank
      // for a file the user might expect to be checked.
      this.item.text = '$(shield) VibeGuard: –';
      this.item.tooltip = 'Not scanned yet. Save the file or run "VibeGuard: Scan File".';
      this.item.color = undefined;
      this.item.backgroundColor = undefined;
      this.item.show();
      return;
    }

    const findings = this.runner.getFindings(uri);
    if (findings.length === 0) {
      // OK 判定 — palette green (#2e7d32) via the `vibeguard.ok` color token.
      this.item.text = '$(pass-filled) VibeGuard: ✓ No issues';
      this.item.tooltip = 'VibeGuard found no security issues in this file.';
      this.item.color = new vscode.ThemeColor('vibeguard.ok');
      this.item.backgroundColor = undefined;
      this.item.show();
      return;
    }

    // VS Code restricts statusBarItem.backgroundColor to the two tokens below,
    // so palette red/yellow are applied to the foreground color instead.
    const hasHigh = findings.some((f) => HIGH_SEVERITIES.has(f.severity));
    // ── THE LEDGER, ON THE SURFACE THE USER ACTUALLY WATCHES ────────────────
    //
    // Some of these findings are not "you wrote something dangerous" but "you
    // wrote a protection in a form a build step removes". The editor cannot
    // check that — it has one file and no build output — and the honest thing
    // is to say which findings are in that class and that they were NOT
    // checked, rather than to let them read as ordinary issues.
    //
    // Every claim built here is NOT_OBSERVED by construction: nothing in this
    // process can settle one, and `claimsFromFindings` could not produce a
    // settled claim even if something tried.
    const claims = claimsFromFindings(findings);
    const ledger = summariseClaims(claims);
    this.item.text = `$(shield) VibeGuard: ${findings.length} ${findings.length === 1 ? 'issue' : 'issues'}`;
    this.item.tooltip = [
      `${findings.length} security finding${findings.length === 1 ? '' : 's'} — click to open the VibeGuard Findings view.`,
      ...(ledger.total
        ? [
            '',
            `${ledger.total} of them declare a protection that a build step can remove.`,
            'This editor cannot see your build output, so they are UNVERIFIED here.',
            'Run: vibeguard <dir> --after-build <your dist directory>',
          ]
        : []),
    ].join('\n');
    this.item.color = new vscode.ThemeColor(hasHigh ? 'vibeguard.critical' : 'vibeguard.issue');
    this.item.backgroundColor = new vscode.ThemeColor(
      hasHigh ? 'statusBarItem.errorBackground' : 'statusBarItem.warningBackground',
    );
    this.item.show();
  }

  dispose(): void {
    for (const d of this.disposables) d.dispose();
  }
}
