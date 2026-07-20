// vibeguard:disable-file VG-INJ-007
// `target.fsPath` is interpolated into a user-facing toast message, not used
// to build a filesystem path. The save dialog already returned an absolute,
// user-confirmed location.
import * as vscode from 'vscode';
import { ENGINE_VERSION } from '@vibeguard/analyzer-core';
import {
  emptySummary,
  summarize,
  compareSeverity,
  type Finding,
  type ScanResponse,
} from '@vibeguard/findings-schema';
import { toSarif } from '@vibeguard/sarif-adapter';
import type { ScanRunner } from './runner.js';

/**
 * C9: workspace-wide export of findings the runner has cached so far.
 *
 * Aggregates every document the user has scanned in this session (each
 * `runner.getAllFindings()` entry is one URI), wraps the findings in a
 * ScanResponse, and writes either SARIF v2.1.0 or VibeGuard JSON depending
 * on the file extension chosen in the save dialog.
 *
 * Why aggregate instead of forcing the user to scan everything first? The
 * cache reflects exactly what the user has touched — fast-feedback for the
 * common "I just scanned a few files, give me the SARIF" workflow.
 */
export async function exportFindings(runner: ScanRunner): Promise<void> {
  const cache = runner.getAllFindings();
  const findings: Finding[] = [];
  for (const list of cache.values()) {
    for (const f of list) findings.push(f);
  }

  if (findings.length === 0) {
    vscode.window.showInformationMessage(
      'VibeGuard: nothing to export. Run a scan first (save a file or use VibeGuard: Scan File).',
    );
    return;
  }

  // Stable ordering: severity desc → file → line. Same shape the CLI uses.
  findings.sort((a, b) => {
    const sev = compareSeverity(a.severity, b.severity);
    if (sev !== 0) return sev;
    const fileA = a.filePath ?? '';
    const fileB = b.filePath ?? '';
    if (fileA !== fileB) return fileA.localeCompare(fileB);
    return (a.startLine ?? 0) - (b.startLine ?? 0);
  });

  const defaultUri = pickDefaultUri();
  const target = await vscode.window.showSaveDialog({
    defaultUri,
    saveLabel: 'Export VibeGuard findings',
    filters: {
      SARIF: ['sarif'],
      JSON: ['json'],
    },
  });
  if (!target) return; // user cancelled

  // Degradations come from the runner's cache, not from `findings`: a partial
  // scan is invisible in the finding list by definition. Omitting them here
  // wrote a truncated scan out as a clean SARIF report — the export is often the
  // artefact that outlives the session, so it is the worst place to lose them.
  const degradations = runner.getAllDegradations();
  // Suppressions for the same reason, and the argument is stronger for them: a
  // suppressed finding is absent from `findings` by design, so an export built
  // from findings alone renders "nothing was found" and "something was found and
  // silenced" as the same document. The tally is the only thing that tells those
  // apart, and this file is where the result stops being a session and starts
  // being evidence.
  const suppressions = runner.getAllSuppressions();
  const response: ScanResponse = {
    summary: findings.length ? summarize(findings) : emptySummary(),
    findings,
    executionTimeMs: 0,
    engineVersions: { core: ENGINE_VERSION },
    generatedAt: new Date().toISOString(),
    ...(degradations.length ? { degradations } : {}),
    ...(suppressions.length ? { suppressions } : {}),
  };

  const lower = target.fsPath.toLowerCase();
  const isSarif = lower.endsWith('.sarif');
  const payload = isSarif
    ? JSON.stringify(toSarif(response, { toolVersion: ENGINE_VERSION }), null, 2)
    : JSON.stringify(response, null, 2);

  await vscode.workspace.fs.writeFile(target, Buffer.from(payload, 'utf8'));
  vscode.window.showInformationMessage(
    `VibeGuard: exported ${findings.length} finding${findings.length === 1 ? '' : 's'} to ${target.fsPath}`,
  );
}

function pickDefaultUri(): vscode.Uri | undefined {
  const first = vscode.workspace.workspaceFolders?.[0];
  if (!first) return undefined;
  return vscode.Uri.joinPath(first.uri, 'vibeguard-findings.sarif');
}
