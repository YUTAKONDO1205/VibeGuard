// vibeguard:disable-file VG-INJ-007
// `target.fsPath` is interpolated into a user-facing toast message, not used
// to build a filesystem path. The save dialog already returned an absolute,
// user-confirmed location.
import * as vscode from 'vscode';
import { ENGINE_VERSION } from '@vibeguard/analyzer-core';
import {
  claimsFromFindings,
  emptySummary,
  summarize,
  compareSeverity,
  type DeclaredPackageVetoRecord,
  type Finding,
  type ScanDegradation,
  type ScanResponse,
  type SuppressionRecord,
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

  const response = buildExportResponse({
    findings,
    // Degradations come from the runner's cache, not from `findings`: a partial
    // scan is invisible in the finding list by definition. Omitting them here
    // wrote a truncated scan out as a clean SARIF report — the export is often the
    // artefact that outlives the session, so it is the worst place to lose them.
    degradations: runner.getAllDegradations(),
    // Suppressions for the same reason, and the argument is stronger for them: a
    // suppressed finding is absent from `findings` by design, so an export built
    // from findings alone renders "nothing was found" and "something was found and
    // silenced" as the same document. The tally is the only thing that tells those
    // apart, and this file is where the result stops being a session and starts
    // being evidence.
    suppressions: runner.getAllSuppressions(),
    // The third way a finding can be absent, and the one this channel could not
    // report at all until the declared-package veto was wired into the runner: a
    // supply-chain finding the project's lockfile refuted. The CLI's JSON and
    // SARIF have carried these records since 0.3.2; an editor export that dropped
    // them would be the same document with one deletion mechanism missing.
    declaredPackageVetoes: runner.getAllDeclaredPackageVetoes(),
    declaredPackageVetoRan: runner.declaredPackageVetoRan(),
    generatedAt: new Date().toISOString(),
  });

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

/** Everything the exported document is built from. No VS Code, no clock. */
export interface ExportInputs {
  /** Already sorted; `buildExportResponse` does not reorder them. */
  findings: Finding[];
  degradations: ScanDegradation[];
  suppressions: SuppressionRecord[];
  declaredPackageVetoes: DeclaredPackageVetoRecord[];
  /** Whether the declared-package veto ran at all — see the three-state note below. */
  declaredPackageVetoRan: boolean;
  /** Passed in rather than read from a clock, so this function stays pure. */
  generatedAt: string;
}

/**
 * The document the export writes, as a pure function of what the runner held.
 *
 * Split out of `exportFindings` so the SHAPE can be asserted without a VS Code
 * host. Every optional field below is here because its absence once made a
 * partial, silenced or unchecked scan read as a clean one, and each of them is
 * exactly the kind of omission that no test running through the editor API
 * would have noticed.
 */
export function buildExportResponse(inputs: ExportInputs): ScanResponse {
  const { findings, degradations, suppressions, declaredPackageVetoes } = inputs;
  // ── THE LEDGER, IN THE ARTEFACT THAT OUTLIVES THE SESSION ────────────────
  //
  // Some findings are not "you wrote something dangerous" but "you wrote a
  // protection in a form a build step removes". This extension has one file and
  // no build output, so it cannot tell whether the protection survived — and
  // the export is precisely where an unasked question turns into a document
  // that looks like it was answered.
  //
  // Every claim built here is NOT_OBSERVED by construction: `claimsFromFindings`
  // has no artefact to read and could not emit a settled claim even if
  // something tried. Nothing here can turn a screen green; it can only add a
  // line saying what was declared and not checked.
  //
  // Rendering is not this function's job. `@vibeguard/sarif-adapter` already
  // turns these into SARIF notifications, and the VibeGuard-JSON branch carries
  // the field verbatim; the only reason the editor's export lacked the ledger
  // is that nothing ever put it on the response.
  //
  // ABSENT, NOT `[]`, WHEN NOBODY CLAIMED ANYTHING. `declaredPackageVetoes`
  // below distinguishes "armed and refuted nothing" (`[]`) from "never armed"
  // (absent) because the veto is a separate mechanism that either ran or did
  // not. Claims have no such prior step: a claim is derived from a finding and
  // nothing else, so "the ledger was built and is empty" and "no finding
  // declared a protection" are the same fact. Emitting `[]` would advertise a
  // distinction this producer cannot honour.
  const claims = claimsFromFindings(findings);
  return {
    summary: findings.length ? summarize(findings) : emptySummary(),
    findings,
    executionTimeMs: 0,
    engineVersions: { core: ENGINE_VERSION },
    generatedAt: inputs.generatedAt,
    ...(degradations.length ? { degradations } : {}),
    ...(suppressions.length ? { suppressions } : {}),
    // Present-but-empty when the veto ran over these documents and removed
    // nothing; absent only when no scanned document had a lockfile to check
    // against. Same three-state contract the analyzer and `scanPath` emit.
    ...(declaredPackageVetoes.length || inputs.declaredPackageVetoRan
      ? { declaredPackageVetoes }
      : {}),
    ...(claims.length ? { protectionClaims: claims } : {}),
  };
}

function pickDefaultUri(): vscode.Uri | undefined {
  const first = vscode.workspace.workspaceFolders?.[0];
  if (!first) return undefined;
  return vscode.Uri.joinPath(first.uri, 'vibeguard-findings.sarif');
}
