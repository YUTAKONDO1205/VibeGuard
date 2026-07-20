import { compareSeverity, type Finding, type ScanResponse, type Severity } from '@vibeguard/findings-schema';

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const GRAY = '\x1b[90m';
const MAGENTA = '\x1b[35m';

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: MAGENTA,
  high: RED,
  medium: YELLOW,
  low: BLUE,
  info: GRAY,
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

export function colorise(s: string, colour: string, useColor: boolean): string {
  return useColor ? `${colour}${s}${RESET}` : s;
}

export function formatHuman(scan: ScanResponse, useColor: boolean): string {
  const { findings, summary } = scan;
  const lines: string[] = [];

  if (findings.length === 0) {
    lines.push(colorise('✓ No findings.', GREEN, useColor));
    lines.push(`Scanned in ${scan.executionTimeMs}ms.`);
    appendRuleErrors(lines, scan, useColor);
    // Deliberately also on the zero-findings path, and this is the case that
    // matters most: "✓ No findings" printed over a scan where every finding was
    // suppressed is precisely the outcome an attacker is buying.
    appendSuppressions(lines, scan, useColor);
    return lines.join('\n');
  }

  for (const f of findings) {
    lines.push(formatFinding(f, useColor));
    lines.push('');
  }

  lines.push(colorise(`${BOLD}Summary${RESET}`, '', useColor));
  lines.push(
    `  ${colorise('critical', SEVERITY_COLOR.critical, useColor)}: ${summary.critical}` +
      `   ${colorise('high', SEVERITY_COLOR.high, useColor)}: ${summary.high}` +
      `   ${colorise('medium', SEVERITY_COLOR.medium, useColor)}: ${summary.medium}` +
      `   ${colorise('low', SEVERITY_COLOR.low, useColor)}: ${summary.low}` +
      `   ${colorise('info', SEVERITY_COLOR.info, useColor)}: ${summary.info}`,
  );
  lines.push(`  total: ${summary.total}    elapsed: ${scan.executionTimeMs}ms`);
  appendRuleErrors(lines, scan, useColor);
  appendDegradations(lines, scan, useColor);
  appendSuppressions(lines, scan, useColor);
  return lines.join('\n');
}

/**
 * Surface findings that a suppression removed (D8).
 *
 * NOT a defence and the wording must not imply one: every finding counted here
 * is gone, on purpose, because someone named its rule ID — the escape hatch that
 * makes suppression usable is intentionally still open. What this fixes is that
 * using it used to be invisible: the output of a scan over a file with a
 * hand-planted `disable-file VG-INJ-004` was character-for-character the output
 * of a scan over a clean file. Printing the tally makes the two distinguishable,
 * so a reviewer can ask why, which is the whole of the claim being made.
 *
 * Rendered in the neutral colour rather than the yellow used for degradations
 * and rule errors: those two report a scan that did not do its job, whereas a
 * suppression is a configured, legitimate operation most of the time. Shouting
 * at every `low` a team has opted out of would train people to ignore the line,
 * and the line only works if it is read.
 *
 * Silent at zero, per the same rule the other two channels follow.
 */
function appendSuppressions(lines: string[], scan: ScanResponse, useColor: boolean): void {
  if (!scan.suppressions?.length) return;
  lines.push('');
  const total = scan.suppressions.reduce((n, s) => n + s.count, 0);
  lines.push(
    colorise(
      `ℹ ${total} finding(s) were SUPPRESSED and are not listed above (rule IDs and counts only):`,
      DIM,
      useColor,
    ),
  );
  for (const s of scan.suppressions) {
    const at = s.filePath ? `${s.filePath} — ` : '';
    lines.push(`  ${at}${s.ruleId}: ${s.count} × ${s.channel}/${s.scope}`);
  }
}

/**
 * Surface PARTIAL scans (D3 ReDoS bounds). Kept apart from rule-error rendering
 * and worded differently on purpose: a degraded rule RAN and reported findings,
 * it just did not finish. Saying "errored and skipped" here — as the first
 * version did by routing these through `ruleErrors` — is a false statement that
 * a reviewer could act on.
 */
function appendDegradations(lines: string[], scan: ScanResponse, useColor: boolean): void {
  if (!scan.degradations?.length) return;
  lines.push('');
  // Counted in FILES, not rules. The entries are deduplicated per file+kind
  // upstream, so "N rule(s)" would report 1 where dozens of rules were actually
  // cut short — an undercount in a channel whose only job is honesty.
  const files = new Set(scan.degradations.map((d) => d.filePath).filter(Boolean));
  const scope = files.size > 0 ? `${files.size} file(s)` : `${scan.degradations.length} scan(s)`;
  // The parenthetical names the CAUSE, and there are now two distinct ones. The
  // header used to say "(ReDoS guard)" unconditionally, which stopped being true
  // when A1-LIMIT started routing match-limit truncations through this channel:
  // that bound is the per-file match cap, not a ReDoS bound, and a reader who
  // went looking for a pathological regex would find none. Each entry's `detail`
  // still says exactly which bound fired.
  const causes = new Set(scan.degradations.map((d) => (d.kind === 'match-limit' ? 'match limit' : 'ReDoS guard')));
  lines.push(
    colorise(
      `⚠ ${scope} were only PARTIALLY scanned (${[...causes].join(', ')}) — results may be incomplete:`,
      YELLOW,
      useColor,
    ),
  );
  for (const d of scan.degradations) {
    const at = d.filePath ? `${d.filePath} — ` : '';
    lines.push(`  ${at}${d.ruleId}: ${d.detail}`);
  }
}

/**
 * Surface skipped-on-crash rules. A rule that throws is dropped so it cannot
 * crash the scan, but that silently removes its findings — so a visible warning
 * here keeps the crash from being an invisible way to suppress findings.
 */
function appendRuleErrors(lines: string[], scan: ScanResponse, useColor: boolean): void {
  if (!scan.ruleErrors?.length) return;
  lines.push('');
  lines.push(
    colorise(
      `⚠ ${scan.ruleErrors.length} rule(s) errored and were skipped — their findings, if any, are NOT reported:`,
      YELLOW,
      useColor,
    ),
  );
  for (const e of scan.ruleErrors) {
    lines.push(`  ${e.ruleId}: ${e.message}`);
  }
}

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🟣',
  high: '🔴',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

const MAX_MARKDOWN_FINDINGS = 30;

export function formatMarkdown(scan: ScanResponse): string {
  const { findings, summary } = scan;
  const lines: string[] = [];
  lines.push('## VibeGuard Security Scan');
  lines.push('');

  if (findings.length === 0) {
    lines.push('No findings detected. ✅');
    lines.push('');
    lines.push(`_Scanned in ${scan.executionTimeMs}ms._`);
    appendRuleErrorsMarkdown(lines, scan);
    // As in the human renderer: a PR comment reading "No findings detected ✅"
    // over a fully-suppressed diff is the exact artifact this channel exists to
    // annotate, so the zero-findings path must not skip it.
    appendSuppressionsMarkdown(lines, scan);
    return lines.join('\n');
  }

  lines.push(
    `- **critical**: ${summary.critical}  **high**: ${summary.high}` +
      `  **medium**: ${summary.medium}  **low**: ${summary.low}  **info**: ${summary.info}`,
  );
  lines.push(`- total: ${summary.total} / scanned in ${scan.executionTimeMs}ms`);
  lines.push('');
  lines.push('### Findings');
  lines.push('');

  const sorted = [...findings].sort((a, b) => {
    const sev = compareSeverity(a.severity, b.severity);
    if (sev !== 0) return sev;
    const pathA = a.filePath ?? '';
    const pathB = b.filePath ?? '';
    if (pathA !== pathB) return pathA < pathB ? -1 : 1;
    return (a.startLine ?? 0) - (b.startLine ?? 0);
  });

  const shown = sorted.slice(0, MAX_MARKDOWN_FINDINGS);
  for (const f of shown) {
    lines.push(formatFindingMarkdown(f));
    lines.push('');
  }

  const omitted = sorted.length - shown.length;
  if (omitted > 0) {
    lines.push(`_… +${omitted} more, see SARIF report._`);
    lines.push('');
  }

  appendRuleErrorsMarkdown(lines, scan);
  appendDegradationsMarkdown(lines, scan);
  appendSuppressionsMarkdown(lines, scan);
  return lines.join('\n');
}

/**
 * The D8 tally in the PR-comment channel — see `appendSuppressions` for why this
 * is observability and not a defence, and why it says so plainly instead of
 * warning. A reviewer looking at a diff has no other way to tell that a line of
 * the diff itself deleted a finding from the report.
 */
function appendSuppressionsMarkdown(lines: string[], scan: ScanResponse): void {
  if (!scan.suppressions?.length) return;
  lines.push('');
  const total = scan.suppressions.reduce((n, s) => n + s.count, 0);
  lines.push(`> ℹ️ **${total} finding(s) were suppressed** and are not listed above:`);
  for (const s of scan.suppressions) {
    const at = s.filePath ? `\`${s.filePath}\` — ` : '';
    lines.push(`> - ${at}\`${s.ruleId}\`: ${s.count} × ${s.channel}/${s.scope}`);
  }
}

/**
 * Surface skipped-on-crash rules in the PR-comment channel. A crashed rule's
 * findings vanish; without this warning a review passes green precisely because
 * a rule was made to throw — the self-defense-as-attack-surface case.
 */
function appendRuleErrorsMarkdown(lines: string[], scan: ScanResponse): void {
  if (!scan.ruleErrors?.length) return;
  lines.push('');
  lines.push(
    `> ⚠️ **${scan.ruleErrors.length} rule(s) errored and were skipped** — their findings, if any, are NOT reported:`,
  );
  for (const e of scan.ruleErrors) {
    lines.push(`> - \`${e.ruleId}\`: ${e.message}`);
  }
}

/** Surface PARTIAL scans (D3 bounds) in the PR-comment channel — see the human
 * renderer for why this is separate from rule errors and worded differently. */
function appendDegradationsMarkdown(lines: string[], scan: ScanResponse): void {
  if (!scan.degradations?.length) return;
  lines.push('');
  const degradedFiles = new Set(scan.degradations.map((d) => d.filePath).filter(Boolean));
  // Same correction as the human renderer: name the bound that actually fired.
  const causes = new Set(
    scan.degradations.map((d) => (d.kind === 'match-limit' ? 'match limit' : 'ReDoS guard')),
  );
  lines.push(
    `> ⚠️ **${degradedFiles.size || scan.degradations.length} file(s) were only partially scanned** (${[...causes].join(', ')}) — results may be incomplete:`,
  );
  for (const d of scan.degradations) {
    const at = d.filePath ? `\`${d.filePath}\` — ` : '';
    lines.push(`> - ${at}\`${d.ruleId}\`: ${d.detail}`);
  }
}

function formatFindingMarkdown(f: Finding): string {
  const out: string[] = [];
  const sev = f.severity.toUpperCase();
  out.push(`#### ${SEVERITY_EMOJI[f.severity]} ${sev} — ${f.title} (\`${f.ruleId}\`)`);
  const location = f.filePath
    ? `\`${f.filePath}:${f.startLine ?? '?'}${f.startColumn ? `:${f.startColumn}` : ''}\``
    : `\`<inline>:${f.startLine ?? '?'}\``;
  out.push(`- ${location}`);
  out.push(`- _confidence_: ${f.confidence}`);
  if (f.remediation) {
    out.push(`- _why_: ${f.remediation.why}`);
    out.push(`- _fix_: ${f.remediation.how}`);
    if (f.remediation.exampleFix) {
      out.push('');
      out.push('  ```');
      for (const line of f.remediation.exampleFix.split('\n')) out.push(`  ${line}`);
      out.push('  ```');
    }
  }
  return out.join('\n');
}

function formatFinding(f: Finding, useColor: boolean): string {
  const sev = colorise(SEVERITY_LABEL[f.severity], SEVERITY_COLOR[f.severity], useColor);
  const location = f.filePath
    ? `${f.filePath}:${f.startLine ?? '?'}${f.startColumn ? `:${f.startColumn}` : ''}`
    : `<inline>:${f.startLine ?? '?'}`;
  const title = colorise(f.title, BOLD, useColor);
  const ruleId = colorise(`[${f.ruleId}]`, DIM, useColor);
  const conf = colorise(`(confidence: ${f.confidence})`, DIM, useColor);

  const out: string[] = [`${sev}  ${title}  ${ruleId} ${conf}`, `  at ${location}`];
  if (f.snippet) {
    const snippetLines = f.snippet.split('\n').slice(0, 3);
    out.push(...snippetLines.map((l) => colorise(`    | ${l}`, DIM, useColor)));
  }
  if (f.remediation) {
    out.push(colorise('  why: ', BOLD, useColor) + f.remediation.why);
    out.push(colorise('  fix: ', BOLD, useColor) + f.remediation.how);
    if (f.remediation.exampleFix) {
      out.push(colorise('  e.g. ', DIM, useColor) + f.remediation.exampleFix);
    }
  }
  return out.join('\n');
}
