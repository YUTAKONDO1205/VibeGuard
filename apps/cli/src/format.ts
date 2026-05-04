import type { Finding, ScanResponse, Severity } from '@vibeguard/findings-schema';

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
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
    lines.push(colorise('No findings.', GRAY, useColor));
    lines.push(`Scanned in ${scan.executionTimeMs}ms.`);
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
  return lines.join('\n');
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
