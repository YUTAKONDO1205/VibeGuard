import { describe, expect, it } from 'vitest';
import type { Finding, ScanResponse } from '@vibeguard/findings-schema';
import { formatHuman, formatMarkdown } from './format.js';

function scan(findings: Finding[], executionTimeMs = 12): ScanResponse {
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: findings.length,
  };
  for (const f of findings) summary[f.severity] += 1;
  return {
    summary,
    findings,
    executionTimeMs,
    engineVersions: { core: '0.1.0' },
    generatedAt: '2026-05-09T00:00:00.000Z',
  };
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    findingId: 'f1',
    ruleId: 'SEC-001',
    title: 'Hardcoded API Key',
    description: 'Detected a hardcoded API key.',
    severity: 'high',
    confidence: 'high',
    category: 'secret',
    filePath: 'packages/foo/src/bar.ts',
    startLine: 42,
    sourceEngine: 'core-rule',
    remediation: {
      why: 'Secrets in source code can leak via VCS.',
      how: 'Move the key to an environment variable.',
      exampleFix: 'const key = process.env.API_KEY;',
    },
    ...over,
  };
}

describe('formatMarkdown', () => {
  it('renders an empty-findings message', () => {
    const md = formatMarkdown(scan([]));
    expect(md).toContain('## VibeGuard Security Scan');
    expect(md).toContain('No findings detected');
    expect(md).toContain('Scanned in 12ms');
  });

  it('renders the summary line and finding details', () => {
    const md = formatMarkdown(scan([finding()]));
    expect(md).toContain('**critical**: 0');
    expect(md).toContain('**high**: 1');
    expect(md).toContain('total: 1 / scanned in 12ms');
    expect(md).toContain('#### 🔴 HIGH — Hardcoded API Key (`SEC-001`)');
    expect(md).toContain('`packages/foo/src/bar.ts:42`');
    expect(md).toContain('_why_:');
    expect(md).toContain('_fix_:');
    expect(md).toContain('process.env.API_KEY');
  });

  it('sorts findings by severity descending', () => {
    const md = formatMarkdown(
      scan([
        finding({ findingId: 'a', severity: 'low', title: 'Low one', ruleId: 'QUAL-001' }),
        finding({ findingId: 'b', severity: 'critical', title: 'Crit one', ruleId: 'INJ-001' }),
        finding({ findingId: 'c', severity: 'medium', title: 'Med one', ruleId: 'AUTH-001' }),
      ]),
    );
    const critIdx = md.indexOf('Crit one');
    const medIdx = md.indexOf('Med one');
    const lowIdx = md.indexOf('Low one');
    expect(critIdx).toBeGreaterThan(-1);
    expect(critIdx).toBeLessThan(medIdx);
    expect(medIdx).toBeLessThan(lowIdx);
  });

  it('truncates above the per-comment cap', () => {
    const many = Array.from({ length: 35 }, (_, i) =>
      finding({ findingId: `f${i}`, ruleId: `RULE-${i}`, startLine: i + 1 }),
    );
    const md = formatMarkdown(scan(many));
    expect(md).toContain('+5 more, see SARIF');
    expect((md.match(/^#### /gm) ?? []).length).toBe(30);
  });

  it('surfaces ruleErrors in markdown, even with no findings', () => {
    const response: ScanResponse = {
      ...scan([]),
      ruleErrors: [{ ruleId: 'VG-TEST-BOOM', message: 'kaboom' }],
    };
    const md = formatMarkdown(response);
    expect(md).toContain('errored and were skipped');
    expect(md).toContain('VG-TEST-BOOM');
    expect(md).toContain('kaboom');
  });

  it('surfaces ruleErrors in human output', () => {
    const response: ScanResponse = {
      ...scan([]),
      ruleErrors: [{ ruleId: 'VG-TEST-BOOM', message: 'kaboom' }],
    };
    const out = formatHuman(response, false);
    expect(out).toContain('errored and were skipped');
    expect(out).toContain('VG-TEST-BOOM: kaboom');
  });

  it('omits the ruleErrors block when there are none', () => {
    expect(formatMarkdown(scan([]))).not.toContain('errored and were skipped');
    expect(formatHuman(scan([]), false)).not.toContain('errored and were skipped');
  });
});

/**
 * D8 rendering. The tally has to reach the two channels a human reads (the
 * terminal and the PR comment), and — the part that carries the weight — it has
 * to reach them on the zero-findings path, since "no findings" over a fully
 * suppressed scan is the artifact the whole thing exists to annotate.
 */
describe('suppression tally rendering (D8)', () => {
  const withSuppressions = (findings: Finding[]): ScanResponse => ({
    ...scan(findings),
    suppressions: [
      { ruleId: 'VG-INJ-004', channel: 'pragma', scope: 'line', filePath: 'src/db.ts', count: 2 },
      { ruleId: 'VG-AUTH-003', channel: 'config', scope: 'path', filePath: 'src/api.ts', count: 1 },
    ],
  });

  it('renders the tally in human output even with zero findings', () => {
    const out = formatHuman(withSuppressions([]), false);
    expect(out).toContain('✓ No findings.');
    expect(out).toContain('3 finding(s) were SUPPRESSED');
    expect(out).toContain('src/db.ts — VG-INJ-004: 2 × pragma/line');
    expect(out).toContain('src/api.ts — VG-AUTH-003: 1 × config/path');
  });

  it('renders the tally in human output alongside findings', () => {
    const out = formatHuman(withSuppressions([finding()]), false);
    expect(out).toContain('3 finding(s) were SUPPRESSED');
  });

  it('renders the tally in markdown, including the zero-findings path', () => {
    expect(formatMarkdown(withSuppressions([]))).toContain('**3 finding(s) were suppressed**');
    const withF = formatMarkdown(withSuppressions([finding()]));
    expect(withF).toContain('**3 finding(s) were suppressed**');
    expect(withF).toContain('`VG-INJ-004`: 2 × pragma/line');
  });

  it('prints nothing at all when no suppression happened', () => {
    // Zero must be silent in both renderers, or the line becomes noise on every
    // clean scan and stops being read.
    for (const out of [formatHuman(scan([finding()]), false), formatMarkdown(scan([finding()]))]) {
      expect(out.toLowerCase()).not.toContain('suppress');
    }
  });
});

// A finding that came back BECAUSE a wildcard suppression was refused is the
// one thing an upgrading project sees first, and without an explanation it reads
// as a false positive appearing from nowhere — the wildcard is still in the file,
// visibly handling it, and the finding is there anyway. The message has to carry
// the migration, because naming the rule IS the migration.
describe('refused suppressions explain themselves', () => {
  const overridden = (channel: 'pragma' | 'config', scope: 'file' | 'line' | 'path'): Finding =>
    finding({
      ruleId: 'VG-INJ-004',
      severity: 'critical',
      suppressionOverridden: { channel, scope },
    });

  it('names the rule to write, for a pragma wildcard', () => {
    const out = formatHuman(scan([overridden('pragma', 'file')]), false);
    expect(out).toContain('vibeguard:disable-file');
    expect(out).toContain('does not apply to critical findings');
    expect(out).toContain('vibeguard:disable-next-line VG-INJ-004');
  });

  it('points at the config entry, for a config wildcard', () => {
    const out = formatHuman(scan([overridden('config', 'path')]), false);
    expect(out).toContain('`suppress` entry in the config');
    // The config channel has its own fix, and offering only the pragma form
    // would send people to edit the wrong file.
    expect(out).toContain("add \"VG-INJ-004\" to the entry's `rules`");
  });

  it('carries the same guidance into markdown, where a PR comment shows it', () => {
    const out = formatMarkdown(scan([overridden('pragma', 'line')]));
    expect(out).toContain('_suppression refused_');
    expect(out).toContain('vibeguard:disable-next-line VG-INJ-004');
  });

  it('says nothing for an ordinary finding', () => {
    // The note is keyed to the marker, not to severity: a critical that nobody
    // tried to suppress must not be told how to suppress it.
    const out = formatHuman(scan([finding({ severity: 'critical' })]), false);
    expect(out).not.toContain('does not apply to');
    expect(out).not.toContain('disable-next-line');
  });
});
