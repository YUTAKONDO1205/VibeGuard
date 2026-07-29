// vibeguard:disable-file VG-INJ-004
// Test fixtures contain intentional vulnerable code to exercise the rules.
import { describe, expect, it } from 'vitest';
import { summarize, type Finding, type ScanResponse } from '@vibeguard/findings-schema';
import { toSarif } from './index.js';

const fakeFinding = (overrides: Partial<Finding> = {}): Finding => ({
  findingId: 'f-1',
  ruleId: 'VG-TEST-001',
  title: 'demo',
  description: 'demo description',
  severity: 'high',
  confidence: 'high',
  category: 'injection',
  filePath: 'src/a.ts',
  startLine: 4,
  endLine: 4,
  snippet: 'eval(x)',
  evidence: ['eval(x)'],
  sourceEngine: 'core-rule',
  ...overrides,
});

const wrap = (findings: Finding[]): ScanResponse => ({
  summary: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0, total: findings.length },
  findings,
  executionTimeMs: 1,
  engineVersions: { core: '0.1.0' },
  generatedAt: '2026-05-04T00:00:00Z',
});

/**
 * The envelope has to point somewhere real, and it has to carry the fields the
 * one consumer that matters actually reads.
 *
 * Both URLs used to 404: `$schema` pointed into a branch of the sarif-spec repo
 * that no longer serves that path, and `informationUri` named a repository
 * (`github.com/vibeguard/vibeguard`) that does not exist. A `$schema` nobody can
 * fetch is worse than none — validators report a load failure instead of a
 * schema violation.
 */
describe('SARIF envelope metadata', () => {
  it('points $schema at the OASIS publication location, not a moving branch', () => {
    const log = toSarif(wrap([fakeFinding()]));
    expect(log.$schema).toBe(
      'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json',
    );
  });

  it('names the repository this tool is actually published from', () => {
    const log = toSarif(wrap([fakeFinding()]));
    expect(log.runs[0]?.tool.driver.informationUri).toBe(
      'https://github.com/YUTAKONDO1205/VibeGuard',
    );
  });

  // SARIF has four levels and VibeGuard has five severities, so `critical` and
  // `high` both collapse to `error`. `security-severity` is where GitHub code
  // scanning recovers the distinction; without it every alert lands in one bucket.
  it('carries security-severity so critical outranks high in code scanning', () => {
    const log = toSarif(
      wrap([
        fakeFinding({ ruleId: 'VG-CRIT', severity: 'critical' }),
        fakeFinding({ ruleId: 'VG-HIGH', severity: 'high' }),
      ]),
    );
    const rules = log.runs[0]?.tool.driver.rules ?? [];
    const sev = (id: string): string | undefined =>
      rules.find((r) => r.id === id)?.properties?.['security-severity'];

    expect(sev('VG-CRIT')).toBe('9.0');
    expect(sev('VG-HIGH')).toBe('7.0');
    expect(Number(sev('VG-CRIT'))).toBeGreaterThan(Number(sev('VG-HIGH')));
    // The collapse this compensates for is still there, by design.
    const level = (id: string): string | undefined => rules.find((r) => r.id === id)
      ?.defaultConfiguration.level;
    expect(level('VG-CRIT')).toBe(level('VG-HIGH'));
  });

  it('derives precision from confidence', () => {
    const log = toSarif(wrap([fakeFinding({ ruleId: 'VG-LOWC', confidence: 'low' })]));
    const rule = log.runs[0]?.tool.driver.rules.find((r) => r.id === 'VG-LOWC');
    expect(rule?.properties?.precision).toBe('low');
  });
});

describe('toSarif', () => {
  it('produces a valid 2.1.0 envelope', () => {
    const sarif = toSarif(wrap([fakeFinding()]));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0]!.tool.driver.name).toBe('VibeGuard');
  });

  it('deduplicates rule descriptors', () => {
    const sarif = toSarif(wrap([fakeFinding(), fakeFinding({ findingId: 'f-2' })]));
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0]!.results).toHaveLength(2);
  });

  it('maps severity to SARIF level', () => {
    const sarif = toSarif(
      wrap([
        fakeFinding({ severity: 'critical' }),
        fakeFinding({ findingId: 'f-2', severity: 'low', ruleId: 'VG-TEST-002' }),
      ]),
    );
    const levels = sarif.runs[0]!.results.map((r) => r.level);
    expect(levels).toEqual(['error', 'note']);
  });

  it('emits a region with startLine', () => {
    const sarif = toSarif(wrap([fakeFinding()]));
    const region = sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.region;
    expect(region.startLine).toBe(4);
  });

  it('records ruleErrors as failed-invocation notifications', () => {
    const response = { ...wrap([]), ruleErrors: [{ ruleId: 'VG-TEST-BOOM', message: 'kaboom' }] };
    const run = toSarif(response).runs[0]!;
    expect(run.invocations?.[0]?.executionSuccessful).toBe(false);
    const notif = run.invocations?.[0]?.toolExecutionNotifications[0];
    expect(notif?.level).toBe('error');
    expect(notif?.associatedRule?.id).toBe('VG-TEST-BOOM');
    expect(notif?.message.text).toContain('kaboom');
  });

  it('omits invocations when no rule errored', () => {
    expect(toSarif(wrap([fakeFinding()])).runs[0]!.invocations).toBeUndefined();
  });

  it('carries confidenceAudit into the property bag', () => {
    const audit = { signals: ['comment' as const], ungated: 'low' as const, floored: true };
    const sarif = toSarif(wrap([fakeFinding({ confidenceAudit: audit })]));
    expect(sarif.runs[0]!.results[0]!.properties?.confidenceAudit).toEqual(audit);
  });

  it('omits the confidenceAudit key for findings that carry no audit', () => {
    const props = toSarif(wrap([fakeFinding()])).runs[0]!.results[0]!.properties!;
    expect('confidenceAudit' in props).toBe(false);
  });

  // SARIF is what the GitHub Action emits by default, so a suppression tally
  // that only reached the JSON and human renderers was invisible on the path
  // most projects actually run.
  it('records suppressions as note-level notifications', () => {
    const response = {
      ...wrap([]),
      suppressions: [
        {
          ruleId: 'VG-INJ-004',
          channel: 'pragma' as const,
          scope: 'file' as const,
          filePath: 'app.js',
          count: 3,
        },
      ],
    };
    const run = toSarif(response).runs[0]!;
    // A suppression is not a failure: the run still succeeded.
    expect(run.invocations?.[0]?.executionSuccessful).toBe(true);
    const notif = run.invocations?.[0]?.toolExecutionNotifications[0];
    expect(notif?.level).toBe('note');
    expect(notif?.associatedRule?.id).toBe('VG-INJ-004');
    expect(notif?.message.text).toContain('3 finding(s)');
    expect(notif?.message.text).toContain('app.js');
  });

  // The tally deliberately carries no line number, and the SARIF rendering must
  // not reintroduce one: that would rebuild the finding the author suppressed,
  // inside the artifact a reviewer reads.
  it('does not leak a location for a suppressed finding', () => {
    const response = {
      ...wrap([]),
      suppressions: [
        {
          ruleId: 'VG-INJ-004',
          channel: 'config' as const,
          scope: 'path' as const,
          filePath: 'app.js',
          count: 1,
        },
      ],
    };
    const run = toSarif(response).runs[0]!;
    expect(run.results).toEqual([]);
    const text = run.invocations![0]!.toolExecutionNotifications[0]!.message.text;
    expect(text).not.toMatch(/line\s*\d+/i);
  });

  it('omits invocations when nothing errored, degraded, or was suppressed', () => {
    expect(toSarif(wrap([fakeFinding()])).runs[0]!.invocations).toBeUndefined();
  });
});

describe('design-smell findings in SARIF', () => {
  const smell = {
    findingId: 'ds1',
    ruleId: 'VG-SMELL-010',
    title: 'Scattered Authorization',
    description: 'Authorization is decided inline in 3 route handlers across 2 files.',
    severity: 'high' as const,
    confidence: 'medium' as const,
    category: 'security-design-smell',
    sourceEngine: 'core-rule' as const,
    scope: 'project' as const,
    filePath: 'src/routes/admin.ts',
    startLine: 12,
    primaryLocation: { filePath: 'src/routes/admin.ts', startLine: 12 },
    relatedLocations: [
      { filePath: 'src/routes/users.ts', startLine: 44, evidence: "user.role !== 'admin'" },
      { filePath: 'src/routes/settings.ts', startLine: 31 },
    ],
    metrics: { duplicatedCheckCount: 3 },
    securityContext: { containsAuthorizationLogic: true },
  };

  const resultFor = (findings: Finding[]) =>
    toSarif({
      summary: summarize(findings),
      findings,
      executionTimeMs: 1,
      engineVersions: { core: '0.2.1' },
      generatedAt: '2026-07-27T00:00:00.000Z',
    }).runs[0]!.results[0]!;

  it('emits relatedLocations, so a cross-file claim survives the default Action format', () => {
    // Without this the flagship finding renders as one line and the "scattered"
    // half — the entire claim — is discarded in the format the GitHub Action
    // produces by default.
    const r = resultFor([smell as unknown as Finding]);
    expect(r.relatedLocations).toHaveLength(2);
    expect(r.relatedLocations![0]!.physicalLocation.artifactLocation.uri).toBe('src/routes/users.ts');
    expect(r.relatedLocations![0]!.physicalLocation.region.startLine).toBe(44);
  });

  it('gives each related location a stable 1-based id', () => {
    const r = resultFor([smell as unknown as Finding]);
    expect(r.relatedLocations!.map((l) => l.id)).toEqual([1, 2]);
  });

  it('carries evidence as the related location message when present', () => {
    const r = resultFor([smell as unknown as Finding]);
    expect(r.relatedLocations![0]!.message?.text).toBe("user.role !== 'admin'");
    // Absent, not present-and-undefined, when the producer had no evidence.
    expect('message' in r.relatedLocations![1]!).toBe(false);
  });

  it('carries scope and metrics in the property bag', () => {
    const r = resultFor([smell as unknown as Finding]);
    expect(r.properties?.scope).toBe('project');
    expect(r.properties?.metrics).toEqual({ duplicatedCheckCount: 3 });
    expect(r.properties?.securityContext).toEqual({ containsAuthorizationLogic: true });
  });

  it('leaves ordinary findings byte-identical — no new keys appear', () => {
    // The regression contract: enabling design smells must not change the SARIF
    // of a scan that has none.
    const plain: Finding = {
      findingId: 'f1',
      ruleId: 'VG-INJ-001',
      title: 'SQL Injection',
      description: 'd',
      severity: 'critical',
      confidence: 'high',
      category: 'injection',
      sourceEngine: 'core-rule',
      filePath: 'src/db.ts',
      startLine: 3,
    };
    const r = resultFor([plain]);
    expect('relatedLocations' in r).toBe(false);
    expect('scope' in (r.properties ?? {})).toBe(false);
    expect('metrics' in (r.properties ?? {})).toBe(false);
  });
});

/**
 * SARIF URIs and finding paths answer to different masters.
 *
 * GitHub code scanning resolves `artifactLocation.uri` from the REPOSITORY
 * ROOT. A finding's `filePath` is relative to the SCAN TARGET, and three other
 * consumers depend on that basis (`fix.ts` reads a finding back as
 * `join(target, filePath)`, config `suppress[].paths` globs are written against
 * it, the human formatter prints it). For a scan of the repo root the two
 * coincide, which is why this went unnoticed; for `vibeguard packages/api` the
 * SARIF named `routes.ts` for a file that lives at `packages/api/routes.ts`, so
 * every alert pointed somewhere that does not exist.
 */
describe('uriPrefix lifts SARIF URIs to the repository root', () => {
  const uriOf = (log: ReturnType<typeof toSarif>): string =>
    log.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri;

  it('is a no-op without a prefix', () => {
    expect(uriOf(toSarif(wrap([fakeFinding({ filePath: 'a.ts' })])))).toBe('a.ts');
  });

  it('prefixes a target-relative path', () => {
    const log = toSarif(wrap([fakeFinding({ filePath: 'a.ts' })]), { uriPrefix: 'packages/api/' });
    expect(uriOf(log)).toBe('packages/api/a.ts');
  });

  it('accepts a prefix with or without its trailing slash', () => {
    const a = toSarif(wrap([fakeFinding({ filePath: 'a.ts' })]), { uriPrefix: 'pkg' });
    const b = toSarif(wrap([fakeFinding({ filePath: 'a.ts' })]), { uriPrefix: 'pkg/' });
    expect(uriOf(a)).toBe('pkg/a.ts');
    expect(uriOf(b)).toBe('pkg/a.ts');
  });

  it('does not double-apply a prefix the path already carries', () => {
    const log = toSarif(wrap([fakeFinding({ filePath: 'pkg/a.ts' })]), { uriPrefix: 'pkg/' });
    expect(uriOf(log)).toBe('pkg/a.ts');
  });

  it('leaves an absolute path alone', () => {
    // The Windows form is built from its code point rather than written as an
    // escape: `'C:	mp'` in source is `C:`+TAB, which is not a path at all and
    // would make this assertion test a different string than it claims to.
    const BS = String.fromCharCode(92);
    for (const p of ['/tmp/a.ts', 'C:/tmp/a.ts', `C:${BS}tmp${BS}a.ts`]) {
      const log = toSarif(wrap([fakeFinding({ filePath: p })]), { uriPrefix: 'pkg/' });
      expect(uriOf(log)).toBe(p);
    }
  });

  it('leaves a finding with no path alone', () => {
    const log = toSarif(wrap([fakeFinding({ filePath: undefined })]), { uriPrefix: 'pkg/' });
    expect(uriOf(log)).toBe('<inline>');
  });
});
