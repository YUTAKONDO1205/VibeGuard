// Self-checks on the mapping table, plus the two package-wide invariants that
// have nowhere else to live: no unbounded regex quantifier, and no way to run a
// process.
//
// These are the assertions that catch a bad EDIT rather than a bad input. The
// table is the only place in this package where a one-character change silently
// alters what "two tools agreed" means, so it gets the same treatment
// scripts/sec-transfer-semgrep.mjs gives its own table: mechanical assertions,
// run every time, with the failure mode named in the test's own name.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  WEAKNESS_FAMILIES,
  classifyCodeqlRuleId,
  classifyRuleId,
  classifySemgrepCheckId,
  classifyVibeguardRuleId,
  toolHasDetectorFor,
  weaknessFamily,
} from './weakness-class.js';

const SRC_DIR = fileURLToPath(new URL('.', import.meta.url));

describe('the mapping table is well formed', () => {
  it('declares a weakness, a VibeGuard rule and a note for every family', () => {
    for (const family of WEAKNESS_FAMILIES) {
      expect(family.weakness).not.toBe('');
      expect(family.vibeguardRules.length).toBeGreaterThan(0);
      expect(family.note).not.toBe('');
    }
  });

  it('is a function, not a relation: no VibeGuard rule is claimed by two families', () => {
    // The same assertion sec-transfer-semgrep.mjs makes as A3, and for the same
    // reason: a rule in two families makes classifyVibeguardRuleId depend on
    // table order, which is a display concern.
    const all = WEAKNESS_FAMILIES.flatMap((f) => f.vibeguardRules);
    expect(all.length).toBe(new Set(all).size);
  });

  it('has a unique class name per family', () => {
    const classes = WEAKNESS_FAMILIES.map((f) => f.weaknessClass);
    expect(classes.length).toBe(new Set(classes).size);
  });

  it('never marks a CodeQL pattern empirically confirmed, because CodeQL has never run here', () => {
    for (const family of WEAKNESS_FAMILIES) {
      expect(family.codeqlEmpiricallyConfirmed).toBe(false);
    }
  });

  it('gives every family at least one tool that can detect it', () => {
    // A family no tool can match is dead weight: it inflates the apparent
    // coverage of the table without contributing a single classification.
    for (const family of WEAKNESS_FAMILIES) {
      expect(family.semgrepPatterns.length + family.codeqlPatterns.length).toBeGreaterThan(0);
    }
  });

  it('exposes each family through weaknessFamily()', () => {
    for (const family of WEAKNESS_FAMILIES) {
      expect(weaknessFamily(family.weaknessClass)).toBe(family);
    }
  });
});

describe('every pattern is quantifier-bounded (the ReDoS house rule)', () => {
  // This package parses reports a USER supplies, so the rule ids it matches
  // against are attacker-influenceable in exactly the way packages/rules' inputs
  // are. scripts/sec-a1-catalog.mjs — the ReDoS census — reads only
  // packages/rules, so nothing outside that directory is covered by it and the
  // bound is the only protection. sec-transfer-codeql.mjs ships two unbounded
  // wildcard patterns; both were rewritten with bounded character classes on the
  // way in, and this test is what stops them coming back.
  const patternSources = WEAKNESS_FAMILIES.flatMap((f) =>
    [...f.semgrepPatterns, ...f.codeqlPatterns].map((re) => ({ family: f.weaknessClass, source: re.source })),
  );

  it('checks a non-empty set of patterns', () => {
    expect(patternSources.length).toBeGreaterThanOrEqual(15);
  });

  it('contains no star or plus quantifier anywhere in the table', () => {
    const offenders = patternSources.filter((p) => /[*+]/.test(p.source)).map((p) => `${p.family}: ${p.source}`);
    expect(offenders).toEqual([]);
  });

  it('contains no whitespace class, which is the shape that crosses lines', () => {
    const offenders = patternSources.filter((p) => p.source.includes('\\s')).map((p) => `${p.family}: ${p.source}`);
    expect(offenders).toEqual([]);
  });

  it('gives every {n,m} repetition an upper bound', () => {
    const openEnded = /\{[0-9]{1,3},\}/;
    const offenders = patternSources.filter((p) => openEnded.test(p.source)).map((p) => `${p.family}: ${p.source}`);
    expect(offenders).toEqual([]);
  });

  it('still matches the two shapes the bounded rewrites were written for', () => {
    // A bound that is too tight is a silent coverage loss, so the rewritten
    // patterns are exercised against the shapes they were meant to keep.
    expect(classifyCodeqlRuleId('py/insecure-download-request')).toBe('tls-verification-disabled');
    expect(classifyCodeqlRuleId('js/insecure-websocket-protocol')).toBe('insecure-transport');
  });

  it('no longer spans a rule-id path separator, which is the declared narrowing', () => {
    expect(classifyCodeqlRuleId('js/insecure-foo/bar-request')).toBeNull();
  });
});

describe('classification', () => {
  it('recognises the check_id tail through a vendored-config path prefix', () => {
    // sec-transfer-semgrep.mjs's header: a vendored ruleset prepends the vendor
    // path to the check_id, which is why the patterns are unanchored. If this
    // regressed, every scan run with a local --config directory would classify
    // as unmapped.
    expect(classifySemgrepCheckId('python.flask.security.audit.debug-enabled.debug-enabled')).toBe('debug-enabled');
    expect(classifySemgrepCheckId('vendor.snapshot.python.flask.security.audit.debug-enabled.debug-enabled')).toBe(
      'debug-enabled',
    );
  });

  it('matches VibeGuard rule ids exactly and never by prefix', () => {
    expect(classifyVibeguardRuleId('VG-INJ-001')).toBe('injection-sql');
    expect(classifyVibeguardRuleId('VG-INJ-0')).toBeNull();
    expect(classifyVibeguardRuleId('VG-INJ-0011')).toBeNull();
    expect(classifyVibeguardRuleId('VG-QUAL-001')).toBeNull();
  });

  it('routes each id space to its own classifier', () => {
    expect(classifyRuleId('vibeguard', 'VG-AUTH-004')).toBe('tls-verification-disabled');
    expect(classifyRuleId('semgrep', 'python.requests.security.disabled-cert-validation.disabled-cert-validation')).toBe(
      'tls-verification-disabled',
    );
    expect(classifyRuleId('codeql', 'py/request-without-cert-validation')).toBe('tls-verification-disabled');
  });

  it('does not classify a CodeQL id with the Semgrep patterns or the reverse', () => {
    // The narrow name parseCodeqlSarifReport exists because feeding it another
    // tool's SARIF would silently produce all-unclassified output. This is the
    // measurement behind that warning.
    expect(classifySemgrepCheckId('py/sql-injection')).toBeNull();
    expect(
      classifyCodeqlRuleId('python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query'),
    ).toBeNull();
  });

  it('returns null for anything unmapped rather than guessing a nearest family', () => {
    for (const id of [
      'go.lang.security.audit.crypto.math_random.math-random-used',
      'python.django.security.audit.csrf-exempt.no-csrf-exempt',
      'javascript.express.security.audit.express-session-hardcoded-secret.express-session-hardcoded-secret',
      '',
    ]) {
      expect(classifySemgrepCheckId(id)).toBeNull();
    }
  });
});

describe('toolHasDetectorFor', () => {
  it('is false for a tool with no mapped pattern, which is what keeps silentTools honest', () => {
    // CodeQL has no mapped weak-crypto, cookie-flags or debug-mode pattern.
    // Crediting it with one would report it as having stayed silent about a
    // weakness this table never taught anyone to recognise from its output.
    expect(toolHasDetectorFor('codeql', 'weak-crypto')).toBe(false);
    expect(toolHasDetectorFor('codeql', 'cookie-session-flags')).toBe(false);
    expect(toolHasDetectorFor('codeql', 'debug-enabled')).toBe(false);
    expect(toolHasDetectorFor('semgrep', 'weak-crypto')).toBe(true);
    expect(toolHasDetectorFor('vibeguard', 'weak-crypto')).toBe(true);
  });

  it('holds the invariant every merge depends on: a classifier hit implies a detector', () => {
    // If a tool's id classifies as family F, that tool MUST report as having a
    // detector for F — otherwise reportedBy could contain a tool absent from
    // couldHaveBeenReportedBy, silentTools would go negative in meaning, and
    // classifyAgreement would compare a count against a smaller one.
    for (const family of WEAKNESS_FAMILIES) {
      for (const pattern of family.semgrepPatterns) {
        expect(toolHasDetectorFor('semgrep', family.weaknessClass)).toBe(true);
        expect(pattern.source).not.toBe('');
      }
      for (const pattern of family.codeqlPatterns) {
        expect(toolHasDetectorFor('codeql', family.weaknessClass)).toBe(true);
        expect(pattern.source).not.toBe('');
      }
    }
  });
});

describe('the package cannot run a process or open a socket', () => {
  // The central claim of types.ts, asserted rather than promised. If someone adds
  // an invocation path later, this fails and they have to argue with the header
  // that explains why neither tool has ever been executed here.
  function sourceFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        out.push(...sourceFiles(full));
        continue;
      }
      if (entry.endsWith('.ts')) out.push(full);
    }
    return out;
  }

  const shipped = sourceFiles(SRC_DIR).filter((f) => !f.endsWith('.test.ts'));

  it('finds the source files it is supposed to be checking', () => {
    // Guard against the check passing because the walk found nothing.
    expect(shipped.length).toBeGreaterThanOrEqual(6);
  });

  it('imports no process, network or child-process module in shipped code', () => {
    const banned = [
      'node:child_process',
      'child_process',
      'node:http',
      'node:https',
      'node:net',
      'node:dgram',
      'node:worker_threads',
      'undici',
    ];
    const fetchCall = /\bfetch[^\S\r\n]{0,4}\(/;
    const violations: string[] = [];
    for (const file of shipped) {
      const source = readFileSync(file, 'utf8');
      for (const module of banned) {
        if (source.includes(`from '${module}'`) || source.includes(`require('${module}')`)) {
          violations.push(`${file} imports ${module}`);
        }
      }
      if (fetchCall.test(source)) violations.push(`${file} calls fetch()`);
      if (source.includes('XMLHttpRequest')) violations.push(`${file} references XMLHttpRequest`);
    }
    // Collected rather than asserted per file, so a failure names every offender
    // at once instead of stopping at the first.
    expect(violations).toEqual([]);
  });

  it('does no filesystem I/O in shipped code either, because adapters take text and not paths', () => {
    // Keeping the parsers pure is what makes them testable without a fixture on
    // disk, and it is why reportPath is provenance rather than an input.
    const violations: string[] = [];
    for (const file of shipped) {
      const source = readFileSync(file, 'utf8');
      if (source.includes("from 'node:fs'") || source.includes("from 'node:fs/promises'")) {
        violations.push(`${file} imports node:fs`);
      }
    }
    expect(violations).toEqual([]);
  });
});
