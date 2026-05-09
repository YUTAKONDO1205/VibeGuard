import { describe, expect, it } from 'vitest';
import { allRules } from './index.js';

const RULE_ID_RE = /^VG-(INJ|AUTH|SEC|CRYPTO|QUAL|FW)-\d{3}$/;
const VALID_SEVERITY = new Set(['critical', 'high', 'medium', 'low', 'info']);
const VALID_CONFIDENCE = new Set(['high', 'medium', 'low']);
// Categories are a richer taxonomy than the rule-ID prefix. The prefix groups
// rules by structural family (which file they live in); the category groups
// them by what kind of risk they represent. They overlap but don't have to
// match 1:1 — VG-AUTH-003 (dummy token) is correctly categorised under
// "secrets", and VG-QUAL-002 (broad access) under "access-control".
const VALID_CATEGORY = new Set([
  'injection',
  'auth',
  'secrets',
  'crypto',
  'quality',
  'access-control',
  'ai-quality',
  'logging',
  'config',
  'logic',
]);

describe('rule registry', () => {
  it('every rule ID matches VG-<CAT>-NNN', () => {
    for (const r of allRules) {
      expect(r.ruleId, `bad ruleId: ${r.ruleId}`).toMatch(RULE_ID_RE);
    }
  });

  it('rule IDs are unique', () => {
    const seen = new Set<string>();
    const dupes: string[] = [];
    for (const r of allRules) {
      if (seen.has(r.ruleId)) dupes.push(r.ruleId);
      seen.add(r.ruleId);
    }
    expect(dupes).toEqual([]);
  });

  it('every rule has required string fields', () => {
    for (const r of allRules) {
      expect(r.name, `${r.ruleId} missing name`).toBeTruthy();
      expect(r.description, `${r.ruleId} missing description`).toBeTruthy();
      expect(typeof r.match, `${r.ruleId} match must be a function`).toBe('function');
    }
  });

  it('severity, confidence, category are from the allowed sets', () => {
    for (const r of allRules) {
      expect(VALID_SEVERITY.has(r.severity), `${r.ruleId} bad severity ${r.severity}`).toBe(true);
      expect(
        VALID_CONFIDENCE.has(r.defaultConfidence),
        `${r.ruleId} bad confidence ${r.defaultConfidence}`,
      ).toBe(true);
      expect(VALID_CATEGORY.has(r.category), `${r.ruleId} bad category ${r.category}`).toBe(true);
    }
  });

  it('languages is non-empty', () => {
    for (const r of allRules) {
      expect(r.languages.length, `${r.ruleId} has empty languages`).toBeGreaterThan(0);
    }
  });

  it('every rule has remediation with why/how', () => {
    for (const r of allRules) {
      expect(r.remediation, `${r.ruleId} missing remediation`).toBeDefined();
      expect(r.remediation?.why, `${r.ruleId} missing remediation.why`).toBeTruthy();
      expect(r.remediation?.how, `${r.ruleId} missing remediation.how`).toBeTruthy();
    }
  });

  it('rule ID prefix is one of the known families', () => {
    const validPrefixes = new Set(['INJ', 'AUTH', 'SEC', 'CRYPTO', 'QUAL', 'FW']);
    for (const r of allRules) {
      const prefix = r.ruleId.split('-')[1];
      expect(validPrefixes.has(prefix ?? ''), `${r.ruleId} unknown prefix`).toBe(true);
    }
  });
});
