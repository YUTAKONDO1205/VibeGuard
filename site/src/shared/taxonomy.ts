/**
 * The eight detection categories — the site's own grouping of the rule set.
 *
 * The rule set has eleven ID families; the front page shows eight circles in a
 * 4x2 grid. This file is the mapping between them, and it lives on the site
 * side because the grouping is an editorial decision about how to explain the
 * product, not a property of the rules.
 *
 * Two build-time assertions in scripts/site-export-rules.mjs keep the mapping
 * honest, and both fail the build rather than warn:
 *
 *   1. Every prefix present in `allRules` maps to a bucket. A new family (say
 *      VG-NET-*) makes the build stop until someone decides which circle it
 *      belongs in — otherwise the site would quietly describe a smaller
 *      product than the one that ships.
 *   2. The bucket counts sum to allRules.length. Catches a rule that got
 *      double-counted or dropped by a mapping edit.
 *
 * The count shown under each circle is generated, never written here. The
 * numbers move every release; a literal in this file would be a lie with a
 * date on it.
 */

export interface Bucket {
  /** Anchor on /rules, and the fragment the front-page circle links to. */
  readonly id: string;
  /** Shown under the circle and as the <h2> of the section on /rules. */
  readonly label: string;
  /**
   * One line under the label. Vocabulary is taken from README.md's rule
   * catalogue and the `name` field of the rule sources — no new phrasing, so
   * every word on the page traces back to a checked-in string.
   */
  readonly blurb: string;
  /** ID families this bucket claims, without the `VG-` prefix. */
  readonly families: readonly string[];
}

export const BUCKETS: readonly Bucket[] = [
  {
    id: 'injection',
    label: 'Injection',
    blurb: 'SQL, command, eval, deserialization, template',
    families: ['INJ'],
  },
  {
    id: 'secrets',
    label: 'Hardcoded secrets',
    blurb: 'AWS keys, PEM blocks, GitHub tokens, API keys',
    families: ['SEC'],
  },
  {
    id: 'auth',
    label: 'Auth & access control',
    blurb: 'Debug bypasses, placeholder tokens, role checks by string literal',
    families: ['AUTH', 'SMELL'],
  },
  {
    id: 'crypto',
    label: 'Weak crypto & cleartext',
    blurb: 'MD5/SHA1, Math.random, http:// endpoints',
    families: ['CRYPTO'],
  },
  {
    id: 'framework',
    label: 'Framework misconfig',
    blurb: 'Django DEBUG, Flask debug=True, CORS wildcard',
    families: ['FW'],
  },
  {
    id: 'memory',
    label: 'Memory safety (C/C++)',
    blurb: 'gets, strcpy, memcpy sized from strlen, same-block use-after-free',
    families: ['MEM'],
  },
  {
    id: 'ai-leftovers',
    label: 'AI leftovers',
    blurb: 'Stub implementations, placeholder emails, "for now" comments, near-miss imports',
    families: ['QUAL', 'AISC'],
  },
  {
    id: 'embedded',
    label: 'Embedded & RTOS',
    blurb: 'Hard-coded Wi-Fi creds, setInsecure(), #define DEBUG 1, ISR-unsafe calls',
    families: ['EMB', 'RTOS'],
  },
] as const;

/** `VG-INJ-004` -> `INJ`. Returns null for anything not in that shape. */
export function familyOf(ruleId: string): string | null {
  const m = /^VG-([A-Z]+)-\d+$/.exec(ruleId);
  return m ? m[1] : null;
}

const FAMILY_TO_BUCKET = new Map<string, string>();
for (const bucket of BUCKETS) {
  for (const family of bucket.families) FAMILY_TO_BUCKET.set(family, bucket.id);
}

export function bucketOf(ruleId: string): string | null {
  const family = familyOf(ruleId);
  return family ? (FAMILY_TO_BUCKET.get(family) ?? null) : null;
}
