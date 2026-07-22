// vibeguard:disable-file VG-AISC-001
// This file *defines* the AI supply-chain rules; the hallucinated-package names
// and near-miss examples appear inside the rule data and descriptions by design.
//
// 0.2.x — FOURTH DEFENCE LINE entry point (AI supply chain), category
// "supply-chain". VG-AISC-001 Hallucinated Dependency: an import names a package
// that is a NEAR MISS of a popular one (the slopsquatting seam) — LOCAL match
// against a bundled known-good set, ZERO network (see ai-supply-chain-data.ts).
//
// THE PRECISION CONTRACT (do not weaken): an unknown package that is NOT a near
// miss is SILENT. "Not popular" is never, on its own, a finding — internal and
// niche packages are unknowable to a bundled list, and flagging them is the FP
// flood that would break the safe-corpus gate on real projects. Only a name that
// collides-modulo-separators with, or is edit-distance-1 from, a popular package
// (or is on the curated hallucination list) is flagged.
import type { RuleDefinition, RuleMatch } from '../rule-types.js';
import { runRegex } from '../matcher-utils.js';
import {
  KNOWN_NPM,
  KNOWN_PYPI,
  NODE_BUILTINS,
  PY_STDLIB,
  ALIAS_STOPLIST,
  CURATED_HALLUCINATIONS,
} from './ai-supply-chain-data.js';

const normKey = (s: string): string => s.toLowerCase().replace(/[-_.]/g, '');

interface KnownIndex {
  set: ReadonlySet<string>;
  normKeys: ReadonlyMap<string, string>; // normalized key -> canonical name
  byLen: ReadonlyMap<number, string[]>;
}

function buildIndex(names: readonly string[]): KnownIndex {
  const set = new Set<string>();
  const normKeys = new Map<string, string>();
  const byLen = new Map<number, string[]>();
  for (const raw of names) {
    const n = raw.toLowerCase();
    set.add(n);
    if (!normKeys.has(normKey(n))) normKeys.set(normKey(n), n);
    const bucket = byLen.get(n.length);
    if (bucket) bucket.push(n);
    else byLen.set(n.length, [n]);
  }
  return { set, normKeys, byLen };
}

// Built once at module load — the known sets are constant, so there is nothing
// per-scan to recompute (and nothing per-scan is read from the filesystem).
const NPM_INDEX = buildIndex(KNOWN_NPM);
const PYPI_INDEX = buildIndex(KNOWN_PYPI);

/** True when the optimal string alignment distance between a and b is ≤ 1. */
function withinEditDistance1(a: string, b: string): boolean {
  if (a === b) return true;
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > 1) return false;
  if (la === lb) {
    // Substitution (1 diff) or one adjacent transposition.
    let diffs = 0;
    let firstDiff = -1;
    for (let i = 0; i < la; i += 1) {
      if (a[i] !== b[i]) {
        diffs += 1;
        if (diffs === 1) firstDiff = i;
        if (diffs > 2) return false;
      }
    }
    if (diffs <= 1) return true;
    if (diffs === 2 && firstDiff >= 0) {
      // Exactly two diffs: a transposition of adjacent chars is distance 1.
      return a[firstDiff] === b[firstDiff + 1] && a[firstDiff + 1] === b[firstDiff];
    }
    return false;
  }
  // Lengths differ by 1 — one insertion/deletion. Walk with a single allowed skip.
  const shorter = la < lb ? a : b;
  const longer = la < lb ? b : a;
  let i = 0;
  let j = 0;
  let skipped = false;
  while (i < shorter.length && j < longer.length) {
    if (shorter[i] === longer[j]) {
      i += 1;
      j += 1;
    } else {
      if (skipped) return false;
      skipped = true;
      j += 1; // consume one extra char from the longer string
    }
  }
  return true;
}

interface Candidate {
  pkg: string; // lowercased package name
  line: number;
}

/** JS/TS import specifiers → candidate package names. */
function jsCandidates(content: string, language: string | undefined): Candidate[] {
  const forms = [
    // `require(` and dynamic `import(` must NOT be a member access: a method
    // literally named `import`/`require` (`registry.import('expresss')`) is a
    // call, not a module load. The `(?:^|[^\w$.])` guard excludes a leading `.`.
    /(?:^|[^\w$.])require[^\S\r\n]{0,2}\([^\S\r\n]{0,2}(["'])(?<spec>[^"'\n]{1,120})\1/g,
    /\bfrom[^\S\r\n]{1,4}(["'])(?<spec>[^"'\n]{1,120})\1/g,
    /(?:^|[^\w$.])import[^\S\r\n]{0,2}\([^\S\r\n]{0,2}(["'])(?<spec>[^"'\n]{1,120})\1/g,
    /(?:^|[^\w$.])import[^\S\r\n]{1,4}(["'])(?<spec>[^"'\n]{1,120})\1/g,
  ];
  const out: Candidate[] = [];
  for (const re of forms) {
    for (const m of runRegex(content, re, { skipCommentLines: true, language })) {
      const spec = m.variables?.spec;
      if (!spec) continue;
      // Skip relative / absolute / scoped / protocol specifiers. Scoped packages
      // (@org/name) are skipped in v1: private-org scopes are unknowable and
      // near-missing on a scope is FP-rich.
      if (/^[.@/~#]/.test(spec) || spec.includes(':')) continue;
      const pkg = spec.split('/')[0]!.toLowerCase();
      if (pkg) out.push({ pkg, line: m.startLine });
    }
  }
  return out;
}

/** Python import statements → candidate top-level module names. */
function pyCandidates(content: string, language: string | undefined): Candidate[] {
  const out: Candidate[] = [];
  // Anchor at the LINE START (m flag) and take only the module after the leading
  // `import`/`from` keyword. Without the anchor, the `import Y` clause of a
  // `from X import Y` statement was matched too, turning imported SYMBOLS into
  // package candidates — `from flask import request` flagged `request` as a
  // near-miss of `requests`, a false positive on nearly every Flask/FastAPI file.
  const re = /^[^\S\r\n]*(?:import|from)[^\S\r\n]+(?<spec>[A-Za-z_][\w.]{0,80})/gm;
  for (const m of runRegex(content, re, { skipCommentLines: true, language })) {
    const spec = m.variables?.spec;
    if (!spec) continue;
    const pkg = spec.split('.')[0]!.toLowerCase();
    if (pkg) out.push({ pkg, line: m.startLine });
  }
  return out;
}

function hallucinatedDeps(content: string, lines: string[], language: string | undefined): RuleMatch[] {
  const isPy = language === 'python';
  const index = isPy ? PYPI_INDEX : NPM_INDEX;
  const builtins = isPy ? PY_STDLIB : NODE_BUILTINS;
  const candidates = isPy ? pyCandidates(content, language) : jsCandidates(content, language);

  const out: RuleMatch[] = [];
  const seen = new Set<string>();
  let processed = 0;
  for (const { pkg, line } of candidates) {
    if (processed >= 100) break;
    processed += 1;
    if (seen.has(pkg)) continue;
    // Cheap exemptions first.
    if (builtins.has(pkg)) continue;
    if (ALIAS_STOPLIST.has(pkg)) continue;
    if (index.set.has(pkg)) continue;

    let didYouMean: string | undefined;
    let confidence: 'high' | 'medium' | undefined;

    if (CURATED_HALLUCINATIONS.has(pkg)) {
      confidence = 'high';
    } else {
      // Normalized-key collision: same name modulo -/_/. separators (pip/npm
      // separator confusion), but not literally equal to a known name.
      const canon = index.normKeys.get(normKey(pkg));
      if (canon && canon !== pkg) {
        didYouMean = canon;
        confidence = 'medium';
      } else if (pkg.length >= 5) {
        // Edit-distance-1 of a popular name (length band avoids comparing against
        // everything; the ≥5 floor stops short names from colliding constantly).
        for (const len of [pkg.length - 1, pkg.length, pkg.length + 1]) {
          const bucket = index.byLen.get(len);
          if (!bucket) continue;
          const hit = bucket.find((known) => withinEditDistance1(pkg, known));
          if (hit) {
            didYouMean = hit;
            confidence = 'medium';
            break;
          }
        }
      }
    }

    if (!confidence) continue; // unknown-but-not-near-miss → SILENT (the contract)
    seen.add(pkg);
    const lineText = lines[line - 1] ?? pkg;
    out.push({
      startLine: line,
      endLine: line,
      startColumn: 1,
      // Span the whole line rather than a zero-width point: the canonical-pass
      // dedup (analyzer `overlaps`) treats a degenerate startCol==endCol span as
      // non-overlapping, so a zero-width match is reported twice (original +
      // canonical). A real span collapses the pair to one finding.
      endColumn: Math.max(2, lineText.length + 1),
      evidence: lineText.trim().slice(0, 200),
      confidence,
      variables: didYouMean ? { package: pkg, didYouMean } : { package: pkg },
    });
  }
  return out;
}

export const hallucinatedDependency: RuleDefinition = {
  ruleId: 'VG-AISC-001',
  name: 'Hallucinated Dependency',
  description:
    'An import names a package that is a near miss of a popular one (edit-distance-1 or separator-confusion) or a documented LLM-hallucinated name. AI code generators fabricate plausible-but-nonexistent package names; an attacker who registers one ("slopsquatting") gets code execution on install.',
  languages: ['javascript', 'typescript', 'python'],
  category: 'supply-chain',
  severity: 'medium',
  defaultConfidence: 'medium',
  // contextConfidence 'off': a hallucinated import in a comment is still worth
  // surfacing, and the import extractor already skips comment lines, so the
  // context layer has nothing useful to add here.
  contextConfidence: 'off',
  cwe: ['CWE-1104'],
  owasp: ['A08:2021'],
  tags: ['supply-chain', 'slopsquatting', 'ai-prone'],
  remediation: {
    why: 'A generated import of a nonexistent-but-plausible package name is a slopsquatting target: register the name and every `npm install` / `pip install` of the generated code runs attacker code. The near-miss to a real package is the tell.',
    how: 'Confirm the package exists and is the one you intend before installing: check the registry page, download counts, and repository. If you meant the popular near-neighbour, fix the name; if the package is genuinely internal, it will not be flagged (only near-misses are).',
    exampleFix: "// meant 'express', not 'expresss' — correct the import specifier",
  },
  match: (ctx) => hallucinatedDeps(ctx.content, ctx.lines, ctx.language),
};

export const aiSupplyChainRules: RuleDefinition[] = [hallucinatedDependency];
