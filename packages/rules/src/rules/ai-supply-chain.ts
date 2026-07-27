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

/**
 * The classification core: given an ALREADY-NORMALIZED (lowercased, no
 * surrounding whitespace) candidate package name, decide whether it is a
 * finding and, if it is a near miss, which popular name it is a near miss OF.
 *
 * Split out of `hallucinatedDeps` for one reason: the CLI's rename fixer
 * (`remediation-engine/fixers.ts`, VG-AISC-001) has to answer exactly the same
 * question — "what did this import mean?" — and `RuleMatch.variables` does NOT
 * survive into a `Finding`, so the fixer cannot read the `didYouMean` the
 * detector already computed; it must recompute it from the file bytes.
 * Recomputing it by COPYING this logic into the fixer is the drift that would
 * eventually rename an import to something the detector never suggested. One
 * exported function (`nearestKnownPackage`) that both sides call makes that
 * class of drift structurally impossible rather than merely discouraged.
 *
 * The exemption order (builtin → alias stoplist → literally known → curated →
 * separator collision → edit distance) is load-bearing and deliberately
 * identical to what it replaced; see the precision contract in the file header.
 */
function classifyImportName(
  pkg: string,
  isPy: boolean,
): { didYouMean?: string; confidence?: 'high' | 'medium' } {
  const index = isPy ? PYPI_INDEX : NPM_INDEX;
  const builtins = isPy ? PY_STDLIB : NODE_BUILTINS;
  // Cheap exemptions first.
  if (builtins.has(pkg)) return {};
  if (ALIAS_STOPLIST.has(pkg)) return {};
  if (index.set.has(pkg)) return {};

  if (CURATED_HALLUCINATIONS.has(pkg)) {
    // Documented hallucination: a finding, but with NO suggestion — the name
    // does not exist and nothing in the bundled data says what was meant.
    return { confidence: 'high' };
  }
  // Normalized-key collision: same name modulo -/_/. separators (pip/npm
  // separator confusion), but not literally equal to a known name.
  const canon = index.normKeys.get(normKey(pkg));
  if (canon && canon !== pkg) return { didYouMean: canon, confidence: 'medium' };
  if (pkg.length >= 5) {
    // Edit-distance-1 of a popular name (length band avoids comparing against
    // everything; the ≥5 floor stops short names from colliding constantly).
    for (const len of [pkg.length - 1, pkg.length, pkg.length + 1]) {
      const bucket = index.byLen.get(len);
      if (!bucket) continue;
      const hit = bucket.find((known) => withinEditDistance1(pkg, known));
      if (hit) return { didYouMean: hit, confidence: 'medium' };
    }
  }
  return {};
}

/**
 * The popular package `importName` is a near miss of, or `null`.
 *
 * PUBLIC because the deterministic rename fixer needs it (see above). The
 * contract is deliberately narrow and fail-closed:
 *   - `null` for anything the detector would not flag at all (a Node/Python
 *     builtin, an import-name alias like `cv2`, a literally-known package),
 *     so a fixer that walks every specifier on a line cannot rename an import
 *     that was never the finding.
 *   - `null` for a CURATED hallucination too: those are flagged with no
 *     `didYouMean`, and inventing a target for them is exactly the "do not
 *     invent data" line the fixer table refuses to cross.
 *   - never a same-name result: a name equal to a known package is exempted
 *     above, so the caller can treat a non-null return as a real edit.
 *
 * `language` is the analyzer's language string; only 'python' selects the PyPI
 * index, mirroring `hallucinatedDeps` (js/ts and anything else → npm).
 */
export function nearestKnownPackage(importName: string, language: string): string | null {
  const pkg = importName.trim().toLowerCase();
  if (!pkg) return null;
  return classifyImportName(pkg, language === 'python').didYouMean ?? null;
}

function hallucinatedDeps(content: string, lines: string[], language: string | undefined): RuleMatch[] {
  const isPy = language === 'python';
  const candidates = isPy ? pyCandidates(content, language) : jsCandidates(content, language);

  const out: RuleMatch[] = [];
  const seen = new Set<string>();
  let processed = 0;
  for (const { pkg, line } of candidates) {
    if (processed >= 100) break;
    processed += 1;
    if (seen.has(pkg)) continue;

    const { didYouMean, confidence } = classifyImportName(pkg, isPy);

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
