// Turning findings into protection claims — the pure half, so every channel
// can carry the ledger.
//
// ── WHY THIS LIVES HERE AND NOT IN artifact-integrity ───────────────────────
//
// It started next to the code that settles claims, which is Node-only: it reads
// build output off disk. That was the right home for the OBSERVER and the wrong
// one for the LEDGER, because a claim is generated from a finding and nothing
// else, and the surfaces that most need to show one — the editor, the browser
// panel, the generation-time guard — cannot import a filesystem walker. The
// packaging invariants forbid it three separate ways, and correctly.
//
// So the split is: this file decides WHAT is claimed, and
// `@vibeguard/artifact-integrity/cross-examine` decides whether the claim
// survived the build. Only the second half needs a disk.
//
// Everything here is a pure function of its arguments. No fs, no network, no
// clock.

import type { ProtectionClaim } from './index.js';

/**
 * Rules whose findings are claims that a protection EXISTS.
 *
 * Only these. A finding that SQL is being concatenated is not a claim that a
 * protection is present — it is the opposite — and feeding it in would produce
 * a "protection" whose disappearance from the build is good news reported as a
 * failure.
 */
export const CLAIM_BEARING_RULES: Readonly<Record<string, { subject: string }>> = Object.freeze({
  'VG-AUTH-008': { subject: 'an authorization check written as a C assert' },
  'VG-AUTH-009': { subject: 'an authorization check that only runs in development' },
  'VG-AUTH-010': { subject: 'an authorization check written as console.assert' },
  'VG-AUTH-011': { subject: 'an authorization check written as a Python assert' },
  'VG-MEM-006': { subject: 'a secret being wiped before it goes out of scope' },
});

const WITNESS_KEYWORDS = new Set([
  'if', 'else', 'return', 'throw', 'new', 'Error', 'const', 'let', 'var',
  'function', 'assert', 'console', 'process', 'env', 'true', 'false', 'null',
  'undefined', 'typeof', 'await', 'async', 'this', 'not', 'and', 'or',
  'production', 'development', 'NODE_ENV', 'raise', 'def', 'import',
  // ── HOST AND LANGUAGE PROPERTY NAMES ──────────────────────────────────────
  //
  // These reach the property branch below and beat the domain name, which is
  // the failure the property-first rule was supposed to fix rather than cause.
  // Measured: `if (import.meta.env.DEV) { if (!session.isOwner) throw }` chose
  // `meta` over `isOwner`. `meta` is in every bundle that uses `import.meta`,
  // so the claim then resolved PRESENT on a token belonging to the module
  // system — the right verdict for the wrong reason, which is worse than a
  // wrong verdict because it looks like the mechanism working.
  'meta', 'length', 'prototype', 'constructor', 'default', 'exports', 'module',
  'window', 'document', 'globalThis', 'self', 'target', 'value', 'data', 'type',
  'name', 'message', 'stack', 'code', 'status', 'error',
]);

/**
 * The token to look for in the shipped bytes.
 *
 * ── PROPERTY NAMES FIRST, AND NOT AS A TIE-BREAK ────────────────────────────
 *
 * A witness is only useful if it would still be spelled the same way after a
 * build, and minifiers treat the two kinds of name completely differently. A
 * local or a parameter is renamed — `session` becomes `s` — because the
 * minifier can see every use. A property read through a dot is not renamed,
 * because it cannot know who else indexes the object; that is why
 * `--mangle-props` is a separate, opt-in, widely-avoided flag.
 *
 * So `session.isAdmin` has exactly one usable witness and it is `isAdmin`. An
 * earlier version took the longest identifier, which on that expression is a
 * tie `session` wins by position — a witness guaranteed to be absent from any
 * minified artefact, and therefore a claim guaranteed to read LOST.
 */
export function identifierWitness(evidence: string): string | null {
  const admissible = (s: string): boolean => !WITNESS_KEYWORDS.has(s) && s.length >= 4;
  const pick = (xs: string[]): string | null => {
    let best: string | null = null;
    for (const x of xs) if (best === null || x.length > best.length) best = x;
    return best;
  };
  const props = (evidence.match(/\.([A-Za-z_$][A-Za-z0-9_$]{2,})/g) ?? [])
    .map((s) => s.slice(1))
    .filter(admissible);
  const fromProps = pick(props);
  if (fromProps) return fromProps;
  return pick((evidence.match(/[A-Za-z_$][A-Za-z0-9_$]{2,}/g) ?? []).filter(admissible));
}

/** The finding shape this module needs. Structural, so any producer fits. */
export interface ClaimSourceFinding {
  ruleId: string;
  evidence?: string[];
  snippet?: string;
  filePath?: string;
  startLine?: number;
}

/**
 * Turn source-layer findings into claims.
 *
 * Every returned claim is `NOT_OBSERVED` with no `crossExaminedAt`, and that
 * holds unconditionally: this function has no access to an artefact, so it has
 * nothing that could settle anything. It is also the whole point — a claim adds
 * something to prove and can never discharge it.
 */
export function claimsFromFindings(findings: readonly ClaimSourceFinding[]): ProtectionClaim[] {
  const out: ProtectionClaim[] = [];
  let n = 0;
  for (const f of findings) {
    const spec = CLAIM_BEARING_RULES[f.ruleId];
    if (!spec) continue;
    const text = [f.snippet ?? '', ...(f.evidence ?? [])].join('\n').trim();
    const witness = text ? identifierWitness(text) : null;
    // The probe is not the witness. The witness answers "is the defence still
    // there"; the probe answers the prior question "which shipped file is this
    // claim even about", and needs to be a longer, distinctive piece of the
    // original text to do that.
    const sourceProbe = (f.snippet ?? '').trim() || (f.evidence ?? [])[0]?.trim() || '';
    out.push({
      id: `claim-${++n}`,
      claimant: f.ruleId,
      claimantLayer: 'source',
      subject: spec.subject,
      ...(witness ? { witness } : {}),
      ...(sourceProbe ? { sourceProbe } : {}),
      ...(f.filePath ? { filePath: f.filePath } : {}),
      ...(f.startLine ? { startLine: f.startLine } : {}),
      state: 'NOT_OBSERVED' as const,
    });
  }
  return out;
}

/**
 * Turn a coding assistant's prose into claims.
 *
 * ── WHY A REGEX AND NOT A MODEL ─────────────────────────────────────────────
 *
 * There is published work doing this conversion properly with a language model,
 * and it does it better. Nothing here may call one: this package is bundled
 * into two browser extensions and the product's promise is that code does not
 * leave the machine.
 *
 * The constraint is survivable because of the rule at the top of the ledger. A
 * missed claim costs a line nobody sees. A wrongly extracted claim costs a line
 * that says NOT_OBSERVED. Neither can produce a false assurance, because no
 * claim from this layer — however it was extracted — may settle itself. The
 * quality of this function bounds how much work it creates, not how much it can
 * mislead.
 */
export function claimsFromAssistantProse(
  prose: string,
  options: { filePath?: string; sourceProbe?: string } = {},
): ProtectionClaim[] {
  const out: ProtectionClaim[] = [];
  let n = 0;
  const segments = prose
    .split(/(?:[.!?]\s+|\n+|^\s*[-*]\s*)/m)
    .map((s) => s.trim())
    .filter((s) => s.length >= 12 && s.length <= 400);
  const ACTION =
    /\b(?:add(?:ed|ing)?|insert(?:ed)?|introduc(?:e|ed)|implement(?:ed)?|enforc(?:e|ed|ing)|check(?:ed|ing)?|validat(?:e|ed|ing|ion)|sanitiz(?:e|ed)|sanitis(?:e|ed)|escap(?:e|ed)|wipe[ds]?|zero(?:ed|ing)?|clear(?:ed)?|guard(?:ed)?|restrict(?:ed)?|requir(?:e|ed|es))\b/i;
  const SUBJECT =
    /\b(?:auth(?:z|entication|orization|orisation)?|permission|privilege|admin|role|access control|input validation|sanitis|sanitiz|escap|csrf|xss|injection|secret|credential|token|password|rate limit)\w*/i;
  for (const seg of segments) {
    if (!ACTION.test(seg)) continue;
    if (!SUBJECT.test(seg)) continue;
    const witness = identifierWitness(seg);
    out.push({
      id: `assistant-claim-${++n}`,
      claimant: 'assistant',
      claimantLayer: 'assistant',
      subject: seg.length > 140 ? `${seg.slice(0, 137)}…` : seg,
      ...(witness ? { witness } : {}),
      // The prose does not identify a shipped file; the code it accompanied
      // does. A caller holding that code passes it, and without it the claim
      // can only ever be NOT_OBSERVED — which is correct, not a gap.
      ...(options.sourceProbe ? { sourceProbe: String(options.sourceProbe).trim() } : {}),
      ...(options.filePath ? { filePath: options.filePath } : {}),
      state: 'NOT_OBSERVED' as const,
    });
  }
  return out;
}

/**
 * How a reader should be told about a set of claims, in one line.
 *
 * Shared so the CLI, the editor status bar, the browser panel and a PR comment
 * cannot drift into describing the same ledger differently — and, more to the
 * point, so none of them can independently decide to phrase NOT_OBSERVED as
 * something reassuring.
 */
export function summariseClaims(claims: readonly ProtectionClaim[]): {
  total: number;
  unverified: number;
  gone: number;
  held: number;
  line: string;
} {
  const unverified = claims.filter((c) => c.state === 'NOT_OBSERVED').length;
  const gone = claims.filter(
    (c) => c.state === 'LOST' || c.state === 'REINTRODUCED' || c.state === 'ABSENT',
  ).length;
  const held = claims.filter((c) => c.state === 'PRESENT').length;
  const parts: string[] = [];
  if (gone) parts.push(`${gone} not in the shipped bytes`);
  if (unverified) parts.push(`${unverified} unverified`);
  if (held) parts.push(`${held} verified present`);
  return {
    total: claims.length,
    unverified,
    gone,
    held,
    line: claims.length ? `${claims.length} declared protection(s): ${parts.join(', ')}` : '',
  };
}
