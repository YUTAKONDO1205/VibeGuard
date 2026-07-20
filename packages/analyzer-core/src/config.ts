/**
 * VibeGuard project config (.vibeguardrc.json).
 *
 * Currently the only thing the config drives is **path-based suppression** —
 * a way to say "rule VG-INJ-004 doesn't apply under samples/vulnerable/**"
 * without scattering pragmas across every fixture file.
 *
 * Example:
 *
 * ```json
 * {
 *   "suppress": [
 *     {
 *       "paths": ["samples/vulnerable/**", "**\/*.test.ts"],
 *       "rules": ["VG-INJ-004", "VG-AUTH-003"],
 *       "reason": "Test fixtures intentionally vulnerable",
 *       "expires": "2026-12-31"
 *     }
 *   ]
 * }
 * ```
 *
 * - `paths` — required; globs matched against the repo-relative file path
 *   (forward slashes, as emitted by the scanner). `**` spans segments.
 * - `rules` — optional; rule IDs to suppress. Omit / empty array = every rule
 *   for the matching files (wildcard). A wildcard entry cannot suppress
 *   findings whose severity carries a security judgement (critical/high/medium,
 *   per `SECURITY_JUDGEMENT_SEVERITIES`); those are reported anyway with a
 *   `suppressionOverridden` marker. Name the rule IDs to suppress them. This is
 *   the same rule the `vibeguard:disable-*` pragmas follow — the config path is
 *   gated by the same predicate precisely because gating one channel and not
 *   the other would just move the blanket-silence attack to the other channel.
 * - `reason` — informational, not used for matching.
 * - `expires` — `YYYY-MM-DD`. Once the current date is past the day, the entry
 *   is silently ignored and the findings reappear.
 *
 * This module is browser-safe: the fs-touching `loadConfig` lives in
 * `config-loader.ts` and is only imported from Node entry points.
 */

import { isSecurityJudgementSeverity, type Severity, type SuppressionOverride } from '@vibeguard/findings-schema';

import { matchesAnyGlob } from './glob.js';

export interface SuppressRuleConfig {
  paths?: string[];
  rules?: string[];
  reason?: string;
  /** YYYY-MM-DD inclusive. Beyond this date the entry is dropped. */
  expires?: string;
}

export interface VibeguardConfig {
  $schema?: string;
  suppress?: SuppressRuleConfig[];
}

const WILDCARD = '*';
export const CONFIG_FILENAMES = ['.vibeguardrc.json', 'vibeguard.config.json'];

function isExpired(entry: SuppressRuleConfig, now: Date): boolean {
  if (!entry.expires) return false;
  const d = new Date(`${entry.expires}T23:59:59.999Z`);
  if (Number.isNaN(d.getTime())) return false; // malformed → treat as permanent rather than always-expired
  return now.getTime() > d.getTime();
}

/**
 * Returns the set of rule IDs (possibly including '*') that the config
 * suppresses for `filePath`. Caller should check `.has('*')` for the wildcard
 * before checking specific IDs.
 */
export function suppressionsForPath(
  config: VibeguardConfig | undefined,
  filePath: string,
  now: Date = new Date(),
): Set<string> {
  const out = new Set<string>();
  if (!config?.suppress) return out;
  for (const entry of config.suppress) {
    if (isExpired(entry, now)) continue;
    if (!matchesAnyGlob(entry.paths, filePath)) continue;
    if (!entry.rules || entry.rules.length === 0) {
      out.add(WILDCARD);
      continue;
    }
    for (const id of entry.rules) out.add(id);
  }
  return out;
}

/**
 * The outcome of consulting the config suppressions for one finding. Same shape
 * and same contract as the pragma channel's decision (`suppress.ts`): the two
 * enforcement points answer the same question, so they answer it in the same
 * words.
 *
 * No `reason` is carried here even though `SuppressRuleConfig` has one:
 * `suppressionsForPath` collapses the matching entries down to a set of rule
 * IDs before this is consulted, so by this point the entry that matched is no
 * longer identifiable. Recording a `reason` picked from whichever entry
 * happened to match first would be a guess, and a guess in an audit record is
 * worse than an absent field.
 */
export interface PathSuppressionDecision {
  suppressed: boolean;
  overridden?: SuppressionOverride;
}

/**
 * Convenience: true if `ruleId` is suppressed for `filePath` per config.
 *
 * `severity` is required, matching `isSuppressed`: an optional parameter would
 * let a call site that was never updated keep compiling with the gate disabled.
 */
export function isPathSuppressed(
  suppressed: Set<string>,
  ruleId: string,
  severity: Severity,
): boolean {
  return evaluatePathSuppression(suppressed, ruleId, severity).suppressed;
}

/** As `isPathSuppressed`, but also reports a wildcard the severity gate refused. */
export function evaluatePathSuppression(
  suppressed: Set<string>,
  ruleId: string,
  severity: Severity,
): PathSuppressionDecision {
  // Naming the rule is honoured at every severity — the escape hatch, identical
  // to the pragma channel's.
  if (suppressed.has(ruleId)) return { suppressed: true };
  if (!suppressed.has(WILDCARD)) return { suppressed: false };
  if (!isSecurityJudgementSeverity(severity)) return { suppressed: true };
  return { suppressed: false, overridden: { channel: 'config', scope: 'path' } };
}

export function parseConfig(raw: string, source: string): VibeguardConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`vibeguard config: ${source} is not valid JSON: ${msg}`);
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error(`vibeguard config: ${source} root must be an object`);
  }
  return parsed as VibeguardConfig;
}
