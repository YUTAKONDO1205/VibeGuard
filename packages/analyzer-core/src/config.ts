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
 *   for the matching files (wildcard).
 * - `reason` — informational, not used for matching.
 * - `expires` — `YYYY-MM-DD`. Once the current date is past the day, the entry
 *   is silently ignored and the findings reappear.
 *
 * This module is browser-safe: the fs-touching `loadConfig` lives in
 * `config-loader.ts` and is only imported from Node entry points.
 */

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

/** Convenience: true if `ruleId` is suppressed for `filePath` per config. */
export function isPathSuppressed(suppressed: Set<string>, ruleId: string): boolean {
  return suppressed.has(WILDCARD) || suppressed.has(ruleId);
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
