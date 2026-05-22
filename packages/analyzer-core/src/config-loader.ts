/**
 * Node-only loader for `.vibeguardrc.json` — kept out of `config.ts` so the
 * browser entry can re-export `suppressionsForPath` without pulling in
 * `node:fs/promises`.
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { CONFIG_FILENAMES, parseConfig, type VibeguardConfig } from './config.js';

export interface LoadConfigResult {
  config: VibeguardConfig;
  filePath: string;
}

/**
 * Look for a config file in `rootDir`. Returns the first match by filename
 * order. If `explicitPath` is supplied, only that path is read (and errors are
 * surfaced rather than swallowed).
 */
export async function loadConfig(
  rootDir: string,
  explicitPath?: string,
): Promise<LoadConfigResult | undefined> {
  if (explicitPath) {
    const raw = await readFile(explicitPath, 'utf8');
    return { config: parseConfig(raw, explicitPath), filePath: explicitPath };
  }
  for (const name of CONFIG_FILENAMES) {
    const candidate = join(rootDir, name);
    let raw: string;
    try {
      raw = await readFile(candidate, 'utf8');
    } catch {
      continue; // not present (or unreadable) — try the next candidate
    }
    // File exists: parse errors propagate so the user notices a typo.
    return { config: parseConfig(raw, candidate), filePath: candidate };
  }
  return undefined;
}
