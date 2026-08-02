// `ensure` used the way every codebase uses it: make a thing exist. Nothing here
// judges the value, and nothing here makes it safe.
import fs from 'node:fs';

export function ensureParentDirectory(dir: string): void {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
