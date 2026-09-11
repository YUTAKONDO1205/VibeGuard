/**
 * Provenance helpers: digests of what was read, where the baseline came from,
 * and a last check that nothing the run writes carries the measuring machine's
 * directory layout.
 *
 * The rows and the manifest may be tracked. A path in them would publish a home
 * directory, a mount point or a drive layout, and would make the same run on
 * another machine produce different bytes. The runner scans every text it is
 * about to write with absolutePathHits() and fails the run (exit 5) on a hit.
 */
import { createHash } from 'node:crypto';
import { resolve, relative, isAbsolute, sep } from 'node:path';

/** sha256 hex of a text exactly as read, or null when there is no text. */
export function sha256Text(text) {
  if (typeof text !== 'string') return null;
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export const PATH_MARKERS = Object.freeze(['/home/', '/root/', '/mnt/', '/Users/']);

/**
 * The absolute-path markers found in `text`, as marker names (never the text
 * around them, which is the thing that must not be printed).
 *
 * A drive letter is a letter, a colon and a separator, not preceded by a letter
 * or digit (so `https://` does not count). In JSON text a backslash is escaped,
 * `C:\\`; the first backslash is enough to match.
 */
export function absolutePathHits(text) {
  if (typeof text !== 'string') return [];
  const hits = PATH_MARKERS.filter((m) => text.includes(m));
  if (/(^|[^A-Za-z0-9])[A-Za-z]:[\\/]/.test(text)) hits.push('drive-letter');
  return hits;
}

/**
 * How the manifest names the baseline rows file: '(default)' for the find step's
 * tracked rows, a repository-relative path with forward slashes for any other
 * file inside the repository, '(outside the repository)' otherwise. Never an
 * absolute path.
 */
export function rowsFileLabel(rowsPath, { defaultPath, repoRoot }) {
  if (resolve(rowsPath) === resolve(defaultPath)) return '(default)';
  const rel = relative(resolve(repoRoot), resolve(rowsPath));
  if (!rel || rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel)) return '(outside the repository)';
  return rel.split(sep).join('/');
}
