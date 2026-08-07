// Binding to the canonicaliser in compiler/evidence/.
//
// The driver does not implement canonicalisation or digesting. There is one
// definition of both (interfaces.md §5) and the independent verifier already
// implements it; a second implementation here would agree with it right up
// until it did not, and the disagreement would show up as a record the verifier
// rejects long after the measurement it describes was taken.
//
// So: import it, and if it is not there, say so and exit 3. Not 0 with a
// warning, and not a local fallback.

import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const EVIDENCE_DIR = resolve(HERE, '..', '..', 'evidence');

// The evidence component owns its own layout; `canon.mjs` is what it landed as.
// The rest are kept as fallbacks rather than deleted because this file is the
// only place the layout is assumed, and a wrong assumption here fails as "no
// canonicaliser" — which is exit 3, loud, and not a silently unchecked build.
const CANDIDATES = [
  'canon.mjs',
  'index.mjs',
  'canonical.mjs',
  'evidence.mjs',
  'lib/canon.mjs',
  'lib/index.mjs',
  'src/index.mjs',
];

export class EvidenceBindingError extends Error {
  constructor(message, tried) {
    super(message);
    this.name = 'EvidenceBindingError';
    this.tried = tried;
  }
}

let cached = null;

/**
 * `sealRecord` is optional here and used when present. The evidence component
 * calls it its generation-side chokepoint — "nothing computes evidenceDigest by
 * hand" — and it also gates absolute paths with that component's own rules,
 * which is a second opinion on the driver's own gate rather than a duplicate of
 * it. When it is absent the two mandated functions are enough.
 *
 * @returns {Promise<{canonicalJson: (o: any) => string, evidenceDigest: (r: any) => string,
 *                    sealRecord: ((r: any, o?: any) => any) | null, from: string}>}
 * @throws {EvidenceBindingError} when compiler/evidence/ is absent or does not
 *         export both mandated functions. The caller turns this into exit 3.
 */
export async function loadEvidenceModule() {
  if (cached) return cached;

  const tried = [];
  const override = process.env.VG_EVIDENCE_MODULE;
  const paths = override ? [resolve(override)] : CANDIDATES.map((c) => resolve(EVIDENCE_DIR, c));

  for (const p of paths) {
    tried.push(p);
    if (!existsSync(p)) continue;
    const mod = await import(pathToFileURL(p).href);
    const missing = ['canonicalJson', 'evidenceDigest'].filter((n) => typeof mod[n] !== 'function');
    if (missing.length > 0) {
      throw new EvidenceBindingError(
        `${p} does not export ${missing.join(' and ')}; interfaces.md fixes the signatures as `
        + '`canonicalJson(obj) -> string` and `evidenceDigest(record) -> string`',
        tried,
      );
    }
    cached = {
      canonicalJson: mod.canonicalJson,
      evidenceDigest: mod.evidenceDigest,
      sealRecord: typeof mod.sealRecord === 'function' ? mod.sealRecord : null,
      from: p,
    };
    return cached;
  }

  throw new EvidenceBindingError(
    'compiler/evidence/ does not expose a canonicaliser. The driver does not carry its own: '
    + 'there is one definition of the canonical form and a second implementation would drift from it silently.',
    tried,
  );
}

export const EVIDENCE_DIR_FOR_TESTS = EVIDENCE_DIR;
