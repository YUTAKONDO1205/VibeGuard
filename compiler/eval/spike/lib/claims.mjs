/**
 * The only module that opens `claims/spike-expected.json`.
 *
 * Keeping the read in one small file is what makes the separation checkable: the
 * measuring half (`measure.mjs`) can be shown not to reach the answers by
 * reading its source, and this file is short enough that what it does with them
 * is obvious. It resolves; it does not decide. The comparison is
 * `spike.mjs`'s, which is pure and does not know where an expectation came from.
 *
 * A malformed or missing claims file is exit-code 4 territory (interfaces.md
 * section 7: policy integrity, nothing else runs) and never a run with no
 * expectations, which would be a gate that passes everything.
 *
 * What such an error may SAY is constrained too. Node's own message for a
 * missing file ends in the absolute path it tried to open; `gate.mjs` puts this
 * message into `verdict.reasons`, and any harness that embeds the verdict in a
 * record would publish the measuring machine's directory layout -- while
 * `run-spike.mjs`'s own absolute-path guard fires first and tells the operator
 * the report carries a path, never that the claims file is missing. Measured on
 * 2026-09-12: the file moved away, and the only line printed was the path
 * refusal. So the errors here name the file the way a record may name it: the
 * repository-relative path, or the basename when it lies outside.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { readFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..', '..', '..');

/** Where the registered answers live, relative to this file. */
export const CLAIMS_PATH = resolve(HERE, '..', 'claims', 'spike-expected.json');

export const SCHEMA_VERSION = 'vibeguard.spike-expected/1';

/**
 * How an error names the claims file: repository-relative with forward slashes,
 * or the basename when the file is outside the repository. Never a machine path.
 *
 * The same reduction `repair-loop/lib/provenance.mjs` makes with `rowsFileLabel`,
 * for the same reason: a diagnosis a caller may write down must not carry the
 * layout of the host that produced it.
 */
export function claimsLabel(path) {
  const abs = resolve(path);
  const rel = relative(REPO, abs);
  if (!rel || isAbsolute(rel) || rel === '..' || rel.startsWith('..' + sep)) return basename(abs);
  return rel.split(sep).join('/');
}

/**
 * Read and structurally check the registered answers.
 *
 * @throws {Error} when the file cannot be read or is not the shape this lane
 *         grades against. The caller turns that into exit 4. The message names
 *         the file by `claimsLabel` and carries no machine path.
 */
export function loadExpected(path = CLAIMS_PATH) {
  const label = claimsLabel(path);
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    // err.message ends in the absolute path; the code is the part that says what
    // happened, and it is the part a record may keep.
    throw new Error(`the pre-registered expectations could not be read from ${label} (${err.code || 'read failed'})`);
  }
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    // JSON.parse reports a position in the text it was handed and never a path.
    throw new Error(`the pre-registered expectations in ${label} are not JSON (${err.message})`);
  }
  if (!doc || typeof doc !== 'object') throw new Error(`the pre-registered expectations in ${label} are not an object`);
  if (doc.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(`the pre-registered expectations in ${label} declare schemaVersion `
      + `${JSON.stringify(doc.schemaVersion)}, and this lane grades ${SCHEMA_VERSION}`);
  }
  if (!doc.expectations || typeof doc.expectations !== 'object') {
    throw new Error(`the pre-registered expectations in ${label} carry no \`expectations\` block`);
  }
  return doc;
}

/**
 * What was registered for one (vendor, level), or null.
 *
 * Null is a real answer and the grader treats it as one: an unregistered
 * configuration recovers nothing. It is deliberately not a thrown error, because
 * a caller sweeping a version ladder should get a red gate naming the
 * configuration rather than a crash naming a file.
 */
export function expectedFor(doc, vendor, opt) {
  const byVendor = doc.expectations[vendor];
  if (!byVendor || typeof byVendor !== 'object') return null;
  const cell = byVendor[opt];
  return cell && typeof cell === 'object' ? cell : null;
}

/** Every (vendor, level) the claims file registers, in file order. */
export function registeredConfigurations(doc) {
  const out = [];
  for (const [vendor, byOpt] of Object.entries(doc.expectations)) {
    if (!byOpt || typeof byOpt !== 'object') continue;
    for (const opt of Object.keys(byOpt)) out.push({ vendor, opt });
  }
  return out;
}

/** What the observer channel was registered to read at one level, or null. */
export function observerExpectedFor(doc, opt) {
  const obs = doc.observer;
  if (!obs || typeof obs !== 'object') return null;
  const cell = obs[opt];
  return cell && typeof cell === 'object' ? cell : null;
}
