/**
 * Lockfile reading for the declared-package veto (§17z-b).
 *
 * This is the ONLY place in VibeGuard that turns a lockfile into evidence. It
 * lives in the CLI, not in analyzer-core and not in a rule, and that placement
 * is a hard boundary rather than a convenience:
 *
 *  - `packages/rules` must stay free of I/O. `match()` is a pure function of
 *    one file's text; the four channels agree only because they share it, and
 *    the no-network CI job asserts that a rule reaches nothing outside its
 *    argument.
 *  - `packages/analyzer-core` must stay bundleable for the browser. It has a
 *    `./browser` entry precisely because `node:fs` in the default entry breaks
 *    the Chrome build; adding a lockfile reader there would put `node:fs` back
 *    on the path every rule-running consumer imports.
 *
 * So the split is: the CLI (which already owns a filesystem) reads, and the
 * analyzer (which owns the detection semantics) decides. The analyzer receives
 * a list of names and nothing else — see `ScanRequest.declaredPackages` and
 * `declared-veto.ts` for what it does with them, and for why "a name in a
 * lockfile" is evidence at all.
 *
 * ── SCOPE: THE SCAN TARGET'S OWN DIRECTORY, AND NOTHING ELSE ──────────────
 *
 * Exactly one directory is searched — the scan target, or its parent when the
 * target is a single file — with the same rule the config-file discovery uses,
 * so a user who understands one understands the other.
 *
 * REJECTED: walking up to the repository root (what package managers and most
 * linters do). It is more likely to find a lockfile and it makes the tool's
 * behaviour unexplainable from the command line: `vibeguard ./src` would
 * silence findings because of a file four directories above `./src` that the
 * user never mentioned, and whether it did so would depend on where the
 * checkout happened to sit. A veto that deletes findings has to be predictable
 * from what was typed; "the lockfile next to what you scanned" is that, and
 * scanning the project root instead is the one-word fix when it is not.
 *
 * REJECTED: recursively collecting every lockfile under the target. Same
 * problem in the other direction, plus it makes an unrelated vendored fixture's
 * lockfile authoritative over the whole tree.
 *
 * ── FAILURE DIRECTION ─────────────────────────────────────────────────────
 *
 * Every failure path here returns FEWER names, never more, and says so out
 * loud. The asymmetry is deliberate and is the safety property of this file:
 * missing a name means a finding is reported that could have been vetoed (a
 * false positive — noisy, visible, arguable), while inventing a name means a
 * real finding disappears (a false negative — silent, invisible, and exactly
 * what an attacker who can write a lockfile would want). A parser that cannot
 * make sense of a file therefore yields nothing FROM THAT FILE and emits a
 * warning; it never yields a wildcard, and it never guesses.
 */

import { readFile, stat } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

/**
 * The lockfiles read, in a fixed order so warnings and `sources` are
 * deterministic across platforms (a `readdir` order would not be).
 *
 * Lockfiles ONLY. package.json, requirements.txt, pyproject.toml, Pipfile and
 * environment.yml are deliberately absent: a manifest records what someone
 * ASKED for, and an LLM that hallucinates an import writes the matching
 * manifest line in the same completion, so a manifest-sourced veto would
 * silence precisely the findings that are true. A lockfile entry only exists
 * because a package manager resolved the name against a registry — see
 * `declared-veto.ts` for the full argument. Adding a manifest to this list
 * would quietly invert the feature; do not.
 */
const LOCKFILES = [
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'poetry.lock',
  'uv.lock',
  'Pipfile.lock',
] as const;

/**
 * Refuse to read a lockfile larger than this. Lockfiles are big (a
 * package-lock.json of a few megabytes is ordinary) but not unbounded, and the
 * parsers below are line- or JSON-shaped, so a pathological input would be paid
 * for in memory before any of them got to reject it. Skipping with a warning
 * keeps the failure in the safe direction: no names from that file.
 */
const MAX_LOCKFILE_BYTES = 32_000_000;

/** Bound on how deep the v1 `dependencies` tree is walked. See `fromNpmV1`. */
const MAX_NPM_V1_DEPTH = 8;

export interface DeclaredPackagesResult {
  /** Every distinct name found, lowercased. Empty when nothing was readable. */
  packages: string[];
  /** Which lockfiles contributed, and how many names each gave. */
  sources: { file: string; count: number }[];
  /**
   * Human-readable problems. NON-EMPTY MEANS THE VETO IS INCOMPLETE — a
   * lockfile was present and could not be turned into names. The caller is
   * expected to print these: a veto that silently failed to apply is a
   * confusing false positive, and a reader who cannot see the parser gave up
   * has no way to explain it.
   */
  warnings: string[];
}

/**
 * Read the declared package names for a scan target.
 *
 * `target` is the path the user asked to scan — a file or a directory. Never
 * throws: an unreadable target yields an empty result, because the scan itself
 * is what should report that the target is bad, and this function failing first
 * would replace a precise error with a vague one.
 */
export async function readDeclaredPackages(target: string): Promise<DeclaredPackagesResult> {
  const result: DeclaredPackagesResult = { packages: [], sources: [], warnings: [] };

  let dir: string;
  try {
    const info = await stat(target);
    dir = info.isFile() ? dirname(resolve(target)) : resolve(target);
  } catch {
    return result;
  }

  const names = new Set<string>();
  for (const file of LOCKFILES) {
    const full = join(dir, file);
    let raw: string;
    try {
      const info = await stat(full);
      if (!info.isFile()) continue;
      if (info.size > MAX_LOCKFILE_BYTES) {
        result.warnings.push(
          `${file} is ${info.size} bytes (over the ${MAX_LOCKFILE_BYTES}-byte cap) and was not read; ` +
            'packages declared in it will NOT suppress hallucinated-dependency findings.',
        );
        continue;
      }
      raw = await readFile(full, 'utf8');
    } catch (err) {
      // ENOENT is the normal case — most projects have one lockfile, not six —
      // and must stay silent, or every scan would print five warnings. Any
      // other error means the file IS there and we could not read it, which is
      // worth saying.
      if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') continue;
      result.warnings.push(
        `${file} could not be read (${err instanceof Error ? err.message : String(err)}); ` +
          'packages declared in it will NOT suppress hallucinated-dependency findings.',
      );
      continue;
    }

    let found: string[];
    try {
      found = parseLockfile(file, raw);
    } catch (err) {
      result.warnings.push(
        `${file} could not be parsed (${err instanceof Error ? err.message : String(err)}); ` +
          'packages declared in it will NOT suppress hallucinated-dependency findings.',
      );
      continue;
    }
    if (found.length === 0) {
      // Present, readable, understood by nothing. Silence here is the failure
      // mode this whole file is written against: the user sees findings for
      // packages they can point at in their lockfile and has no way to learn
      // the parser bounced off it.
      result.warnings.push(
        `${file} was read but no resolved package entries were recognised in it; ` +
          'packages declared in it will NOT suppress hallucinated-dependency findings.',
      );
      continue;
    }
    result.sources.push({ file, count: found.length });
    for (const n of found) names.add(n);
  }

  result.packages = [...names].sort();
  return result;
}

/** Dispatch on filename. Throws on a parse failure; the caller turns that into a warning. */
function parseLockfile(file: string, raw: string): string[] {
  switch (file) {
    case 'package-lock.json':
      return fromPackageLock(raw);
    case 'yarn.lock':
      return fromYarnLock(raw);
    case 'pnpm-lock.yaml':
      return fromPnpmLock(raw);
    case 'poetry.lock':
    case 'uv.lock':
      return fromTomlPackages(raw);
    case 'Pipfile.lock':
      return fromPipfileLock(raw);
    default:
      return [];
  }
}

/** Normalise and accept a candidate name, or reject it. Shared by every parser. */
function pushName(out: Set<string>, name: string | undefined): void {
  if (!name) return;
  const trimmed = name.trim().toLowerCase();
  if (!trimmed) return;
  // A lockfile key that is not a package name (a path, a URL, a placeholder)
  // must not become a veto entry. Bounded character class, no quantifier
  // nesting — the D3 three-second contract applies to every regex in the
  // repository, not only to the ones inside rules.
  if (!/^(?:@[a-z0-9._-]{1,120}\/)?[a-z0-9][a-z0-9._-]{0,120}$/.test(trimmed)) return;
  out.add(trimmed);
}

/**
 * package-lock.json.
 *
 * v2/v3 key off `packages`, whose keys are INSTALL PATHS
 * (`node_modules/express`, `node_modules/a/node_modules/b`) — so the name is
 * whatever follows the LAST `node_modules/`. Entries whose key contains no
 * `node_modules/` are the root project and workspace links; they are not
 * registry resolutions and are skipped.
 *
 * v1 is also handled, via `dependencies`, even though the task named only
 * v2/v3. It is ten lines, lockfileVersion 1 files are still in circulation, and
 * the alternative is a silent no-veto on a project that has a perfectly good
 * lockfile — the confusing-false-positive case this file exists to avoid.
 *
 * A `version` is required on every entry taken. That is the entire evidentiary
 * basis of the veto: an entry with a resolved version is a registry receipt,
 * and an entry without one is a link, an alias, or a fragment.
 */
function fromPackageLock(raw: string): string[] {
  const parsed: unknown = JSON.parse(raw);
  if (!isRecord(parsed)) throw new Error('top level is not a JSON object');
  const out = new Set<string>();

  const packages = parsed['packages'];
  if (isRecord(packages)) {
    for (const [key, value] of Object.entries(packages)) {
      if (!isRecord(value) || typeof value['version'] !== 'string') continue;
      const marker = key.lastIndexOf('node_modules/');
      if (marker < 0) continue;
      pushName(out, key.slice(marker + 'node_modules/'.length));
    }
  }

  const deps = parsed['dependencies'];
  if (isRecord(deps)) fromNpmV1(deps, out, 0);

  return [...out];
}

/** Recursive half of the v1 `dependencies` tree, depth-bounded. */
function fromNpmV1(deps: Record<string, unknown>, out: Set<string>, depth: number): void {
  if (depth > MAX_NPM_V1_DEPTH) return;
  for (const [name, value] of Object.entries(deps)) {
    if (!isRecord(value)) continue;
    if (typeof value['version'] === 'string') pushName(out, name);
    const nested = value['dependencies'];
    if (isRecord(nested)) fromNpmV1(nested, out, depth + 1);
  }
}

/**
 * yarn.lock — classic (v1) and Berry (v2+) both.
 *
 * The two formats differ in the range separator (`express@^4.17.1` vs
 * `express@npm:^4.17.1`) and in how the version line is written (`version
 * "4.18.2"` vs `version: 4.18.2`), but share the shape this parser needs: an
 * unindented header line ending in `:` that lists one or more specifiers,
 * followed by an indented block containing the resolved version. Handling both
 * costs one extra alternative and avoids a silent no-veto on any project that
 * has migrated to Berry.
 *
 * The version line is REQUIRED before the header's names are accepted — a
 * header alone is a request, and the resolution underneath it is the receipt.
 */
function fromYarnLock(raw: string): string[] {
  const out = new Set<string>();
  let pending: string[] = [];
  let resolved = false;

  const flush = (): void => {
    if (resolved) for (const n of pending) pushName(out, n);
    pending = [];
    resolved = false;
  };

  for (const line of raw.split('\n')) {
    if (line.length === 0 || line.startsWith('#')) continue;
    const indented = line.startsWith(' ') || line.startsWith('\t');
    if (!indented) {
      flush();
      const header = line.trimEnd();
      if (!header.endsWith(':')) continue;
      // `__metadata:` (Berry) and any other bare section head has no specifier.
      const body = header.slice(0, -1);
      if (!body.includes('@')) continue;
      for (const spec of body.split(',')) {
        const name = yarnSpecName(spec.trim());
        if (name) pending.push(name);
      }
      continue;
    }
    if (pending.length === 0) continue;
    const trimmed = line.trim();
    if (trimmed.startsWith('version ') || trimmed.startsWith('version:')) resolved = true;
  }
  flush();
  return [...out];
}

/**
 * `express@^4.17.1` / `"@babel/core@npm:^7.0.0"` → the package name.
 *
 * Split at the LAST `@` rather than the first, because a scoped name starts
 * with one; `slice(1)` before searching keeps that leading `@` out of the way.
 */
function yarnSpecName(spec: string): string | undefined {
  let s = spec.trim();
  if (s.startsWith('"') || s.startsWith("'")) s = s.slice(1);
  if (s.endsWith('"') || s.endsWith("'")) s = s.slice(0, -1);
  if (!s) return undefined;
  const at = s.slice(1).lastIndexOf('@');
  if (at < 0) return undefined;
  return s.slice(0, at + 1);
}

/**
 * pnpm-lock.yaml.
 *
 * Reads the `packages:` section only, whose two-space-indented keys carry the
 * name AND the resolved version in three historical spellings:
 *
 *   v5   `/express/4.18.2:`            `/@babel/core/7.0.0:`
 *   v6   `/express@4.18.2:`            `/@babel/core@7.0.0:`
 *   v9   `express@4.18.2:`             `@babel/core@7.0.0:`
 *
 * plus peer-dependency suffixes (`axios@1.6.0(debug@4.3.4)`), which are cut off
 * first so the `@` inside them cannot be mistaken for the version separator.
 * The version half must start with a digit; that check is what keeps a stray
 * `dependencies:` sub-key from being read as a package.
 *
 * A hand-rolled reader rather than a YAML dependency: analyzer-core and the CLI
 * ship with no parser dependency today, and the alternative to twenty lines
 * here is a transitive dependency in a security tool whose selling point
 * includes having almost none.
 */
function fromPnpmLock(raw: string): string[] {
  const out = new Set<string>();
  let inPackages = false;
  for (const line of raw.split('\n')) {
    if (line.length === 0 || line.trimStart().startsWith('#')) continue;
    if (!line.startsWith(' ') && !line.startsWith('\t')) {
      inPackages = line.trimEnd() === 'packages:';
      continue;
    }
    if (!inPackages) continue;
    const trimmed = line.trim();
    if (!trimmed.endsWith(':')) continue;
    // Depth matters: `resolution:` and `dependencies:` live deeper than the
    // package keys, which sit at exactly two spaces.
    if (!/^ {2}\S/.test(line)) continue;
    let key = trimmed.slice(0, -1);
    if (key.startsWith("'") || key.startsWith('"')) key = key.slice(1, -1);
    const name = pnpmKeyName(key);
    if (name) pushName(out, name);
  }
  return [...out];
}

function pnpmKeyName(rawKey: string): string | undefined {
  let key = rawKey;
  const paren = key.indexOf('(');
  if (paren >= 0) key = key.slice(0, paren);
  if (key.startsWith('/')) key = key.slice(1);
  if (!key) return undefined;

  // Everything after a scope prefix decides which spelling this is: a `/` in
  // the remainder means the v5 name/version form, otherwise the `@` form.
  const scopeEnd = key.startsWith('@') ? key.indexOf('/') : -1;
  const remainder = scopeEnd >= 0 ? key.slice(scopeEnd + 1) : key;
  const slash = remainder.lastIndexOf('/');
  if (slash >= 0) {
    const version = remainder.slice(slash + 1);
    if (!/^\d/.test(version)) return undefined;
    return key.slice(0, key.length - version.length - 1);
  }
  const at = remainder.lastIndexOf('@');
  if (at <= 0) return undefined;
  const version = remainder.slice(at + 1);
  if (!/^\d/.test(version)) return undefined;
  return key.slice(0, key.length - version.length - 1);
}

/**
 * poetry.lock and uv.lock — the same `[[package]]` array-of-tables shape:
 *
 *   [[package]]
 *   name = "requests"
 *   version = "2.31.0"
 *
 * Only `name` and `version` are read, only at the top level of a `[[package]]`
 * block, and both are required. Reading line-shaped TOML rather than adding a
 * TOML parser is the same trade as pnpm above; the risk it accepts is a `name =`
 * key nested inside a sub-table of a package block, which is why any `[` line
 * closes the current block.
 */
function fromTomlPackages(raw: string): string[] {
  const out = new Set<string>();
  let inPackage = false;
  let name: string | undefined;
  let version: string | undefined;

  const flush = (): void => {
    if (inPackage && name && version) pushName(out, name);
    name = undefined;
    version = undefined;
  };

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('[')) {
      flush();
      inPackage = trimmed.startsWith('[[package]]');
      continue;
    }
    if (!inPackage) continue;
    const kv = /^(name|version)[^\S\r\n]{0,4}=[^\S\r\n]{0,4}"([^"\n]{1,200})"/.exec(trimmed);
    if (!kv) continue;
    if (kv[1] === 'name') name = kv[2];
    else version = kv[2];
  }
  flush();
  return [...out];
}

/**
 * Pipfile.lock — JSON, with package names as the keys of `default` / `develop`.
 *
 * `_meta` is skipped by name (it is the hash/source block, not a package).
 * A `version` or a `ref` is required: pipenv writes `"version": "==2.31.0"` for
 * registry packages and `"ref": "<sha>"` for VCS ones, and both are resolutions
 * — an entry with neither is not one.
 */
function fromPipfileLock(raw: string): string[] {
  const parsed: unknown = JSON.parse(raw);
  if (!isRecord(parsed)) throw new Error('top level is not a JSON object');
  const out = new Set<string>();
  for (const section of ['default', 'develop']) {
    const group = parsed[section];
    if (!isRecord(group)) continue;
    for (const [name, value] of Object.entries(group)) {
      if (name === '_meta' || !isRecord(value)) continue;
      if (typeof value['version'] !== 'string' && typeof value['ref'] !== 'string') continue;
      pushName(out, name);
    }
  }
  return [...out];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
