#!/usr/bin/env node
// Offline extractor of REAL package names from a local repository corpus, for
// auditing VG-AISC-001's bundled known-package data (§17z-a).
//
// WHY A CORPUS AND NOT A POPULARITY DUMP
// -------------------------------------
// VG-AISC-001 is near-miss-only: an import that is edit-distance-1 from (or
// separator-confused with) a name in KNOWN_NPM / KNOWN_PYPI is flagged. So the
// list's failure mode is not "missing a popular package" — it is "missing a REAL
// package that happens to sit one edit away from a listed one" (psycopg vs
// psycopg2, preact vs react, merge2 vs merge, enquirer vs inquirer). Every such
// name is a guaranteed false positive on any project that depends on it.
//
// A top-N download dump ranks by popularity, which is the wrong axis: the FP risk
// is adjacency, not rank, and a dump has to be fetched from the network. The
// dependency manifests of a large corpus of real repositories give us the actual
// distribution of names that real projects declare — i.e. the very population
// that produces the false positives — with zero network access.
//
// REJECTED ALTERNATIVES
//   - Fetching the npm/PyPI dumps at authoring time: still fine to do, but it is
//     strictly additive; it cannot beat the corpus at telling us which names are
//     actually *used together with* the ones we already list. Kept optional in
//     gen-aisc-known-packages.mjs (--npm/--pypi) rather than made a prerequisite.
//   - Extracting `import` statements from corpus source files instead of
//     manifests: that IS the literal FP population, but it mixes registry
//     packages with LOCAL modules (`import myhelpers`), and a local module name
//     must never be written into a "known packages" allowlist — it would silence
//     the same name for everyone. Manifest keys are unambiguously registry names.
//     (`--imports` below emits import names too, but only as a *diagnostic* set
//     for a human to read; nothing feeds it into the known list automatically.)
//   - Running the corpus through the scanner and collecting VG-AISC-001 findings:
//     equivalent output, minutes instead of seconds, and it cannot see a
//     dependency that no file happens to import.
//
// USAGE
//   node scripts/aisc-corpus-extract.mjs --roots paper_data/corpus1k,paper_data/corpus1k_vibe \
//        --out-npm npm-real.json --out-pypi pypi-real.json [--imports py-imports.json]
//
// Output files are JSON arrays of lowercased names, sorted, deduped. Feed them to
//   node scripts/gen-aisc-known-packages.mjs --audit --npm-real npm-real.json ...

import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const args = process.argv.slice(2);
const opt = (flag) => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};

// Directories that never contain a project's OWN manifest, only vendored copies
// of other people's. Walking them is both slow and wrong: `node_modules/*/package
// .json` would flood the output with transitive names we cannot attribute, and
// `.git` object stores are pure noise.
const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'bower_components', 'vendor', 'third_party', 'thirdparty',
  '.venv', 'venv', 'env', 'virtualenv', 'site-packages', '__pycache__', '.tox', '.nox',
  'dist', 'build', 'out', 'target', '.next', '.nuxt', '.cache', '.yarn', '.pnpm-store',
  'coverage', '.gradle', '.idea', '.vscode-test', 'Pods', 'DerivedData',
]);

const MAX_DEPTH = 5; // repo/a/b/c/d — deep enough for monorepo packages/*/app/*

/** Recursively collect interesting manifest paths under `dir`. */
function collectManifests(dir, depth, acc) {
  if (depth > MAX_DEPTH) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // unreadable (permissions, broken symlink, long path) — skip silently
  }
  for (const e of entries) {
    const name = e.name;
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(name)) continue;
      collectManifests(join(dir, name), depth + 1, acc);
      continue;
    }
    if (!e.isFile()) continue;
    if (name === 'package.json') acc.npmManifests.push(join(dir, name));
    else if (/^requirements[\w.-]*\.txt$/i.test(name)) acc.pyManifests.push(join(dir, name));
    else if (name === 'pyproject.toml') acc.pyProjects.push(join(dir, name));
    else if (name === 'Pipfile') acc.pipfiles.push(join(dir, name));
  }
}

const read = (p) => {
  try {
    const st = statSync(p);
    if (st.size > 2_000_000) return null; // a 2 MB manifest is generated junk
    return readFileSync(p, 'utf8');
  } catch {
    return null;
  }
};

// --- npm -------------------------------------------------------------------

const NPM_DEP_FIELDS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];

function npmNamesFrom(text) {
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    return []; // corpus repos contain hand-broken / templated package.json files
  }
  if (!json || typeof json !== 'object') return [];
  const out = [];
  for (const field of NPM_DEP_FIELDS) {
    const block = json[field];
    if (!block || typeof block !== 'object') continue;
    for (const [key, rawSpec] of Object.entries(block)) {
      const spec = typeof rawSpec === 'string' ? rawSpec : '';
      // ALIAS ENTRIES: `"immer5": "npm:immer@5"` / `"typescript3": "npm:typescript@^3"`.
      // The KEY is a local install alias invented by that one project — it is NOT
      // a registry name, and admitting it would teach the allowlist that `immer5`
      // and `typescript3` are real packages. The registry name is on the VALUE.
      // (Found by auditing: immer5/6/7/8/9 and typescript3 all came in this way.)
      if (spec.startsWith('npm:')) {
        const aliased = spec.slice(4).replace(/^(@[^/]+\/)?/, '$1');
        const at = aliased.lastIndexOf('@');
        out.push(at > 0 ? aliased.slice(0, at) : aliased);
        continue;
      }
      // Local protocols: the key names something on disk / in this monorepo, not
      // in the registry.
      if (/^(workspace:|file:|link:|portal:|git\+|https?:)/.test(spec)) continue;
      out.push(key);
    }
  }
  // REJECTED: including the manifest's own `name`. A published package's name is
  // a real registry name, but most corpus manifests are unpublished apps, and
  // their names leaked straight into the MUST-ADD set (`vMongodb`, `super-agent`,
  // `flaskr`, `openui`). A dependency KEY is a name someone actually installed;
  // a `name` field is a name someone typed.
  return out;
}

// --- PyPI ------------------------------------------------------------------

/** One requirements.txt line → a distribution name, or null. */
function pyReqName(rawLine) {
  let line = rawLine.split('#')[0].trim();
  if (!line) return null;
  // Options (-r other.txt, -e ., --index-url ...), VCS/URL requirements, and
  // path requirements carry no plain distribution name we can trust.
  if (/^[-.]/.test(line)) return null;
  if (/^(git\+|https?:|file:|ssh:)/i.test(line)) return null;
  if (line.includes('://')) return null;
  // Strip environment markers and extras: `foo[bar]>=1.0 ; python_version<"3.9"`
  line = line.split(';')[0].trim();
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(line);
  return m ? m[1] : null;
}

function pyProjectNames(text) {
  const out = [];
  // PEP 621 / setuptools / hatch: dependencies = ["foo>=1", "bar"] (also
  // build-system.requires).
  for (const m of text.matchAll(/(?:^|\n)\s*(?:requires|dependencies)\s*=\s*\[([\s\S]{0,4000}?)\]/g)) {
    for (const s of m[1].matchAll(/["']([^"'\n]{1,120})["']/g)) {
      const n = pyReqName(s[1]);
      if (n) out.push(n);
    }
  }
  const sections = text.split(/(?=^\s*\[)/m);
  for (const sec of sections) {
    const header = /^\s*\[([^\]\n]*)\]/.exec(sec);
    if (!header) continue;
    const table = header[1];
    // EXTRAS TABLES ([project.optional-dependencies], [tool.poetry.extras]) look
    // like dependency tables but their KEYS are extras-GROUP names and the values
    // are the requirement lists. Reading the keys is how `http2`, `toolkit`,
    // `slack` and `mssql` (all group names in real pyproject.toml files) entered
    // the first audit run as if they were PyPI distributions.
    if (/optional-dependencies|extras/.test(table)) {
      for (const s of sec.matchAll(/["']([^"'\n]{1,120})["']/g)) {
        const n = pyReqName(s[1]);
        if (n) out.push(n);
      }
      continue;
    }
    // Poetry: [tool.poetry.dependencies] / [tool.poetry.group.<g>.dependencies]
    // are TABLES whose KEYS are the distribution names.
    if (!/dependencies/.test(table)) continue;
    for (const line of sec.split('\n').slice(1)) {
      if (/^\s*\[/.test(line)) break;
      const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/.exec(line);
      // `python = "^3.11"` in a poetry table is the INTERPRETER constraint, not a
      // dependency. Admitting it made `python` a near-miss target, which in turn
      // dragged `ipython`/`bpython` into the closure — a two-round cascade off one
      // parsing mistake.
      if (m && m[1].toLowerCase() !== 'python') out.push(m[1]);
    }
  }
  // REJECTED: the project's own [project]/[tool.poetry] `name`. See npmNamesFrom.
  return out;
}

function pipfileNames(text) {
  const out = [];
  const sections = text.split(/(?=^\s*\[)/m);
  for (const sec of sections) {
    if (!/^\s*\[(packages|dev-packages)\]/.test(sec)) continue;
    for (const line of sec.split('\n').slice(1)) {
      if (/^\s*\[/.test(line)) break;
      const m = /^\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*=/.exec(line);
      if (m) out.push(m[1]);
    }
  }
  return out;
}

// --- optional: python import names (diagnostic only, see header) -----------

const PY_IMPORT_RE = /^[^\S\r\n]*(?:import|from)[^\S\r\n]+([A-Za-z_][\w.]{0,80})/gm;

function collectPyImports(dir, depth, acc, budget) {
  if (depth > MAX_DEPTH || budget.left <= 0) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (budget.left <= 0) return;
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      collectPyImports(join(dir, e.name), depth + 1, acc, budget);
    } else if (e.isFile() && e.name.endsWith('.py')) {
      const text = read(join(dir, e.name));
      if (!text) continue;
      budget.left -= 1;
      for (const m of text.matchAll(PY_IMPORT_RE)) {
        const top = m[1].split('.')[0].toLowerCase();
        if (top) acc.add(top);
      }
    }
  }
}

// --- main ------------------------------------------------------------------

const roots = (opt('--roots') ?? 'paper_data/corpus1k,paper_data/corpus1k_vibe')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const acc = { npmManifests: [], pyManifests: [], pyProjects: [], pipfiles: [] };
for (const root of roots) {
  let repos;
  try {
    repos = readdirSync(root, { withFileTypes: true });
  } catch {
    console.error(`corpus root not readable: ${root}`);
    continue;
  }
  for (const r of repos) {
    if (!r.isDirectory()) continue;
    collectManifests(join(root, r.name), 1, acc);
  }
}

const npm = new Set();
const pypi = new Set();

for (const p of acc.npmManifests) {
  const text = read(p);
  if (!text) continue;
  for (const n of npmNamesFrom(text)) {
    const low = String(n).trim().toLowerCase();
    // Scoped packages (@org/name) are skipped by the rule itself, so they can
    // neither be flagged nor act as a near-miss target — excluding them here
    // keeps the audit input aligned with what the rule can actually see.
    if (!low || low.startsWith('@') || low.includes('/')) continue;
    if (!/^[a-z0-9][a-z0-9._-]*$/.test(low)) continue;
    npm.add(low);
  }
}

for (const p of acc.pyManifests) {
  const text = read(p);
  if (!text) continue;
  for (const line of text.split('\n')) {
    const n = pyReqName(line);
    if (n) pypi.add(n.toLowerCase());
  }
}
for (const p of acc.pyProjects) {
  const text = read(p);
  if (!text) continue;
  for (const n of pyProjectNames(text)) pypi.add(n.toLowerCase());
}
for (const p of acc.pipfiles) {
  const text = read(p);
  if (!text) continue;
  for (const n of pipfileNames(text)) pypi.add(n.toLowerCase());
}

const npmList = [...npm].sort();
const pypiList = [...pypi].sort();

console.log(
  `manifests: ${acc.npmManifests.length} package.json, ${acc.pyManifests.length} requirements*.txt, ` +
    `${acc.pyProjects.length} pyproject.toml, ${acc.pipfiles.length} Pipfile`,
);
console.log(`names: npm=${npmList.length} pypi=${pypiList.length}`);

if (opt('--out-npm')) writeFileSync(opt('--out-npm'), JSON.stringify(npmList, null, 0));
if (opt('--out-pypi')) writeFileSync(opt('--out-pypi'), JSON.stringify(pypiList, null, 0));

if (opt('--imports')) {
  const imports = new Set();
  const budget = { left: Number(opt('--import-budget') ?? 40000) };
  for (const root of roots) {
    let repos;
    try {
      repos = readdirSync(root, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const r of repos) {
      if (!r.isDirectory()) continue;
      collectPyImports(join(root, r.name), 1, imports, budget);
    }
  }
  const list = [...imports].sort();
  console.log(`python import names (diagnostic): ${list.length} (files budget left ${budget.left})`);
  writeFileSync(opt('--imports'), JSON.stringify(list, null, 0));
}
