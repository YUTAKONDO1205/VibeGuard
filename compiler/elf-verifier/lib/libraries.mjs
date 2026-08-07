// Resolve DT_NEEDED to files on disk, and index what each one actually defines.
//
// This is what makes `dependency-derived` a measurement rather than a guess. The
// alternative — "the name starts with _ZNSt so it is probably libstdc++" — is a
// name grammar, and a name grammar cannot tell the difference between a symbol
// libstdc++ exports and a symbol that merely looks like one.
//
// A library that cannot be found is reported as missing, and every symbol that
// would have needed it becomes Unresolved. It is not treated as "defines
// nothing", which would turn a missing file into a page of findings.

import { existsSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { readElf, DT, dynTags, SHN } from './elf.mjs';

const DEFAULT_SEARCH = [
  '/lib/x86_64-linux-gnu',
  '/usr/lib/x86_64-linux-gnu',
  '/lib64',
  '/usr/lib64',
  '/usr/lib',
  '/lib',
  '/usr/local/lib',
];

function runpathDirs(elf) {
  const out = [];
  for (const tag of [DT.RUNPATH, DT.RPATH]) {
    for (const d of dynTags(elf, tag)) {
      if (!d.string) continue;
      for (const p of d.string.split(':')) if (p && !p.includes('$')) out.push(p);
    }
  }
  return out;
}

export function buildLibraryIndex(elf, { extraSearch = [], allowed = null } = {}) {
  const needed = dynTags(elf, DT.NEEDED).map((d) => d.string).filter(Boolean);
  const dirs = [...runpathDirs(elf), ...extraSearch, ...DEFAULT_SEARCH];
  const index = new Map();
  const missing = [];
  const resolved = [];
  for (const soname of needed) {
    let found = null;
    for (const d of dirs) {
      const p = join(d, soname);
      if (existsSync(p)) {
        found = realpathSync(p);
        break;
      }
    }
    if (!found) {
      missing.push(soname);
      continue;
    }
    const lib = readElf(found);
    if (!lib.supported) {
      missing.push(`${soname} (${lib.reason})`);
      continue;
    }
    let count = 0;
    for (const s of lib.dynsym) {
      if (s.st_shndx === SHN.UNDEF || !s.name) continue;
      const base = s.name.split('@')[0];
      if (!index.has(base)) index.set(base, []);
      const arr = index.get(base);
      if (!arr.includes(soname)) arr.push(soname);
      count++;
    }
    resolved.push({ soname, exported: count });
  }
  return {
    available: missing.length === 0,
    index,
    missing,
    resolved,
    needed,
    allowed: allowed ? new Set(allowed) : null,
  };
}
