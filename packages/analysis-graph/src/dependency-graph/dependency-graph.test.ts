import { describe, expect, it } from 'vitest';
import { indexFile } from '../structure-indexer/index.js';
import {
  buildDependencyGraph,
  fanIn,
  fanOut,
  includeClosure,
  normalizePath,
  resolveSpecifier,
  toSourceFile,
} from './index.js';
import type { StructureIndex } from '../types.js';

const indexAll = (files: { path: string; lang: string; src: string }[]): StructureIndex[] =>
  files.map((f) => indexFile(toSourceFile(f.path, f.lang, f.src)));

describe('normalizePath', () => {
  it('converts backslashes so Windows and import specifiers agree', () => {
    expect(normalizePath('src\\routes\\a.ts')).toBe('src/routes/a.ts');
  });
  it('collapses . and ..', () => {
    expect(normalizePath('src/routes/../middleware/./auth.ts')).toBe('src/middleware/auth.ts');
  });
  it('keeps a leading .. that cannot be popped', () => {
    expect(normalizePath('../outside/a.ts')).toBe('../outside/a.ts');
  });
  it('collapses duplicate separators', () => {
    expect(normalizePath('src//routes///a.ts')).toBe('src/routes/a.ts');
  });
});

describe('resolveSpecifier — JS/TS', () => {
  const known = new Set([
    'src/routes/admin.ts',
    'src/middleware/auth.ts',
    'src/services/index.ts',
    'src/legacy.js',
  ]);
  const edge = (from: string, spec: string) =>
    ({ fromFile: from, specifier: spec, names: [], line: 1, syntax: 'esm' as const });

  it('resolves a relative import without an extension', () => {
    expect(resolveSpecifier(edge('src/routes/admin.ts', '../middleware/auth'), known)).toBe(
      'src/middleware/auth.ts',
    );
  });

  it('rewrites a NodeNext .js specifier back to the .ts source', () => {
    expect(resolveSpecifier(edge('src/routes/admin.ts', '../middleware/auth.js'), known)).toBe(
      'src/middleware/auth.ts',
    );
  });

  it('resolves a directory to its index file', () => {
    expect(resolveSpecifier(edge('src/routes/admin.ts', '../services'), known)).toBe(
      'src/services/index.ts',
    );
  });

  it('leaves a bare package specifier unresolved rather than guessing', () => {
    expect(resolveSpecifier(edge('src/routes/admin.ts', 'express'), known)).toBeUndefined();
  });

  it('leaves a relative import at a path that does not exist unresolved', () => {
    expect(resolveSpecifier(edge('src/routes/admin.ts', './nope'), known)).toBeUndefined();
  });
});

describe('resolveSpecifier — Python', () => {
  const known = new Set(['app/routes/admin.py', 'app/auth.py', 'app/pkg/__init__.py']);
  const edge = (from: string, spec: string) =>
    ({ fromFile: from, specifier: spec, names: [], line: 1, syntax: 'python' as const });

  it('resolves a single-dot relative import within the package', () => {
    expect(resolveSpecifier(edge('app/routes/admin.py', '.helpers'), known)).toBeUndefined();
    expect(resolveSpecifier(edge('app/admin.py', '.auth'), known)).toBe('app/auth.py');
  });

  it('resolves a two-dot import one package up', () => {
    expect(resolveSpecifier(edge('app/routes/admin.py', '..auth'), known)).toBe('app/auth.py');
  });

  it('resolves a package to its __init__.py', () => {
    expect(resolveSpecifier(edge('app/routes/admin.py', '..pkg'), known)).toBe('app/pkg/__init__.py');
  });
});

describe('resolveSpecifier — C/C++ includes', () => {
  const known = new Set(['src/main.c', 'src/sensor.h', 'vendor/sdk/gpio.h', 'other/sdk/gpio.h']);
  const edge = (from: string, spec: string, syntax: 'quoted' | 'angled') =>
    ({ fromFile: from, specifier: spec, names: [], line: 1, syntax });

  it('resolves a quoted include relative to the including file', () => {
    expect(resolveSpecifier(edge('src/main.c', 'sensor.h', 'quoted'), known)).toBe('src/sensor.h');
  });

  it('leaves an ambiguous suffix match unresolved rather than picking one', () => {
    // Both vendor/sdk/gpio.h and other/sdk/gpio.h end with /sdk/gpio.h. Which one
    // wins is decided by the include path, which is exactly what is unavailable.
    expect(resolveSpecifier(edge('src/main.c', 'sdk/gpio.h', 'angled'), known)).toBeUndefined();
  });

  it('accepts an unambiguous suffix match', () => {
    const single = new Set(['src/main.c', 'vendor/sdk/gpio.h']);
    expect(resolveSpecifier(edge('src/main.c', 'sdk/gpio.h', 'angled'), single)).toBe(
      'vendor/sdk/gpio.h',
    );
  });

  it('leaves a system header outside the project unresolved', () => {
    expect(resolveSpecifier(edge('src/main.c', 'stdio.h', 'angled'), known)).toBeUndefined();
  });
});

describe('buildDependencyGraph', () => {
  const structures = indexAll([
    { path: 'src/routes/admin.ts', lang: 'typescript', src: 'import { requireAdmin } from "../middleware/auth";\nimport express from "express";\n' },
    { path: 'src/routes/users.ts', lang: 'typescript', src: 'import { requireAdmin } from "../middleware/auth";\n' },
    { path: 'src/middleware/auth.ts', lang: 'typescript', src: 'export function requireAdmin() {\n  return 1;\n}\n' },
  ]);
  const graph = buildDependencyGraph(structures);

  it('records forward edges only for resolved specifiers', () => {
    expect([...graph.importsOf.get('src/routes/admin.ts')!]).toEqual(['src/middleware/auth.ts']);
  });

  it('records the reverse edge', () => {
    expect([...graph.importedBy.get('src/middleware/auth.ts')!].sort()).toEqual([
      'src/routes/admin.ts',
      'src/routes/users.ts',
    ]);
  });

  it('writes resolvedFile back onto the edge the structure holds', () => {
    const edge = structures[0]!.imports.find((i) => i.specifier === '../middleware/auth')!;
    expect(edge.resolvedFile).toBe('src/middleware/auth.ts');
  });

  it('leaves an unresolvable package edge in the list with no resolvedFile', () => {
    const edge = structures[0]!.imports.find((i) => i.specifier === 'express')!;
    expect(edge.resolvedFile).toBeUndefined();
    expect(graph.edges).toContain(edge);
  });

  it('computes fan-in and fan-out from resolved edges', () => {
    expect(fanIn('src/middleware/auth.ts', graph)).toBe(2);
    expect(fanOut('src/routes/admin.ts', graph)).toBe(1);
    expect(fanIn('src/routes/admin.ts', graph)).toBe(0);
  });

  it('gives every known file an entry, so consumers never see undefined', () => {
    for (const s of structures) {
      expect(graph.importsOf.has(s.filePath)).toBe(true);
      expect(graph.importedBy.has(s.filePath)).toBe(true);
    }
  });

  it('does not create a self-edge for a file importing itself', () => {
    const selfish = indexAll([
      { path: 'src/a.ts', lang: 'typescript', src: 'import { x } from "./a";\n' },
    ]);
    const g = buildDependencyGraph(selfish);
    expect([...g.importsOf.get('src/a.ts')!]).toEqual([]);
  });
});

describe('includeClosure', () => {
  const build = (files: { path: string; src: string }[]) => {
    const structures = indexAll(files.map((f) => ({ path: f.path, lang: 'c', src: f.src })));
    buildDependencyGraph(structures);
    return new Map(structures.map((s) => [s.filePath, s]));
  };

  it('follows includes transitively', () => {
    const m = build([
      { path: 'src/main.c', src: '#include "a.h"\n' },
      { path: 'src/a.h', src: '#include "b.h"\nvoid a(void);\n' },
      { path: 'src/b.h', src: 'void b(void);\n' },
    ]);
    const closure = includeClosure('src/main.c', m);
    expect(closure.files).toEqual(['src/a.h', 'src/b.h', 'src/main.c']);
    expect(closure.complete).toBe(true);
  });

  it('marks the closure incomplete when any include is unresolved', () => {
    const m = build([
      { path: 'src/main.c', src: '#include <stdio.h>\n#include "a.h"\n' },
      { path: 'src/a.h', src: 'void a(void);\n' },
    ]);
    const closure = includeClosure('src/main.c', m);
    expect(closure.complete).toBe(false);
    expect(closure.files).toEqual(['src/a.h', 'src/main.c']);
  });

  it('terminates on a cycle', () => {
    const m = build([
      { path: 'src/a.h', src: '#include "b.h"\n' },
      { path: 'src/b.h', src: '#include "a.h"\n' },
    ]);
    const closure = includeClosure('src/a.h', m);
    expect(closure.files).toEqual(['src/a.h', 'src/b.h']);
    expect(closure.complete).toBe(true);
  });
});

describe('toSourceFile', () => {
  it('normalises the path so graph keys match on Windows', () => {
    expect(toSourceFile('src\\a.ts', 'typescript', 'x').filePath).toBe('src/a.ts');
  });
});
