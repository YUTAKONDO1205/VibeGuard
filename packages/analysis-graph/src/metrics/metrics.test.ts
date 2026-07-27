// Tests for the metrics-calculator.
//
// The fixtures are built BY HAND from literal objects rather than by running the
// structure-indexer over sample files. That is deliberate and worth stating: this
// module's contract is "given these interfaces, produce these numbers", and a
// test that reached the numbers through the indexer would fail whenever the
// indexer changed, in a file whose name says the metrics broke. Offsets are
// derived with `indexOf` on the fixture text instead of being written out as
// integers, because a hand-counted offset that drifts by one produces plausible
// numbers computed over the wrong slice — the failure this suite exists to catch.

import { describe, expect, it } from 'vitest';

import type { DependencyGraph, ImportEdge, IndexedSymbol, SourceFile, StructureIndex } from '../types.js';
import { blankCommentsAndStrings } from '@vibeguard/rules';
import { fanMetrics, fileMetrics, mergeMetrics, symbolMetrics } from './index.js';

function sourceFile(filePath: string, language: string, content: string): SourceFile {
  return { filePath, language, content, lines: content.split(/\r?\n/) };
}

function structure(file: SourceFile, parts: Partial<StructureIndex> = {}): StructureIndex {
  return {
    filePath: file.filePath,
    language: file.language,
    symbols: [],
    imports: [],
    routes: [],
    exportedNames: [],
    // Left EMPTY on purpose in most fixtures: the length check in `blankedOf`
    // rejects it and the module recomputes from `file.content`. That is the code
    // path a caller who forgot to blank would hit, so it is the one under test
    // unless a case says otherwise.
    blanked: '',
    ...parts,
  };
}

/**
 * A function symbol whose body is the first balanced `{ … }` block in `content`.
 * `bodyStart` is the offset AFTER the opening brace, matching what
 * `IndexedSymbol` documents.
 */
function braceSymbol(file: SourceFile, name: string, kind: IndexedSymbol['kind'] = 'function'): IndexedSymbol {
  const open = file.content.indexOf('{');
  let depth = 0;
  let close = -1;
  for (let i = open; i < file.content.length; i += 1) {
    if (file.content[i] === '{') depth += 1;
    else if (file.content[i] === '}') {
      depth -= 1;
      if (depth === 0) {
        close = i;
        break;
      }
    }
  }
  return {
    name,
    kind,
    filePath: file.filePath,
    startLine: 1,
    endLine: file.lines.length,
    startColumn: 1,
    bodyStart: open + 1,
    bodyEnd: close,
    exported: false,
  };
}

/** A Python symbol whose body is everything after the first `:` line. */
function pySymbol(file: SourceFile, name: string): IndexedSymbol {
  const colon = file.content.indexOf(':\n') >= 0 ? file.content.indexOf(':\n') : file.content.indexOf(':\r\n');
  return {
    name,
    kind: 'function',
    filePath: file.filePath,
    startLine: 1,
    endLine: file.lines.length,
    startColumn: 1,
    bodyStart: colon + 1,
    bodyEnd: file.content.length,
    exported: false,
  };
}

function edge(specifier: string, resolvedFile?: string): ImportEdge {
  return { fromFile: 'a.ts', specifier, resolvedFile, names: [], line: 1, syntax: 'esm' };
}

describe('symbolMetrics — branch counting is immune to prose', () => {
  it('does not count a branch keyword inside a string literal', () => {
    const file = sourceFile(
      'src/a.ts',
      'typescript',
      ['function f(q: string) {', '  const sql = "if x then for while case";', '  return sql;', '}'].join('\n'),
    );
    const m = symbolMetrics(braceSymbol(file, 'f'), file);
    expect(m.branchCount).toBe(0);
    expect(m.loc).toBe(2);
  });

  it('does not count a branch keyword inside a line or block comment', () => {
    const file = sourceFile(
      'src/a.ts',
      'typescript',
      [
        'function f() {',
        '  // if the user is admin && allowed, return early',
        '  /* while (true) { case 1: } */',
        '  return 1;',
        '}',
      ].join('\n'),
    );
    const m = symbolMetrics(braceSymbol(file, 'f'), file);
    expect(m.branchCount).toBe(0);
    // Only `return 1;` survives: two comment lines contribute nothing to loc.
    expect(m.loc).toBe(1);
  });

  it('does not count `if` embedded in an identifier', () => {
    const file = sourceFile(
      'src/a.ts',
      'typescript',
      ['function f(notify: () => void) {', '  const ifconfig = notify;', '  return ifconfig;', '}'].join('\n'),
    );
    expect(symbolMetrics(braceSymbol(file, 'f'), file).branchCount).toBe(0);
  });

  it('counts real branch words and logical operators', () => {
    const file = sourceFile(
      'src/a.ts',
      'typescript',
      [
        'function f(u: User) {',
        '  if (u.admin && u.active) {',
        '    for (const r of u.roles) {',
        '      if (r === "x" || r === "y") return true;',
        '    }',
        '  }',
        '  return false;',
        '}',
      ].join('\n'),
    );
    // if, if, for  = 3 words; &&, || = 2 operators.
    expect(symbolMetrics(braceSymbol(file, 'f'), file).branchCount).toBe(5);
  });

  it('counts a ternary `?` but not `?.` or `??`', () => {
    const file = sourceFile(
      'src/a.ts',
      'typescript',
      ['function f(u: any) {', '  const a = u?.name ?? "anon";', '  return a ? 1 : 0;', '}'].join('\n'),
    );
    expect(symbolMetrics(braceSymbol(file, 'f'), file).branchCount).toBe(1);
  });

  it('counts Python `and`/`or` and not JS operators', () => {
    const file = sourceFile(
      'src/a.py',
      'python',
      ['def f(u):', '    if u.admin and u.active:', '        return "and or"', '    return False'].join('\n'),
    );
    // `if` + `and`; the `and or` inside the string literal must not count.
    expect(symbolMetrics(pySymbol(file, 'f'), file).branchCount).toBe(2);
  });
});

describe('symbolMetrics — nesting and size', () => {
  it('measures brace nesting relative to the body', () => {
    const file = sourceFile(
      'src/a.ts',
      'typescript',
      [
        'function f(u: User) {',
        '  if (u) {',
        '    while (u.next) {',
        '      u = u.next;',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    );
    const m = symbolMetrics(braceSymbol(file, 'f'), file);
    expect(m.nestingDepth).toBe(2);
  });

  it('does not let a brace inside a string or comment change the depth', () => {
    const file = sourceFile(
      'src/a.ts',
      'typescript',
      ['function f() {', '  const s = "{{{";', '  // }}}', '  return s;', '}'].join('\n'),
    );
    expect(symbolMetrics(braceSymbol(file, 'f'), file).nestingDepth).toBe(0);
  });

  it('measures Python nesting from indentation, ignoring docstring interiors', () => {
    const file = sourceFile(
      'src/a.py',
      'python',
      [
        'def f(items):',
        '    """Doc.',
        '',
        '                deeply indented prose that is not code',
        '    """',
        '    for i in items:',
        '        if i:',
        '            return i',
        '    return None',
      ].join('\n'),
    );
    const m = symbolMetrics(pySymbol(file, 'f'), file);
    expect(m.nestingDepth).toBe(2);
  });

  it('does not count a Python docstring as lines of code', () => {
    const file = sourceFile(
      'src/a.py',
      'python',
      ['def f():', '    """Summary.', '', '    Detail.', '    """', '    return 1'].join('\n'),
    );
    const m = symbolMetrics(pySymbol(file, 'f'), file);
    expect(m.loc).toBe(1);
    // …but a line that opens a docstring AND carries code keeps its line.
    const assigned = sourceFile('src/b.py', 'python', ['def g():', '    sql = """', '    SELECT 1', '    """'].join('\n'));
    expect(symbolMetrics(pySymbol(assigned, 'g'), assigned).loc).toBe(1);
  });

  it('handles CRLF without inflating loc or nesting', () => {
    const lines = ['function f(u: User) {', '  if (u) {', '    return 1;', '  }', '', '  return 0;', '}'];
    const lf = sourceFile('src/a.ts', 'typescript', lines.join('\n'));
    const crlf = sourceFile('src/a.ts', 'typescript', lines.join('\r\n'));
    const a = symbolMetrics(braceSymbol(lf, 'f'), lf);
    const b = symbolMetrics(braceSymbol(crlf, 'f'), crlf);
    expect(b).toEqual(a);
    expect(b.loc).toBe(4);
    expect(b.nestingDepth).toBe(1);
    expect(b.branchCount).toBe(1);
  });

  it('reports zeros — not absences — for an empty body', () => {
    const file = sourceFile('src/a.ts', 'typescript', 'function f() {}');
    const m = symbolMetrics(braceSymbol(file, 'f'), file);
    expect(m.loc).toBe(0);
    expect(m.branchCount).toBe(0);
    expect(m.nestingDepth).toBe(0);
    // Measured-as-zero, so the keys must be PRESENT.
    expect('loc' in m).toBe(true);
    expect('branchCount' in m).toBe(true);
  });

  it('tolerates an indexer that included the outer braces in the body span', () => {
    const file = sourceFile('src/a.ts', 'typescript', ['function f() {', '  if (x) { y(); }', '}'].join('\n'));
    const tight = braceSymbol(file, 'f');
    const loose: IndexedSymbol = { ...tight, bodyStart: tight.bodyStart - 1, bodyEnd: tight.bodyEnd + 1 };
    expect(symbolMetrics(loose, file).nestingDepth).toBe(symbolMetrics(tight, file).nestingDepth);
    expect(symbolMetrics(loose, file).nestingDepth).toBe(1);
  });
});

describe('fileMetrics', () => {
  const content = [
    '// a header comment',
    '/**',
    ' * A doc block.',
    ' */',
    "import { a } from './auth';",
    "import { b } from './auth';",
    "import express from 'express';",
    '',
    'export function handler() {',
    '  return a(b);',
    '}',
  ].join('\n');

  const file = sourceFile('src/routes/admin.ts', 'typescript', content);

  it('counts only code-bearing lines', () => {
    const m = fileMetrics(structure(file), file);
    // 3 imports + 3 lines of function = 6; header comment, doc block (3 lines)
    // and the blank line contribute nothing.
    expect(m.loc).toBe(6);
  });

  it('counts distinct modules, not import statements', () => {
    const s = structure(file, {
      imports: [edge('./auth', 'src/auth.ts'), edge('./auth.js', 'src/auth.ts'), edge('express')],
    });
    expect(fileMetrics(s, file).importCount).toBe(2);
  });

  it('counts functions and methods but not classes', () => {
    const symbols: IndexedSymbol[] = [
      { ...braceSymbol(file, 'C'), kind: 'class' },
      { ...braceSymbol(file, 'm'), kind: 'method', declaredKind: 'method', enclosingClass: 'C' },
      { ...braceSymbol(file, 'h'), kind: 'route-handler' },
    ];
    expect(fileMetrics(structure(file, { symbols }), file).methodCount).toBe(2);
  });

  it('omits fieldCount entirely for a file with no class', () => {
    const m = fileMetrics(structure(file, { symbols: [braceSymbol(file, 'handler')] }), file);
    expect('fieldCount' in m).toBe(false);
    expect(m.fieldCount).toBeUndefined();
  });

  it('reports fieldCount 0 — present — for a class with no fields', () => {
    const f = sourceFile('src/c.ts', 'typescript', ['class C {', '  run() {', '    const x = 1;', '  }', '}'].join('\n'));
    const m = fileMetrics(structure(f, { symbols: [{ ...braceSymbol(f, 'C'), kind: 'class' }] }), f);
    expect('fieldCount' in m).toBe(true);
    expect(m.fieldCount).toBe(0);
  });

  it('counts declared fields and constructor assignments once each', () => {
    const f = sourceFile(
      'src/c.ts',
      'typescript',
      [
        'class C {',
        '  private cache: Map<string, string>;',
        '  #secret = "x";',
        '  constructor(opts: Opts) {',
        '    this.cache = new Map();',
        '    this.name = opts.name;',
        '    const local = 1;',
        '  }',
        '}',
      ].join('\n'),
    );
    // cache (declared + assigned = 1), #secret, name. `local` is not a field.
    expect(fileMetrics(structure(f, { symbols: [{ ...braceSymbol(f, 'C'), kind: 'class' }] }), f).fieldCount).toBe(3);
  });

  it('counts Python class attributes from class body and self assignment', () => {
    const f = sourceFile(
      'src/c.py',
      'python',
      [
        'class C:',
        '    LIMIT = 10',
        '    def __init__(self):',
        '        self.name = "x"',
        '        local = 2',
        '',
        '    def run(self):',
        '        self.name = "y"',
      ].join('\n'),
    );
    const cls: IndexedSymbol = {
      ...pySymbol(f, 'C'),
      kind: 'class',
      bodyStart: f.content.indexOf(':\n') + 1,
      bodyEnd: f.content.length,
    };
    // LIMIT + name; `local` is a method-local, and the second `self.name` is the
    // same field.
    expect(fileMetrics(structure(f, { symbols: [cls] }), f).fieldCount).toBe(2);

    // The structure-indexer's Python class span starts AT the `class` keyword
    // rather than after a brace, so the header line is inside the slice. Both
    // conventions must give the same answer.
    const withHeader: IndexedSymbol = { ...cls, bodyStart: f.content.indexOf('class') };
    expect(fileMetrics(structure(f, { symbols: [withHeader] }), f).fieldCount).toBe(2);
  });

  it('ignores a StructureIndex.blanked whose length disagrees with the content', () => {
    // A truncated `blanked` would shift every offset. The module must fall back
    // to blanking `file.content` itself rather than measure the wrong text.
    const s = structure(file, { blanked: 'nonsense' });
    expect(fileMetrics(s, file).loc).toBe(6);
  });

  it('uses a caller-supplied blanked string when its length agrees', () => {
    // Every character replaced by a space: a caller-supplied blanking that says
    // "there is no code here". Length matches, so it is trusted, and loc is 0.
    const s = structure(file, { blanked: ' '.repeat(file.content.length) });
    expect(fileMetrics(s, file).loc).toBe(0);
  });

  it('handles CRLF input identically to LF', () => {
    const crlf = sourceFile('src/routes/admin.ts', 'typescript', content.split('\n').join('\r\n'));
    expect(fileMetrics(structure(crlf), crlf).loc).toBe(6);
  });
});

describe('fanMetrics', () => {
  const graph: DependencyGraph = {
    edges: [],
    importsOf: new Map([['src/a.ts', new Set(['src/b.ts', 'src/c.ts'])]]),
    importedBy: new Map([
      ['src/b.ts', new Set(['src/a.ts'])],
      ['src/c.ts', new Set(['src/a.ts', 'src/d.ts'])],
    ]),
  };

  it('reads distinct importers and imported files off the graph', () => {
    expect(fanMetrics('src/c.ts', graph)).toEqual({ fanIn: 2, fanOut: 0 });
    expect(fanMetrics('src/a.ts', graph)).toEqual({ fanIn: 0, fanOut: 2 });
  });

  it('normalises a Windows-style path to the graph key space', () => {
    expect(fanMetrics('src\\c.ts', graph).fanIn).toBe(2);
  });

  it('always reports both keys, because the graph was consulted', () => {
    const m = fanMetrics('src/unknown.ts', graph);
    expect('fanIn' in m).toBe(true);
    expect('fanOut' in m).toBe(true);
    expect(m).toEqual({ fanIn: 0, fanOut: 0 });
  });
});

describe('mergeMetrics', () => {
  it('returns an empty object for no parts and for all-undefined parts', () => {
    expect(mergeMetrics()).toEqual({});
    const m = mergeMetrics(undefined, undefined);
    expect(m).toEqual({});
    expect(Object.keys(m)).toHaveLength(0);
  });

  it('leaves unmeasured keys ABSENT rather than present-and-undefined', () => {
    const m = mergeMetrics({ loc: 12 });
    expect('loc' in m).toBe(true);
    expect('fanIn' in m).toBe(false);
    expect('duplicatedCheckCount' in m).toBe(false);
    expect(Object.keys(m)).toEqual(['loc']);
  });

  it('never lets an undefined overwrite a measured value', () => {
    const m = mergeMetrics({ loc: 12, branchCount: 3 }, { loc: undefined, nestingDepth: 4 });
    expect(m.loc).toBe(12);
    expect(m.branchCount).toBe(3);
    expect(m.nestingDepth).toBe(4);
    // The plain-spread behaviour this function exists to avoid.
    expect('loc' in { ...{ loc: 12 }, ...{ loc: undefined } }).toBe(true);
    expect({ ...{ loc: 12 }, ...{ loc: undefined } }.loc).toBeUndefined();
  });

  it('lets a later measured value win, and preserves a measured zero', () => {
    const m = mergeMetrics({ loc: 12 }, { loc: 0 });
    expect(m.loc).toBe(0);
    expect('loc' in m).toBe(true);
  });

  it('ignores keys that are not DesignMetrics fields, including __proto__', () => {
    const hostile = JSON.parse('{"loc": 5, "__proto__": {"polluted": true}, "bogus": 9}') as Record<string, unknown>;
    const m = mergeMetrics(hostile as never);
    expect(m).toEqual({ loc: 5 });
    expect(Object.keys(m)).toEqual(['loc']);
    expect((m as Record<string, unknown>).bogus).toBeUndefined();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.getPrototypeOf(m)).toBe(Object.prototype);
  });

  it('emits keys in the fixed schema order regardless of producer order', () => {
    const a = mergeMetrics({ fanIn: 1 }, { loc: 2 });
    const b = mergeMetrics({ loc: 2 }, { fanIn: 1 });
    expect(Object.keys(a)).toEqual(Object.keys(b));
    expect(Object.keys(a)).toEqual(['loc', 'fanIn']);
  });

  it('composes the three producers the way a rule will', () => {
    const file = sourceFile(
      'src/a.ts',
      'typescript',
      ['import x from "y";', 'export function f(u: User) {', '  if (u) return 1;', '  return 0;', '}'].join('\n'),
    );
    const sym = braceSymbol(file, 'f');
    const graph: DependencyGraph = {
      edges: [],
      importsOf: new Map([['src/a.ts', new Set(['src/y.ts'])]]),
      importedBy: new Map(),
    };
    const merged = mergeMetrics(
      fileMetrics(structure(file, { symbols: [sym], imports: [edge('y', 'src/y.ts')] }), file),
      fanMetrics('src/a.ts', graph),
      symbolMetrics(sym, file),
    );
    // The symbol's own loc wins over the file's (specific beats general).
    expect(merged.loc).toBe(2);
    expect(merged.methodCount).toBe(1);
    expect(merged.importCount).toBe(1);
    expect(merged.branchCount).toBe(1);
    expect(merged.nestingDepth).toBe(0);
    expect(merged.fanIn).toBe(0);
    expect(merged.fanOut).toBe(1);
    // Nothing invented: the three metrics this phase does not compute stay out.
    expect('fieldCount' in merged).toBe(false);
    expect('responsibilityCount' in merged).toBe(false);
    expect('duplicatedCheckCount' in merged).toBe(false);
  });
});

describe('countCodeLines — the two blankers disagree about `/*`', () => {
  // Regression for a defect found by comparing byte-identical C and TypeScript.
  // `blankCommentsAndStrings` (used for C by the structure indexer) blanks the
  // `*` of an opening `/*` and leaves a lone `/`, which the residue stripper did
  // not recognise, so every block-comment opener counted as a line of code.
  const cFile = (content: string): SourceFile => sourceFile('src/a.c', 'c', content);

  it('does not count a C block-comment opener as code', () => {
    const f = cFile('/* why this exists */\nint x = 1;\n');
    const st = structure(f, { blanked: blankCommentsAndStrings(f.content) });
    expect(fileMetrics(st, f).loc).toBe(1);
  });

  it('does not count the body lines of a multi-line C block comment', () => {
    const src = '/**\n * WHY: house style demands prose here.\n *\n * And more.\n */\nint x = 1;\n';
    const f = cFile(src);
    const st = structure(f, { blanked: blankCommentsAndStrings(f.content) });
    expect(fileMetrics(st, f).loc).toBe(1);
  });

  it('gives the same loc for the same code in C and TypeScript', () => {
    // The property that makes the metric comparable across languages, which is
    // what a cross-language design smell would rely on.
    const body = '/**\n * Doc.\n */\nint handler(void) {\n  return 1;\n}\n';
    const cf = cFile(body);
    const cLoc = fileMetrics(structure(cf, { blanked: blankCommentsAndStrings(cf.content) }), cf).loc;

    const tsBody = '/**\n * Doc.\n */\nfunction handler(): number {\n  return 1;\n}\n';
    const tf = sourceFile('src/a.ts', 'typescript', tsBody);
    const tsLoc = fileMetrics(structure(tf), tf).loc;

    expect(cLoc).toBe(3);
    expect(cLoc).toBe(tsLoc);
  });

  it('still counts a line that has real code beside a comment', () => {
    const f = cFile('int x = 1; /* keep */\n');
    const st = structure(f, { blanked: blankCommentsAndStrings(f.content) });
    expect(fileMetrics(st, f).loc).toBe(1);
  });

  it('still counts a division expression', () => {
    // The bare `/` in the residue pattern must not empty a real statement.
    const f = cFile('int r = a / b;\n');
    const st = structure(f, { blanked: blankCommentsAndStrings(f.content) });
    expect(fileMetrics(st, f).loc).toBe(1);
  });
});
