// vibeguard:disable-file VG-INJ-004 VG-INJ-006
// Test fixtures contain intentional vulnerable code to exercise the rules: this
// suite asserts that taint analysis FINDS `eval(req.body)` and
// `el.innerHTML = req.query`, so the strings have to be here. Naming the two
// rules rather than a bare wildcard keeps the escape hatch narrow — a real
// injection introduced into this file under any OTHER rule still reports.
// Tests for H1 taint-lite.
//
// The fixtures are written as whole files with a hand-rolled mini-indexer
// (`indexSymbols`) rather than by hand-constructing `IndexedSymbol` literals with
// invented offsets. Hand-written offsets are a way of testing that the analysis
// agrees with the numbers the test author wanted, which is not the property under
// test — `bodyStart`/`bodyEnd` come from a real balanced-block extraction here,
// so an off-by-one in the span is a failing assertion rather than a shared
// assumption between fixture and code.
//
// THE MOST IMPORTANT TEST IN THIS FILE is "source and sink in different
// functions". Everything else checks that a flow is found; that one checks that
// the intraprocedural boundary is real, which is the claim the module's whole
// design rests on. It is deliberately asserted three ways: from each function
// individually, and through `analyzeProjectTaint`, which is where a nesting
// mistake would reintroduce the flow through an enclosing symbol.

import { describe, expect, it } from 'vitest';
import { blankJsLiterals, extractBlockAfter, indexToPosition } from '@vibeguard/rules';
import type { IndexedSymbol, SourceFile, StructureIndex } from '../types.js';
import { analyzeFunction, analyzeProjectTaint, type TaintFlow } from './index.js';

function makeFile(content: string, language = 'javascript', filePath = 'src/handler.js'): SourceFile {
  return { filePath, language, content, lines: content.split('\n') };
}

/** `function NAME(`, `const NAME = (` and `const NAME = function(` heads. */
const HEAD_RE =
  /(?:^|[^\w$.])(?:(?:async[^\S\r\n]{1,4})?function[^\S\r\n]{1,4}(?<fnA>[\w$]{1,60})|(?:const|let|var)[^\S\r\n]{1,4}(?<fnB>[\w$]{1,60})[^\S\r\n]{0,4}=[^\S\r\n]{0,4}(?:async[^\S\r\n]{1,4})?(?:function[^\S\r\n]{0,4})?)[^\S\r\n]{0,4}\(/g;

function indexSymbols(file: SourceFile): IndexedSymbol[] {
  const blanked = blankJsLiterals(file.content);
  const symbols: IndexedSymbol[] = [];
  HEAD_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = HEAD_RE.exec(blanked)) !== null) {
    const leading = m[0].length - m[0].replace(/^[^\w$.]/, '').length;
    const headIndex = m.index + leading;
    const block = extractBlockAfter(blanked, m.index + m[0].length - 1);
    if (!block) continue;
    const head = indexToPosition(file.content, headIndex);
    const end = indexToPosition(file.content, block.end);
    symbols.push({
      name: m.groups?.fnA ?? m.groups?.fnB ?? `<anonymous@${head.line}>`,
      kind: 'function',
      filePath: file.filePath,
      startLine: head.line,
      startColumn: head.column,
      endLine: end.line,
      bodyStart: block.start + 1,
      bodyEnd: block.end - 1,
      exported: false,
    });
  }
  return symbols;
}

/** Analyse every function in a one-file fixture, the way a caller would. */
function flowsIn(content: string, language = 'javascript'): TaintFlow[] {
  const file = makeFile(content, language);
  return indexSymbols(file).flatMap((s) => analyzeFunction(s, file));
}

function structureFor(file: SourceFile): StructureIndex {
  return {
    filePath: file.filePath,
    language: file.language,
    symbols: indexSymbols(file),
    imports: [],
    routes: [],
    exportedNames: [],
    blanked: blankJsLiterals(file.content),
  };
}

describe('mask invariants', () => {
  // The module's offset arithmetic is only valid because blanking is
  // length-preserving. That is asserted here rather than trusted, because every
  // line number this module prints depends on it.
  it('blanking preserves length and the position of every line terminator', () => {
    const src = 'const a = "x";\r\nconst b = `t ${q} u`; // req.body\r\nconst c = /a"b/;\r\n';
    const blanked = blankJsLiterals(src);
    expect(blanked.length).toBe(src.length);
    const terminators = (t: string): number[] =>
      [...t].map((c, i) => (c === '\n' || c === '\r' ? i : -1)).filter((i) => i >= 0);
    expect(terminators(blanked)).toEqual(terminators(src));
  });

  it('reports the same line and column as indexToPosition on CRLF input', () => {
    // The module resolves positions from a precomputed line table instead of
    // calling indexToPosition per offset (which is O(n) each time). This pins the
    // two definitions together: CRLF is where they would first diverge, because
    // `\r` belongs to the end of the previous line.
    const content = 'function h(req, res) {\r\n  const q = req.query.id;\r\n  db.query(q);\r\n}\r\n';
    const file = makeFile(content);
    const [symbol] = indexSymbols(file);
    const flows = analyzeFunction(symbol!, file);
    expect(flows).toHaveLength(1);
    const flow = flows[0]!;
    const sourceIndex = content.indexOf('req.query.id');
    const expected = indexToPosition(content, sourceIndex);
    expect(flow.source.line).toBe(expected.line);
    expect(flow.source.column).toBe(expected.column);
    expect(flow.source.line).toBe(2);
    expect(flow.sink.line).toBe(3);
  });
});

describe('analyzeFunction — flows that exist', () => {
  it('finds a direct source→sink flow with no hops', () => {
    const flows = flowsIn(['function h(req, res) {', '  db.query(req.query.id);', '}'].join('\n'));
    expect(flows).toHaveLength(1);
    const flow = flows[0]!;
    expect(flow.source.name).toBe('req.query');
    expect(flow.source.line).toBe(2);
    expect(flow.sink.name).toBe('db.query');
    expect(flow.sink.kind).toBe('query');
    expect(flow.sink.line).toBe(2);
    expect(flow.hops).toEqual([]);
    expect(flow.symbolName).toBe('h');
    expect(flow.filePath).toBe('src/handler.js');
  });

  it('slices `expression` from the original content, not from the mask', () => {
    const flows = flowsIn(
      ['function h(req, res) {', '  db.query("SELECT " + req.body.name);', '}'].join('\n'),
    );
    expect(flows).toHaveLength(1);
    // If the module sliced the mask, the string literal would come back blanked.
    expect(flows[0]!.sink.expression).toContain('SELECT');
    expect(flows[0]!.source.expression).toBe('req.body');
  });

  it('follows one assignment hop', () => {
    const flows = flowsIn(
      ['function h(req, res) {', '  const sql = req.body.q;', '  db.query(sql);', '}'].join('\n'),
    );
    expect(flows).toHaveLength(1);
    expect(flows[0]!.hops).toEqual([{ name: 'sql', line: 2 }]);
    expect(flows[0]!.source.name).toBe('req.body');
  });

  it('follows two assignment hops in order', () => {
    const flows = flowsIn(
      [
        'function h(req, res) {',
        '  const raw = req.params.id;',
        '  const sql = raw;',
        '  db.query(sql);',
        '}',
      ].join('\n'),
    );
    expect(flows).toHaveLength(1);
    expect(flows[0]!.hops).toEqual([
      { name: 'raw', line: 2 },
      { name: 'sql', line: 3 },
    ]);
  });

  it('carries taint through a template interpolation', () => {
    // The `${…}` restore exists for exactly this shape; the plain blanker erases
    // the interpolation along with the SQL around it.
    const flows = flowsIn(
      ['function h(req, res) {', '  db.query(`SELECT * FROM t WHERE id = ${req.query.id}`);', '}'].join('\n'),
    );
    expect(flows).toHaveLength(1);
    expect(flows[0]!.source.name).toBe('req.query');
    expect(flows[0]!.sink.kind).toBe('query');
  });

  it('treats a conventionally named parameter as a source', () => {
    const flows = flowsIn(['function render(userInput) {', '  eval(userInput);', '}'].join('\n'));
    expect(flows).toHaveLength(1);
    expect(flows[0]!.source.name).toBe('userInput');
    expect(flows[0]!.source.line).toBe(1);
    expect(flows[0]!.sink.kind).toBe('eval');
  });

  it('handles the flat `const { body } = req` destructure', () => {
    const flows = flowsIn(
      ['function h(req, res) {', '  const { body } = req;', '  res.send(body);', '}'].join('\n'),
    );
    expect(flows).toHaveLength(1);
    expect(flows[0]!.source.name).toBe('req');
    expect(flows[0]!.hops).toEqual([{ name: 'body', line: 2 }]);
    expect(flows[0]!.sink.kind).toBe('response');
  });

  it('classifies each sink kind', () => {
    const byKind = (src: string): string[] => flowsIn(src).map((f) => f.sink.kind);
    expect(byKind(['function a(req) {', '  cp.execSync(req.query.cmd);', '}'].join('\n'))).toEqual(['exec']);
    expect(byKind(['function b(req) {', '  exec(req.body.cmd);', '}'].join('\n'))).toEqual(['exec']);
    expect(byKind(['function c(req) {', '  eval(req.body.js);', '}'].join('\n'))).toEqual(['eval']);
    expect(byKind(['function d(req, res) {', '  res.send(req.query.q);', '}'].join('\n'))).toEqual(['response']);
    expect(byKind(['function e(req) {', '  el.innerHTML = req.query.html;', '}'].join('\n'))).toEqual(['response']);
    expect(
      byKind(
        ['function f(req) {', '  const p = path.join(base, req.query.f);', '  fs.readFile(p, cb);', '}'].join('\n'),
      ),
    ).toEqual(['file']);
  });

  it('propagates across a loop-carried alias on a later sweep', () => {
    // `y` is aliased from `x` textually BEFORE `x` is tainted, which is correct
    // on the second iteration of the loop and is exactly what the extra
    // propagation sweeps buy. The first sweep finds nothing here.
    const flows = flowsIn(
      [
        'function h(req, res) {',
        '  while (more()) {',
        '    const y = x;',
        '    x = req.body.next;',
        '    db.query(y);',
        '  }',
        '}',
      ].join('\n'),
    );
    expect(flows).toHaveLength(1);
    expect(flows[0]!.sink.line).toBe(5);
    expect(flows[0]!.source.line).toBe(4);
    expect(flows[0]!.hops.map((h) => h.name)).toEqual(['x', 'y']);
  });
});

describe('analyzeFunction — flows that must NOT exist', () => {
  it('does not fire on a source that appears only in a comment', () => {
    const flows = flowsIn(
      [
        'function h(a, res) {',
        '  // read req.query.id here later',
        '  /* or maybe req.body */',
        '  db.query(a);',
        '}',
      ].join('\n'),
    );
    expect(flows).toEqual([]);
  });

  it('does not fire on a source that appears only inside a string literal', () => {
    const flows = flowsIn(
      [
        'function h(a, res) {',
        '  const note = "req.query.id is the interesting one";',
        "  const other = 'process.env';",
        '  db.query(note + other);',
        '}',
      ].join('\n'),
    );
    expect(flows).toEqual([]);
  });

  it('does not fire on a sink with no source reaching it', () => {
    const flows = flowsIn(
      ['function h(a, res) {', '  const sql = "SELECT 1";', '  db.query(sql);', '}'].join('\n'),
    );
    expect(flows).toEqual([]);
  });

  it('kills taint on reassignment to an untainted value', () => {
    const flows = flowsIn(
      [
        'function h(req, res) {',
        '  let sql = req.query.q;',
        "  sql = 'SELECT 1';",
        '  db.query(sql);',
        '}',
      ].join('\n'),
    );
    expect(flows).toEqual([]);
  });

  it('still reports a sink that precedes the kill', () => {
    // The control for the test above: the kill must remove taint from that point
    // on, not retroactively erase a flow that already happened.
    const flows = flowsIn(
      [
        'function h(req, res) {',
        '  let sql = req.query.q;',
        '  db.query(sql);',
        "  sql = 'SELECT 1';",
        '}',
      ].join('\n'),
    );
    expect(flows).toHaveLength(1);
    expect(flows[0]!.sink.line).toBe(3);
  });

  it('does not track object property writes', () => {
    const flows = flowsIn(
      ['function h(req, res) {', '  o.sql = req.query.q;', '  db.query(o.sql);', '}'].join('\n'),
    );
    expect(flows).toEqual([]);
  });

  it('does not treat regex .exec() as a query sink', () => {
    const flows = flowsIn(['function h(req, res) {', '  const m = re.exec(req.query.q);', '}'].join('\n'));
    expect(flows).toEqual([]);
  });

  it('returns nothing for an empty body', () => {
    const file = makeFile('function h(req, res) {}\n');
    const [symbol] = indexSymbols(file);
    expect(symbol!.bodyEnd).toBe(symbol!.bodyStart);
    expect(analyzeFunction(symbol!, file)).toEqual([]);
  });

  it('returns nothing for Python, whatever the file contains', () => {
    const content = ['def h(request):', '    q = request.args.get("q")', '    db.query(q)', ''].join('\n');
    const file = makeFile(content, 'python', 'src/app.py');
    const symbol: IndexedSymbol = {
      name: 'h',
      kind: 'function',
      filePath: file.filePath,
      startLine: 1,
      startColumn: 1,
      endLine: 3,
      bodyStart: content.indexOf('\n') + 1,
      bodyEnd: content.length,
      exported: false,
    };
    expect(analyzeFunction(symbol, file)).toEqual([]);
  });
});

describe('the intraprocedural boundary', () => {
  const twoFunctions = [
    'function readIt(req, res) {',
    '  stash = req.query.id;',
    '}',
    '',
    'function useIt(a, res) {',
    '  db.query(stash);',
    '}',
  ].join('\n');

  it('does not connect a source in one function to a sink in another', () => {
    const file = makeFile(twoFunctions);
    const symbols = indexSymbols(file);
    expect(symbols.map((s) => s.name)).toEqual(['readIt', 'useIt']);
    expect(analyzeFunction(symbols[0]!, file)).toEqual([]);
    expect(analyzeFunction(symbols[1]!, file)).toEqual([]);
    expect(analyzeProjectTaint([structureFor(file)], [file])).toEqual([]);
  });

  it('does not connect two callbacks that share an enclosing function', () => {
    // The lexical body span of `routes` physically contains both callbacks, so
    // this is where the boundary is easiest to lose. `analyzeProjectTaint` blanks
    // nested bodies out of their parent to keep it.
    const content = [
      'function routes(app) {',
      '  const first = (req, res) => {',
      '    stash = req.query.id;',
      '  };',
      '  const second = (a, res) => {',
      '    db.query(stash);',
      '  };',
      '}',
    ].join('\n');
    const file = makeFile(content);
    expect(analyzeProjectTaint([structureFor(file)], [file])).toEqual([]);
  });

  it('still reports a flow contained in a single nested callback', () => {
    // The negative control for the test above: blanking nested bodies out of the
    // parent must not blank them out of themselves.
    const content = [
      'function routes(app) {',
      '  const first = (req, res) => {',
      '    db.query(req.query.id);',
      '  };',
      '}',
    ].join('\n');
    const file = makeFile(content);
    const flows = analyzeProjectTaint([structureFor(file)], [file]);
    expect(flows).toHaveLength(1);
    expect(flows[0]!.symbolName).toBe('first');
    expect(flows[0]!.sink.line).toBe(3);
  });
});

describe('bounds', () => {
  it('does not let a body full of assignments starve the sinks', () => {
    // REGRESSION. With one shared event budget this returned zero flows — not
    // "partial", just clean — because the assignments were collected first and
    // used all of it. The generated files where that happens are precisely the
    // ones nobody reads by hand.
    let body = '  const v0 = req.query.id;\n';
    for (let i = 1; i < 600; i += 1) {
      body += `  const v${i} = v${i - 1};\n  const w${i} = "aaaaaaaaaaaaaaaaaaaaaaaa";\n\n\n`;
    }
    body += '  db.query(req.body.late);\n';
    const content = `function h(req, res) {\n${body}}\n`;
    const file = makeFile(content);
    const blanked = blankJsLiterals(content);
    const block = extractBlockAfter(blanked, content.indexOf('('), { maxBodyLength: 400_000 })!;
    const symbol: IndexedSymbol = {
      name: 'h',
      kind: 'function',
      filePath: file.filePath,
      startLine: 1,
      startColumn: 1,
      endLine: indexToPosition(content, block.end).line,
      bodyStart: block.start + 1,
      bodyEnd: block.end - 1,
      exported: false,
    };
    const started = Date.now();
    const flows = analyzeFunction(symbol, file);
    // A loose bound on purpose: this is a check that nothing here is
    // super-linear (it measures in single-digit milliseconds), not a benchmark,
    // and a tight bound on a shared CI runner is a flaky test.
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(flows.some((f) => f.source.name === 'req.body' && f.hops.length === 0)).toBe(true);
  });
});

describe('analyzeProjectTaint', () => {
  it('analyses every supported file and skips unsupported ones', () => {
    const js = makeFile(
      ['function h(req, res) {', '  db.query(req.query.id);', '}'].join('\n'),
      'javascript',
      'src/a.js',
    );
    const ts = makeFile(
      ['function g(req: Request, res: Response) {', '  res.send(req.body.html);', '}'].join('\n'),
      'typescript',
      'src/b.ts',
    );
    const py = makeFile('def f(request):\n    db.query(request.args)\n', 'python', 'src/c.py');
    const flows = analyzeProjectTaint(
      [structureFor(js), structureFor(ts), structureFor(py)],
      [js, ts, py],
    );
    expect(flows.map((f) => f.filePath).sort()).toEqual(['src/a.js', 'src/b.ts']);
    expect(flows.every((f) => f.hops.length === 0)).toBe(true);
  });

  it('ignores a structure whose file was not admitted to the scan', () => {
    const js = makeFile(['function h(req) {', '  eval(req.body.js);', '}'].join('\n'), 'javascript', 'src/a.js');
    expect(analyzeProjectTaint([structureFor(js)], [])).toEqual([]);
  });
});
