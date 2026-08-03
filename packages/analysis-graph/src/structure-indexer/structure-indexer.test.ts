import { describe, expect, it } from 'vitest';
import { indexFile, isIndexableLanguage, symbolBody } from './index.js';
import type { SourceFile } from '../types.js';

const file = (filePath: string, language: string, content: string): SourceFile => ({
  filePath,
  language,
  content,
  lines: content.split('\n'),
});

const js = (content: string, path = 'src/a.ts'): SourceFile => file(path, 'typescript', content);
const py = (content: string, path = 'src/a.py'): SourceFile => file(path, 'python', content);
const c = (content: string, path = 'src/a.c'): SourceFile => file(path, 'c', content);

describe('indexFile — JS/TS functions', () => {
  it('finds a plain function declaration with its body span', () => {
    const f = js('function handle(req, res) {\n  return 1;\n}\n');
    const idx = indexFile(f);
    const fn = idx.symbols.find((s) => s.name === 'handle');
    expect(fn).toBeDefined();
    expect(fn!.startLine).toBe(1);
    expect(fn!.endLine).toBe(3);
    expect(symbolBody(fn!, f)).toContain('return 1;');
  });

  it('finds an arrow function assigned to a const', () => {
    const idx = indexFile(js('const handle = (req, res) => {\n  res.send(1);\n};\n'));
    expect(idx.symbols.map((s) => s.name)).toContain('handle');
  });

  it('finds a class and attributes its methods to it', () => {
    const idx = indexFile(
      js('export class UserService {\n  find(id: string) {\n    return id;\n  }\n}\n'),
    );
    const cls = idx.symbols.find((s) => s.kind === 'class');
    expect(cls?.name).toBe('UserService');
    expect(cls?.exported).toBe(true);
    const method = idx.symbols.find((s) => s.name === 'find');
    expect(method?.enclosingClass).toBe('UserService');
    expect(method?.kind).toBe('method');
  });

  it('does not mistake control-flow keywords for functions', () => {
    const idx = indexFile(
      js('function real() {\n  if (x) {\n    while (y) {\n      switch (z) { }\n    }\n  }\n}\n'),
    );
    expect(idx.symbols.map((s) => s.name)).toEqual(['real']);
  });

  it('is not fooled by a brace inside a string literal', () => {
    const f = js('function a() {\n  const s = "}";\n  return s;\n}\nfunction b() {\n  return 2;\n}\n');
    const idx = indexFile(f);
    const a = idx.symbols.find((s) => s.name === 'a')!;
    // If the string brace had counted, a's body would have ended on line 2.
    expect(a.endLine).toBe(4);
    expect(idx.symbols.map((s) => s.name)).toEqual(['a', 'b']);
  });

  it('is not fooled by a function head inside a comment', () => {
    const idx = indexFile(js('// function ghost() {}\nfunction real() {\n  return 1;\n}\n'));
    expect(idx.symbols.map((s) => s.name)).toEqual(['real']);
  });

  it('reports correct line numbers with CRLF', () => {
    const idx = indexFile(js('const x = 1;\r\n\r\nfunction handle() {\r\n  return 1;\r\n}\r\n'));
    const fn = idx.symbols.find((s) => s.name === 'handle')!;
    expect(fn.startLine).toBe(3);
    expect(fn.endLine).toBe(5);
  });

  it('records decorators stacked above a method', () => {
    const idx = indexFile(
      js(
        'class C {\n  @Get("/users")\n  @UseGuards(AuthGuard)\n  list(req) {\n    return 1;\n  }\n}\n',
      ),
    );
    const m = idx.symbols.find((s) => s.name === 'list');
    expect(m?.decorators).toEqual(['Get', 'UseGuards']);
  });

  it('does not attribute a previous member’s decorator to the next one', () => {
    const idx = indexFile(
      js('class C {\n  @Get("/a")\n  first(r) {\n    return 1;\n  }\n\n  second(r) {\n    return 2;\n  }\n}\n'),
    );
    expect(idx.symbols.find((s) => s.name === 'second')?.decorators).toBeUndefined();
  });
});

describe('indexFile — JS/TS imports and exports', () => {
  it('reads ESM import specifiers and binding names', () => {
    const idx = indexFile(js('import express, { Router } from "express";\nimport "./side-effect";\n'));
    expect(idx.imports.map((i) => i.specifier)).toEqual(['express', './side-effect']);
    expect(idx.imports[0]!.names).toEqual(['express', 'Router']);
    expect(idx.imports[0]!.syntax).toBe('esm');
    expect(idx.imports[1]!.names).toEqual([]);
  });

  it('resolves `as` aliases to the local binding', () => {
    const idx = indexFile(js('import { requireAdmin as guard } from "./auth";\n'));
    expect(idx.imports[0]!.names).toEqual(['guard']);
  });

  it('reads CommonJS require', () => {
    const idx = indexFile(js('const { Router } = require("express");\n', 'src/a.js'));
    expect(idx.imports[0]).toMatchObject({ specifier: 'express', syntax: 'require', names: ['Router'] });
  });

  it('collects exported names from several syntaxes', () => {
    const idx = indexFile(
      js('export const a = 1;\nfunction b() {\n  return 1;\n}\nexport { b };\nexport function cc() {\n  return 2;\n}\n'),
    );
    expect(idx.exportedNames).toContain('a');
    expect(idx.exportedNames).toContain('b');
    expect(idx.exportedNames).toContain('cc');
  });
});

describe('indexFile — route bindings', () => {
  it('separates per-route guards from the handler', () => {
    const idx = indexFile(
      js('router.get("/admin", requireAdmin, listAdmins);\nfunction listAdmins(req, res) {\n  return 1;\n}\n'),
    );
    expect(idx.routes).toHaveLength(1);
    const r = idx.routes[0]!;
    expect(r.method).toBe('get');
    expect(r.path).toBe('/admin');
    expect(r.middlewareNames).toEqual(['requireAdmin']);
    expect(r.handlerName).toBe('listAdmins');
  });

  it('takes the callee of an invoked guard factory', () => {
    const idx = indexFile(js('router.get("/x", requireRole("admin"), h);\n'));
    expect(idx.routes[0]!.middlewareNames).toEqual(['requireRole']);
  });

  it('records an inline handler as a symbol with a real body span', () => {
    const f = js('router.post("/users", (req, res) => {\n  res.send(1);\n});\n');
    const idx = indexFile(f);
    const inline = idx.routes[0]!.inlineHandler;
    expect(inline).toBeDefined();
    expect(inline!.kind).toBe('route-handler');
    expect(symbolBody(inline!, f)).toContain('res.send(1)');
    expect(idx.routes[0]!.middlewareNames).toEqual([]);
  });

  it('treats app.use as a mount and captures the mounted name', () => {
    const idx = indexFile(js('app.use(requireAuth);\n'));
    expect(idx.routes[0]!.method).toBe('use');
    // With no path argument the sole argument is the handler position.
    expect(idx.routes[0]!.handlerName).toBe('requireAuth');
  });

  it('promotes a named handler and a named guard to their roles', () => {
    const idx = indexFile(
      js(
        'function requireAdmin(req, res, next) {\n  next();\n}\n' +
          'function listUsers(req, res) {\n  return 1;\n}\n' +
          'router.get("/u", requireAdmin, listUsers);\n',
      ),
    );
    expect(idx.symbols.find((s) => s.name === 'requireAdmin')?.kind).toBe('middleware');
    expect(idx.symbols.find((s) => s.name === 'listUsers')?.kind).toBe('route-handler');
    // The syntactic fact survives the role override.
    expect(idx.symbols.find((s) => s.name === 'listUsers')?.declaredKind).toBe('function');
  });

  it('does not invent a route from an unrelated .get call', () => {
    const idx = indexFile(js('const v = map.get("k");\n'));
    // `map.get(...)` matches the shape; the guard is that it yields no handler
    // and no path, so downstream consumers see an empty registration rather
    // than a fabricated one.
    expect(idx.routes[0]?.handlerName).toBeUndefined();
  });
});

describe('indexFile — Python', () => {
  it('finds defs with indentation-delimited spans', () => {
    const idx = indexFile(py('def outer():\n    x = 1\n    return x\n\ndef other():\n    return 2\n'));
    const outer = idx.symbols.find((s) => s.name === 'outer')!;
    expect(outer.startLine).toBe(1);
    // 3, not 4: the blank line between the two defs belongs to neither.
    expect(outer.endLine).toBe(3);
    expect(idx.symbols.map((s) => s.name)).toEqual(['outer', 'other']);
  });

  it('does not end a block on a blank or comment-only line', () => {
    const idx = indexFile(py('def f():\n    a = 1\n\n# a comment at column 0\n    b = 2\n'));
    expect(idx.symbols.find((s) => s.name === 'f')!.endLine).toBe(5);
  });

  it('attributes methods to their class', () => {
    const idx = indexFile(py('class Service:\n    def find(self, id):\n        return id\n'));
    expect(idx.symbols.find((s) => s.name === 'find')?.enclosingClass).toBe('Service');
    expect(idx.symbols.find((s) => s.name === 'find')?.kind).toBe('method');
  });

  it('records decorators above a def', () => {
    const idx = indexFile(py('@app.route("/x")\n@login_required\ndef view():\n    return 1\n'));
    expect(idx.symbols.find((s) => s.name === 'view')?.decorators).toEqual(['app.route', 'login_required']);
  });

  it('reads both import forms', () => {
    const idx = indexFile(py('import os\nfrom .auth import require_admin, check\n'));
    expect(idx.imports.map((i) => i.specifier)).toEqual(['os', '.auth']);
    expect(idx.imports[1]!.names).toEqual(['require_admin', 'check']);
  });

  it('is not fooled by a def inside a docstring', () => {
    const idx = indexFile(py('def real():\n    """\n    def ghost():\n        pass\n    """\n    return 1\n'));
    expect(idx.symbols.map((s) => s.name)).toEqual(['real']);
  });

  it('marks leading-underscore names as not exported', () => {
    const idx = indexFile(py('def _private():\n    return 1\n\ndef public():\n    return 2\n'));
    expect(idx.symbols.find((s) => s.name === '_private')?.exported).toBe(false);
    expect(idx.exportedNames).toEqual(['public']);
  });
});

describe('indexFile — C/C++', () => {
  it('separates quoted from angled includes', () => {
    const idx = indexFile(c('#include <stdio.h>\n#include "sdk/gpio.h"\n'));
    expect(idx.imports.map((i) => [i.specifier, i.syntax])).toEqual([
      ['stdio.h', 'angled'],
      ['sdk/gpio.h', 'quoted'],
    ]);
  });

  it('finds definitions but not prototypes', () => {
    const idx = indexFile(c('void sensor_init(void);\n\nvoid sensor_init(void) {\n  return;\n}\n'));
    expect(idx.symbols.filter((s) => s.name === 'sensor_init')).toHaveLength(1);
    expect(idx.symbols[0]!.startLine).toBe(3);
  });

  it('marks static functions as not exported', () => {
    const idx = indexFile(c('static void helper(void) {\n  return;\n}\n'));
    expect(idx.symbols[0]!.exported).toBe(false);
  });

  it('does not treat a control-flow block as a function', () => {
    const idx = indexFile(c('void f(void) {\n  if (x) {\n    return;\n  }\n}\n'));
    expect(idx.symbols.map((s) => s.name)).toEqual(['f']);
  });

  it('finds a definition written in Allman style (brace on its own line)', () => {
    // The dominant style in embedded C and in generated firmware. Requiring the
    // brace on the parameter-list line indexed ZERO functions in such files,
    // which made the whole #20b arm silently report nothing on exactly the
    // codebases it exists for.
    const idx = indexFile(c('int crypto_init(void)\n{\n  return 0;\n}\n'));
    expect(idx.symbols.map((s) => s.name)).toEqual(['crypto_init']);
    expect(idx.symbols[0]!.startLine).toBe(1);
    expect(idx.symbols[0]!.endLine).toBe(4);
  });

  it('still refuses a prototype when the next definition is Allman style', () => {
    const idx = indexFile(c('void a(void);\n\nvoid b(void)\n{\n  return;\n}\n'));
    expect(idx.symbols.map((s) => s.name)).toEqual(['b']);
  });

  it('handles Allman style with CRLF', () => {
    const idx = indexFile(c('int rng_init(void)\r\n{\r\n  return 0;\r\n}\r\n'));
    expect(idx.symbols.map((s) => s.name)).toEqual(['rng_init']);
  });
});

describe('indexFile — languages this phase does not index', () => {
  it('returns an empty index rather than guessing', () => {
    const idx = indexFile(file('a.go', 'go', 'func main() {\n}\n'));
    expect(idx.symbols).toEqual([]);
    expect(idx.imports).toEqual([]);
    expect(isIndexableLanguage('go')).toBe(false);
  });

  it('knows which languages it does handle', () => {
    for (const lang of ['typescript', 'javascript', 'python', 'c', 'cpp']) {
      expect(isIndexableLanguage(lang)).toBe(true);
    }
  });
});

describe('indexFile — offsets stay valid in the original content', () => {
  it('slices real (unblanked) text for a body containing a string', () => {
    const f = js('function a() {\n  const secret = "hello world";\n  return secret;\n}\n');
    const idx = indexFile(f);
    // The blanked copy has spaces where "hello world" was; the body must not.
    expect(symbolBody(idx.symbols[0]!, f)).toContain('hello world');
  });

  it('reads the real import specifier, not the blanked one', () => {
    const idx = indexFile(js('import { a } from "./deeply/nested/module";\n'));
    expect(idx.imports[0]!.specifier).toBe('./deeply/nested/module');
  });
});

describe('indexFile — baseClasses (0.3.0-β, for VG-SMELL-030)', () => {
  it('records a JS/TS extends clause', () => {
    const idx = indexFile(js('export class AdminController extends BaseController {\n}\n'));
    const cls = idx.symbols.find((s) => s.kind === 'class');
    expect(cls?.baseClasses).toEqual(['BaseController']);
  });

  it('records a dotted base exactly as written, without resolving it', () => {
    const idx = indexFile(js('class A extends mod.Base {\n}\n'));
    expect(idx.symbols.find((s) => s.kind === 'class')?.baseClasses).toEqual(['mod.Base']);
  });

  it('omits the key entirely when there is no extends clause', () => {
    const idx = indexFile(js('class Plain {\n}\n'));
    const cls = idx.symbols.find((s) => s.kind === 'class');
    // Absent, not `[]`: the same discipline the SARIF properties bag follows.
    // A consumer enumerating keys must be able to tell "no base" from "a base
    // we failed to read", and an empty array reads as the second.
    expect(cls).toBeDefined();
    expect('baseClasses' in cls!).toBe(false);
  });

  it('records every base of a Python multiple-inheritance declaration', () => {
    const idx = indexFile(py('class View(LoginRequiredMixin, DetailView):\n    pass\n'));
    expect(idx.symbols.find((s) => s.kind === 'class')?.baseClasses).toEqual([
      'LoginRequiredMixin',
      'DetailView',
    ]);
  });

  it('drops Python keyword arguments from the base list', () => {
    // `metaclass=ABCMeta` is not a base, and a consumer resolving it against
    // the import graph would either miss or match something unrelated.
    const idx = indexFile(py('class A(Base, metaclass=ABCMeta):\n    pass\n'));
    expect(idx.symbols.find((s) => s.kind === 'class')?.baseClasses).toEqual(['Base']);
  });

  it('omits the key for a Python class with no bases', () => {
    const idx = indexFile(py('class Plain:\n    pass\n'));
    const cls = idx.symbols.find((s) => s.kind === 'class');
    expect(cls).toBeDefined();
    expect('baseClasses' in cls!).toBe(false);
  });
});

describe('indexFile — C definitions with the return type on its own line', () => {
  it('indexes the LLVM/libcxxabi style, where the type sits above the name', () => {
    // ★ FOUND BY A CORPUS SWEEP, NOT BY REVIEW. Before this, every function
    // written this way was missing from `symbols` outright — and because a
    // missing symbol is silent, it surfaced only downstream: VG-AISC-002
    // reported `parse_number` in lucasg/Dependencies as a call to a function
    // "defined nowhere in the project", while pointing at the line of its own
    // definition.
    const idx = indexFile(
      c('const char*\nparse_number(const char* first, const char* last)\n{\n  return first;\n}\n'),
    );
    expect(idx.symbols.map((s) => s.name)).toContain('parse_number');
  });

  it('handles the storage-class form too', () => {
    const idx = indexFile(c('static bool\nparse_thing(int a)\n{\n  return true;\n}\n'));
    expect(idx.symbols.map((s) => s.name)).toContain('parse_thing');
  });

  it('still indexes the same-line form it always did', () => {
    const idx = indexFile(c('int crypto_init(void)\n{\n  return 0;\n}\n'));
    expect(idx.symbols.map((s) => s.name)).toContain('crypto_init');
  });

  it('still refuses a PROTOTYPE, which is the distinction the trailing brace makes', () => {
    // A header declaration must not count as a definition: #20b reasons about
    // "defined but never called", and counting prototypes would make every
    // externally-called function look defined-and-unused.
    const idx = indexFile(c('const char*\nparse_number(const char* first);\n'));
    expect(idx.symbols.map((s) => s.name)).not.toContain('parse_number');
  });
});
