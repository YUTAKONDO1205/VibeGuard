// Tests for the two 0.3.x additions to `structure-indexer`: routes declared by
// FILE PATH (the Next.js conventions) and symbols bound to a WRAPPER CALL.
//
// ★ WHY THESE ARE A SEPARATE FILE FROM `structure-indexer.test.ts`.
//
// Both additions exist for one measured reason, and the reason is the thing that
// has to stay readable next to the assertions:
// `design-smells-crossfile/index.ts` records that VG-SMELL-013 reached its
// decision point ZERO times in 1,000 real repositories, and that neither arm
// failed on a threshold — Next.js `pages/api` endpoints emit no route
// registration, so the guard premise could not form, and their
// `const handler = withX(…, async (req,res) => {…})` arrows were not symbols, so
// the handler premise could not form either. Of 569 authorization-shaped
// decisions in that corpus, exactly ONE lay inside an indexed handler body.
//
// So the tests below are not "does the regex work". They are the two structural
// claims that measurement demanded, plus the false-positive controls that decide
// whether the widening is safe — because the population these feed
// (VG-SMELL-010 / 011 / 013 / 021) is one whose false positives land on
// well-factored code.
//
// ★ EVERY POSITIVE ASSERTS AN EXACT VALUE, NEVER A NON-EMPTY ONE.
//
// `expect(routes.length).toBeGreaterThan(0)` passes on a route with the wrong
// path, the wrong method, and no middleware — which is to say it passes on a
// route that would give VG-SMELL-013 a premise it has not earned. The spans are
// asserted as exact line numbers for the same reason: a symbol whose body span
// is a guess is worse than a missing symbol, and the guess is the specific
// failure `peelHandlerExpression` refuses a concise arrow body to avoid.

import { describe, expect, it } from 'vitest';
import { fileRouteConvention, indexFile, symbolBody } from './index.js';
import type { RouteBinding, SourceFile } from '../types.js';

const file = (filePath: string, content: string): SourceFile => ({
  filePath,
  language: filePath.endsWith('.js') || filePath.endsWith('.jsx') ? 'javascript' : 'typescript',
  content,
  lines: content.split('\n'),
});

/** The single route, asserted single first so a failure names the count. */
function onlyRoute(routes: RouteBinding[]): RouteBinding {
  expect(routes).toHaveLength(1);
  return routes[0]!;
}

// ---------------------------------------------------------------------------
// `fileRouteConvention` — the path predicate, alone
// ---------------------------------------------------------------------------

describe('fileRouteConvention — which paths are routes by convention', () => {
  it('recognises a pages/api endpoint and derives its URL path', () => {
    expect(fileRouteConvention('pages/api/users.ts')).toEqual({
      kind: 'pages-api',
      routePath: '/api/users',
    });
  });

  it('keeps a dynamic segment verbatim rather than resolving it', () => {
    // `[id]` is not turned into `:id`. The path is a DERIVATION for a consumer
    // that word-matches and prints it, not a claim about what Next.js serves.
    expect(fileRouteConvention('src/pages/api/users/[id].ts')).toEqual({
      kind: 'pages-api',
      routePath: '/api/users/[id]',
    });
  });

  it('maps an index file to its directory, not to `/index`', () => {
    expect(fileRouteConvention('pages/api/index.ts')).toEqual({
      kind: 'pages-api',
      routePath: '/api',
    });
    expect(fileRouteConvention('pages/api/teams/index.js')).toEqual({
      kind: 'pages-api',
      routePath: '/api/teams',
    });
  });

  it('recognises an App Router route handler', () => {
    expect(fileRouteConvention('app/api/users/route.ts')).toEqual({
      kind: 'app-route',
      routePath: '/api/users',
    });
  });

  it('drops a route GROUP, which contributes no URL segment', () => {
    expect(fileRouteConvention('src/app/(marketing)/contact/route.ts')).toEqual({
      kind: 'app-route',
      routePath: '/contact',
    });
  });

  it('maps the root route handler to `/`', () => {
    expect(fileRouteConvention('app/route.ts')).toEqual({ kind: 'app-route', routePath: '/' });
  });

  // ── FALSE-POSITIVE CONTROLS ──────────────────────────────────────────────
  //
  // Each of these is one character away from a match, and each names the reason
  // a looser predicate would be wrong rather than merely noisy.

  it('refuses a PAGE under pages/, which is not an endpoint', () => {
    // The whole UI of every Next.js project lives here. Admitting it would put
    // every React component into the route-handler population.
    expect(fileRouteConvention('pages/index.tsx')).toBeNull();
    expect(fileRouteConvention('pages/dashboard/settings.tsx')).toBeNull();
  });

  it('refuses a file merely NAMED api', () => {
    // `api` in a file name is an HTTP client, not an endpoint. A substring test
    // would turn every such wrapper in every project into a registration.
    expect(fileRouteConvention('lib/api.ts')).toBeNull();
    expect(fileRouteConvention('src/services/api/client.ts')).toBeNull();
  });

  it('refuses `route.ts` that is not under an `app` directory', () => {
    expect(fileRouteConvention('src/route.ts')).toBeNull();
    expect(fileRouteConvention('lib/router/route.ts')).toBeNull();
  });

  it('refuses an App Router PAGE, which renders rather than serving a method', () => {
    expect(fileRouteConvention('app/dashboard/page.tsx')).toBeNull();
    expect(fileRouteConvention('app/layout.tsx')).toBeNull();
  });

  it('refuses Next.js’s own underscore-prefixed reserved files', () => {
    expect(fileRouteConvention('pages/api/_middleware.ts')).toBeNull();
    expect(fileRouteConvention('pages/_app.tsx')).toBeNull();
  });

  it('refuses a declaration file, which has types and no handler', () => {
    expect(fileRouteConvention('pages/api/users.d.ts')).toBeNull();
    expect(fileRouteConvention('app/api/users/route.d.ts')).toBeNull();
  });

  it('refuses a non-source extension under a matching directory', () => {
    expect(fileRouteConvention('pages/api/users.json')).toBeNull();
    expect(fileRouteConvention('app/api/users/route.css')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// `pages/api` — the arm that had no registration to read
// ---------------------------------------------------------------------------

describe('indexFile — pages/api endpoints become routes', () => {
  it('registers a plain default-exported handler', () => {
    const f = file(
      'pages/api/users.ts',
      'export default async function handler(req, res) {\n  res.status(200).json([]);\n}\n',
    );
    const idx = indexFile(f);
    const route = onlyRoute(idx.routes);
    // `*`, not a verb: one `pages/api` handler serves every method and switches
    // on `req.method` internally, so any verb here would be an invented fact.
    expect(route.method).toBe('*');
    expect(route.path).toBe('/api/users');
    expect(route.handlerName).toBe('handler');
    expect(route.middlewareNames).toEqual([]);
    expect(idx.symbols.find((s) => s.name === 'handler')!.kind).toBe('route-handler');
  });

  it('★ puts the WRAPPER in the middleware position — the premise 013 needs', () => {
    // `export default withAnyRole(['admin'], handler)` is the same delegation
    // `router.get('/x', requireAdmin, handler)` expresses, written by a framework
    // that has no registration call. It has to land in the same field or
    // VG-SMELL-013's condition (a) can never form on a Next.js project.
    const f = file(
      'pages/api/reports.ts',
      "import { withAnyRole } from '../../lib/authz';\n" +
        "const handler = withAnyRole(['admin'], async (req, res) => {\n" +
        '  res.status(200).json([]);\n' +
        '});\n' +
        'export default handler;\n',
    );
    const idx = indexFile(f);
    const route = onlyRoute(idx.routes);
    expect(route.middlewareNames).toEqual(['withAnyRole']);
    expect(route.handlerName).toBe('handler');
    expect(route.path).toBe('/api/reports');
  });

  it('★ gives that wrapped handler a body span a rule can search', () => {
    // The other half of the 013 zero: the arrow was not a symbol at all, so
    // "is the authorization check written INSIDE this handler" had nothing to
    // read. The span is asserted exactly — a guessed span is worse than none.
    const f = file(
      'pages/api/reports.ts',
      "import { withSession } from '../../lib/session';\n" +
        'const handler = withSession(async (req, res) => {\n' +
        "  if (req.session.user.role !== 'admin') {\n" +
        "    return res.status(403).json({ error: 'forbidden' });\n" +
        '  }\n' +
        '  res.status(200).json([]);\n' +
        '});\n' +
        'export default handler;\n',
    );
    const idx = indexFile(f);
    const handler = idx.symbols.find((s) => s.name === 'handler')!;
    expect(handler.kind).toBe('route-handler');
    expect(handler.startLine).toBe(2);
    expect(handler.endLine).toBe(7);
    expect(symbolBody(handler, f)).toContain("req.session.user.role !== 'admin'");
    // And the body stops at the arrow's own closing brace, so the export
    // statement after it is not attributed to the handler.
    expect(symbolBody(handler, f)).not.toContain('export default');
  });

  it('peels a stack of wrappers, outermost first', () => {
    const f = file(
      'pages/api/multi.ts',
      'const base = async (req, res) => {\n  res.end();\n};\n' +
        'export default withSentry(withAuth(base));\n',
    );
    const route = onlyRoute(indexFile(f).routes);
    expect(route.middlewareNames).toEqual(['withSentry', 'withAuth']);
    expect(route.handlerName).toBe('base');
  });

  it('records an anonymous inline default export as a route-handler symbol', () => {
    const f = file(
      'pages/api/index.ts',
      'export default withAuth(async (req, res) => {\n  res.status(200).json([]);\n});\n',
    );
    const idx = indexFile(f);
    const route = onlyRoute(idx.routes);
    expect(route.middlewareNames).toEqual(['withAuth']);
    expect(route.handlerName).toBe('<anonymous@1>');
    expect(route.inlineHandler!.kind).toBe('route-handler');
    expect(symbolBody(route.inlineHandler!, f)).toContain('res.status(200)');
  });

  // ── FALSE-POSITIVE CONTROLS, at the indexer level ────────────────────────

  it('does not register a page component under pages/', () => {
    const idx = indexFile(
      file('pages/index.tsx', 'export default function Home() {\n  return null;\n}\n'),
    );
    expect(idx.routes).toEqual([]);
    expect(idx.symbols.find((s) => s.name === 'Home')!.kind).toBe('function');
  });

  it('does not register a client module merely named api', () => {
    const idx = indexFile(
      file('lib/api.ts', 'export default function apiClient(path) {\n  return fetch(path);\n}\n'),
    );
    expect(idx.routes).toEqual([]);
    expect(idx.symbols.find((s) => s.name === 'apiClient')!.kind).toBe('function');
  });

  it('does not register a pages/api file with no default export', () => {
    // The path predicate is necessary and NOT sufficient. A helper module that
    // happens to sit under `pages/api/` exports no handler and is not one.
    const idx = indexFile(
      file('pages/api/shared.ts', 'export function parseRange(q) {\n  return q;\n}\n'),
    );
    expect(idx.routes).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// App Router — `app/**/route.ts`
// ---------------------------------------------------------------------------

describe('indexFile — App Router route handlers become routes', () => {
  it('registers one route per HTTP-method export, with the real verb', () => {
    // Unlike `pages/api`, the method IS known here: it is the export's name. A
    // `*` would throw away a fact the file states outright.
    const idx = indexFile(
      file(
        'app/api/users/route.ts',
        'export async function GET(req) {\n  return Response.json([]);\n}\n' +
          'export async function DELETE(req) {\n  return Response.json([]);\n}\n',
      ),
    );
    expect(idx.routes.map((r) => [r.method, r.path, r.handlerName])).toEqual([
      ['get', '/api/users', 'GET'],
      ['delete', '/api/users', 'DELETE'],
    ]);
    expect(idx.routes.every((r) => r.middlewareNames.length === 0)).toBe(true);
  });

  it('reads the wrapper off `export const POST = withAuth(handler)`', () => {
    const idx = indexFile(
      file(
        'app/api/orders/route.ts',
        'async function create(req) {\n  return Response.json(1);\n}\n' +
          'export const POST = withAuth(create);\n',
      ),
    );
    const route = onlyRoute(idx.routes);
    expect(route.method).toBe('post');
    expect(route.middlewareNames).toEqual(['withAuth']);
    // The alias is followed: the body belongs to `create`, not to `POST`.
    expect(route.handlerName).toBe('create');
    expect(idx.symbols.find((s) => s.name === 'create')!.kind).toBe('route-handler');
  });

  it('reads the wrapper off `export const GET = withAuth(async () => {…})`', () => {
    const f = file(
      'app/api/orders/route.ts',
      'export const GET = withAuth(async (req) => {\n  return Response.json(1);\n});\n',
    );
    const idx = indexFile(f);
    const route = onlyRoute(idx.routes);
    expect(route.method).toBe('get');
    expect(route.middlewareNames).toEqual(['withAuth']);
    expect(route.handlerName).toBe('GET');
    expect(symbolBody(idx.symbols.find((s) => s.name === 'GET')!, f)).toContain('Response.json(1)');
  });

  it('refuses a lowercase export, which is a helper and not a handler', () => {
    // Next.js matches the UPPERCASE name. Admitting `export const post = …`
    // would turn an ordinary binding into a route registration.
    const idx = indexFile(
      file('app/api/x/route.ts', 'export const post = async (req) => {\n  return 1;\n};\n'),
    );
    expect(idx.routes).toEqual([]);
  });

  it('refuses an UNEXPORTED method-named function', () => {
    const idx = indexFile(
      file('app/api/x/route.ts', 'function GET(req) {\n  return 1;\n}\n'),
    );
    expect(idx.routes).toEqual([]);
  });

  it('refuses `route.ts` under an `app` directory that exports no method', () => {
    // The path predicate is necessary and NOT sufficient: `app/router/route.ts`
    // in a non-Next project is a module about routing, not a route.
    const idx = indexFile(
      file('app/router/route.ts', 'export function createRouter() {\n  return null;\n}\n'),
    );
    expect(idx.routes).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Wrapped bindings in ORDINARY files — the population question
// ---------------------------------------------------------------------------

describe('indexFile — `const X = wrapper(…, fn)` bindings', () => {
  it('indexes the binding with the wrapped function’s exact body span', () => {
    const f = file(
      'src/queue.ts',
      'const work = withRetry(3, async (job) => {\n  await run(job);\n  return job.id;\n});\n',
    );
    const idx = indexFile(f);
    const work = idx.symbols.find((s) => s.name === 'work')!;
    expect(work.startLine).toBe(1);
    expect(work.endLine).toBe(4);
    expect(work.declaredKind).toBe('function');
    expect(symbolBody(work, f)).toContain('await run(job);');
  });

  it('does not duplicate a plain arrow binding `JS_HEAD` already indexes', () => {
    // `const h = async (req,res) => {…}` reaches the new pattern too (`async`
    // matches its `callee` group). Requiring at least one WRAPPER is what
    // refuses it — a shape test rather than a keyword blocklist.
    const idx = indexFile(
      file('src/plain.ts', 'const h = async (req, res) => {\n  res.end();\n};\n'),
    );
    expect(idx.symbols.map((s) => s.name)).toEqual(['h']);
  });

  it('★ refuses a CONCISE arrow body rather than guessing a span', () => {
    // `extractBlockAfter` takes the first `{` within its head gap. Given
    // `(i) => ({ id: i.id })` that brace is an OBJECT LITERAL, and given
    // `(x) => f(x)` it is whatever block happens to come next in the file. Both
    // produce a symbol whose span contains code it does not contain, which is
    // the one way this addition could fabricate evidence.
    const objectLiteral = indexFile(
      file('src/rows.ts', 'const rows = items.map((i) => ({ id: i.id, name: i.name }));\n'),
    );
    expect(objectLiteral.symbols.map((s) => s.name)).toEqual([]);

    const expressionBody = indexFile(
      file(
        'src/mask.ts',
        'const quoted = text.replace(RE, (m) => mask(m));\n' +
          'function unrelated() {\n  return 1;\n}\n',
      ),
    );
    // `unrelated`'s body is the next `{` in the file. It must not become
    // `quoted`'s.
    expect(expressionBody.symbols.map((s) => s.name)).toEqual(['unrelated']);
  });

  it('indexes a wrapped `function` expression as well as an arrow', () => {
    const f = file(
      'src/legacy.js',
      'const boot = once(function () {\n  start();\n});\n',
    );
    const idx = indexFile(f);
    const boot = idx.symbols.find((s) => s.name === 'boot')!;
    expect(boot.endLine).toBe(3);
    expect(symbolBody(boot, f)).toContain('start();');
  });

  it('keeps the syntactic name when the wrapped function has one', () => {
    // `const h = wrap(function inner() {…})` binds two names to one body.
    // `JS_HEAD` already indexes `inner`; recording `h` as a second symbol with
    // the same span would let a rule count one function twice.
    const idx = indexFile(
      file('src/named.ts', 'const h = wrap(function inner() {\n  return 1;\n});\n'),
    );
    expect(idx.symbols.map((s) => s.name)).toEqual(['inner']);
  });

  it('marks an exported wrapped binding as exported', () => {
    const idx = indexFile(
      file('src/e.ts', 'export const run = withLock(async () => {\n  await go();\n});\n'),
    );
    expect(idx.symbols.find((s) => s.name === 'run')!.exported).toBe(true);
    expect(idx.exportedNames).toContain('run');
  });

  it('reads a wrapper call formatted one argument per line', () => {
    const f = file(
      'pages/api/split.ts',
      'const handler = withAnyRole(\n' +
        "  ['admin'],\n" +
        '  async (req, res) => {\n' +
        '    res.end();\n' +
        '  },\n' +
        ');\n' +
        'export default handler;\n',
    );
    const route = onlyRoute(indexFile(f).routes);
    expect(route.middlewareNames).toEqual(['withAnyRole']);
    expect(route.handlerName).toBe('handler');
  });

  it('leaves a call with no function argument alone', () => {
    const idx = indexFile(file('src/cfg.ts', 'const cfg = load("a", "b");\n'));
    expect(idx.symbols).toEqual([]);
    expect(idx.routes).toEqual([]);
  });
});
