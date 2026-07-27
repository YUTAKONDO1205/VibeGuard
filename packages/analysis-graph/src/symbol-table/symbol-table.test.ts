// Tests for the symbol-table builder.
//
// WHY THE FIXTURES ARE HAND-WRITTEN `StructureIndex` OBJECTS
//
// Not because the structure-indexer is unavailable, but because depending on it
// would make every assertion here a joint claim about two modules. A failure in
// "guard used as middleware in another file is registered" would then have two
// possible causes — the inference or the indexing of `router.get(...)` — and the
// test would stop being a statement about this file. Literal fixtures also let
// the adversarial cases exist at all: there is no source text that produces a
// symbol whose name ends in a stray `\r`, which is precisely the CRLF hazard
// worth pinning.

import { describe, expect, it } from 'vitest';
import type { IndexedSymbol, RouteBinding, StructureIndex, SymbolRole } from '../types.js';
import { buildSymbolTable, guardKey, inferRoles } from './index.js';

function file(filePath: string, parts: Partial<StructureIndex> = {}): StructureIndex {
  return {
    filePath,
    language: 'typescript',
    symbols: [],
    imports: [],
    routes: [],
    exportedNames: [],
    blanked: '',
    ...parts,
  };
}

function sym(name: string, exported = true, parts: Partial<IndexedSymbol> = {}): IndexedSymbol {
  return {
    name,
    kind: 'function',
    filePath: 'unused.ts',
    startLine: 1,
    endLine: 2,
    startColumn: 1,
    bodyStart: 0,
    bodyEnd: 1,
    exported,
    ...parts,
  };
}

function route(middlewareNames: string[], parts: Partial<RouteBinding> = {}): RouteBinding {
  return {
    filePath: 'unused.ts',
    line: 1,
    method: 'get',
    path: '/x',
    middlewareNames,
    ...parts,
  };
}

/** `inferRoles` as a set-membership question, which is how every case reads. */
function hasRole(name: string, role: SymbolRole): boolean {
  return inferRoles(name).includes(role);
}

describe('inferRoles — the vocabularies in §8.2', () => {
  it('infers role/permission/token from the identifiers the spec names', () => {
    expect(hasRole('role', 'role')).toBe(true);
    expect(hasRole('hasRole', 'role')).toBe(true);
    expect(hasRole('userRole', 'role')).toBe(true);
    expect(hasRole('permission', 'permission')).toBe(true);
    expect(hasRole('permissions', 'permission')).toBe(true);
    expect(hasRole('hasPermission', 'permission')).toBe(true);
    expect(hasRole('canDelete', 'permission')).toBe(true);
    expect(hasRole('token', 'token')).toBe(true);
    expect(hasRole('accessToken', 'token')).toBe(true);
    expect(hasRole('jwt', 'token')).toBe(true);
    expect(hasRole('bearerHeader', 'token')).toBe(true);
    // Acronym boundary: `JWTToken` must split into two words, not one blob.
    expect(inferRoles('JWTToken')).toContain('token');
  });

  it('infers user/session/request/response', () => {
    expect(hasRole('user', 'user')).toBe(true);
    expect(hasRole('currentUser', 'user')).toBe(true);
    expect(hasRole('req.user', 'user')).toBe(true);
    expect(hasRole('req.user', 'request')).toBe(true);
    expect(hasRole('username', 'user')).toBe(true);
    expect(hasRole('session', 'session')).toBe(true);
    expect(hasRole('sessionStore', 'session')).toBe(true);
    expect(hasRole('request', 'request')).toBe(true);
    expect(hasRole('req', 'request')).toBe(true);
    expect(hasRole('response', 'response')).toBe(true);
    expect(hasRole('res', 'response')).toBe(true);
  });

  it('infers validator/sanitizer/guard/middleware', () => {
    expect(hasRole('validate', 'validator')).toBe(true);
    expect(hasRole('validator', 'validator')).toBe(true);
    expect(hasRole('isValid', 'validator')).toBe(true);
    expect(hasRole('sanitize', 'sanitizer')).toBe(true);
    expect(hasRole('sanitizeInput', 'sanitizer')).toBe(true);
    expect(hasRole('escapeHtml', 'sanitizer')).toBe(true);
    expect(hasRole('DOMPurify', 'sanitizer')).toBe(true);
    expect(hasRole('guard', 'guard')).toBe(true);
    expect(hasRole('authGuard', 'guard')).toBe(true);
    expect(hasRole('requireAdmin', 'guard')).toBe(true);
    expect(hasRole('ensureLoggedIn', 'guard')).toBe(true);
    expect(hasRole('assertOwner', 'guard')).toBe(true);
    expect(hasRole('checkPermission', 'guard')).toBe(true);
    expect(hasRole('canActivate', 'guard')).toBe(true);
    expect(hasRole('middleware', 'middleware')).toBe(true);
    expect(hasRole('mw', 'middleware')).toBe(true);
    expect(hasRole('authInterceptor', 'middleware')).toBe(true);
  });

  it('handles snake_case, SCREAMING_CASE and dotted paths the same as camelCase', () => {
    expect(hasRole('has_role', 'role')).toBe(true);
    expect(hasRole('ACCESS_TOKEN', 'token')).toBe(true);
    expect(hasRole('user_can_delete', 'permission')).toBe(true);
    expect(hasRole('ctx.session.id', 'session')).toBe(true);
  });

  it('deduplicates and emits roles in the canonical SymbolRole order', () => {
    // `user` appears twice and `role` once; the output must be one of each, in
    // declaration order (role before user), not insertion or discovery order.
    expect(inferRoles('userRoleForUser')).toEqual(['role', 'user']);
    expect(inferRoles('requireUserPermission')).toEqual(['permission', 'user', 'guard']);
  });
});

describe('inferRoles — adversarial substring cases', () => {
  it('does not read words that are only substrings of other words', () => {
    // The whole reason for camelCase-aware segmentation.
    expect(inferRoles('cancel')).toEqual([]);
    expect(hasRole('cancelOrder', 'permission')).toBe(false);
    expect(inferRoles('candidate')).toEqual([]);
    expect(inferRoles('canvas')).toEqual([]);
    expect(inferRoles('tokenizer')).toEqual([]);
    expect(inferRoles('tokenize')).toEqual([]);
    expect(inferRoles('roleplay')).toEqual([]);
    expect(inferRoles('controller')).toEqual([]);
    expect(inferRoles('resource')).toEqual([]);
    expect(inferRoles('result')).toEqual([]);
    expect(inferRoles('required')).toEqual([]);
    expect(inferRoles('invalid')).toEqual([]);
    expect(inferRoles('author')).toEqual([]);
  });

  it('excludes userAgent from the user role, and says why in the source', () => {
    // DECISION: `userAgent` is an attacker-controlled request header, not the
    // authenticated principal. Treating it as `user` would be the seed of a real
    // authorization confusion, so the adjacent pair user+agent is suppressed.
    expect(hasRole('userAgent', 'user')).toBe(false);
    expect(hasRole('USER_AGENT', 'user')).toBe(false);
    expect(hasRole('user_agent', 'user')).toBe(false);
    // Narrow, not blanket: a second, unqualified `user` still counts.
    expect(hasRole('userAgentOfCurrentUser', 'user')).toBe(true);
  });

  it('requires can/is/has to be followed by something to mean anything', () => {
    // `can` alone is not a permission question; `canEdit` is.
    expect(hasRole('can', 'permission')).toBe(false);
    expect(hasRole('canEdit', 'permission')).toBe(true);
    // Predicate heads need a SECURITY word before they are a checkpoint.
    expect(hasRole('isEmpty', 'guard')).toBe(false);
    expect(hasRole('hasChildren', 'guard')).toBe(false);
    expect(hasRole('isAdmin', 'guard')).toBe(true);
    expect(hasRole('isAuthenticated', 'guard')).toBe(true);
  });

  it('pins the DELIBERATE over-admission of imperative heads', () => {
    // `checkStock` is not authorization anything, and it is admitted anyway.
    // Documented in `isGuardShapedName`: an over-admitted guard costs a missed
    // finding, a missed guard costs a finding fired on well-factored code, and
    // this repository's hard `samples/safe == 0` gate makes the second error the
    // expensive one. Pinned here so the trade cannot be silently reversed.
    expect(hasRole('checkStock', 'guard')).toBe(true);
    expect(hasRole('ensureDirectory', 'guard')).toBe(true);
  });

  it('does not treat a middleware word alone as a guard', () => {
    expect(hasRole('loggingMiddleware', 'guard')).toBe(false);
    expect(hasRole('loggingMiddleware', 'middleware')).toBe(true);
    expect(hasRole('authMiddleware', 'guard')).toBe(true);
  });

  it('returns [] rather than throwing for degenerate names', () => {
    expect(inferRoles('')).toEqual([]);
    expect(inferRoles('   ')).toEqual([]);
    expect(inferRoles('_')).toEqual([]);
    expect(inferRoles('<anonymous@12>')).toEqual([]);
    // Past NAME_LENGTH_CAP the tail is not read; the head still is.
    expect(inferRoles(`accessToken_${'x'.repeat(500)}`)).toContain('token');
    expect(inferRoles(`${'x'.repeat(500)}_accessToken`)).toEqual([]);
    // A digit run is its own word, so a disambiguating suffix does not hide one.
    expect(inferRoles('token1')).toEqual(['token']);
    expect(inferRoles('sha256Hash')).toEqual([]);
  });
});

describe('buildSymbolTable — roles map', () => {
  it('returns an empty table for an empty project', () => {
    const table = buildSymbolTable([]);
    expect(table.roles.size).toBe(0);
    expect(table.guards.size).toBe(0);
  });

  it('collects names from symbols, imports, exports, routes and inline handlers', () => {
    const table = buildSymbolTable([
      file('src/a.ts', {
        symbols: [sym('validateBody')],
        imports: [{ fromFile: 'src/a.ts', specifier: './auth', names: ['accessToken'], line: 1, syntax: 'esm' }],
        exportedNames: ['sessionStore'],
        routes: [
          route(['requireAdmin'], {
            handlerName: 'listUsers',
            inlineHandler: sym('<anonymous@9>', false),
          }),
        ],
      }),
    ]);

    expect(table.roles.get('validateBody')).toEqual(['validator']);
    expect(table.roles.get('accessToken')).toEqual(['token']);
    expect(table.roles.get('sessionStore')).toEqual(['session']);
    expect(table.roles.get('requireAdmin')).toEqual(['guard']);
    expect(table.roles.get('listUsers')).toEqual(['user']);
    // The synthetic name of an anonymous handler infers nothing, so it is absent.
    expect(table.roles.has('<anonymous@9>')).toBe(false);
  });

  it('never stores an empty roles array', () => {
    const table = buildSymbolTable([
      file('src/util.ts', {
        symbols: [sym('formatDuration'), sym('i'), sym('data'), sym('requireAdmin')],
        exportedNames: ['formatDuration'],
      }),
    ]);
    expect(table.roles.has('formatDuration')).toBe(false);
    for (const [name, roles] of table.roles) {
      expect(roles.length, `roles for ${name}`).toBeGreaterThan(0);
    }
  });

  it('is deterministic across runs on the same input', () => {
    const build = (): StructureIndex[] => [
      file('src/auth/guards.ts', { symbols: [sym('requireAdmin'), sym('isOwner')] }),
      file('src/routes.ts', { routes: [route(['requireAdmin'])] }),
    ];
    const first = buildSymbolTable(build());
    const second = buildSymbolTable(build());
    expect([...first.roles.keys()]).toEqual([...second.roles.keys()]);
    expect([...first.guards]).toEqual([...second.guards]);
  });
});

describe('buildSymbolTable — guards', () => {
  it('registers a guard defined in one file and used as middleware in another', () => {
    const table = buildSymbolTable([
      file('src/auth/guards.ts', { symbols: [sym('requireAdmin')], exportedNames: ['requireAdmin'] }),
      file('src/routes/admin.ts', {
        imports: [
          { fromFile: 'src/routes/admin.ts', specifier: '../auth/guards', names: ['requireAdmin'], line: 1, syntax: 'esm' },
        ],
        routes: [route(['requireAdmin'], { handlerName: 'adminHandler' })],
      }),
    ]);

    expect(table.guards.has(guardKey('src/auth/guards.ts', 'requireAdmin'))).toBe(true);
    // Registered at the using file too: a consumer standing at the route holds
    // the name as it is spelled there.
    expect(table.guards.has(guardKey('src/routes/admin.ts', 'requireAdmin'))).toBe(true);
    expect(table.guards.has(guardKey('src/routes/admin.ts', 'adminHandler'))).toBe(false);
  });

  it('accepts route-middleware usage as evidence even when the name says nothing', () => {
    // The strongest signal: observed behaviour, not a naming guess. `mw7` would
    // be rejected by every lexical clause in the module.
    expect(inferRoles('mw7')).toEqual(['middleware']);
    const table = buildSymbolTable([
      file('src/plumbing.ts', { symbols: [sym('attachTiming')] }),
      file('src/routes.ts', { routes: [route(['attachTiming'])] }),
    ]);
    expect(isGuardShapeOnly('attachTiming')).toBe(false);
    expect(table.guards.has(guardKey('src/plumbing.ts', 'attachTiming'))).toBe(true);
    expect(table.guards.has(guardKey('src/routes.ts', 'attachTiming'))).toBe(true);
  });

  it('registers guard-shaped names with no route evidence at all', () => {
    const table = buildSymbolTable([
      file('src/service.ts', {
        symbols: [sym('ensureTenantAccess'), sym('hasPermission'), sym('formatDuration', true)],
      }),
    ]);
    expect(table.guards.has(guardKey('src/service.ts', 'ensureTenantAccess'))).toBe(true);
    expect(table.guards.has(guardKey('src/service.ts', 'hasPermission'))).toBe(true);
    expect(table.guards.has(guardKey('src/service.ts', 'formatDuration'))).toBe(false);
  });

  it('treats export from a security-named directory as evidence, by path WORD', () => {
    const table = buildSymbolTable([
      file('src/middleware/rateLimit.ts', {
        symbols: [sym('rateLimit', true), sym('bucketFor', false)],
        exportedNames: ['rateLimit'],
      }),
      // `authors` is not `auth`: the path rule matches whole tokenised words.
      file('src/authors/list.ts', { symbols: [sym('listAuthors', true)], exportedNames: ['listAuthors'] }),
    ]);

    expect(table.guards.has(guardKey('src/middleware/rateLimit.ts', 'rateLimit'))).toBe(true);
    // Non-exported helper in the same file: placement alone is not enough.
    expect(table.guards.has(guardKey('src/middleware/rateLimit.ts', 'bucketFor'))).toBe(false);
    expect(table.guards.has(guardKey('src/authors/list.ts', 'listAuthors'))).toBe(false);
  });

  it('does not leak a guard key into an unrelated file that never mentions the name', () => {
    const table = buildSymbolTable([
      file('src/auth/guards.ts', { symbols: [sym('requireAdmin')] }),
      file('src/unrelated.ts', { symbols: [sym('renderPage')] }),
    ]);
    expect(table.guards.has(guardKey('src/unrelated.ts', 'requireAdmin'))).toBe(false);
  });
});

describe('buildSymbolTable — CRLF and key hygiene', () => {
  it('normalises a carriage return welded to an identifier by \\n-only splitting', () => {
    // A producer that split a CRLF file on \n leaves `\r` on the last token of
    // every line. Without normalisation the table looks populated and every
    // consumer lookup misses.
    const table = buildSymbolTable([
      file('src/auth/guards.ts', {
        symbols: [sym('requireAdmin\r')],
        exportedNames: ['requireAdmin\r'],
        blanked: 'export function requireAdmin() {}\r\n',
      }),
      file('src/routes.ts', { routes: [route(['requireAdmin\r'])] }),
    ]);

    expect(table.roles.has('requireAdmin')).toBe(true);
    expect(table.roles.has('requireAdmin\r')).toBe(false);
    expect(table.guards.has(guardKey('src/auth/guards.ts', 'requireAdmin'))).toBe(true);
    expect([...table.guards].some((k) => k.includes('\r'))).toBe(false);
  });

  it('strips the key separator out of names so a key cannot be forged', () => {
    const nul = String.fromCharCode(0);
    expect(guardKey('a.ts', `admin${nul}`)).toBe(guardKey('a.ts', 'admin'));
    const table = buildSymbolTable([file('a.ts', { symbols: [sym(`requireAdmin${nul}b.ts`)] })]);
    expect(table.guards.has(guardKey('a.ts', 'requireAdminb.ts'))).toBe(true);
    expect(table.guards.has(guardKey('b.ts', 'requireAdmin'))).toBe(false);
  });

  it('builds guard keys as filePath + NUL + name', () => {
    expect(guardKey('src/a.ts', 'requireAdmin')).toBe(`src/a.ts${String.fromCharCode(0)}requireAdmin`);
  });
});

/**
 * Whether the name alone (no project context) would be judged guard-shaped.
 *
 * The module keeps `isGuardShapedName` private — it is an implementation detail
 * of two public functions — so the test asks the same question through the
 * `guard` role, which is defined to be exactly that shape. Keeping this in one
 * helper means the coupling is stated once rather than assumed in every case.
 */
function isGuardShapeOnly(name: string): boolean {
  return inferRoles(name).includes('guard');
}
