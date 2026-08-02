// End-to-end tests for VG-SMELL-052, run over the real fixture corpus on disk.
//
// Deliberately NOT unit tests over hand-built `ProjectIndex` objects, for the
// reason written at the top of `scattered-authorization.test.ts`: the risk in a
// cross-file rule is never its own arithmetic, it is whether the indexer, the
// graph, the route linker and the taint pass together produce the facts it
// assumes. A hand-built index tests the rule against the author's belief about
// those facts.
//
// ★ WHY EVERY NEGATIVE CARRIES PRECONDITION ASSERTIONS
//
// `expect(findings).toEqual([])` is worth nothing on its own. It passes when the
// rule declined the directory for the reason the directory was built to test,
// and it passes just as green when the fixture never satisfied any precondition
// at all — a typo in a symbol name, a route the indexer did not recognise, a
// taint flow that silently stopped being found. A corpus of six negatives can go
// entirely vacuous without a single test turning red.
//
// So each negative below asserts, from the same on-disk fixture, that every
// condition EXCEPT the one it isolates is satisfied: the symbol exists and its
// name is in the vocabulary, the routing evidence is present, the taint flow is
// present. Silence is then attributable. Where a negative works by removing a
// condition (`neg-no-untrusted-input`, `neg-all-routes-guarded`) the test asserts
// that this specific condition is absent and the others hold, which is the same
// discipline stated from the other side.
//
// The rule is NOT in `crossFileRules` yet — registration is a separate task — so
// these run it directly against a built index rather than through
// `analyzeProject`. Everything upstream of the rule is the real pipeline.

import { describe, expect, it } from 'vitest';
import { resolve } from 'node:path';
import { createBudget } from '../budget.js';
import { buildProjectIndex, collectProjectFiles } from '../project.js';
import { analyzeProjectTaint, type TaintFlow } from '../taint/index.js';
import type { CrossFileFinding, ProjectIndex, StructureIndex } from '../types.js';
import {
  classifyBoilerplateName,
  generatedBoilerplateUnintegrated,
} from './generated-boilerplate-unintegrated.js';

const REPO_ROOT = resolve(__dirname, '../../../..');
const sample = (name: string): string => resolve(REPO_ROOT, 'samples', name);

const indexOf = async (dir: string): Promise<ProjectIndex> => {
  const budget = createBudget({});
  const files = await collectProjectFiles(dir, budget);
  return buildProjectIndex(dir, files, budget);
};

const smellsIn = async (dir: string): Promise<CrossFileFinding[]> => {
  const budget = createBudget({});
  const files = await collectProjectFiles(dir, budget);
  const project = buildProjectIndex(dir, files, budget);
  return generatedBoilerplateUnintegrated.analyze({ project, budget });
};

/** Structures in the languages the rule accepts, in the order the rule sees them. */
const jsStructures = (project: ProjectIndex): StructureIndex[] =>
  [...project.structures.keys()]
    .sort()
    .map((k) => project.structures.get(k)!)
    .filter((s) => generatedBoilerplateUnintegrated.languages.includes(s.language));

/**
 * The rule's taint precondition, recomputed independently in the test.
 *
 * Deliberately re-derived here rather than exported from the rule: a test that
 * calls the rule's own helper to check the rule's own precondition proves only
 * that the helper is deterministic. This walks `kind === 'route-handler'` from
 * the index and the flows from `analyzeProjectTaint`, which is what the rule
 * claims to be doing.
 */
const routeHandlerFlowsOf = (project: ProjectIndex): TaintFlow[] => {
  const structures = jsStructures(project);
  const handlers = new Map<string, Set<string>>();
  for (const structure of structures) {
    for (const symbol of structure.symbols) {
      if (symbol.kind !== 'route-handler') continue;
      const names = handlers.get(structure.filePath) ?? new Set<string>();
      names.add(symbol.name);
      handlers.set(structure.filePath, names);
    }
  }
  return analyzeProjectTaint(structures, project.files).filter(
    (f) => handlers.get(f.filePath)?.has(f.symbolName) ?? false,
  );
};

/**
 * Registrations with an endpoint and no guard — the rule's "empty slot" evidence.
 *
 * Re-derived from the index rather than imported, same reasoning as
 * `routeHandlerFlowsOf`. The path test is not optional: without it,
 * `req.get('authorization')` inside a guard body counts as an unguarded
 * endpoint, which is how this helper's first draft made
 * `neg-all-routes-guarded` look like it had one.
 */
const openRegistrationsOf = (project: ProjectIndex): { filePath: string; line: number }[] =>
  jsStructures(project).flatMap((s) =>
    s.routes
      .filter(
        (r) =>
          r.method !== 'use' &&
          r.handlerName !== undefined &&
          r.path !== undefined &&
          /^(?:\/|\*$)/.test(r.path) &&
          r.middlewareNames.length === 0,
      )
      .map((r) => ({ filePath: s.filePath, line: r.line })),
  );

/** Every symbol in the project whose name reads as generated security boilerplate. */
const boilerplateSymbolsOf = (project: ProjectIndex): string[] =>
  jsStructures(project)
    .flatMap((s) => s.symbols.map((sym) => sym.name))
    .filter((name) => classifyBoilerplateName(name) !== undefined)
    .sort();

/**
 * Files OTHER than `definedIn` whose blanked text writes `name`.
 *
 * The reference condition, recomputed in the test for the same reason as the
 * other two preconditions. Every negative that is quiet for a wiring reason has
 * to show that the reference scan is not what silenced it, or the directory
 * proves nothing about the condition it was built for.
 */
const filesNaming = (project: ProjectIndex, name: string, definedIn: string): string[] =>
  jsStructures(project)
    .filter((s) => s.filePath !== definedIn)
    .filter((s) => new RegExp(String.raw`\b${name}\b`).test(s.blanked))
    .map((s) => s.filePath)
    .sort();

// ---------------------------------------------------------------------------
// The vocabulary
// ---------------------------------------------------------------------------

describe('VG-SMELL-052 — the vocabulary', () => {
  it('admits the shapes AI actually generates', () => {
    expect(classifyBoilerplateName('validateInput')).toBe('validator');
    expect(classifyBoilerplateName('validateRequestBody')).toBe('validator');
    expect(classifyBoilerplateName('escapeHtml')).toBe('validator');
    expect(classifyBoilerplateName('sanitizeUserInput')).toBe('sanitizer');
    expect(classifyBoilerplateName('sanitize_search_term')).toBe('sanitizer');
    expect(classifyBoilerplateName('requireAuth')).toBe('authentication');
    expect(classifyBoilerplateName('verifyToken')).toBe('authentication');
    expect(classifyBoilerplateName('csrfProtection')).toBe('authentication');
    expect(classifyBoilerplateName('checkPermission')).toBe('authorization');
    expect(classifyBoilerplateName('requireAdmin')).toBe('authorization');
    expect(classifyBoilerplateName('hasAccess')).toBe('authorization');
    expect(classifyBoilerplateName('authorize')).toBe('authorization');
  });

  it('refuses the names the symbol table deliberately over-admits as guards', () => {
    // `isGuardShapedName` in ../symbol-table/index.ts admits both of these on the
    // imperative head alone and documents that the over-admission is safe THERE
    // because it can only suppress a VG-SMELL-010 finding. Here it would invent
    // one, so the same names must be refused. This test is the seam between the
    // two rules' opposite error directions.
    expect(classifyBoilerplateName('checkStock')).toBeUndefined();
    expect(classifyBoilerplateName('ensureDirectory')).toBeUndefined();
    expect(classifyBoilerplateName('requireConfig')).toBeUndefined();
  });

  it('refuses substring look-alikes', () => {
    // Word matching, not substring matching: each of these contains a
    // vocabulary entry as a prefix or an infix and is not the thing.
    expect(classifyBoilerplateName('escapeRegExp')).toBeUndefined();
    expect(classifyBoilerplateName('tokenizer')).toBeUndefined();
    expect(classifyBoilerplateName('authorityCheck')).toBeUndefined();
    expect(classifyBoilerplateName('scanDirectory')).toBeUndefined();
    expect(classifyBoilerplateName('canvasRenderer')).toBeUndefined();
  });

  it('refuses the vocabulary that was considered and rejected', () => {
    // See the REFUSED VOCABULARY block in the rule. Recorded as assertions so a
    // future widening is a deliberate act with a failing test attached.
    expect(classifyBoilerplateName('rateLimiter')).toBeUndefined();
    expect(classifyBoilerplateName('throttleRequests')).toBeUndefined();
    expect(classifyBoilerplateName('encryptPassword')).toBeUndefined();
    expect(classifyBoilerplateName('hashPassword')).toBeUndefined();
    expect(classifyBoilerplateName('auditLog')).toBeUndefined();
    expect(classifyBoilerplateName('validateConfig')).toBeUndefined();
  });

  it('returns nothing for names with no words at all', () => {
    expect(classifyBoilerplateName('')).toBeUndefined();
    expect(classifyBoilerplateName('___')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Positives
// ---------------------------------------------------------------------------

describe('VG-SMELL-052 — the canonical positive', () => {
  const dir = sample('crossfile-fixtures/smell-052-unwired-validator');

  it('reports the validator that nothing mounts', async () => {
    const findings = await smellsIn(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('VG-SMELL-052');
    expect(findings[0]!.filePath).toBe('middleware/validate-input.ts');
    expect(findings[0]!.description).toContain('validateInput');
  });

  it('escalates to high because the untrusted value reaches a query sink', async () => {
    const [finding] = await smellsIn(dir);
    expect(finding!.severity).toBe('high');
    expect(finding!.confidence).toBe('medium');
    expect(finding!.securityContext?.containsValidationLogic).toBe(true);
  });

  it('cites the unguarded registrations and not the `app.use` mounts', async () => {
    // app.ts has four registrations: two `app.use` (one of which mounts a NAMED
    // function, `requestLogger`) and two `app.get`. Only the `app.get` pair is a
    // place a guard was omitted. A rule that reads `app.use(requestLogger)` as an
    // unguarded endpoint cites three.
    const [finding] = await smellsIn(dir);
    const registrations = (finding!.relatedLocations ?? []).filter((l) =>
      (l.evidence ?? '').includes('registered with no guard'),
    );
    expect(registrations.map((l) => `${l.filePath}:${l.startLine}`)).toEqual([
      'app.ts:11',
      'app.ts:12',
    ]);
    expect(registrations.every((l) => (l.evidence ?? '').includes('validateInput'))).toBe(true);
  });

  it('cites the line the registration is actually written on', async () => {
    // The rule corrects an off-by-one in `RouteBinding.line`: `JS_ROUTE` consumes
    // the character before the object identifier, so a registration at the start
    // of its line is recorded against the line above it — which here is blank.
    // Asserted against the FILE rather than against a constant, so this stays a
    // statement about the source and not a transcription of the current output.
    const project = await indexOf(dir);
    const appLines = project.files.find((f) => f.filePath === 'app.ts')!.lines;
    // The raw index really is one low; if this stops being true the correction
    // below has become a no-op and the test that follows it proves nothing.
    const raw = openRegistrationsOf(project).map((r) => r.line);
    expect(raw).toEqual([10, 11]);
    expect(appLines[9]!.trim()).toBe('');

    const [finding] = await smellsIn(dir);
    for (const location of (finding!.relatedLocations ?? []).filter((l) =>
      (l.evidence ?? '').includes('registered with no guard'),
    )) {
      expect(appLines[location.startLine - 1]).toContain('app.get(');
    }
  });

  it('carries the taint flow as checkable evidence, not as prose', async () => {
    const [finding] = await smellsIn(dir);
    const flowLine = (finding!.evidence ?? []).find((e) => e.startsWith('taint: '));
    expect(flowLine).toBeDefined();
    expect(flowLine).toContain('req.query');
    expect(flowLine).toContain('db.query');
    expect(flowLine).toContain('[query]');

    const source = (finding!.relatedLocations ?? []).find((l) =>
      (l.evidence ?? '').startsWith('untrusted input enters here'),
    );
    const sink = (finding!.relatedLocations ?? []).find((l) =>
      (l.evidence ?? '').startsWith('and reaches'),
    );
    expect(source?.filePath).toBe('routes/search.ts');
    expect(sink?.filePath).toBe('routes/search.ts');
    expect(source!.startLine).toBeLessThan(sink!.startLine);
  });

  it('keeps primaryLocation in agreement with the flat fields', async () => {
    const [finding] = await smellsIn(dir);
    expect(finding!.primaryLocation?.filePath).toBe(finding!.filePath);
    expect(finding!.primaryLocation?.startLine).toBe(finding!.startLine);
    expect(finding!.primaryLocation?.endLine).toBe(finding!.endLine);
    expect(finding!.primaryLocation?.startColumn).toBe(finding!.startColumn);
  });

  it('measures the boilerplate rather than asserting it exists', async () => {
    const [finding] = await smellsIn(dir);
    // fanIn is the number the confidence band is derived from, so it has to be
    // present and it has to be the graph's answer.
    expect(finding!.metrics?.fanIn).toBe(0);
    expect(finding!.metrics?.loc).toBeGreaterThan(1);
  });

  it('is deterministic across runs', async () => {
    const a = await smellsIn(dir);
    const b = await smellsIn(dir);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

describe('VG-SMELL-052 — the positive in JavaScript and CommonJS', () => {
  const dir = sample('crossfile-fixtures/smell-052-unmounted-auth');

  it('sees a `module.exports = { … }` symbol as exported', async () => {
    const findings = await smellsIn(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.filePath).toBe('security/require-auth.js');
    expect(findings[0]!.description).toContain('requireAuth');
    expect(findings[0]!.securityContext?.containsAuthLogic).toBe(true);
  });

  it('stays at medium when the flow ends in a response rather than an injection sink', async () => {
    const [finding] = await smellsIn(dir);
    expect(finding!.severity).toBe('medium');
    expect((finding!.evidence ?? []).some((e) => e.includes('[response]'))).toBe(true);
    expect(finding!.description).not.toContain('injection sink');
  });
});

describe('VG-SMELL-052 — the positive with no import to be missing', () => {
  const dir = sample('crossfile-fixtures/smell-052-orphan-sanitizer');

  it('does not read `export { sanitizeUserInput }` as a use', async () => {
    const findings = await smellsIn(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.filePath).toBe('api.ts');
    expect(findings[0]!.description).toContain('sanitizeUserInput');
    expect(findings[0]!.securityContext?.containsValidationLogic).toBe(true);
  });

  it('drops to low confidence when something imports the defining module', async () => {
    const [finding] = await smellsIn(dir);
    expect(finding!.severity).toBe('high');
    expect(finding!.confidence).toBe('low');
    expect(finding!.metrics?.fanIn).toBe(1);
  });

  it('attributes the flow to the inline handler the route registered', async () => {
    const [finding] = await smellsIn(dir);
    expect(finding!.description).toMatch(/handler `<anonymous@\d+>`/);
  });
});

describe('VG-SMELL-052 — the positive written as a default export', () => {
  const dir = sample('crossfile-fixtures/smell-052-default-export');

  it('sees `export default function` as an export at all', async () => {
    // ★ REGRESSION. Three separate mechanisms miss this shape and the rule
    // consults all three, so a test that only checks the finding would not say
    // which one was repaired. The first two are asserted to still be blind,
    // because if the indexer ever starts answering them the export-surface
    // widening becomes dead code that nothing would notice.
    const project = await indexOf(dir);
    const structure = project.structures.get('validators/validate-search-query.ts')!;
    const symbol = structure.symbols.find((s) => s.name === 'validateSearchQuery')!;
    expect(symbol.exported).toBe(false);
    expect(structure.exportedNames).not.toContain('validateSearchQuery');
    expect(structure.exportedNames).toContain('default');

    const findings = await smellsIn(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.filePath).toBe('validators/validate-search-query.ts');
    expect(findings[0]!.description).toContain('validateSearchQuery');
  });

  it('stays at medium confidence because nothing imports the module', async () => {
    // No inbound edge means no default import either, so the binding this shape
    // is reached through does not exist anywhere in the project.
    const [finding] = await smellsIn(dir);
    expect(finding!.metrics?.fanIn).toBe(0);
    expect(finding!.confidence).toBe('medium');
    expect(finding!.severity).toBe('high');
  });
});

describe('VG-SMELL-052 — the positive with more than one flow', () => {
  const dir = sample('crossfile-fixtures/smell-052-two-flows');

  it('cites the flow that justifies the severity, not the one that sorts first', async () => {
    const project = await indexOf(dir);
    // The precondition that makes this test mean anything: the two flows are in
    // this order, and the first one is NOT the injection.
    const flows = routeHandlerFlowsOf(project).slice().sort((a, b) =>
      a.filePath < b.filePath ? -1 : a.filePath > b.filePath ? 1 : 0,
    );
    expect(flows.map((f) => `${f.filePath} ${f.sink.kind}`)).toEqual([
      'routes/a-profile.ts response',
      'routes/b-search.ts query',
    ]);

    const [finding] = await smellsIn(dir);
    expect(finding!.severity).toBe('high');
    const flowLine = (finding!.evidence ?? []).find((e) => e.startsWith('taint: '))!;
    expect(flowLine).toContain('routes/b-search.ts');
    expect(flowLine).toContain('[query]');
    expect(flowLine).not.toContain('a-profile');
  });

  it('lists both unguarded registrations as places the sanitizer would have gone', async () => {
    const [finding] = await smellsIn(dir);
    const registrations = (finding!.relatedLocations ?? []).filter((l) =>
      (l.evidence ?? '').includes('registered with no guard'),
    );
    expect(registrations.map((l) => `${l.filePath}:${l.startLine}`)).toEqual(['app.ts:9', 'app.ts:10']);
  });
});

describe('VG-SMELL-052 — the polyglot positive', () => {
  const dir = sample('crossfile-fixtures/smell-052-mixed-language');

  it('reports the TypeScript validator and not the identically-smelly Python one', async () => {
    const project = await indexOf(dir);
    // Preconditions for the Python half: it IS in the vocabulary, it IS indexed,
    // and it IS exported by Python's convention — so the silence about it comes
    // from the per-file language filter and from nothing else.
    expect(classifyBoilerplateName('validate_request_payload')).toBe('validator');
    const python = project.structures.get('jobs/verify_upload.py')!;
    expect(python.language).toBe('python');
    const pythonSymbol = python.symbols.find((s) => s.name === 'validate_request_payload')!;
    expect(pythonSymbol.exported).toBe(true);
    expect(filesNaming(project, 'validate_request_payload', 'jobs/verify_upload.py')).toEqual([]);

    const findings = await smellsIn(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.filePath).toBe('middleware/validate-upload-payload.ts');
  });
});

describe('VG-SMELL-052 — the positive that calls itself', () => {
  const dir = sample('crossfile-fixtures/smell-052-recursive-sanitizer');

  it('does not read a recursive call as somebody using the sanitizer', async () => {
    const project = await indexOf(dir);
    // The precondition: the identifier really does occur twice in its own file,
    // and the second occurrence really is inside the symbol's own body. Without
    // this the fixture could go green while testing nothing.
    const structure = project.structures.get('security/sanitize-comment-tree.ts')!;
    const symbol = structure.symbols.find((s) => s.name === 'sanitizeCommentTree')!;
    const occurrences = [...structure.blanked.matchAll(/\bsanitizeCommentTree\b/g)].map((m) => m.index!);
    expect(occurrences).toHaveLength(2);
    expect(occurrences[1]).toBeGreaterThanOrEqual(symbol.bodyStart);
    expect(occurrences[1]).toBeLessThan(symbol.bodyEnd);
    expect(filesNaming(project, 'sanitizeCommentTree', 'security/sanitize-comment-tree.ts')).toEqual([]);

    const findings = await smellsIn(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.filePath).toBe('security/sanitize-comment-tree.ts');
    expect(findings[0]!.securityContext?.containsValidationLogic).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ★ The three defects the first implementation of this rule shipped with.
//
// Each of these directories is a reproduction, not an invention: they are the
// probes an adversarial review used to break the rule, written out as fixtures
// so the repair has something to fail against. Each asserts the graph fact the
// repair depends on, because "no finding" is equally consistent with the repair
// working and with the fixture never having reproduced anything.
// ---------------------------------------------------------------------------

describe('VG-SMELL-052 — the defects the first implementation shipped with', () => {
  it('does not convict a retired package with a live package\'s routes', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-monorepo');
    const project = await indexOf(dir);

    // Every condition is satisfied SOMEWHERE. That is the whole point.
    expect(boilerplateSymbolsOf(project)).toContain('validateInvoicePayload');
    expect(
      filesNaming(project, 'validateInvoicePayload', 'packages/legacy/src/validate-invoice-payload.ts'),
    ).toEqual([]);
    const open = openRegistrationsOf(project);
    const flows = routeHandlerFlowsOf(project);
    expect(open.length).toBeGreaterThan(0);
    expect(flows.length).toBeGreaterThan(0);
    // …and every one of them is satisfied in the OTHER package.
    for (const path of [...open.map((o) => o.filePath), ...flows.map((f) => f.filePath)]) {
      expect(path.startsWith('packages/api/')).toBe(true);
    }

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('does not report a guard that an `export *` barrel mounts', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-barrel-export-star');
    const project = await indexOf(dir);

    expect(boilerplateSymbolsOf(project)).toContain('requireAdminRole');
    expect(openRegistrationsOf(project).length).toBeGreaterThan(0);
    expect(routeHandlerFlowsOf(project).length).toBeGreaterThan(0);
    // The reference scan genuinely finds nothing: the barrel re-exports without
    // naming, and `app.ts` iterates the namespace object.
    expect(filesNaming(project, 'requireAdminRole', 'security/require-admin-role.ts')).toEqual([]);
    // ★ AND THE GRAPH IS EMPTY TOO, which is what made the old confidence band
    // read this as the STRONGEST case rather than the weakest. `export *` is not
    // an `import`, so `JS_IMPORT` never matched it and no edge was ever drawn.
    expect(project.graph.importedBy.get('security/require-admin-role.ts')?.size ?? 0).toBe(0);
    // The barrel itself is imported, and that edge is the one the repair walks
    // backwards from.
    expect([...(project.graph.importedBy.get('security/index.ts') ?? [])]).toEqual(['app.ts']);

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('does not report a guard mounted off a namespace object', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-namespace-mount');
    const project = await indexOf(dir);

    expect(boilerplateSymbolsOf(project)).toContain('requireOwnerScope');
    expect(openRegistrationsOf(project).length).toBeGreaterThan(0);
    expect(routeHandlerFlowsOf(project).length).toBeGreaterThan(0);
    expect(filesNaming(project, 'requireOwnerScope', 'security/guards.ts')).toEqual([]);
    // ★ Unlike the barrel case, the edge EXISTS and is resolved — so `fanIn` is
    // 1 and the old confidence band would have called this `low` rather than
    // silent. `low` is still a finding, and this one would have been wrong: the
    // guard runs on every request. What decides it is the binding FORM, and
    // `ImportEdge.names` has already discarded that (`import * as guards` and
    // `import { guards }` both flatten to `['guards']`), which is why the syntax
    // is re-read rather than inferred from the edge.
    expect([...(project.graph.importedBy.get('security/guards.ts') ?? [])]).toEqual(['app.ts']);
    const edge = project.structures
      .get('app.ts')!
      .imports.find((e) => e.resolvedFile === 'security/guards.ts')!;
    expect(edge.names).toEqual(['guards']);

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('does not report a guard mounted as `app.use(require(...))`', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-cjs-whole-module');
    const project = await indexOf(dir);

    expect(boilerplateSymbolsOf(project)).toContain('requireBearerAuth');
    expect(openRegistrationsOf(project).length).toBeGreaterThan(0);
    expect(routeHandlerFlowsOf(project).length).toBeGreaterThan(0);
    expect(filesNaming(project, 'requireBearerAuth', 'security/require-bearer-auth.js')).toEqual([]);
    // ★ THE OPPOSITE GRAPH FACT FROM THE BARREL CASE, and the reason both
    // fixtures exist. Here the edge was there the whole time — an inline
    // `require` resolves exactly like any other CommonJS import — and the rule
    // read it only as a number to pick a confidence band with.
    expect([...(project.graph.importedBy.get('security/require-bearer-auth.js') ?? [])]).toEqual([
      'server.js',
    ]);
    // And the destructured require next to it is NOT a whole-module handle: it
    // names what it takes, so the lexical scan can see that one.
    const destructured = project.structures
      .get('server.js')!
      .imports.find((e) => e.resolvedFile === 'handlers/report.js')!;
    expect(destructured.names).toEqual(['renderReport']);

    expect(await smellsIn(dir)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Negatives. Each asserts its own preconditions first — see the header.
// ---------------------------------------------------------------------------

describe('VG-SMELL-052 — the falsification corpus', () => {
  it('stays silent when the validator is mounted at the route', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-mounted');
    const project = await indexOf(dir);
    expect(boilerplateSymbolsOf(project)).toContain('validateInput');
    expect(openRegistrationsOf(project).length).toBeGreaterThan(0);
    expect(routeHandlerFlowsOf(project).length).toBeGreaterThan(0);

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('stays silent when the sanitizer is called on the taint path itself', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-on-taint-path');
    const project = await indexOf(dir);
    expect(boilerplateSymbolsOf(project)).toContain('sanitizeSearchTerm');
    // The route is registered with NO guard, so the "empty slot" evidence the
    // positive relies on is present here too.
    expect(openRegistrationsOf(project).length).toBeGreaterThan(0);
    // And the flow survives the sanitizer — taint-lite does not model
    // sanitization — so this directory is quiet because the name is referenced,
    // not because the taint precondition failed.
    const flows = routeHandlerFlowsOf(project);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows[0]!.filePath).toBe('routes/search.ts');

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('stays silent when a non-route module imports and uses it', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-imported-service');
    const project = await indexOf(dir);
    expect(boilerplateSymbolsOf(project)).toContain('verifyToken');
    expect(openRegistrationsOf(project).length).toBeGreaterThan(0);
    expect(routeHandlerFlowsOf(project).length).toBeGreaterThan(0);
    // Nothing in any route's middleware list names it — the guard runs on a
    // WebSocket upgrade. A route-shaped rule fires here.
    const middleware = jsStructures(project).flatMap((s) =>
      s.routes.flatMap((r) => r.middlewareNames),
    );
    expect(middleware).not.toContain('verifyToken');

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('stays silent when the only reference is under the test tree', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-test-only');
    const project = await indexOf(dir);
    expect(boilerplateSymbolsOf(project)).toContain('validateInput');
    expect(openRegistrationsOf(project).length).toBeGreaterThan(0);
    expect(routeHandlerFlowsOf(project).length).toBeGreaterThan(0);
    // The reference really is only in the test tree: no production file names it.
    const naming = jsStructures(project)
      .filter((s) => s.filePath !== 'middleware/validate-input.ts')
      .filter((s) => /\bvalidateInput\b/.test(s.blanked))
      .map((s) => s.filePath);
    expect(naming).toEqual(['__tests__/validate-input-cases.ts']);

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('stays silent when no untrusted input is handled at all', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-no-untrusted-input');
    const project = await indexOf(dir);
    // Everything the positive has, except the flow.
    expect(boilerplateSymbolsOf(project)).toContain('validateInput');
    expect(openRegistrationsOf(project).length).toBeGreaterThan(0);
    const naming = jsStructures(project)
      .filter((s) => s.filePath !== 'middleware/validate-input.ts')
      .filter((s) => /\bvalidateInput\b/.test(s.blanked));
    expect(naming).toEqual([]);
    // The isolated condition: sinks are present, sources are not.
    expect(routeHandlerFlowsOf(project)).toEqual([]);

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('stays silent when every registration already carries a guard', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-all-routes-guarded');
    const project = await indexOf(dir);
    expect(boilerplateSymbolsOf(project)).toContain('sanitizeReportTitle');
    expect(routeHandlerFlowsOf(project).length).toBeGreaterThan(0);
    const naming = jsStructures(project)
      .filter((s) => s.filePath !== 'security/sanitize-report-title.ts')
      .filter((s) => /\bsanitizeReportTitle\b/.test(s.blanked));
    expect(naming).toEqual([]);
    // The isolated condition. `app.use(requireAdmin)` is here on purpose: read as
    // a route it looks like an unguarded endpoint, and a rule that counts it
    // reports one open registration instead of none.
    expect(openRegistrationsOf(project)).toEqual([]);

    expect(await smellsIn(dir)).toEqual([]);
  });

  // ── The six below were added because a mutation audit found the conditions
  //    they isolate could each be DELETED without turning a single test red.
  //    A condition no test constrains is a condition nobody is checking, and
  //    three of these are ones the rule argues for at length in prose.

  it('stays silent when the helper was never exported', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-not-exported');
    const project = await indexOf(dir);
    expect(boilerplateSymbolsOf(project)).toContain('validateCommentBody');
    expect(openRegistrationsOf(project).length).toBeGreaterThan(0);
    expect(routeHandlerFlowsOf(project).length).toBeGreaterThan(0);
    expect(filesNaming(project, 'validateCommentBody', 'middleware/validate-comment-body.ts')).toEqual(
      [],
    );
    // The isolated condition, asserted against all three spellings the rule
    // consults — the file HAS an export surface (`export { logRejection }`), so
    // the third one is a real question rather than a vacuous one.
    const structure = project.structures.get('middleware/validate-comment-body.ts')!;
    expect(structure.symbols.find((s) => s.name === 'validateCommentBody')!.exported).toBe(false);
    expect(structure.exportedNames).toEqual(['logRejection']);

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('stays silent about a guard CLASS nothing names', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-class-guard');
    const project = await indexOf(dir);
    // The name qualifies, so the vocabulary is not what silences this.
    expect(classifyBoilerplateName('RequireAdminGuard')).toBe('authorization');
    expect(boilerplateSymbolsOf(project)).toContain('RequireAdminGuard');
    expect(openRegistrationsOf(project).length).toBeGreaterThan(0);
    expect(routeHandlerFlowsOf(project).length).toBeGreaterThan(0);
    expect(filesNaming(project, 'RequireAdminGuard', 'security/require-admin.guard.ts')).toEqual([]);
    // The isolated condition: it is a class, and it is exported, so every other
    // gate is open.
    const symbol = project.structures
      .get('security/require-admin.guard.ts')!
      .symbols.find((s) => s.name === 'RequireAdminGuard')!;
    expect(symbol.kind).toBe('class');
    expect(symbol.exported).toBe(true);

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('stays silent when every `.get(` in the file is something other than a route', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-not-a-route');
    const project = await indexOf(dir);
    expect(boilerplateSymbolsOf(project)).toContain('sanitizeIncidentTitle');
    expect(routeHandlerFlowsOf(project).length).toBeGreaterThan(0);
    expect(filesNaming(project, 'sanitizeIncidentTitle', 'security/sanitize-incident-title.ts')).toEqual(
      [],
    );

    // ★ The three registration-shaped things in `app.ts`, each excluded by a
    // DIFFERENT condition. Asserted from the index rather than described, so a
    // change to the indexer that collapses two of them into one shape fails here
    // instead of quietly making one of the rule's checks untested.
    const appRoutes = project.structures
      .get('app.ts')!
      .routes.filter((r) => r.method === 'get')
      .map((r) => ({
        path: r.path,
        handler: r.handlerName,
        guards: r.middlewareNames.length,
      }));
    expect(appRoutes).toEqual([
      // a settings key: has a path literal, and it is not a route path
      { path: 'database.url', handler: 'DEFAULT_DATABASE_URL', guards: 0 },
      // a cache read: no literal first argument at all, so no path
      { path: undefined, handler: 'reportCacheKey', guards: 0 },
      // a real endpoint whose handler is a computed member access
      { path: '/incidents', handler: undefined, guards: 0 },
      // and the one real registration, which carries a guard
      { path: '/search', handler: 'searchIncidents', guards: 1 },
    ]);
    expect(openRegistrationsOf(project)).toEqual([]);

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('stays silent when the unwired helper is itself a test helper', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-candidate-in-tests');
    const project = await indexOf(dir);
    expect(boilerplateSymbolsOf(project)).toContain('validateSignupInput');
    expect(openRegistrationsOf(project).length).toBeGreaterThan(0);
    expect(routeHandlerFlowsOf(project).length).toBeGreaterThan(0);
    expect(
      filesNaming(project, 'validateSignupInput', '__tests__/helpers/validate-signup-input.ts'),
    ).toEqual([]);
    // The isolated condition: the definition is under the test tree, and the
    // routing and taint evidence are not.
    const definition = project.structures.get('__tests__/helpers/validate-signup-input.ts')!;
    expect(definition.symbols.find((s) => s.name === 'validateSignupInput')!.exported).toBe(true);
    for (const path of [
      ...openRegistrationsOf(project).map((o) => o.filePath),
      ...routeHandlerFlowsOf(project).map((f) => f.filePath),
    ]) {
      expect(path.startsWith('__tests__/')).toBe(false);
    }

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('stays silent when the only unguarded registration is a test probe', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-open-only-in-tests');
    const project = await indexOf(dir);
    expect(boilerplateSymbolsOf(project)).toContain('requireTenantAccess');
    expect(routeHandlerFlowsOf(project).length).toBeGreaterThan(0);
    expect(filesNaming(project, 'requireTenantAccess', 'security/require-tenant-access.ts')).toEqual([]);
    // The isolated condition. `openRegistrationsOf` here is the UNFILTERED
    // helper, so it sees the probe; the rule's own scan excludes the test tree
    // and therefore sees nothing.
    expect(openRegistrationsOf(project).map((o) => o.filePath)).toEqual([
      '__tests__/invoices.test.ts',
    ]);
    expect(routeHandlerFlowsOf(project).every((f) => !f.filePath.startsWith('__tests__/'))).toBe(true);

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('stays silent when the untrusted-input flow is in a script, not a handler', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-flow-outside-handlers');
    const project = await indexOf(dir);
    expect(boilerplateSymbolsOf(project)).toContain('requireOrderAccess');
    expect(filesNaming(project, 'requireOrderAccess', 'security/require-order-access.ts')).toEqual([]);
    expect(openRegistrationsOf(project).map((o) => o.filePath)).toEqual(['app.ts']);
    // The isolated condition: there IS a flow to a query sink in this project,
    // and its enclosing symbol was never registered against a route, so no
    // route-level middleware could have stood in front of it.
    const everyFlow = analyzeProjectTaint(jsStructures(project), project.files);
    expect(everyFlow.map((f) => `${f.filePath}#${f.symbolName} ${f.sink.kind}`)).toEqual([
      'scripts/reindex-orders.ts#reindexOrders query',
    ]);
    const script = project.structures.get('scripts/reindex-orders.ts')!;
    expect(script.symbols.find((s) => s.name === 'reindexOrders')!.kind).toBe('function');
    expect(routeHandlerFlowsOf(project)).toEqual([]);

    expect(await smellsIn(dir)).toEqual([]);
  });

  it('stays silent when the only untrusted-input flow is inside a test', async () => {
    const dir = sample('crossfile-fixtures/smell-052-neg-flow-only-in-tests');
    const project = await indexOf(dir);
    expect(boilerplateSymbolsOf(project)).toContain('escapeCommentHtml');
    expect(filesNaming(project, 'escapeCommentHtml', 'security/escape-comment-html.ts')).toEqual([]);
    // The product really does register an endpoint with no guard. (The probe in
    // the test tree registers one too, which is why this list has two entries —
    // the rule's own scan drops that one, and `neg-open-only-in-tests` is the
    // directory that isolates THAT exclusion.)
    expect(openRegistrationsOf(project).map((o) => o.filePath)).toContain('app.ts');
    // …and the only flow in the tree is the test's own echo probe.
    expect(routeHandlerFlowsOf(project).map((f) => f.filePath)).toEqual(['__tests__/status.test.ts']);

    expect(await smellsIn(dir)).toEqual([]);
  });
});

describe('VG-SMELL-052 — the existing corpora stay quiet', () => {
  it('reports nothing on the well-factored cross-file sample', async () => {
    expect(await smellsIn(sample('crossfile-safe'))).toEqual([]);
  });

  it('reports nothing on the scattered-authorization sample', async () => {
    // `crossfile-vulnerable` is a real Express service with guards, handlers and
    // request data. It is a VG-SMELL-010 positive and must not become a
    // VG-SMELL-052 one: a design smell that fires on two unrelated rules'
    // fixtures is a rule with no defined population.
    expect(await smellsIn(sample('crossfile-vulnerable'))).toEqual([]);
  });

  it('does not let one directory\'s routing table convict another directory\'s helper', async () => {
    // ★ MEASURED TWICE, AND THE SECOND MEASUREMENT IS WHY LOCALITY EXISTS.
    //
    // FIRST MEASUREMENT, against the rule as first written. Scanning the whole
    // fixture root produced THREE findings, and the third was
    // `smell-052-neg-all-routes-guarded/security/sanitize-report-title.ts` — a
    // directory that is a NEGATIVE precisely because it has no unguarded
    // registration of its own. Its siblings supplied plenty, so a condition
    // missing from that product was restored by code in a different one. Every
    // firing condition was project-scoped, so unioning unrelated services did
    // not merely add findings, it CREATED one.
    //
    // That is not a curiosity about a fixture directory. It is the monorepo
    // failure mode: a retired package's helper convicted by a live package's
    // routes and a third package's taint flow. The `APP UNITS` section of the
    // rule is the repair, and `smell-052-neg-monorepo/` is the fixture that
    // states it in the layout it actually occurs in.
    //
    // SECOND MEASUREMENT, with locality in place. The invented finding is gone
    // and the two honest ones survive:
    //
    //   silent  smell-052-unwired-validator   `validateInput` collides with the
    //                                         copies in `neg-mounted/` and
    //                                         `neg-test-only/`, which reference
    //                                         theirs. Name collision across
    //                                         directories — still a real
    //                                         property of a lexical scan, and
    //                                         still recorded rather than fixed.
    //   FIRES   each positive directory       every one of them supplies its own
    //                                         unguarded registration and its own
    //                                         flow, from inside its own
    //                                         territory.
    //
    // Every surviving finding is one the directory produces on its own — the
    // list below is exactly the positives minus the name collision, and no
    // negative directory appears in it. The collision is the remaining
    // cross-directory effect and it is the safe direction: it SUPPRESSES
    // findings. "Project" still means what you pointed the scanner at; what
    // changed is that the rule no longer treats everything under that root as
    // one program.
    const findings = await smellsIn(sample('crossfile-fixtures'));
    expect(findings.map((f) => f.filePath).sort()).toEqual([
      'smell-052-default-export/validators/validate-search-query.ts',
      'smell-052-mixed-language/middleware/validate-upload-payload.ts',
      'smell-052-orphan-sanitizer/api.ts',
      'smell-052-recursive-sanitizer/security/sanitize-comment-tree.ts',
      'smell-052-two-flows/security/sanitize-order-note.ts',
      'smell-052-unmounted-auth/security/require-auth.js',
    ]);
  });

  it('reports nothing on a project with no TypeScript or JavaScript in it', async () => {
    // The C fixture for VG-AISC-003. The two rules make a similar-looking
    // judgement and must never both speak about one file; disjoint `languages`
    // is what guarantees it, and this is the assertion of that guarantee.
    expect(await smellsIn(sample('crossfile-fixtures/embedded-unintegrated'))).toEqual([]);
  });
});
