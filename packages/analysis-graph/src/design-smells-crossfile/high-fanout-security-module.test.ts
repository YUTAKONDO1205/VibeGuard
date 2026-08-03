// Tests for VG-SMELL-021 — High Fan-out Security Module.
//
// Run against the rule OBJECT rather than through `analyzeProject`, because the
// rule is deliberately not in `design-smells-crossfile/index.ts` yet and
// `analyzeProject` would not run it at all. Same reason and same shape as the
// VG-SMELL-041 tests next door.
//
// ★ EVERY NEGATIVE ASSERTS ITS PREMISE BEFORE IT ASSERTS SILENCE
//
// This rule has five independent conditions, four of which are numeric, so a
// fixture can stop testing what it was written for without anyone noticing: a
// negative that drifts to fan-out 6 passes "0 findings" perfectly and proves
// nothing about the condition it was built for. Each negative therefore states
// what it would have been reported for — the fan-out, the module count, the
// security operations the rule really did find — and only then asserts silence.
// A vacuous pass is the failure this repository has already had to reject once.
//
// ★ WHY SOME PROJECTS ARE ON DISK AND SOME ARE GENERATED
//
// The rule cannot fire below 24 modules (fan-out 8 × the project-share
// denominator 3), so every fixture for it is at least an order of magnitude
// larger than the six-file fixtures the other cross-file rules use. The
// substantive cases — the three positives and the three negatives the
// commissioning note named — are on disk under `samples/crossfile-fixtures/`,
// where they can be read. The BOUNDARY cases are generated into a temp
// directory: "fan-out 7 is silent and 8 is not" is a statement about a number,
// nobody learns anything from reading twenty-four filler modules to check it,
// and putting a hundred more files in the sample tree to express it would make
// the fixtures that DO carry meaning harder to find. `mkdtemp` fixtures are an
// established pattern here — `temporal-security-coupling.test.ts` uses them for
// its pathological-input bounds.

import { afterAll, describe, expect, it } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { designSmellLocationsAgree, type DesignSmellFinding } from '@vibeguard/findings-schema';
import { createBudget } from '../budget.js';
import { fanMetrics } from '../metrics/index.js';
import { buildProjectIndex, collectProjectFiles } from '../project.js';
import type { CrossFileFinding, ProjectIndex } from '../types.js';
import { highFanoutSecurityModule, securityOperations } from './high-fanout-security-module.js';

const REPO_ROOT = resolve(__dirname, '../../../..');
const fixture = (name: string): string => resolve(REPO_ROOT, 'samples', 'crossfile-fixtures', name);

interface Analysis {
  findings: CrossFileFinding[];
  project: ProjectIndex;
  /** Modules of a language the rule handles, excluding test paths. */
  moduleCount: number;
}

async function analyse(dir: string): Promise<Analysis> {
  const budget = createBudget({});
  const files = await collectProjectFiles(dir, budget);
  const project = buildProjectIndex(dir, files, budget);
  const moduleCount = [...project.structures.values()].filter(
    (s) => highFanoutSecurityModule.languages.includes(s.language) && !/(^|\/)__tests__(\/|$)/.test(s.filePath),
  ).length;
  return { findings: highFanoutSecurityModule.analyze({ project, budget }), project, moduleCount };
}

/** Fan-out of one file, from the same producer the rule thresholds on. */
const fanOut = (analysis: Analysis, filePath: string): number =>
  fanMetrics(filePath, analysis.project.graph).fanOut ?? 0;

const fanIn = (analysis: Analysis, filePath: string): number =>
  fanMetrics(filePath, analysis.project.graph).fanIn ?? 0;

/** The operations the rule found in one file, as `family@line`. */
function operationsOf(analysis: Analysis, filePath: string): string[] {
  const structure = analysis.project.structures.get(filePath)!;
  const source = analysis.project.files.find((f) => f.filePath === filePath)!;
  return securityOperations(structure, source.content).map((o) => `${o.family}@${o.line}`);
}

// ---------------------------------------------------------------------------
// Generated projects, for the numeric boundaries.
// ---------------------------------------------------------------------------

const temporary: string[] = [];

afterAll(async () => {
  for (const dir of temporary) await rm(dir, { recursive: true, force: true });
});

async function writeProject(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'vg-smell-021-'));
  temporary.push(dir);
  for (const [path, content] of Object.entries(files)) {
    const full = join(dir, path);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
  return dir;
}

interface Shape {
  /** How many project modules the security module imports. */
  dependencies: number;
  /** Total modules in the project, including the security module itself. */
  modules: number;
  /** Whether anything imports the security module. */
  consumed?: boolean;
  /** Where the security module lives. */
  path?: string;
  /** Body of the security module, after its imports. */
  body?: string;
  /** Extra modules that also have a high fan-out, to raise the project's p90. */
  rivals?: number;
  rivalDependencies?: number;
}

/**
 * A project with one security module of a chosen shape.
 *
 * Everything the numeric conditions are about is a parameter, so a test reads as
 * the sentence it is checking ("fan-out 7 in a 30-module project is silent")
 * rather than as a directory listing.
 */
const DEFAULT_BODY = [
  'export function decide(user: { role: string; permissions: string[] }): boolean {',
  "  if (user.role === 'admin') return true;",
  "  return user.permissions.includes('read');",
  '}',
];

async function shaped(shape: Shape): Promise<string> {
  const path = shape.path ?? 'src/security/decide.ts';
  const files: Record<string, string> = {};
  const depth = path.split('/').length - 1;
  const up = '../'.repeat(depth);

  const imports: string[] = [];
  for (let i = 0; i < shape.dependencies; i += 1) {
    files[`src/dep-${i}.ts`] = `export const value${i} = ${i};\n`;
    imports.push(`import { value${i} } from '${up}src/dep-${i}.js';`);
  }
  files[path] = `${[...imports, '', ...(shape.body ? [shape.body] : DEFAULT_BODY)].join('\n')}\n`;

  const rivals = shape.rivals ?? 0;
  for (let r = 0; r < rivals; r += 1) {
    const rivalImports: string[] = [];
    for (let i = 0; i < (shape.rivalDependencies ?? shape.dependencies); i += 1) {
      rivalImports.push(`import { value${i} as v${i} } from '../src/dep-${i}.js';`);
    }
    files[`src/rival-${r}.ts`] =
      `${rivalImports.join('\n')}\nexport const total${r} = ${
        Array.from({ length: shape.rivalDependencies ?? shape.dependencies }, (_, i) => `v${i}`).join(' + ') || '0'
      };\n`;
  }

  if (shape.consumed !== false) {
    files['src/consumer.ts'] = `import { decide } from '${path.replace(/^src\//, './').replace(/\.ts$/, '.js')}';\n\nexport const gate = decide;\n`;
  }

  let filler = 0;
  const used = (): number => Object.keys(files).filter((f) => /\.ts$/.test(f)).length;
  while (used() < shape.modules) {
    files[`src/filler-${filler}.ts`] = `export const filler${filler} = '${filler}';\n`;
    filler += 1;
  }

  return writeProject(files);
}

// ---------------------------------------------------------------------------
// Positives
// ---------------------------------------------------------------------------

describe('VG-SMELL-021 — the authorization policy that reaches into a third of the project', () => {
  it('reports it, with the shape and the location the schema requires', async () => {
    const analysis = await analyse(fixture('smell-021-authz-hub'));
    expect(analysis.findings).toHaveLength(1);
    const [finding] = analysis.findings;
    expect(finding!.ruleId).toBe('VG-SMELL-021');
    expect(finding!.title).toBe('High Fan-out Security Module');
    expect(finding!.scope).toBe('module');
    expect(finding!.filePath).toBe('src/security/authorize.ts');
    // Anchored at the first security operation — the inference — and not at the
    // first import, which is the part the graph already knows.
    expect(finding!.startLine).toBe(26);
    expect(designSmellLocationsAgree({ ...finding!, findingId: 'test' } as DesignSmellFinding)).toBe(true);
    for (const related of finding!.relatedLocations ?? []) {
      expect(`${related.filePath}:${related.startLine}`).not.toBe(
        `${finding!.primaryLocation!.filePath}:${finding!.primaryLocation!.startLine}`,
      );
    }
  });

  it('stands on the numbers it reports: fan-out 8, of 24 modules, imported by 3', async () => {
    // The premise of the whole fixture, asserted so it cannot drift over the
    // project-share boundary (8 × 3 = 24) without a test saying so.
    const analysis = await analyse(fixture('smell-021-authz-hub'));
    expect(fanOut(analysis, 'src/security/authorize.ts')).toBe(8);
    expect(fanIn(analysis, 'src/security/authorize.ts')).toBe(3);
    expect(analysis.moduleCount).toBe(24);
    const [finding] = analysis.findings;
    expect(finding!.metrics).toMatchObject({ fanOut: 8, fanIn: 3, importCount: 8 });
  });

  it('is high/high — it enforces, and its path agrees with its behaviour', async () => {
    const [finding] = (await analyse(fixture('smell-021-authz-hub'))).findings;
    expect(finding!.severity).toBe('high');
    expect(finding!.confidence).toBe('high');
    expect(finding!.securityContext).toEqual({
      containsAuthLogic: false,
      containsAuthorizationLogic: true,
      containsCryptoLogic: false,
      containsTokenLogic: false,
    });
  });

  it('names both kinds of authorization decision it found', async () => {
    const analysis = await analyse(fixture('smell-021-authz-hub'));
    // A privilege comparison AND a membership test: two different patterns, and
    // the rule needs two operations, so removing either one silences the
    // fixture.
    expect(operationsOf(analysis, 'src/security/authorize.ts')).toEqual([
      'authorization@26',
      'authorization@36',
    ]);
  });

  it('lists every dependency, sorted, so the evidence is stable between runs', async () => {
    const [finding] = (await analyse(fixture('smell-021-authz-hub'))).findings;
    const dependencies = finding!.evidence!.filter((e) => e.includes(' → ')).map((e) => e.split(' → ')[1]);
    expect(dependencies).toEqual([
      'src/cache/redis-cache.ts',
      'src/config/env.ts',
      'src/db/client.ts',
      'src/repositories/tenant-repository.ts',
      'src/repositories/user-repository.ts',
      'src/services/audit-log.ts',
      'src/services/feature-flags.ts',
      'src/util/logger.ts',
    ]);
    // Import order in the file is env, db, cache, … — so this list being sorted
    // is a property of the rule and not of the fixture.
    expect([...dependencies].sort()).toEqual(dependencies);
  });
});

describe('VG-SMELL-021 — the crypto module nobody named after security', () => {
  it('reports it at medium/medium: it computes rather than decides, and only behaviour says security', async () => {
    const analysis = await analyse(fixture('smell-021-envelope-service'));
    expect(analysis.findings).toHaveLength(1);
    const [finding] = analysis.findings;
    expect(finding!.filePath).toBe('src/services/envelope.ts');
    expect(finding!.severity).toBe('medium');
    expect(finding!.confidence).toBe('medium');
    expect(finding!.securityContext).toMatchObject({
      containsCryptoLogic: true,
      containsAuthorizationLogic: false,
      containsTokenLogic: false,
    });
  });

  it('finds the primitive whether it is called on `crypto.` or imported by name', async () => {
    // `crypto.createCipheriv(...)` is a method call and `createDecipheriv(...)`
    // is a free call after a named import. They are found by two different
    // patterns and the module needs both to reach the two-operation floor.
    const analysis = await analyse(fixture('smell-021-envelope-service'));
    expect(operationsOf(analysis, 'src/services/envelope.ts')).toEqual(['crypto@18', 'crypto@30']);
    expect(fanOut(analysis, 'src/services/envelope.ts')).toBe(8);
    expect(analysis.moduleCount).toBe(24);
  });

  it('does not treat `randomBytes` as the security operation', async () => {
    // The module calls it, and the vocabulary refuses it: identifiers, nonces
    // and test fixtures all call `randomBytes`. If it counted, this fixture
    // would reach the floor on one cipher call plus it, which is not the claim.
    const analysis = await analyse(fixture('smell-021-envelope-service'));
    const source = analysis.project.files.find((f) => f.filePath === 'src/services/envelope.ts')!;
    expect(source.content).toContain('randomBytes(12)');
    expect(operationsOf(analysis, 'src/services/envelope.ts')).toHaveLength(2);
  });
});

describe('VG-SMELL-021 — a CommonJS JavaScript token guard', () => {
  it('reports it: `require` resolves, and the package binding names the family', async () => {
    const analysis = await analyse(fixture('smell-021-jwt-guard'));
    expect(analysis.findings).toHaveLength(1);
    const [finding] = analysis.findings;
    expect(finding!.filePath).toBe('src/auth/verify-token.js');
    expect(finding!.severity).toBe('high');
    expect(finding!.confidence).toBe('high');
    expect(finding!.metrics).toMatchObject({ fanOut: 8, fanIn: 2 });
    expect(operationsOf(analysis, 'src/auth/verify-token.js')).toEqual(['token@12', 'token@16']);
    expect(analysis.moduleCount).toBe(24);
  });

  it('counts each operation once even though two arms recognise it', async () => {
    // `jwt.verify(...)` is both a call to a `jsonwebtoken` binding and a token
    // method on a token-named receiver. Two operations, not four.
    const analysis = await analyse(fixture('smell-021-jwt-guard'));
    expect(operationsOf(analysis, 'src/auth/verify-token.js')).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Negatives — on disk
// ---------------------------------------------------------------------------

describe('VG-SMELL-021 — the router barrel', () => {
  it('has the fan-out of a hub and is not one', async () => {
    const analysis = await analyse(fixture('smell-021-neg-router-barrel'));
    // The premise: it clears every fan-out condition the rule has.
    expect(fanOut(analysis, 'src/routes/index.ts')).toBe(8);
    expect(fanIn(analysis, 'src/routes/index.ts')).toBe(1);
    expect(analysis.moduleCount).toBe(25);
    // And it declares a function, so the silence is not "the file is empty".
    expect(analysis.project.structures.get('src/routes/index.ts')!.symbols.length).toBeGreaterThan(0);
    // It decides nothing.
    expect(operationsOf(analysis, 'src/routes/index.ts')).toEqual([]);
    expect(analysis.findings).toEqual([]);
  });
});

describe('VG-SMELL-021 — the guard that depends on almost nothing', () => {
  it('is recognised as a security module and still not reported', async () => {
    const analysis = await analyse(fixture('smell-021-neg-focused-guard'));
    // The premise that matters most: the rule DOES see this as a security
    // module. A negative that passed because the membership test failed would
    // be testing nothing about the fan-out conditions.
    expect(operationsOf(analysis, 'src/security/require-role.ts')).toEqual([
      'authorization@5',
      'authorization@6',
      'authorization@10',
    ]);
    expect(fanOut(analysis, 'src/security/require-role.ts')).toBe(2);
    expect(analysis.findings).toEqual([]);
  });
});

describe('VG-SMELL-021 — the project that is too small to have a hub', () => {
  it('stays silent when the fan-out IS most of the project', async () => {
    const analysis = await analyse(fixture('smell-021-neg-small-project'));
    expect(fanOut(analysis, 'src/auth/authorize.ts')).toBe(8);
    expect(fanIn(analysis, 'src/auth/authorize.ts')).toBe(1);
    expect(operationsOf(analysis, 'src/auth/authorize.ts')).toEqual([
      'authorization@16',
      'authorization@20',
    ]);
    // Eight of twelve. Everything except the project-share condition passes.
    expect(analysis.moduleCount).toBe(12);
    expect(analysis.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Negatives and positives at the numeric boundaries — generated
// ---------------------------------------------------------------------------

describe('VG-SMELL-021 — the absolute fan-out floor', () => {
  it('is silent at 7 and reports at 8, with everything else held constant', async () => {
    const below = await analyse(await shaped({ dependencies: 7, modules: 30 }));
    expect(fanOut(below, 'src/security/decide.ts')).toBe(7);
    expect(operationsOf(below, 'src/security/decide.ts')).toHaveLength(2);
    expect(below.findings).toEqual([]);

    const at = await analyse(await shaped({ dependencies: 8, modules: 30 }));
    expect(fanOut(at, 'src/security/decide.ts')).toBe(8);
    expect(at.findings).toHaveLength(1);
  });
});

describe('VG-SMELL-021 — the project-share floor', () => {
  it('is silent at 8 of 20 and reports at 8 of 24', async () => {
    // 8 × 3 = 24. Twenty modules is below it and twenty-four is exactly on it,
    // so this pair pins the denominator itself and not merely its presence.
    const tight = await analyse(await shaped({ dependencies: 8, modules: 20 }));
    expect(fanOut(tight, 'src/security/decide.ts')).toBe(8);
    expect(tight.moduleCount).toBe(20);
    expect(tight.findings).toEqual([]);

    const roomy = await analyse(await shaped({ dependencies: 8, modules: 24 }));
    expect(roomy.moduleCount).toBe(24);
    expect(roomy.findings).toHaveLength(1);
  });
});

describe('VG-SMELL-021 — house style', () => {
  it('is silent when the project`s own p90 is as high as the module', async () => {
    // Three rival modules import the same nine dependencies, so a fan-out of 9
    // is what an ordinary module in this project looks like. Reporting it would
    // be reporting the architecture.
    const layered = await analyse(
      await shaped({ dependencies: 9, modules: 30, rivals: 3 }),
    );
    expect(fanOut(layered, 'src/security/decide.ts')).toBe(9);
    expect(fanOut(layered, 'src/rival-0.ts')).toBe(9);
    expect(operationsOf(layered, 'src/security/decide.ts')).toHaveLength(2);
    expect(layered.findings).toEqual([]);
  });

  it('reports again as soon as the module is genuinely an outlier', async () => {
    const outlier = await analyse(
      await shaped({ dependencies: 10, modules: 30, rivals: 3, rivalDependencies: 9 }),
    );
    expect(fanOut(outlier, 'src/security/decide.ts')).toBe(10);
    expect(fanOut(outlier, 'src/rival-0.ts')).toBe(9);
    expect(outlier.findings).toHaveLength(1);
    expect(outlier.findings[0]!.filePath).toBe('src/security/decide.ts');
  });
});

describe('VG-SMELL-021 — the application entry point', () => {
  it('stays silent when nothing imports the module', async () => {
    const entry = await analyse(
      await shaped({ dependencies: 9, modules: 30, consumed: false, path: 'src/server.ts' }),
    );
    expect(fanOut(entry, 'src/server.ts')).toBe(9);
    expect(fanIn(entry, 'src/server.ts')).toBe(0);
    expect(operationsOf(entry, 'src/server.ts')).toHaveLength(2);
    expect(entry.findings).toEqual([]);
  });
});

describe('VG-SMELL-021 — the two-operation floor', () => {
  it('stays silent on a module whose only security operation is one call', async () => {
    const incidental = await analyse(
      await shaped({
        dependencies: 9,
        modules: 30,
        body: [
          'export function signature(body: string, key: string): string {',
          "  return require('node:crypto').createHmac('sha256', key).update(body).digest('hex');",
          '}',
          'export const decide = signature;',
        ].join('\n'),
      }),
    );
    expect(operationsOf(incidental, 'src/security/decide.ts')).toHaveLength(1);
    expect(fanOut(incidental, 'src/security/decide.ts')).toBe(9);
    expect(incidental.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// What is not a security module
// ---------------------------------------------------------------------------

describe('VG-SMELL-021 — the other three meanings of `role`', () => {
  it('reads no authorization decision out of chat message roles', async () => {
    const chat = await analyse(
      await shaped({
        dependencies: 9,
        modules: 30,
        path: 'src/llm/client.ts',
        body: [
          'export function render(m: { role: string; text: string }): string {',
          "  if (m.role === 'user') return `> ${m.text}`;",
          "  return m.role === 'assistant' ? m.text : '';",
          '}',
          'export const decide = render;',
        ].join('\n'),
      }),
    );
    expect(fanOut(chat, 'src/llm/client.ts')).toBe(9);
    expect(operationsOf(chat, 'src/llm/client.ts')).toEqual([]);
    expect(chat.findings).toEqual([]);
  });

  it('reads no authorization decision out of ARIA roles', async () => {
    const aria = await analyse(
      await shaped({
        dependencies: 9,
        modules: 30,
        path: 'src/tools/input.ts',
        body: [
          'export function isOption(child: { role: string }, node: { role: string }): boolean {',
          "  if (child.role === 'option') return true;",
          "  return node.role === 'combobox';",
          '}',
          'export const decide = isOption;',
        ].join('\n'),
      }),
    );
    expect(operationsOf(aria, 'src/tools/input.ts')).toEqual([]);
    expect(aria.findings).toEqual([]);
  });

  it('reads no authorization decision out of the browser`s permission API', async () => {
    // The fourth meaning. `Notification.permission` is whether the user let the
    // page show a toast; `odysseus-dev__odysseus/static/js/notes.js` was
    // reported on three of these before the exclusion existed.
    const browser = await analyse(
      await shaped({
        dependencies: 9,
        modules: 30,
        path: 'src/ui/notes.ts',
        body: [
          'declare const Notification: { permission: string };',
          'export function decide(): boolean {',
          "  if (Notification.permission === 'granted') return true;",
          "  return Notification.permission === 'denied' ? false : true;",
          '}',
        ].join('\n'),
      }),
    );
    expect(fanOut(browser, 'src/ui/notes.ts')).toBe(9);
    expect(operationsOf(browser, 'src/ui/notes.ts')).toEqual([]);
    expect(browser.findings).toEqual([]);
  });

  it('still reads one off a subject, whatever the value compared against', async () => {
    // The allowlist must not have turned into "only literal admin counts": a
    // project with its own role vocabulary is the normal case.
    const custom = await analyse(
      await shaped({
        dependencies: 9,
        modules: 30,
        body: [
          'export function decide(account: { role: string }, session: { role: string }): boolean {',
          "  if (account.role === 'tenant_operator') return true;",
          "  return session.role !== 'read_only';",
          '}',
        ].join('\n'),
      }),
    );
    expect(operationsOf(custom, 'src/security/decide.ts')).toHaveLength(2);
    expect(custom.findings).toHaveLength(1);
  });
});

describe('VG-SMELL-021 — vocabulary edges', () => {
  it('does not mistake an LLM tokeniser for a token operation', async () => {
    const tokenizer = await analyse(
      await shaped({
        dependencies: 9,
        modules: 30,
        path: 'src/nlp/encode.ts',
        body: [
          'declare const tokenizer: { decode(ids: number[]): string; sign(x: string): string };',
          'export function decide(ids: number[]): string {',
          '  const text = tokenizer.decode(ids);',
          '  return tokenizer.sign(text);',
          '}',
        ].join('\n'),
      }),
    );
    expect(operationsOf(tokenizer, 'src/nlp/encode.ts')).toEqual([]);
    expect(tokenizer.findings).toEqual([]);
  });

  it('does read a token operation off a token-named receiver', async () => {
    const jwtService = await analyse(
      await shaped({
        dependencies: 9,
        modules: 30,
        body: [
          'declare const jwtService: { verify(t: string): unknown; decode(t: string): unknown };',
          'export function decide(raw: string): unknown {',
          '  jwtService.decode(raw);',
          '  return jwtService.verify(raw);',
          '}',
        ].join('\n'),
      }),
    );
    expect(operationsOf(jwtService, 'src/security/decide.ts')).toEqual(['token@13', 'token@14']);
    expect(jwtService.findings).toHaveLength(1);
    expect(jwtService.findings[0]!.severity).toBe('high');
  });

  it('does not count raising a package`s error type as performing its operation', async () => {
    // `express-jwt` exports both the middleware factory and `UnauthorizedError`.
    // Throwing the error is what a module does after something else verified a
    // token. One operation here, not three, so the module stays below the floor.
    const throwing = await analyse(
      await shaped({
        dependencies: 9,
        modules: 30,
        body: [
          "import { expressjwt, UnauthorizedError } from 'express-jwt';",
          'export function decide(secret: string, bad: boolean): unknown {',
          "  if (bad) throw new UnauthorizedError('invalid_token', { message: 'no' });",
          "  if (!secret) throw new UnauthorizedError('credentials_bad_scheme', { message: 'no' });",
          '  return expressjwt({ secret, algorithms: [] });',
          '}',
        ].join('\n'),
      }),
    );
    expect(operationsOf(throwing, 'src/security/decide.ts')).toEqual(['token@15']);
    expect(throwing.findings).toEqual([]);
  });

  it('reads a password comparison off the package that defines it', async () => {
    const hashing = await analyse(
      await shaped({
        dependencies: 9,
        modules: 30,
        body: [
          "import bcrypt from 'bcrypt';",
          'export async function decide(password: string, stored: string): Promise<boolean> {',
          '  const rehashed = await bcrypt.hash(password, 10);',
          '  return bcrypt.compare(rehashed, stored);',
          '}',
        ].join('\n'),
      }),
    );
    expect(operationsOf(hashing, 'src/security/decide.ts')).toEqual([
      'authentication@13',
      'authentication@14',
    ]);
    // Authentication is machinery, not enforcement: medium.
    expect(hashing.findings).toHaveLength(1);
    expect(hashing.findings[0]!.severity).toBe('medium');
  });
});

describe('VG-SMELL-021 — what the population excludes', () => {
  it('does not report a security module that lives under a test path', async () => {
    const inTests = await analyse(
      await shaped({ dependencies: 9, modules: 30, path: 'src/__tests__/decide.ts' }),
    );
    expect(fanOut(inTests, 'src/__tests__/decide.ts')).toBe(9);
    expect(
      operationsOf(inTests, 'src/__tests__/decide.ts'),
    ).toHaveLength(2);
    expect(inTests.findings).toEqual([]);
  });

  it('does not report a Python module, because it could not stay quiet on a Python guard', async () => {
    // The fan-out half of the rule is language-neutral and the membership half
    // is a list of Node APIs, so Python is excluded at the population rather
    // than being silently unable to fire. This asserts the exclusion is real:
    // the operations ARE there to be found in the text.
    const files: Record<string, string> = {};
    const imports: string[] = [];
    for (let i = 0; i < 9; i += 1) {
      files[`app/dep_${i}.py`] = `value_${i} = ${i}\n`;
      imports.push(`from .dep_${i} import value_${i}`);
    }
    files['app/authorize.py'] = `${imports.join('\n')}\n\n\ndef authorize(user):\n    if user.role == 'admin':\n        return True\n    return user.role != 'guest'\n`;
    files['app/main.py'] = 'from .authorize import authorize\n\nhandler = authorize\n';
    for (let f = 0; f < 20; f += 1) files[`app/filler_${f}.py`] = `filler_${f} = ${f}\n`;
    const python = await analyse(await writeProject(files));

    expect(fanOut(python, 'app/authorize.py')).toBe(9);
    const structure = python.project.structures.get('app/authorize.py')!;
    const source = python.project.files.find((s) => s.filePath === 'app/authorize.py')!;
    expect(securityOperations(structure, source.content)).toHaveLength(2);
    expect(python.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

describe('VG-SMELL-021 — determinism', () => {
  it('produces byte-identical findings across two independent scans', async () => {
    const first = await analyse(fixture('smell-021-authz-hub'));
    const second = await analyse(fixture('smell-021-authz-hub'));
    expect(JSON.stringify(second.findings)).toBe(JSON.stringify(first.findings));
  });

  it('declares the metadata the runner and the report depend on', async () => {
    expect(highFanoutSecurityModule.ruleId).toBe('VG-SMELL-021');
    expect(highFanoutSecurityModule.languages).toEqual(['typescript', 'javascript']);
    expect(highFanoutSecurityModule.category).toBe('security-design-smell');
    expect(highFanoutSecurityModule.cwe).toContain('CWE-1047');
  });
});

// ---------------------------------------------------------------------------
// Type erasure (#35)
// ---------------------------------------------------------------------------

/**
 * A security module with `values` value dependencies and `types` dependencies
 * that TypeScript deletes, written in whichever erasure form the test names.
 *
 * The shape is `whyour/qinglong back/loaders/express.ts` reduced to its
 * arithmetic: nine resolved edges, two of them erased, threshold eight. That
 * corpus finding is the reason this block exists, so the generator reproduces
 * the way it was written — `form: 'target'` is a PLAIN named import whose target
 * declares the name with `interface`/`type`, which no statement-level test can
 * see.
 */
async function erasureProject(opts: {
  values: number;
  types: number;
  form: 'target' | 'statement' | 'inline' | 'mixed' | 'doubled';
  modules: number;
}): Promise<string> {
  const files: Record<string, string> = {};
  const imports: string[] = [];

  for (let i = 0; i < opts.values; i += 1) {
    files[`src/dep-${i}.ts`] = `export const value${i} = ${i};\n`;
    imports.push(`import { value${i} } from '../dep-${i}.js';`);
  }
  for (let i = 0; i < opts.types; i += 1) {
    files[`src/shape-${i}.ts`] =
      opts.form === 'target' || opts.form === 'mixed' || opts.form === 'doubled'
        ? `export interface Shape${i} { id: string }\nexport const shapeName${i} = 'shape${i}';\n`
        : `export interface Shape${i} { id: string }\n`;
    if (opts.form === 'statement') imports.push(`import type { Shape${i} } from '../shape-${i}.js';`);
    else if (opts.form === 'inline') imports.push(`import { type Shape${i} } from '../shape-${i}.js';`);
    else if (opts.form === 'mixed') imports.push(`import { type Shape${i}, shapeName${i} } from '../shape-${i}.js';`);
    else if (opts.form === 'doubled') {
      imports.push(`import type { Shape${i} } from '../shape-${i}.js';`);
      imports.push(`import { shapeName${i} } from '../shape-${i}.js';`);
    } else imports.push(`import { Shape${i} } from '../shape-${i}.js';`);
  }

  files['src/security/decide.ts'] = `${[
    ...imports,
    '',
    'export function decide(user: { role: string; permissions: string[] }): boolean {',
    "  if (user.role === 'admin') return true;",
    "  return user.permissions.includes('read');",
    '}',
  ].join('\n')}\n`;
  files['src/consumer.ts'] = "import { decide } from './security/decide.js';\n\nexport const gate = decide;\n";

  let filler = 0;
  const used = (): number => Object.keys(files).filter((f) => /\.ts$/.test(f)).length;
  while (used() < opts.modules) {
    files[`src/filler-${filler}.ts`] = `export const filler${filler} = '${filler}';\n`;
    filler += 1;
  }
  return writeProject(files);
}

describe('VG-SMELL-021 — imports the compiler deletes are not fan-out', () => {
  const SECURITY = 'src/security/decide.ts';

  it('is silent at 7 value + 2 type-by-target imports, and says so about a RAW fan-out of 9', async () => {
    const analysis = await analyse(await erasureProject({ values: 7, types: 2, form: 'target', modules: 30 }));
    // ★ The premise, asserted first: the graph really does hold nine edges. This
    // is the number the rule used to threshold on, and the number that made
    // qinglong a finding. If the indexer ever stops producing these edges the
    // silence below would be vacuous, and this line is what fails instead.
    expect(fanOut(analysis, SECURITY)).toBe(9);
    expect(operationsOf(analysis, SECURITY).length).toBeGreaterThanOrEqual(2);
    expect(analysis.findings).toEqual([]);
  });

  it('fires at 8 value + 2 type-by-target imports — erasure removes edges, it does not disable the rule', async () => {
    const analysis = await analyse(await erasureProject({ values: 8, types: 2, form: 'target', modules: 30 }));
    expect(fanOut(analysis, SECURITY)).toBe(10);
    expect(analysis.findings).toHaveLength(1);
    // What the finding REPORTS is the filtered count, not the raw one — the
    // header's rule that the thresholded quantity and the published quantity are
    // the same number.
    expect(analysis.findings[0]!.metrics).toMatchObject({ fanOut: 8 });
    expect((analysis.findings[0]!.relatedLocations ?? []).length).toBeGreaterThan(0);
    for (const related of analysis.findings[0]!.relatedLocations ?? []) {
      expect(related.filePath).not.toMatch(/shape-\d+\.ts$/);
    }
  });

  it('erases the statement form `import type { X }`', async () => {
    const analysis = await analyse(await erasureProject({ values: 7, types: 2, form: 'statement', modules: 30 }));
    expect(fanOut(analysis, SECURITY)).toBe(9);
    expect(analysis.findings).toEqual([]);
  });

  it('erases the inline form `import { type X }`', async () => {
    const analysis = await analyse(await erasureProject({ values: 7, types: 2, form: 'inline', modules: 30 }));
    expect(fanOut(analysis, SECURITY)).toBe(9);
    expect(analysis.findings).toEqual([]);
  });

  it('keeps a mixed clause `import { type X, value }` — it still loads the module', async () => {
    const analysis = await analyse(await erasureProject({ values: 6, types: 2, form: 'mixed', modules: 30 }));
    expect(fanOut(analysis, SECURITY)).toBe(8);
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]!.metrics).toMatchObject({ fanOut: 8 });
  });

  it('counts a target imported twice — once for a type, once for a value — exactly once, and keeps it', async () => {
    // The failure this guards against is subtracting erased EDGES from a count of
    // TARGETS: two statements, one module, and the module is loaded.
    const analysis = await analyse(await erasureProject({ values: 6, types: 2, form: 'doubled', modules: 30 }));
    expect(fanOut(analysis, SECURITY)).toBe(8);
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]!.metrics).toMatchObject({ fanOut: 8 });
  });
});
