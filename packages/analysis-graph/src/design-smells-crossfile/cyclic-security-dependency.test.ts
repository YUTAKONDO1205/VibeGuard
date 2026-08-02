// Tests for VG-SMELL-020 — Cyclic Security Dependency.
//
// Run against the rule OBJECT rather than through `analyzeProject`, because the
// rule is deliberately not in `design-smells-crossfile/index.ts` yet and
// `analyzeProject` would therefore never call it. The corpus is on disk under
// `samples/crossfile-fixtures/smell-020-*`, one directory per shape.
//
// ★ WHY EVERY NEGATIVE STATES ITS PREMISE BEFORE IT STATES ITS SILENCE
//
// `expect(findings).toEqual([])` is satisfied by an empty directory, by a fixture
// that lost a file in a rename, and by a rule that has stopped working. This
// repository has already had to reject that vacuous pass once. So each negative
// below first proves the thing that would have made the rule fire is present:
//
//   - "there is a cycle, and it is not a SECURITY cycle" asserts `runtimeCycles`
//     is non-empty.
//   - "these are security modules, and there is no cycle" asserts
//     `securityModulesIn` names them AND `runtimeCycles` is empty.
//   - "the edge is erased before the program runs" asserts the RAW dependency
//     graph still has both directions, so the silence comes from this rule's edge
//     filter and not from a fixture whose import stopped resolving.
//
// Without the premise, a fixture that decayed and a fixture that works are the
// same green tick.

import { describe, expect, it } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { designSmellLocationsAgree, type DesignSmellFinding } from '@vibeguard/findings-schema';
import { createBudget, type CreateBudgetOptions } from '../budget.js';
import { buildProjectIndex, collectProjectFiles } from '../project.js';
import type { CrossFileFinding, GraphBudget, ProjectIndex } from '../types.js';
import {
  cyclicSecurityDependency,
  runtimeCycles,
  securityModulesIn,
} from './cyclic-security-dependency.js';

const REPO_ROOT = resolve(__dirname, '../../../..');
const fixture = (name: string): string => resolve(REPO_ROOT, 'samples/crossfile-fixtures', name);

interface Analysis {
  findings: CrossFileFinding[];
  project: ProjectIndex;
  budget: GraphBudget;
}

/**
 * Index a directory once and return both the index and what the rule said.
 *
 * ONE `ProjectIndex` feeds both, deliberately: a helper that built a second index
 * for the premise assertions would let the premise pass against a graph the rule
 * never saw, which is precisely the failure the premises exist to rule out.
 */
const analyze = async (dir: string, options: CreateBudgetOptions = {}): Promise<Analysis> => {
  const budget = createBudget(options);
  const files = await collectProjectFiles(dir, budget, options);
  const project = buildProjectIndex(dir, files, budget);
  return { findings: cyclicSecurityDependency.analyze({ project, budget }), project, budget };
};

/** Whether the RAW graph — before this rule's edge filter — has both directions. */
const rawMutualEdge = (project: ProjectIndex, a: string, b: string): boolean =>
  (project.graph.importsOf.get(a)?.has(b) ?? false) &&
  (project.graph.importsOf.get(b)?.has(a) ?? false);

describe('VG-SMELL-020 — positive shapes', () => {
  it('reports the two-module ESM cycle a security module sits in', async () => {
    const { findings } = await analyze(fixture('smell-020-esm-pair'));
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.ruleId).toBe('VG-SMELL-020');
    expect(finding.filePath).toBe('src/auth/authenticator.ts');
    // The line of the import that carries the cycle out of the security module,
    // which is the line a fix has to touch.
    expect(finding.startLine).toBe(6);
    expect(finding.evidence).toEqual([
      "src/auth/authenticator.ts:6 imports '../app/context.js' → src/app/context.ts",
      "src/app/context.ts:3 imports '../auth/authenticator.js' → src/auth/authenticator.ts",
    ]);
  });

  it('files a single security module cycle at medium', async () => {
    const [finding] = (await analyze(fixture('smell-020-esm-pair'))).findings;
    expect(finding!.severity).toBe('medium');
    expect(finding!.confidence).toBe('medium');
    expect(finding!.scope).toBe('module');
  });

  it('raises severity when two security modules are on the same cycle', async () => {
    const { findings } = await analyze(fixture('smell-020-crypto-chain'));
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.severity).toBe('high');
    // Anchored at the lexicographically FIRST security module in the component,
    // not at whichever one a traversal reached first.
    expect(finding.filePath).toBe('src/crypto/jwt-signer.ts');
    expect(finding.description).toContain('2 of the modules on this cycle are security modules');
    expect(finding.evidence).toEqual([
      "src/crypto/jwt-signer.ts:3 imports '../config/runtime.js' → src/config/runtime.ts",
      "src/config/runtime.ts:3 imports '../crypto/keystore.js' → src/crypto/keystore.ts",
      "src/crypto/keystore.ts:3 imports './jwt-signer.js' → src/crypto/jwt-signer.ts",
    ]);
  });

  it('reports a module-scope CommonJS require cycle', async () => {
    const { findings } = await analyze(fixture('smell-020-cjs-require'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.filePath).toBe('lib/auth/permissions.js');
    expect(findings[0]!.severity).toBe('medium');
  });

  it('reports a Python package cycle', async () => {
    const { findings } = await analyze(fixture('smell-020-python-package'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.filePath).toBe('app/auth/oauth_client.py');
    expect(findings[0]!.evidence).toEqual([
      "app/auth/oauth_client.py:8 imports 'app.core.gateway' → app/core/gateway.py",
      "app/core/gateway.py:1 imports 'app.auth.oauth_client' → app/auth/oauth_client.py",
    ]);
  });

  it('derives securityContext from the words actually on the cycle', async () => {
    // `crypto`/`jwt` — an authorization flag here would be a claim the rule did
    // not make about a module that signs and decides nothing.
    const [crypto] = (await analyze(fixture('smell-020-crypto-chain'))).findings;
    expect(crypto!.securityContext).toEqual({ containsTokenLogic: true, containsCryptoLogic: true });
    const [authn] = (await analyze(fixture('smell-020-esm-pair'))).findings;
    expect(authn!.securityContext).toEqual({ containsAuthorizationLogic: true });
  });

  it('keeps the flat location and the structured one in agreement', async () => {
    for (const name of ['smell-020-esm-pair', 'smell-020-crypto-chain', 'smell-020-cjs-require']) {
      const [finding] = (await analyze(fixture(name))).findings;
      expect(designSmellLocationsAgree(finding as DesignSmellFinding)).toBe(true);
      expect(finding!.primaryLocation!.filePath).toBe(finding!.filePath);
    }
  });

  it('cites the rest of the cycle as related locations', async () => {
    const [finding] = (await analyze(fixture('smell-020-crypto-chain'))).findings;
    expect((finding!.relatedLocations ?? []).map((l) => l.filePath)).toEqual([
      'src/config/runtime.ts',
      'src/crypto/keystore.ts',
    ]);
  });

  it('measures fan-in and fan-out through the shared metrics module', async () => {
    const [finding] = (await analyze(fixture('smell-020-esm-pair'))).findings;
    expect(finding!.metrics).toEqual({ importCount: 1, fanIn: 1, fanOut: 1 });
  });

  it('produces byte-identical findings on a second run', async () => {
    // Determinism is the property the SCC formulation was chosen for; a rotation
    // that varied between runs would defeat `stableId` and every baseline built
    // on it.
    const first = await analyze(fixture('smell-020-crypto-chain'));
    const second = await analyze(fixture('smell-020-crypto-chain'));
    expect(JSON.stringify(second.findings)).toBe(JSON.stringify(first.findings));
  });
});

describe('VG-SMELL-020 — the falsification corpus', () => {
  it('stays silent on a cycle between modules that are not security modules', async () => {
    const { findings, project } = await analyze(fixture('smell-020-neg-plain-cycle'));
    // Premise: the cycle IS there and this rule's own graph sees it.
    expect(runtimeCycles(project)).toEqual([['src/cart/basket.ts', 'src/cart/pricing.ts']]);
    expect(securityModulesIn(project)).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('stays silent when a security word appears with no security placement', async () => {
    const { findings, project } = await analyze(fixture('smell-020-neg-surface-only'));
    expect(runtimeCycles(project)).toEqual([['src/billing/invoice.ts', 'src/billing/ledger.ts']]);
    // The surface half of the test would pass — `encryptInvoice` carries a word.
    expect(project.structures.get('src/billing/invoice.ts')!.exportedNames).toContain(
      'encryptInvoice',
    );
    expect(securityModulesIn(project)).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('stays silent when a security placement has no security surface', async () => {
    const { findings, project } = await analyze(fixture('smell-020-neg-placement-only'));
    expect(runtimeCycles(project)).toEqual([['src/app/boot.ts', 'src/auth/constants.ts']]);
    // The placement half of the test would pass — the file is under `auth/`.
    expect(project.structures.has('src/auth/constants.ts')).toBe(true);
    expect(securityModulesIn(project)).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('stays silent on security modules that are correctly acyclic', async () => {
    const { findings, project } = await analyze(fixture('smell-020-neg-no-cycle'));
    // Premise, both halves: the security modules ARE recognised, and there is no
    // cycle for them to be in.
    expect(securityModulesIn(project)).toEqual(['src/auth/keystore.ts', 'src/auth/verifier.ts']);
    expect(runtimeCycles(project)).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('stays silent when one direction of the cycle is `import type`', async () => {
    const { findings, project } = await analyze(fixture('smell-020-neg-type-only'));
    // Premise: the RAW graph has both directions, so the silence comes from this
    // rule's edge filter rather than from an import that stopped resolving.
    expect(rawMutualEdge(project, 'src/auth/verifier.ts', 'src/app/context.ts')).toBe(true);
    expect(securityModulesIn(project)).toEqual(['src/auth/verifier.ts']);
    expect(runtimeCycles(project)).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('stays silent when a TYPE is imported without the `type` keyword', async () => {
    const { findings, project } = await analyze(fixture('smell-020-neg-type-by-target'));
    expect(rawMutualEdge(project, 'src/auth/verifier.ts', 'src/app/context.ts')).toBe(true);
    // The import STATEMENT looks exactly like a value import — the fact that
    // `SessionShape` is erasable lives in the file being imported.
    expect(project.structures.get('src/auth/verifier.ts')!.imports[0]!.names).toEqual([
      'SessionShape',
    ]);
    expect(securityModulesIn(project)).toEqual(['src/auth/verifier.ts']);
    expect(runtimeCycles(project)).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('stays silent on a cycle between two view components', async () => {
    const { findings, project } = await analyze(fixture('smell-020-neg-view-components'));
    expect(
      rawMutualEdge(
        project,
        'src/components/login/auth-form.ts',
        'src/components/login/otp-form.ts',
      ),
    ).toBe(true);
    expect(runtimeCycles(project)).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('stays silent when a Python back edge is under `if TYPE_CHECKING:`', async () => {
    const { findings, project } = await analyze(fixture('smell-020-neg-type-checking'));
    expect(rawMutualEdge(project, 'pkg/auth/oauth_client.py', 'pkg/core/gateway.py')).toBe(true);
    expect(securityModulesIn(project)).toEqual(['pkg/auth/oauth_client.py']);
    expect(runtimeCycles(project)).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('stays silent when the `require` was deferred into a function', async () => {
    const { findings, project } = await analyze(fixture('smell-020-neg-lazy-require'));
    expect(rawMutualEdge(project, 'lib/auth/permissions.js', 'lib/registry.js')).toBe(true);
    expect(securityModulesIn(project)).toEqual(['lib/auth/permissions.js']);
    expect(runtimeCycles(project)).toEqual([]);
    expect(findings).toEqual([]);
    // And the module-scope twin of the same project still fires, so the silence
    // above is the deferral and not the shape.
    expect((await analyze(fixture('smell-020-cjs-require'))).findings).toHaveLength(1);
  });

  it('stays silent on a C `#include` cycle between two crypto headers', async () => {
    const { findings, project } = await analyze(fixture('smell-020-neg-c-headers'));
    expect(rawMutualEdge(project, 'src/crypto_engine.h', 'src/keystore.h')).toBe(true);
    // Both headers would qualify as security modules if the edges counted, which
    // is what makes this fixture a test of `RUNTIME_SYNTAX` rather than of the
    // vocabulary.
    expect(securityModulesIn(project)).toContain('src/keystore.h');
    expect(securityModulesIn(project)).toContain('src/crypto_engine.h');
    expect(runtimeCycles(project)).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('stays silent on an ORM schema cycle between two table definitions', async () => {
    const { findings, project } = await analyze(fixture('smell-020-neg-orm-models'));
    expect(rawMutualEdge(project, 'src/models/certificate.ts', 'src/models/server.ts')).toBe(true);
    expect(runtimeCycles(project)).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('stays silent when the cycle only closes through a test harness', async () => {
    const { findings, project } = await analyze(fixture('smell-020-neg-test-path'));
    expect(rawMutualEdge(project, 'src/auth/verifier.ts', 'tests/harness.ts')).toBe(true);
    expect(runtimeCycles(project)).toEqual([]);
    expect(findings).toEqual([]);
  });

  it('reports nothing on the safe corpus', async () => {
    const safe = resolve(REPO_ROOT, 'samples/crossfile-safe');
    const { findings } = await analyze(safe);
    expect(findings).toEqual([]);
  });
});

/**
 * Shapes that no checked-in fixture can express.
 *
 * Written to a temporary directory rather than to `samples/`, because each one
 * needs either hundreds of files or a spelling nobody writes by hand, and a
 * corpus directory is read by people as much as by tests.
 */
describe('VG-SMELL-020 — bounds and synthetic shapes', () => {
  const withProject = async (
    files: Record<string, string>,
    body: (dir: string) => Promise<void>,
  ): Promise<void> => {
    const dir = await mkdtemp(join(tmpdir(), 'vg-smell020-'));
    try {
      for (const [name, content] of Object.entries(files)) {
        await mkdir(dirname(join(dir, name)), { recursive: true });
        await writeFile(join(dir, name), content, 'utf8');
      }
      await body(dir);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  };

  it('excludes `.d.ts` files, which emit no code to order', async () => {
    // The only spelling that makes a declaration file resolvable at all: the
    // NodeNext `.js` suffix, which `resolveSpecifier` rewrites back onto
    // `crypto-keys.d`. Contrived on purpose — it is the one shape that reaches
    // the check, and a check nothing can reach is a check nobody has run. Both
    // imports are VALUE imports, so `DECLARATION_FILE` is the only thing standing
    // between this project and a finding.
    await withProject(
      {
        'src/crypto-keys.d.ts':
          "import { useKeystore } from './runtime.js';\n" +
          'export function keystoreShape(): string {\n  return useKeystore();\n}\n',
        'src/runtime.ts':
          "import { keystoreShape } from './crypto-keys.d.js';\n" +
          "export function useKeystore(): string {\n  return 'k';\n}\n" +
          'export function shape(): string {\n  return keystoreShape();\n}\n',
      },
      async (dir) => {
        const { findings, project } = await analyze(dir);
        // Premise: the file was read, and the raw graph really does close a loop.
        expect(project.structures.has('src/crypto-keys.d.ts')).toBe(true);
        expect(rawMutualEdge(project, 'src/crypto-keys.d.ts', 'src/runtime.ts')).toBe(true);
        expect(runtimeCycles(project)).toEqual([]);
        expect(findings).toEqual([]);
      },
    );
  });

  it('truncates the illustrated path and says so', async () => {
    // One security module (`src/auth/authenticator.ts`) and fourteen ordinary
    // hops, so the shortest cycle through it is fifteen modules long.
    const hop = (i: number): string => `src/hop${String(i).padStart(2, '0')}.ts`;
    const files: Record<string, string> = {
      'src/auth/authenticator.ts':
        "import { hop01 } from '../hop01.js';\n" +
        'export function authenticate(): number {\n  return hop01();\n}\n',
    };
    for (let i = 1; i <= 14; i += 1) {
      const nextSpecifier = i === 14 ? './auth/authenticator.js' : `./hop${String(i + 1).padStart(2, '0')}.js`;
      const nextName = i === 14 ? 'authenticate' : `hop${String(i + 1).padStart(2, '0')}`;
      files[hop(i)] =
        `import { ${nextName} } from '${nextSpecifier}';\n` +
        `export function hop${String(i).padStart(2, '0')}(): number {\n  return ${nextName}();\n}\n`;
    }
    await withProject(files, async (dir) => {
      const { findings } = await analyze(dir);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.filePath).toBe('src/auth/authenticator.ts');
      expect(findings[0]!.evidence).toHaveLength(12);
      expect(findings[0]!.description).toContain('truncated at 12 modules');
    });
  });

  it('caps the number of cycles examined and reports the truncation', async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 201; i += 1) {
      const tag = String(i).padStart(3, '0');
      files[`pkg${tag}/authenticator.ts`] =
        `import { authorize } from './authority-check.js';\nexport function authenticate(): boolean {\n  return authorize();\n}\n`;
      files[`pkg${tag}/authority-check.ts`] =
        `import { authenticate } from './authenticator.js';\nexport function authorize(): boolean {\n  return authenticate();\n}\n`;
    }
    await withProject(files, async (dir) => {
      // A generous deadline, so the truncation under test is the COMPONENT cap
      // and not the wall clock — `createBudget` reports one `graph-deadline` per
      // scan, and the two would be indistinguishable in the assertion below.
      const { findings, budget } = await analyze(dir, { deadlineMs: 600_000 });
      expect(findings).toHaveLength(200);
      const detail = budget.degradations().map((d) => d.detail).join('\n');
      expect(detail).toContain('VG-SMELL-020 examined the first 200 of 201 import cycles');
    });
  });

  it('picks the same successor whatever order the imports were written in', async () => {
    // `alpha` and `zeta` close cycles of equal length back to `hub`, so the only
    // thing separating them is the order the adjacency list is walked in. The
    // imports are written zeta-first, so an unsorted successor list would cite
    // `zeta` and a sorted one cites `alpha`.
    await withProject(
      {
        'src/auth/hub.ts':
          "import { zeta } from './zeta.js';\nimport { alpha } from './alpha.js';\n" +
          'export function authenticate(): number {\n  return zeta() + alpha();\n}\n',
        'src/auth/zeta.ts':
          "import { authenticate } from './hub.js';\nexport function zeta(): number {\n  return authenticate();\n}\n",
        'src/auth/alpha.ts':
          "import { authenticate } from './hub.js';\nexport function alpha(): number {\n  return authenticate();\n}\n",
      },
      async (dir) => {
        const { findings } = await analyze(dir);
        expect(findings).toHaveLength(1);
        expect(findings[0]!.evidence![0]).toBe(
          "src/auth/hub.ts:2 imports './alpha.js' → src/auth/alpha.ts",
        );
      },
    );
  });

  it('does not depend on the order the index was populated in', async () => {
    // `Map` iteration is insertion order, and insertion order here is the
    // directory walk — already sorted, so no on-disk fixture can exercise the
    // explicit sort. Re-inserting the same structures backwards is the only way
    // to ask the question, and a caller that builds a `ProjectIndex` some other
    // way is exactly who the sort protects.
    const forward = await analyze(fixture('smell-020-crypto-chain'));
    const reversed: ProjectIndex = {
      ...forward.project,
      files: [...forward.project.files].reverse(),
      structures: new Map([...forward.project.structures.entries()].reverse()),
    };
    const findings = cyclicSecurityDependency.analyze({
      project: reversed,
      budget: createBudget(),
    });
    expect(JSON.stringify(findings)).toBe(JSON.stringify(forward.findings));
  });

  it('orders findings by cycle rather than by the order cycles were discovered', async () => {
    // Tarjan emits a component when its root FINISHES. `aaa-entry.ts` sorts
    // first, so it is the first DFS root, and it leads straight into the
    // `yankee`/`zulu` cycle — which is therefore DISCOVERED before the
    // `bravo`/`charlie` one even though it sorts after it. Discovery order is
    // yankee-then-bravo; sorted order is bravo-then-yankee.
    await withProject(
      {
        'src/auth/aaa-entry.ts': "import { zulu } from './zulu.js';\nexport const ENTRY = zulu;\n",
        'src/auth/yankee.ts':
          "import { zulu } from './zulu.js';\nexport function yankee(): number {\n  return zulu();\n}\nexport function authenticate(): boolean {\n  return true;\n}\n",
        'src/auth/zulu.ts':
          "import { yankee } from './yankee.js';\nexport function zulu(): number {\n  return yankee();\n}\n",
        'src/auth/bravo.ts':
          "import { charlie } from './charlie.js';\nexport function bravo(): number {\n  return charlie();\n}\nexport function authorize(): boolean {\n  return true;\n}\n",
        'src/auth/charlie.ts':
          "import { bravo } from './bravo.js';\nexport function charlie(): number {\n  return bravo();\n}\n",
      },
      async (dir) => {
        const { findings } = await analyze(dir);
        expect(findings.map((f) => f.filePath)).toEqual(['src/auth/bravo.ts', 'src/auth/yankee.ts']);
      },
    );
  });

  it('returns nothing, loudly, when the budget is already spent', async () => {
    const { findings, budget } = await analyze(fixture('smell-020-esm-pair'), { deadlineMs: 0 });
    expect(findings).toEqual([]);
    expect(budget.degradations().some((d) => d.kind === 'graph-deadline')).toBe(true);
  });
});
