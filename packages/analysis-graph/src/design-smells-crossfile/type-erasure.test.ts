/**
 * What `type-erasure.ts` promises INDEPENDENTLY OF THE STRUCTURE INDEXER (#41).
 *
 * The behavioural tests for the filter live where the two consumers live —
 * `high-fanout-security-module.test.ts` (the six #35 regressions, qinglong's
 * shape as the lead case) and `cyclic-security-dependency.test.ts`. Nothing here
 * duplicates them.
 *
 * What is here is the property those tests cannot state, because they run the
 * real indexer and therefore inherit whatever it happens to record today: the
 * answer must not change when `exportedNames` starts carrying type declarations.
 * Until this commit it did change — `export interface Cfg` is indexed as
 * `exportedNames: ['interface']`, and `importsOnlyTypes` was reading that
 * accident as "Cfg is not a value". Ledger #36 will widen `JS_EXPORT`; the tests
 * below are written so that when it does, they still pass.
 *
 * The technique throughout: index the fixture for real, then ALSO hand the same
 * question a structure whose `exportedNames` is what a corrected indexer would
 * produce, and assert the two agree. No test asserts what the indexer currently
 * emits — that would be a tripwire on #36 rather than a guard for this file.
 */
import { describe, expect, it } from 'vitest';

import { indexFile } from '../structure-indexer/index.js';
import type { ImportEdge, SourceFile, StructureIndex } from '../types.js';
import { type ExportKinds, importsOnlyTypes } from './type-erasure.js';

function source(content: string, filePath = 'src/cfg.ts'): SourceFile {
  return { filePath, language: 'typescript', content, lines: content.split('\n') };
}

/** A plain named import — the `(c)` form, with no `type` keyword to read. */
function edgeFor(names: string[], resolvedFile = 'src/cfg.ts'): ImportEdge {
  return { fromFile: 'src/consumer.ts', specifier: './cfg.js', resolvedFile, names, line: 1, syntax: 'esm' };
}

/**
 * The same file as the indexer would see it AFTER `JS_EXPORT` learns about type
 * declarations: every name declared with `export type` / `export interface` also
 * present in `exportedNames`, and the bare-modifier artefacts (`'interface'`,
 * `'type'`, `'declare'`) gone.
 *
 * Simulated rather than produced by a patched indexer so that the assertion is
 * about THIS file's contract and does not need a second copy of the indexer to
 * exist. The simulation is exact for the case that matters: `values` gains the
 * type names.
 */
function asIfIndexerFixed(structure: StructureIndex, typeNames: string[]): StructureIndex {
  const kept = structure.exportedNames.filter((n) => !['interface', 'type', 'declare', 'abstract'].includes(n));
  return { ...structure, filePath: `${structure.filePath}#fixed`, exportedNames: [...new Set([...kept, ...typeNames])] };
}

/** Asks both structures the same question and fails unless they answer alike. */
function bothIndexers(content: string, typeNames: string[], names: string[]): boolean {
  const real = indexFile(source(content));
  const fixed = asIfIndexerFixed(real, typeNames);
  const cache = new Map<string, ExportKinds>();
  const a = importsOnlyTypes(edgeFor(names), real, cache);
  const b = importsOnlyTypes(edgeFor(names, fixed.filePath), fixed, cache);
  expect({ withCurrentIndexer: a, withCorrectedIndexer: b }).toEqual({ withCurrentIndexer: a, withCorrectedIndexer: a });
  return a;
}

describe('type erasure — the (c) form does not depend on how the indexer records exports', () => {
  it('erases `export interface Cfg` whether or not `exportedNames` contains `Cfg`', () => {
    expect(bothIndexers('export interface Cfg {\n  a: string;\n}\n', ['Cfg'], ['Cfg'])).toBe(true);
  });

  it('erases `export type Scope` whether or not `exportedNames` contains `Scope`', () => {
    expect(bothIndexers("export type Scope = 'a' | 'b';\n", ['Scope'], ['Scope'])).toBe(true);
  });

  it('erases `export declare interface D` in both worlds', () => {
    expect(bothIndexers('export declare interface D {\n  a: string;\n}\n', ['D'], ['D'])).toBe(true);
  });

  it("reproduces qinglong's pair — an interface and a type alias beside a real value export", () => {
    const content = [
      'export interface AuthInfo {',
      '  token: string;',
      '}',
      "export type AppScope = 'a' | 'b';",
      "export const VERSION = '1';",
      '',
    ].join('\n');
    expect(bothIndexers(content, ['AuthInfo', 'AppScope'], ['AuthInfo'])).toBe(true);
    expect(bothIndexers(content, ['AuthInfo', 'AppScope'], ['AuthInfo', 'AppScope'])).toBe(true);
    // The value export in the same file is untouched by the subtraction.
    expect(bothIndexers(content, ['AuthInfo', 'AppScope'], ['VERSION'])).toBe(false);
    expect(bothIndexers(content, ['AuthInfo', 'AppScope'], ['AuthInfo', 'VERSION'])).toBe(false);
  });

  it('reproduces the #35 fixture shape — `export interface ShapeN` beside `export const shapeNameN`', () => {
    const content = 'export interface Shape0 { id: string }\nexport const shapeName0 = \'shape0\';\n';
    expect(bothIndexers(content, ['Shape0'], ['Shape0'])).toBe(true);
    expect(bothIndexers(content, ['Shape0'], ['shapeName0'])).toBe(false);
  });
});

describe('type erasure — declaration merging is still a value (the constraint on #41)', () => {
  it('keeps `export interface Foo` + `export const Foo` as a value in both worlds', () => {
    expect(bothIndexers('export interface Foo {\n  a: string;\n}\nexport const Foo = { a: "1" };\n', ['Foo'], ['Foo'])).toBe(
      false,
    );
  });

  it('keeps `export interface Foo` + `export function Foo` as a value in both worlds', () => {
    const content = 'export interface Foo {\n  a: string;\n}\nexport function Foo(): number {\n  return 1;\n}\n';
    expect(bothIndexers(content, ['Foo'], ['Foo'])).toBe(false);
  });

  it('keeps `export interface Foo` + `export class Foo` as a value in both worlds', () => {
    const content = 'export interface Foo {\n  a: string;\n}\nexport class Foo {\n  a = "1";\n}\n';
    expect(bothIndexers(content, ['Foo'], ['Foo'])).toBe(false);
  });

  it('keeps `export type N` + `export namespace N` as a value — a namespace emits an IIFE', () => {
    // ★ This one is a REPAIR, not a preservation, and it is the only answer #41
    // changes on the indexer as it stands. `JS_EXPORT`'s modifier list omits
    // `namespace` exactly as it omits `interface`, so `exportedNames` reads
    // `['type', 'namespace']` and `N` was absent from `values` — a real runtime
    // dependency DROPPED, which is the unsafe direction. Both halves are legal
    // TypeScript; `tsc --noEmit` accepts this file. (`enum` is not testable here:
    // TS2567 forbids merging an enum with a type or an interface, so no name can
    // be in `types` and declared as an enum at the same time.)
    const content = "export type N = 'a';\nexport namespace N {\n  export const x = 1;\n}\n";
    expect(bothIndexers(content, ['N'], ['N'])).toBe(false);
  });

  it('keeps `export interface F` + `export namespace F` as a value — the same merge, type side', () => {
    const content = 'export interface F {\n  a: string;\n}\nexport namespace F {\n  export const x = 1;\n}\n';
    expect(bothIndexers(content, ['F'], ['F'])).toBe(false);
  });
});

describe('type erasure — forms the filter still refuses to touch', () => {
  it('treats a locally declared type released with `export { Foo }` as a value', () => {
    // Known limit 2 in the header: the list form carries no kind, and
    // `EXPORT_TYPE` needs `export` before `type`, so `Foo` is in neither `types`
    // nor the subtraction. Conservative direction — the edge survives. The other
    // arrangement, `export interface Foo` PLUS `export { Foo }`, is not a case
    // this has to answer: `tsc --noEmit` rejects it with TS2484.
    const content = 'type Foo = { a: string };\nexport { Foo };\n';
    expect(bothIndexers(content, [], ['Foo'])).toBe(false);
  });

  it('does not erase a name the target never exports at all', () => {
    expect(bothIndexers('export interface Cfg {\n  a: string;\n}\n', ['Cfg'], ['Other'])).toBe(false);
  });

  it('does not erase a bare side-effect import or a require', () => {
    const structure = indexFile(source('export interface Cfg {\n  a: string;\n}\n'));
    const cache = new Map<string, ExportKinds>();
    expect(importsOnlyTypes({ ...edgeFor([]), names: [] }, structure, cache)).toBe(false);
    expect(importsOnlyTypes({ ...edgeFor(['Cfg']), syntax: 'require' }, structure, cache)).toBe(false);
  });

  it('does not promote an unrelated value export when a type export exists beside it', () => {
    // The subtraction loops over `types`, so `helper` can never be reached by it
    // no matter what the indexer records.
    const content = 'export interface Cfg {\n  a: string;\n}\nexport const helper = 1;\n';
    expect(bothIndexers(content, ['Cfg'], ['helper'])).toBe(false);
  });
});
