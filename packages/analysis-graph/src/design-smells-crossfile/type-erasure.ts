/**
 * What TypeScript erases, in one place — shared by the cross-file rules that have
 * to count edges the running program actually has.
 *
 * ★ WHY THIS FILE EXISTS AT ALL. It was extracted, verbatim and with its
 * measurements intact, from `cyclic-security-dependency.ts` (VG-SMELL-020),
 * where it was written and where it was private. VG-SMELL-021 read
 * `fanMetrics().fanOut` — the raw resolved-edge count — and therefore counted the
 * imports the compiler deletes. Two rules in the same directory held opposite
 * assumptions about the same question, and the corpus said which one was wrong:
 * `whyour/qinglong back/loaders/express.ts` was reported at fan-out 9 when two of
 * those nine were `AuthInfo` (an `interface`) and `AppScope` (a `type`). The real
 * fan-out is 7, below the rule's own threshold of 8. Copying the two functions
 * would have made a third answer possible; this file makes there be one.
 *
 * ★ WHAT IS DELIBERATELY NOT HERE. `isTypeCheckingGuarded` (Python
 * `if TYPE_CHECKING:`) and `isDeferredImport` (a `require` inside a function body)
 * stay in VG-SMELL-020. Neither is erasure: both describe an import that exists at
 * run time but does not run AT LOAD TIME, which is the only thing 020's
 * initialisation-order argument cares about. A lazily required module is still a
 * module the security decision depends on, so removing it from a FAN-OUT count
 * would understate the coupling this file's other consumer is measuring. The
 * distinction is the reason this module is named for erasure and not for
 * "imports that don't count".
 *
 * ★ KNOWN LIMITS OF THE ERASURE TEST, collected here so both consumers inherit the
 * same list rather than each discovering it:
 *   1. `export type { Foo } from './y'` — a type-only RE-EXPORT. `EXPORT_TYPE`
 *      wants an identifier after `type` and finds `{`, so `Foo` lands in neither
 *      set and the edge survives.
 *   2. `type Foo = …` declared locally and released with `export { Foo }` — the
 *      list form is recorded in `exportedNames` with no kind, so it reads as a
 *      value (also stated at `exportKindsOf` below).
 *   3. `import * as T from './types'` used only in type position — the namespace
 *      binding is a value by definition and cannot be resolved name by name.
 *   4. `.d.ts` targets, which are erased in full. VG-SMELL-020 drops them from the
 *      graph before it gets here; VG-SMELL-021's population filter does not, so
 *      the edge survives there. Left as-is rather than patched in passing: making
 *      the two rules agree about declaration files is a change to what 020
 *      considers a node, and it belongs in the commit that measures it.
 *   Every one of the four fails in the SAME direction — an edge is kept that could
 *   have been dropped — which for both consumers is the conservative side.
 *
 * ★ A THIRD, PARTIAL IMPLEMENTATION EXISTS and is not folded in:
 * `generated-boilerplate-unintegrated.ts` (VG-SMELL-052) has a `(?!type[^\\S\\r\\n])`
 * look-ahead of its own. It feeds a CONFIDENCE band rather than a threshold, and a
 * miscount there weakens the finding instead of inventing one, so the incentive to
 * unify is weaker. Recorded so the next person finds two call sites and not three.
 */

import type { ImportEdge, ProjectIndex, SourceFile, StructureIndex } from '../types.js';
/**
 * Whether an import statement is erased before the program runs.
 *
 * ★ THE TYPE-ONLY QUESTION, AND WHAT THE INDEX DOES NOT CARRY.
 *
 * `ImportEdge` has no type-only field: the structure indexer's `bindingNames`
 * drops the `type` keyword while splitting the clause and records nothing about
 * having seen it, so an `import type { User } from './user'` edge is
 * indistinguishable from a value import as far as `types.ts` is concerned. That
 * matters here more than anywhere else in the package, because a type-only cycle
 * is the single most common cycle in a TypeScript codebase and is completely
 * harmless — `import type` is elided by the compiler, so there is no load-time
 * dependency and no initialisation order to be wrong about.
 *
 * Rather than widen `ImportEdge` (a shared type, changed for one consumer) or
 * accept the false positives, the fact is recovered from the source text at
 * `edge.line`. That is exact for the forms the indexer can produce, which is the
 * important qualifier: `JS_IMPORT` requires the specifier and the `from` clause
 * on the SAME LINE as the `import` keyword, so a multi-line import produces no
 * edge at all and there is no case where this function is handed a statement
 * whose `type` marker lives on a line it cannot see.
 *
 * ★ MEASURED LIMIT — the multi-line import. The same property means a cycle
 * carried by a multi-line `import {\n  a,\n  b,\n} from './x'` is INVISIBLE to
 * this rule, because the graph has no edge for it. That is a recall loss, it is
 * not small in prettier-formatted codebases, and it is not repaired here: the fix
 * belongs in the structure indexer, where it would benefit every consumer, and
 * making it in a rule would mean this rule's graph disagreeing with the one every
 * other rule reads. The direction of the loss is the safe one — a missing edge
 * can only remove a cycle, never invent one.
 *
 * Both forms of erasure are handled: the statement-level `import type {...}` and
 * the inline `import { type A, type B }` where EVERY binding is a type. A mixed
 * `import { type A, b }` is a value import (it keeps `b` at runtime) and is
 * correctly not erased.
 */
const IMPORT_CLAUSE = /^[^\S\r\n]{0,8}import[^\S\r\n]{1,4}(?<clause>[^;'"\n]{0,200}?)[^\S\r\n]{1,4}from[^\S\r\n]{0,4}['"]/;

export function isTypeOnlyImport(lineText: string): boolean {
  const clause = IMPORT_CLAUSE.exec(lineText)?.groups?.clause;
  if (clause === undefined) return false;
  const trimmed = clause.trim();
  // `import type X from` / `import type { X } from` / `import type * as X from`.
  if (/^type\b/.test(trimmed)) return true;
  // Inline modifiers. Only a pure named clause can be wholly erased: a default
  // binding or a namespace binding is a value by definition, so `{` first and
  // `}` last is a precondition, not a convenience.
  if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) return false;
  const parts = trimmed
    .slice(1, -1)
    .split(',')
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  return parts.length > 0 && parts.every((p) => /^type\b/.test(p));
}

/**
 * What a module exports, split into what survives compilation and what does not.
 *
 * ★★ MEASURED CORRECTION — `import type` IS NOT THE ONLY ERASED IMPORT.
 *
 * From the 630-repository run:
 *
 *   pavlobu/deskreen  src/renderer/src/utils/message.ts
 *                     ↔ …/handleRecieveEncryptedMessage.ts
 *
 *   message.ts:1                          import { ProcessedMessage } from './handleRecieveEncryptedMessage';
 *   handleRecieveEncryptedMessage.ts:56   export type ProcessedMessage =
 *
 * `ProcessedMessage` is a TYPE, imported without the `type` keyword — which is
 * legal, extremely common in codebases predating TypeScript 3.8, and erased by
 * the compiler exactly as `import type` is, because the import is never used in a
 * value position. `isTypeOnlyImport` reads the import STATEMENT and cannot see
 * that: the statement is indistinguishable from a value import. The fact lives in
 * the file being imported.
 *
 * So the question is asked there instead. A name is erasable when the target
 * declares it with `type` or `interface` and does NOT also export it as a value.
 * Both halves are needed: declaration merging (`export interface Foo` alongside
 * `export const Foo`) is a real TypeScript idiom, and treating such a name as
 * erasable would drop an edge that does exist at run time.
 *
 * Computed once per file and cached, rather than per edge: the naive version
 * compiles two regexes for every imported name in the project, which on a
 * two-thousand-file repository is tens of thousands of `RegExp` constructions for
 * an answer that depends only on the target.
 *
 * ★ WHAT THIS DOES NOT CATCH, stated because the gap is the interesting part: a
 * name exported through `export { Foo }` at the bottom of the file is recorded in
 * `exportedNames` with no indication of whether it was a type, so it is treated
 * as a VALUE and the edge survives. That is the conservative direction — the rule
 * keeps an edge it might have dropped, which can only produce a cycle it might
 * have missed, never one that is not there.
 */
export interface ExportKinds {
  /** Names the compiler erases: `export type X`, `export interface X`. */
  types: Set<string>;
  /** Names that exist at run time. */
  values: Set<string>;
}

const EXPORT_TYPE =
  /(?:^|\n)[^\S\r\n]{0,8}export[^\S\r\n]{1,4}(?:declare[^\S\r\n]{1,4})?(?:type|interface)[^\S\r\n]{1,4}(?<name>[\w$]{1,60})/g;

function exportKindsOf(structure: StructureIndex, cache: Map<string, ExportKinds>): ExportKinds {
  const hit = cache.get(structure.filePath);
  if (hit) return hit;

  const types = new Set<string>();
  EXPORT_TYPE.lastIndex = 0;
  for (let m = EXPORT_TYPE.exec(structure.blanked); m; m = EXPORT_TYPE.exec(structure.blanked)) {
    const name = m.groups?.name;
    if (name) types.add(name);
    if (EXPORT_TYPE.lastIndex === m.index) EXPORT_TYPE.lastIndex += 1;
  }

  // `exportedNames` already carries every value export the indexer recognised —
  // including the `export { a, b }` list form — and the symbol names cover the
  // declarations it turned into symbols. Union of the two, so a name that is a
  // value by either route is a value.
  const values = new Set<string>(structure.exportedNames);
  for (const symbol of structure.symbols) values.add(symbol.name);

  const kinds = { types, values };
  cache.set(structure.filePath, kinds);
  return kinds;
}

/** Whether every name this ESM edge imports is erased by the TypeScript compiler. */
export function importsOnlyTypes(edge: ImportEdge, target: StructureIndex, cache: Map<string, ExportKinds>): boolean {
  // A bare `import './x'` is a side-effect import and is never erased; a
  // `require` has no types to erase.
  if (edge.syntax !== 'esm' || edge.names.length === 0) return false;
  const kinds = exportKindsOf(target, cache);
  for (const name of edge.names) {
    if (!kinds.types.has(name)) return false;
    if (kinds.values.has(name)) return false;
  }
  return true;
}

/**
 * The set of project files a module depends on AT RUN TIME — `graph.importsOf`
 * minus the edges the compiler deletes.
 *
 * ★ WHY A SET OF TARGETS AND NOT A COUNT OF EDGES. A module can import the same
 * file twice, once for a type and once for a value:
 *
 *   import type { Session } from './session';
 *   import { openSession } from './session';
 *
 * Subtracting erased EDGES from the fan-out would remove `./session` from a count
 * it belongs in. The question is per target — "is there any surviving reason to
 * load this file" — so the answer is accumulated per target, and one surviving
 * edge is enough.
 *
 * ★ MIRRORS `buildDependencyGraph`. The self-edge exclusion
 * (`resolved === edge.fromFile`, `dependency-graph/index.ts:181`) is repeated here
 * rather than inherited, because this function returns a subset of `importsOf` and
 * a subset that contained a key the superset cannot is not a subset. If that loop
 * ever admits self-edges, this one has to follow, and the test that catches the
 * divergence is the one asserting the unfiltered size equals `fanMetrics().fanOut`.
 *
 * `file` is optional because the statement-level test needs the source text and a
 * caller may not have it; passing `undefined` degrades to the target-side test
 * alone, which is the conservative direction (fewer edges dropped).
 */
export function runtimeImportTargets(
  structure: StructureIndex,
  project: ProjectIndex,
  file: SourceFile | undefined,
  cache: Map<string, ExportKinds>,
): Set<string> {
  const out = new Set<string>();
  for (const edge of structure.imports) {
    const target = edge.resolvedFile;
    if (target === undefined || target === structure.filePath) continue;
    if (file !== undefined && isTypeOnlyImport(file.lines[edge.line - 1] ?? '')) continue;
    const targetStructure = project.structures.get(target);
    if (targetStructure && importsOnlyTypes(edge, targetStructure, cache)) continue;
    out.add(target);
  }
  return out;
}
