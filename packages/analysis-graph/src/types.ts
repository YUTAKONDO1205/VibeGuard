// Internal types for the cross-file analysis graph.
//
// WHY THIS FILE EXISTS SEPARATELY FROM findings-schema
//
// `@vibeguard/findings-schema` is the contract with the OUTSIDE: what a consumer
// of a scan result receives. Everything here is the contract between the four
// submodules INSIDE this package (structure-indexer, dependency-graph,
// symbol-table, metrics) and the cross-file rules that read them. Those two
// contracts change for different reasons and at different rates — an internal
// refactor of how handlers are located must not be a schema change visible to
// the SARIF adapter — so they are separate files, and only the finding shapes
// cross the boundary.
//
// WHY THESE TYPES ARE BACKEND-AGNOSTIC
//
// 0.3.0-α indexes source LEXICALLY: regex heads plus balanced-block extraction
// over text with strings and comments blanked out, reusing the primitives that
// `@vibeguard/rules` already ships and already tests (`extractBlockAfter`,
// `blankJsLiterals`, `blankPyLiterals`). No AST parser is introduced, and that
// is a deliberate decision rather than a shortcut:
//
//  - The absolute constraint on this phase is that AST dependencies stay inside
//    this package so the "zero dependency / light / four channels agree" pillars
//    survive. Taking a parser dependency satisfies the letter of that (it IS
//    inside this package) while spending the thing the constraint protects: a
//    CLI user would install tens of megabytes of parser to run a design-smell
//    check. Not taking one satisfies it absolutely — this package has no
//    third-party dependencies at all.
//  - A parser buys exactness in TS/JS and nothing at all in Python, C, or the
//    five other languages on the roadmap, each of which would need its own. The
//    lexical layer generalises across all of them with one mechanism.
//
// The cost is real and is not hidden: lexical indexing cannot resolve types,
// cannot follow aliases, and will mis-handle sufficiently exotic syntax. Every
// rule built on it is therefore written to be conservative — see the negative
// conditions in design-smells-crossfile — and the finding confidence caps in
// this package reflect that the evidence is structural, not semantic.
//
// The escape hatch is the shape of `StructureIndex` itself: it describes WHAT a
// backend must produce, not HOW. Swapping in an AST-backed indexer later means
// adding a producer, not changing every consumer.

import type { CodeLocation, Confidence, DesignSmellFinding, Severity } from '@vibeguard/findings-schema';

/** A file admitted to the graph, already read and split. */
export interface SourceFile {
  /** Repo-relative, forward-slash separated. See `normalizePath`. */
  filePath: string;
  /** Detected language tag, matching `@vibeguard/rules` language names. */
  language: string;
  content: string;
  lines: string[];
}

/**
 * What kind of thing a `IndexedSymbol` is.
 *
 * `route-handler` and `middleware` are ROLES rather than syntactic kinds — the
 * same arrow function is one or the other depending on which argument position
 * it was registered in. They live in the same union because every consumer that
 * asks "what is this symbol" wants the role answer, and splitting kind from role
 * would mean every call site joins two fields to get back to the question it
 * actually had. `declaredKind` keeps the syntactic fact when it differs.
 */
export type SymbolKind =
  | 'function'
  | 'method'
  | 'class'
  | 'route-handler'
  | 'middleware';

/**
 * A named (or positionally identified) code structure with a body span.
 *
 * `bodyStart`/`bodyEnd` are offsets into `SourceFile.content`, NOT into the
 * blanked copy. Blanking preserves length by construction — every primitive in
 * `@vibeguard/rules` that blanks replaces characters one-for-one — so offsets
 * are interchangeable between the two, and keeping them anchored to the real
 * content means a consumer can slice the original text for a snippet without
 * having to know blanking happened.
 */
export interface IndexedSymbol {
  /** Best available name. Anonymous callbacks get a synthetic `<anonymous@LINE>`. */
  name: string;
  kind: SymbolKind;
  /** The syntactic kind, when the role in `kind` overrode it. */
  declaredKind?: 'function' | 'method' | 'class';
  filePath: string;
  /** 1-based line of the declaration head. */
  startLine: number;
  /** 1-based line of the last line of the body. */
  endLine: number;
  /** 1-based column of the declaration head. */
  startColumn: number;
  /** Offset of the first character of the body (after `{` / after the `:` line). */
  bodyStart: number;
  /** Offset one past the last character of the body. */
  bodyEnd: number;
  /** Whether the symbol is reachable from outside the file (`export`, `module.exports`). */
  exported: boolean;
  /** Decorator / annotation names attached to the declaration, without `@`. */
  decorators?: string[];
  /** The class this method belongs to, when applicable. */
  enclosingClass?: string;
}

/** One `import`/`require`/`#include` relationship between two files. */
export interface ImportEdge {
  fromFile: string;
  /** The specifier exactly as written (`./auth`, `express`, `sdk/gpio.h`). */
  specifier: string;
  /** Repo-relative path this resolved to, when it resolved inside the project. */
  resolvedFile?: string;
  /** Imported binding names, when the syntax names them. Empty for bare imports. */
  names: string[];
  /** 1-based line of the import statement. */
  line: number;
  /**
   * How the edge was written. `quoted`/`angled` are the C/C++ `#include` forms
   * and are kept apart because the distinction carries meaning there that it
   * does not in JS: an unresolved `quoted` include is a project file that is
   * missing, an unresolved `angled` one is usually just a system header the
   * analysis cannot see. Rules that must not guess (VG-AISC-002) key off this.
   */
  syntax: 'esm' | 'require' | 'quoted' | 'angled' | 'python';
}

/** A route registration binding an HTTP method + path to a handler. */
export interface RouteBinding {
  filePath: string;
  line: number;
  /** Lowercase HTTP verb, or `use` for middleware mounting, or `*` when unknown. */
  method: string;
  /** Route path literal, when it was a literal. */
  path?: string;
  /**
   * Names appearing BEFORE the final handler argument. In Express these are the
   * per-route guards (`router.get('/x', requireAdmin, handler)`), which is the
   * evidence that authorization was delegated rather than inlined.
   */
  middlewareNames: string[];
  /** Name of the final handler argument, or the synthetic name of an inline one. */
  handlerName?: string;
  /** The inline handler symbol, when the handler was written in place. */
  inlineHandler?: IndexedSymbol;
}

/**
 * The semantic role a symbol name suggests, from `symbol-table-builder`.
 *
 * A GUESS from the identifier, explicitly. The design addendum §8.2 calls this
 * module "identifier meaning inference", and inference from a name is exactly as
 * reliable as the naming discipline of the codebase — which for AI-generated
 * code is usually good, since generated names are conventional almost to a
 * fault. It is used to raise or lower confidence and to exclude candidates, and
 * never on its own as the reason a finding fires.
 */
export type SymbolRole =
  | 'role'
  | 'permission'
  | 'token'
  | 'user'
  | 'session'
  | 'request'
  | 'response'
  | 'validator'
  | 'sanitizer'
  | 'guard'
  | 'middleware';

/** What one file's structure looks like after indexing. */
export interface StructureIndex {
  filePath: string;
  language: string;
  symbols: IndexedSymbol[];
  imports: ImportEdge[];
  routes: RouteBinding[];
  /** Names this file exports, for resolving cross-file references. */
  exportedNames: string[];
  /** Content with strings and comments blanked, length-preserved. */
  blanked: string;
}

/** Identifier → inferred roles, project-wide. */
export interface SymbolTable {
  /** Roles inferred for a given identifier. Empty array is never stored. */
  roles: Map<string, SymbolRole[]>;
  /** Symbols judged to BE a guard/middleware, by `filePath\0name`. */
  guards: Set<string>;
}

/** The project-level dependency graph. */
export interface DependencyGraph {
  edges: ImportEdge[];
  /** file → files it imports (resolved only). */
  importsOf: Map<string, Set<string>>;
  /** file → files that import it (resolved only). */
  importedBy: Map<string, Set<string>>;
}

/**
 * Everything the cross-file rules read. Built once per scan, then read-only.
 */
export interface ProjectIndex {
  /** Absolute path of the directory the scan was rooted at. */
  rootDir: string;
  files: SourceFile[];
  /** filePath → structure. Same key space as `files[].filePath`. */
  structures: Map<string, StructureIndex>;
  graph: DependencyGraph;
  symbols: SymbolTable;
  /** Budget outcomes, empty when the whole project was analysed. */
  degradations: GraphDegradation[];
}

/**
 * A cross-file scan that COMPLETED but saw less than the whole project.
 *
 * Mirrors `ScanDegradation` in the schema rather than reusing it, because the
 * budget dimensions are different: a regex bound is per-rule and per-file, a
 * graph bound is per-PROJECT and has no rule to attribute to. It is converted to
 * a `ScanDegradation` at the point findings leave this package, where the
 * `ruleId` field can honestly be filled with the graph's own identifier.
 */
export interface GraphDegradation {
  kind: 'file-limit' | 'byte-cap' | 'graph-deadline';
  /** Human-readable, and explicit that the result is partial. */
  detail: string;
  /** Files admitted, of files seen. */
  admittedFiles?: number;
  totalFiles?: number;
}

/** Read-only view of the remaining budget, threaded through every phase. */
export interface GraphBudget {
  /** Whether the wall-clock deadline has passed. Checked at phase boundaries. */
  expired(): boolean;
  /** Record a degradation. Idempotent per kind. */
  report(d: GraphDegradation): void;
  degradations(): GraphDegradation[];
}

/** What a cross-file rule is handed. */
export interface CrossFileRuleContext {
  project: ProjectIndex;
  budget: GraphBudget;
}

/**
 * A rule that needs more than one file to reach its verdict.
 *
 * Deliberately NOT `RuleDefinition` from `@vibeguard/rules`. That interface
 * takes a single `content: string` and returns spans within it, which is not a
 * limitation to work around but the load-bearing property of the core engine:
 * it is what makes the same rule set runnable in a browser extension over a
 * textarea, and it is why all four channels can be shown to agree. Widening it
 * to accept a project would push cross-file analysis into the shared path and
 * from there into the Chrome and VS Code bundles — the exact outcome the phase
 * constraint forbids. So cross-file rules get their own interface, on this side
 * of the boundary, and the two rule systems meet only as `Finding`s.
 *
 * `analyze` returns findings WITHOUT `findingId`; the runner assigns those, so a
 * rule cannot accidentally emit duplicates or non-deterministic ids.
 */
export interface CrossFileRule {
  ruleId: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  defaultConfidence: Confidence;
  /** Languages the rule applies to; `['*']` for any. */
  languages: string[];
  cwe?: string[];
  owasp?: string[];
  references?: string[];
  remediation?: { why: string; how: string; exampleFix?: string };
  analyze(ctx: CrossFileRuleContext): CrossFileFinding[];
}

/** What a cross-file rule emits: a design-smell finding minus the assigned id. */
export type CrossFileFinding = Omit<DesignSmellFinding, 'findingId'>;

/** Re-exported for submodules so they need one import, not two. */
export type { CodeLocation };
