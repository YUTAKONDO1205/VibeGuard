// VG-RTOS-003 — cross-file shared ISR variable missing `volatile`.
//
// #20d, and the third deliverable #20b was split away from. VG-RTOS-002 in
// `@vibeguard/rules` already catches this defect when the interrupt handler and
// the reader live in ONE file — its own description says "SAME-FILE ONLY". This
// is the rest of it: the handler in `isr.c`, the reader in `main.c`, and the
// shared variable declared in a header that both translation units include.
// That split is not an exotic arrangement; it is how a driver is normally
// written, and it is where a code generator puts one by default.
//
// ★ WHY THIS DID NOT WAIT FOR TYPE INFORMATION
//
// The plan (実装順 #20d) deferred this to 山③ "until type information is
// available", on the correct observation that `volatile` is a property of the
// DECLARATION's type and that a lexical scan cannot tell one `count` from
// another `count`. The premise stopped holding when #20 decided not to take an
// AST/parser dependency at all: there is no later phase in which types arrive
// for free, so "wait for types" would have meant waiting forever while the
// same-file half of the rule shipped and the cross-file half stayed a TODO. A
// permanently deferred rule and a deleted rule are the same artefact.
//
// So this is built the way VG-AISC-002 and VG-AISC-003 were: comparative
// evidence rather than absolute, a quoted-include closure as the guard on
// identity, deliberate under-approximation everywhere the text is ambiguous,
// and confidence capped at `medium` because the evidence is lexical.
//
// ★ THE ONE FALSE POSITIVE THAT MATTERS: TWO VARIABLES, ONE NAME
//
// Everything hard about this rule is that `tick_count` in `isr.c` and
// `tick_count` in `main.c` may be two unrelated objects. Three guards kill that,
// and each one is a silence rather than a guess:
//
//  1. EXACTLY ONE declaration in a project header, project-wide. Two headers
//     declaring the same name means the include path decides which one a given
//     file sees, and the include path is precisely what this analysis does not
//     have (`resolveSpecifier` refuses ambiguous suffix matches for the same
//     reason). Two declarations therefore produce silence, not a choice.
//  2. A CLOSED SET OF BUILTIN TYPES. `typedef volatile uint32_t reg_t;` makes
//     `reg_t tick;` a correctly-qualified declaration that contains no
//     `volatile` token, and no amount of regex on the declaration line can see
//     it. So a declaration whose type is not one of the builtin scalars is not
//     "unqualified", it is UNKNOWN, and unknown means quiet. This is why the
//     type set here is narrower than VG-RTOS-002's: that rule accepts `word` and
//     `byte`, which are Arduino typedefs and could carry `volatile` the same way.
//  3. NO SHADOWING DECLARATION in the accusing files. A parameter, a local, or a
//     struct member with the same name in the handler's file or the reader's
//     file means the token this rule counted as "the shared variable" may be
//     something else entirely. Silence again.
//
// ★ OPTIONS CONSIDERED AND REJECTED
//
//  - "Report any non-volatile global written in an ISR." Unshippable for the
//    same reason the naive form of VG-AISC-002 was: a file-local counter that
//    nothing outside the handler reads is not a bug, and firmware is full of
//    them. The finding has to be about a variable that is demonstrably SHARED,
//    which is what the header declaration plus a reader in another file
//    establishes.
//  - "Accept several declarations and pick the one inside the reader's include
//    closure." Attractive and wrong: preprocessor conditionals mean two
//    declarations can both be in the closure and only one be live, and this
//    analysis does not evaluate `#if`. Picking would be inventing the answer.
//  - "Trust that a name is shared because it looks global (SCREAMING_CASE, a
//    `g_` prefix)." A naming convention is not a declaration, and a rule that
//    fires on spelling would fire hardest on the tidy generated code this
//    project is aimed at.
//  - "Report the ISR write site instead of the declaration." The fix is on the
//    declaration — and on the definition, which must agree with it — so that is
//    where the finding is filed. The write and the read travel as
//    `relatedLocations`, which is what §21's schema exists for.
//
// ★ WHY THE ISR HEAD FORMS ARE COPIED RATHER THAN IMPORTED
//
// `collectIsrBlocks` is private to `packages/rules/src/rules/embedded-rtos.ts`.
// Exporting it would promote one rule's internal heuristic into
// `@vibeguard/rules`' published surface so that a single consumer on the other
// side of the package boundary could share it — the same trade `metrics/index.ts`
// refused when it duplicated `BRANCH_WORD`/`BRANCH_OP`, and it is refused here
// for the same reason. The copy is exact and the mitigation is the same one: the
// head forms are pinned in this rule's test, so a divergence from VG-RTOS-002
// surfaces as a failing assertion rather than as two rules quietly disagreeing
// about what an interrupt handler is.

import type { Confidence, Severity } from '@vibeguard/findings-schema';
import { DESIGN_SMELL_CATEGORY } from '@vibeguard/findings-schema';
import { extractBlockAfter, REGEX_MATCH_LIMIT, type ExtractedBlock } from '@vibeguard/rules';
import { includeClosure } from '../dependency-graph/index.js';
import { fanMetrics } from '../metrics/index.js';
import type {
  CodeLocation,
  CrossFileFinding,
  CrossFileRule,
  CrossFileRuleContext,
  StructureIndex,
} from '../types.js';

/** Languages this rule applies to. Enforced PER FILE — see `analyze`. */
const C_LANGUAGES = new Set(['c', 'cpp']);

/** Header extensions. A declaration only counts as shared when it is in one. */
const HEADER = /\.(?:h|hpp|hh|ipp)$/i;

/** Path segments whose contents are fixtures, not shipped firmware. */
const TEST_PATH =
  /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|mocks?|examples?|samples?|testdata)(?:\/|$)|_test\.[ch]\w{0,3}$/i;

/**
 * How many distinct identifiers written inside interrupt handlers are examined.
 *
 * A bound rather than a judgement: every candidate costs one declaration scan
 * per file, so an adversarial input with hundreds of assignments in one handler
 * would otherwise turn a linear pass into a quadratic one. 200 is far above what
 * any real handler writes (they are supposed to be short), so the cap is a
 * safety net that never fires on the population the rule targets.
 */
const MAX_CANDIDATES = 200;

/** Readers listed in `relatedLocations`. The claim needs one; more is context. */
const MAX_RELATED_READERS = 4;

/**
 * Scalar types a declaration may use and still be REPORTABLE.
 *
 * Deliberately narrower than VG-RTOS-002's `SCALAR_TYPE`, which also accepts
 * `word` and `byte`. Those are Arduino typedefs, and a typedef is exactly the
 * hole this rule cannot see through: `typedef volatile uint8_t byte;` would make
 * a correctly-qualified declaration look bare. Only types whose definition is
 * the language's own are admitted.
 */
const BUILTIN_TYPE = '(?:bool|_Bool|char|short|int|long|float|double|size_t|u?int(?:8|16|32|64)_t)';

/**
 * Types a declaration may use and still be RECOGNISED as a declaration.
 *
 * Wider on purpose. Recognition and reportability are different questions: a
 * `reg_t tick;` must be seen (so it can veto the finding, both as a second
 * declaration and as a shadowing local) but must never be reported (its
 * qualification is unknowable here). Anything ending in `_t` is the C convention
 * for a typedef and is the shape almost every SDK register type takes.
 *
 * `auto` is here for the C++ arm: `auto tick_count = 0;` inside a function is a
 * local that shadows, and a pattern that did not recognise it as a declaration
 * would let that local be mistaken for the shared variable.
 */
const OPAQUE_TYPE = '(?:word|byte|auto|[A-Za-z_]\\w{0,38}_t)';

const ANY_TYPE = `(?:${BUILTIN_TYPE}|${OPAQUE_TYPE})`;

/** Storage-class and type-modifier keywords that may precede the type. */
const QUALIFIER = '(?:extern|static|const|volatile|register|_Atomic|unsigned|signed|long|short)';

/**
 * Qualification that means the variable is NOT the defect this rule reports.
 *
 * `volatile` and the atomics are the fix. `const` and `register` are a different
 * (and compiler-caught) problem: an ISR cannot legally write either, so a match
 * means this rule mis-read the text and must not accuse anyone. Matched case
 * insensitively and as a substring for `atomic`, so `_Atomic`, `atomic_uint`,
 * and `std::atomic` are all covered by one test.
 */
const PROTECTED = /atomic|volatile|\bconst\b|\bregister\b/i;

/**
 * How far back from a declaration the `volatile` search reaches.
 *
 * A declaration split across lines — `extern volatile\n uint32_t tick;` — puts
 * the qualifier outside the matched text, and reporting it would be reporting a
 * correctly-written variable. The look-back can only ADD silence, so a window
 * that is too generous costs recall and never correctness.
 */
const QUALIFIER_LOOKBACK = 120;

/**
 * A bare-identifier write. Byte-identical to VG-RTOS-002's `WRITE`.
 *
 * The lookbehind is what keeps `s.count = 1` and `p->count = 1` out: a member
 * write is a write to the struct, and the struct is not what any header declared
 * as a scalar. `=[^=]` excludes `==`; `!=`, `<=`, and `>=` are excluded because
 * their operator character is not in the class.
 */
const WRITE = /(?<![\w.>])(?<name>[A-Za-z_]\w{0,40})[ \t]{0,8}(?:=[^=]|\+\+|--|[+\-*/%|&^]=)/g;

/** Identifiers that appear in write position but are not variables. */
const NOT_A_VARIABLE = new Set(['if', 'for', 'while', 'switch', 'return', 'else', 'do', 'case']);

function escapeRe(name: string): string {
  return name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Every declaration-shaped occurrence of `name`, wherever it sits.
 *
 * One pattern for both questions the rule asks — "is this declared at file scope
 * in a header" and "is something with this name declared locally" — because two
 * patterns would drift and the drift would be invisible: a local form the
 * shadow check did not recognise is a false positive, and there is no test that
 * fails when a regex quietly stops covering a case.
 *
 * KNOWN MISS: a second declarator in a list (`uint32_t a, tick;`) is not seen,
 * because the type token belongs to the first. VG-RTOS-002 has the same gap. The
 * consequence is a missed veto, so it is recorded here rather than papered over.
 */
function declPattern(name: string): RegExp {
  return new RegExp(
    `(?:^|[;{(,\\n])[ \\t]{0,20}` +
      `(?<decl>(?:${QUALIFIER}[ \\t]{1,8}){0,4}(?<type>${ANY_TYPE})[ \\t]{1,8}` +
      `(?<ptr>\\*{0,3})[ \\t]{0,4}${escapeRe(name)}[ \\t]{0,8}(?<tail>[=;,)\\[]))`,
    'g',
  );
}

const IS_BUILTIN = new RegExp(`^${BUILTIN_TYPE}$`);

/**
 * Brace nesting depth at every brace offset, so "file scope" can be asked
 * properly instead of guessed from the column.
 *
 * VG-RTOS-002 approximates file scope as "starts in column 0", which is right
 * for C and wrong for the C++ this rule also runs on: a class or namespace body
 * written flush-left puts a MEMBER declaration in column 0, and reporting that
 * as a shared global would be an accusation about the wrong object. Counting
 * braces over blanked text (strings and comments already neutralised, so a brace
 * inside either is not counted) answers the question exactly, and one pass per
 * file amortises over every candidate name.
 */
interface BraceIndex {
  offsets: number[];
  depths: number[];
}

function buildBraceIndex(blanked: string): BraceIndex {
  const offsets: number[] = [];
  const depths: number[] = [];
  let depth = 0;
  for (let i = 0; i < blanked.length; i += 1) {
    const c = blanked.charCodeAt(i);
    if (c === 123 /* { */) {
      depth += 1;
      offsets.push(i);
      depths.push(depth);
    } else if (c === 125 /* } */) {
      depth -= 1;
      offsets.push(i);
      depths.push(depth);
    }
  }
  return { offsets, depths };
}

/** Nesting depth immediately before `offset`. */
function depthAt(index: BraceIndex, offset: number): number {
  let lo = 0;
  let hi = index.offsets.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (index.offsets[mid]! < offset) {
      found = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return found === -1 ? 0 : index.depths[found]!;
}

/** 1-based line/column of `offset` in `text`. */
function positionOf(text: string, offset: number): { line: number; column: number } {
  let line = 1;
  let lastBreak = -1;
  const limit = Math.min(offset, text.length);
  for (let i = 0; i < limit; i += 1) {
    if (text[i] === '\n') {
      line += 1;
      lastBreak = i;
    }
  }
  return { line, column: offset - lastBreak };
}

/**
 * The balanced bodies of every interrupt handler in `scanText`, deduped by start
 * offset.
 *
 * PORTED VERBATIM from `collectIsrBlocks` in
 * `packages/rules/src/rules/embedded-rtos.ts` — see the module header for why it
 * is a copy. Three head forms: an AVR `ISR(VECT)`, an ESP32/ESP8266
 * `IRAM_ATTR`/`ICACHE_RAM_ATTR` handler, and a function named by
 * `attachInterrupt`. For the last, the first `void fn(` may be a forward
 * declaration (`extractBlockAfter` returns null on the `;` guard), so the loop
 * continues to the real definition.
 */
function collectIsrBlocks(scanText: string): ExtractedBlock[] {
  const blocks: ExtractedBlock[] = [];
  const seen = new Set<number>();
  const add = (block: ExtractedBlock | null): void => {
    if (block && !seen.has(block.start)) {
      seen.add(block.start);
      blocks.push(block);
    }
  };

  const directHeads = [
    /(?<![\w.>])ISR[ \t]{0,8}\([ \t]{0,8}\w{1,40}[ \t]{0,8}\)/g,
    /\b(?:IRAM_ATTR|ICACHE_RAM_ATTR)[ \t]{1,8}\w{1,40}[ \t]{0,8}\([^)\n]{0,80}\)/g,
  ];
  for (const re of directHeads) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let count = 0;
    while ((m = re.exec(scanText)) !== null && count < REGEX_MATCH_LIMIT) {
      count += 1;
      add(extractBlockAfter(scanText, m.index + m[0].length));
    }
  }

  const attach = /\battachInterrupt[ \t]{0,8}\([^,;\n]{0,80},[ \t]{0,8}(\w{1,60})[ \t]{0,8},/g;
  let a: RegExpExecArray | null;
  let seenAttach = 0;
  while ((a = attach.exec(scanText)) !== null && seenAttach < REGEX_MATCH_LIMIT) {
    seenAttach += 1;
    const fn = a[1]!; // `\w+` — safe to interpolate.
    const defRe = new RegExp(
      `\\bvoid[ \\t]{1,8}(?:(?:IRAM_ATTR|ICACHE_RAM_ATTR)[ \\t]{1,8})?${fn}[ \\t]{0,8}\\(`,
      'g',
    );
    let def: RegExpExecArray | null;
    while ((def = defRe.exec(scanText)) !== null) {
      const block = extractBlockAfter(scanText, def.index + def[0].length);
      if (block) {
        add(block);
        break;
      }
    }
  }
  return blocks;
}

/** One declaration-shaped occurrence, already classified. */
interface DeclSite {
  filePath: string;
  /** Offset of the first character of the declaration, indentation excluded. */
  start: number;
  end: number;
  text: string;
  line: number;
  column: number;
  /** Column 1 AND brace depth 0 — a genuine file-scope declaration. */
  fileScope: boolean;
  isStatic: boolean;
  isExtern: boolean;
  /**
   * The declaration exists but this rule cannot reason about its qualification:
   * a typedef'd type, a pointer (where `volatile` binds to one of two different
   * things depending on where it is written), or an array.
   */
  opaque: boolean;
  protectedAlready: boolean;
}

function declarationsIn(
  structure: StructureIndex,
  braces: BraceIndex,
  name: string,
): DeclSite[] {
  // Cheap reject before the expensive one. This function is called once per
  // candidate name per file, so on a 2,000-file project the regex would run
  // hundreds of thousands of times over text that does not contain the name at
  // all. A substring test settles that case at memory speed; only files that
  // actually mention the identifier pay for a pattern.
  if (!structure.blanked.includes(name)) return [];

  const pattern = declPattern(name);
  const out: DeclSite[] = [];
  pattern.lastIndex = 0;
  for (let m = pattern.exec(structure.blanked); m; m = pattern.exec(structure.blanked)) {
    if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
    const decl = m.groups?.decl;
    const type = m.groups?.type;
    if (decl === undefined || type === undefined) continue;
    if (out.length >= REGEX_MATCH_LIMIT) break;

    const start = m.index + m[0].length - decl.length;
    const { line, column } = positionOf(structure.blanked, start);
    const lookBack = structure.blanked.slice(Math.max(0, start - QUALIFIER_LOOKBACK), start);
    out.push({
      filePath: structure.filePath,
      start,
      end: start + decl.length,
      text: decl,
      line,
      column,
      fileScope: column === 1 && depthAt(braces, start) === 0,
      isStatic: /\bstatic\b/.test(decl),
      isExtern: /\bextern\b/.test(decl),
      opaque:
        !IS_BUILTIN.test(type) ||
        (m.groups?.ptr ?? '').length > 0 ||
        (m.groups?.tail ?? '') === '[',
      protectedAlready: PROTECTED.test(decl) || PROTECTED.test(lookBack),
    });
  }
  return out;
}

/**
 * Where an interrupt handler writes a candidate name.
 *
 * Carries the raw offset rather than a line number because `positionOf` is a
 * linear scan and almost every candidate is discarded by a guard before its
 * position is ever printed. Converting on emit means the cost is paid once per
 * FINDING instead of once per assignment in every handler in the project.
 */
interface WriteSite {
  filePath: string;
  offset: number;
}

function analyze(ctx: CrossFileRuleContext): CrossFileFinding[] {
  const { project } = ctx;

  // PER-FILE language filter. `runCrossFileRules` gates at the PROJECT level —
  // "does this project contain any C at all" — which is the right question for
  // whether to run the rule and the wrong one for which files it may read. A
  // firmware repo with a Python build script or a TypeScript dashboard passes
  // the project gate, and every non-C file then reaches patterns written for C
  // declarations. See `scattered-authorization.ts`, where evaluation over real
  // repositories caught exactly this.
  const structures = [...project.structures.keys()]
    .sort()
    .map((k) => project.structures.get(k)!)
    .filter((s) => C_LANGUAGES.has(s.language) && !TEST_PATH.test(s.filePath));

  if (structures.length === 0) return [];

  const braceCache = new Map<string, BraceIndex>();
  const bracesOf = (s: StructureIndex): BraceIndex => {
    let index = braceCache.get(s.filePath);
    if (!index) {
      index = buildBraceIndex(s.blanked);
      braceCache.set(s.filePath, index);
    }
    return index;
  };

  // Interrupt handler bodies, per implementation file. Headers are skipped: a
  // handler defined in a header would be compiled into every including
  // translation unit, which is a different (and louder) problem than this one.
  const isrBlocks = new Map<string, ExtractedBlock[]>();
  for (const s of structures) {
    if (HEADER.test(s.filePath)) continue;
    const blocks = collectIsrBlocks(s.blanked);
    if (blocks.length > 0) isrBlocks.set(s.filePath, blocks);
  }
  if (isrBlocks.size === 0) return [];

  // Candidate names, in deterministic order: file order, then order of
  // appearance within the file. `analyze` must produce the same list on every
  // run or a baseline diff never settles.
  const writes = new Map<string, WriteSite[]>();
  for (const s of structures) {
    const blocks = isrBlocks.get(s.filePath);
    if (!blocks) continue;
    for (const block of blocks) {
      WRITE.lastIndex = 0;
      for (let m = WRITE.exec(block.body); m; m = WRITE.exec(block.body)) {
        if (WRITE.lastIndex === m.index) WRITE.lastIndex += 1;
        const name = m.groups?.name;
        if (!name || NOT_A_VARIABLE.has(name)) continue;
        if (!writes.has(name) && writes.size >= MAX_CANDIDATES) continue;
        const offset = block.start + m.index + m[0].indexOf(name);
        const sites = writes.get(name) ?? [];
        if (!sites.some((w) => w.filePath === s.filePath)) {
          sites.push({ filePath: s.filePath, offset });
        }
        writes.set(name, sites);
      }
    }
  }
  if (writes.size === 0) return [];

  const closureCache = new Map<string, { files: Set<string>; quotedResolved: boolean }>();
  const closureOf = (filePath: string): { files: Set<string>; quotedResolved: boolean } => {
    let cached = closureCache.get(filePath);
    if (!cached) {
      const closure = includeClosure(filePath, project.structures);
      // Every QUOTED include on the path must have resolved. An unresolved
      // quoted include means a PROJECT header is missing from the scan, and a
      // missing header is exactly where the second declaration of this name
      // would be hiding — so the "exactly one declaration" test below would be
      // answering a question about a tree it has not fully seen. Angled includes
      // are allowed to dangle: they are the system and SDK headers the scan
      // legitimately cannot see, and requiring them would make the rule inert,
      // which is the mistake VG-AISC-002 documents having made first.
      const quotedResolved = closure.files
        .map((f) => project.structures.get(f))
        .every((s) =>
          (s?.imports ?? []).every((e) => e.syntax !== 'quoted' || e.resolvedFile !== undefined),
        );
      cached = { files: new Set(closure.files), quotedResolved };
      closureCache.set(filePath, cached);
    }
    return cached;
  };

  /**
   * Offsets where `filePath` mentions `name` outside every interrupt handler
   * body and outside its own declarations.
   *
   * One helper for the two questions the loop below asks — "does the handler's
   * own file already read this, so VG-RTOS-002 covers it" and "does this other
   * file read it" — because they must be the same question asked from two
   * sides. They were two separate expressions in the first draft and had
   * already drifted on whether a declaration counted as a read.
   */
  const readOffsets = (filePath: string, name: string): number[] => {
    const structure = project.structures.get(filePath);
    if (!structure) return [];
    const blocks = isrBlocks.get(filePath) ?? [];
    const decls = declarationsIn(structure, bracesOf(structure), name);
    const pattern = new RegExp(String.raw`\b${escapeRe(name)}\b`, 'g');
    const out: number[] = [];
    for (let m = pattern.exec(structure.blanked); m; m = pattern.exec(structure.blanked)) {
      if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
      const at = m.index;
      if (blocks.some((b) => at >= b.start && at < b.end)) continue;
      if (decls.some((d) => at >= d.start && at < d.end)) continue;
      out.push(at);
      if (out.length >= REGEX_MATCH_LIMIT) break;
    }
    return out;
  };

  // Headers only, for the pre-filter below.
  const headers = structures.filter((s) => HEADER.test(s.filePath));
  if (headers.length === 0) return [];

  const findings: CrossFileFinding[] = [];

  for (const name of [...writes.keys()].sort()) {
    // The graph deadline, checked between candidates rather than inside one.
    // A candidate that has started should finish, so a half-evaluated name never
    // produces a finding that skipped a guard.
    if (ctx.budget.expired()) break;

    // A name that appears in no header cannot have the one header declaration
    // this rule requires, and most candidates are of that kind — loop counters,
    // scratch flags, anything an interrupt handler touches locally. Settling
    // them against the (few) headers instead of against every file in the
    // project is what keeps the per-candidate cost from scaling with repo size.
    if (!headers.some((h) => h.blanked.includes(name))) continue;

    const sites = writes.get(name)!;

    // Every declaration-shaped occurrence of the name, project-wide.
    const allDecls: DeclSite[] = [];
    for (const s of structures) allDecls.push(...declarationsIn(s, bracesOf(s), name));
    if (allDecls.length === 0) continue;

    const fileScope = allDecls.filter((d) => d.fileScope);

    // A `static` declaration anywhere is a file-local object, which is the
    // breeding ground for two variables with one name. It is not evidence
    // against THIS variable being shared — but the rule cannot tell the two
    // apart, and the whole design of this rule is that ambiguity is silence.
    // The cost is a real false negative when an unrelated file happens to
    // contain a same-named static; that cost is paid deliberately.
    if (fileScope.some((d) => d.isStatic)) continue;

    // A type this rule cannot see through (`reg_t`, a pointer, an array) is not
    // an unqualified declaration, it is an unknown one.
    if (fileScope.some((d) => d.opaque)) continue;

    // Already `volatile` / `_Atomic` / `const` — nothing to report.
    if (fileScope.some((d) => d.protectedAlready)) continue;

    // EXACTLY ONE declaration in a project header. Zero means nothing says this
    // variable is shared; two or more means the include path picks, and the
    // include path is not available here.
    const headerDecls = fileScope.filter((d) => HEADER.test(d.filePath));
    if (headerDecls.length !== 1) continue;
    const headerDecl = headerDecls[0]!;

    // At most one definition (a non-`extern` file-scope declaration) outside the
    // headers. Two would be two objects, or a link error — either way, not a
    // claim this rule can make.
    //
    // `static` is excluded here even though a static declaration already
    // returned above, so that the two guards stay INDEPENDENT: with statics
    // counted, a fixture written to test the static rule would also trip this
    // one, and neither test would prove which guard is doing the work.
    const definitions = fileScope.filter(
      (d) => !HEADER.test(d.filePath) && !d.isExtern && !d.isStatic,
    );
    if (definitions.length > 1) continue;

    // Files where a declaration of this name sits somewhere other than file
    // scope: a parameter, a local, a struct member. The token this rule would
    // count as the shared variable may be that other thing instead.
    const shadowed = new Set(allDecls.filter((d) => !d.fileScope).map((d) => d.filePath));

    // The handler side. The handler's file must see the header, or the object it
    // writes is not the object the header declares.
    const isrFiles = sites.filter((w) => {
      if (shadowed.has(w.filePath)) return false;
      const closure = closureOf(w.filePath);
      if (!closure.quotedResolved) return false;
      if (!closure.files.has(headerDecl.filePath)) return false;
      // Leave the same-file case to VG-RTOS-002. If the handler's own file also
      // reads the variable outside every handler body, that rule already reports
      // it, at a declaration in that same file — two findings for one defect,
      // filed in different places, is worse than one. This rule is the
      // COMPLEMENT of VG-RTOS-002, not an extension of it.
      return readOffsets(w.filePath, name).length === 0;
    });
    if (isrFiles.length === 0) continue;

    // The reader side: a DIFFERENT implementation file that also sees the
    // header and mentions the name outside any handler body.
    const readers: CodeLocation[] = [];
    for (const s of structures) {
      if (HEADER.test(s.filePath)) continue;
      if (isrFiles.some((w) => w.filePath === s.filePath)) continue;
      if (shadowed.has(s.filePath)) continue;
      const closure = closureOf(s.filePath);
      if (!closure.quotedResolved) continue;
      if (!closure.files.has(headerDecl.filePath)) continue;
      const read = readOffsets(s.filePath, name)[0];
      if (read === undefined) continue;
      readers.push({
        filePath: s.filePath,
        startLine: positionOf(s.blanked, read).line,
        evidence: `reads ${name} outside interrupt context`,
      });
      if (readers.length >= MAX_RELATED_READERS) break;
    }
    if (readers.length === 0) continue;

    // Line numbers are resolved HERE, once a finding is certain — see the note
    // on `WriteSite`.
    const isrLocations = isrFiles.map((w) => ({
      filePath: w.filePath,
      startLine: positionOf(project.structures.get(w.filePath)!.blanked, w.offset).line,
      evidence: `interrupt handler writes ${name}`,
    }));
    const isr = isrLocations[0]!;
    const severity: Severity = 'medium';
    /**
     * `medium`, and capped there.
     *
     * Not `low` (VG-RTOS-002's default), because the cross-file form carries
     * evidence the same-file form does not: exactly one non-static declaration
     * of a builtin scalar type in a header, every quoted include on both sides
     * resolved, and no shadowing declaration in either accusing file. Not
     * `high`, because all of that is still lexical — a `volatile` behind a macro
     * (`#define SHARED volatile`), a qualifier applied through a preprocessor
     * conditional this analysis does not evaluate, or a declarator list the
     * pattern does not split would each produce this shape with nothing wrong.
     */
    const confidence: Confidence = 'medium';

    const fixed = headerDecl.text.replace(/^(?:extern[ \t]{1,8})?/, (lead) => `${lead}volatile `);

    findings.push({
      ruleId: 'VG-RTOS-003',
      title: 'Shared ISR variable missing volatile (cross-file)',
      description:
        `\`${name}\` is written inside an interrupt handler in \`${isr.filePath}\` and read in ` +
        `\`${readers[0]!.filePath}\`, but the single declaration the two files share — ` +
        `\`${headerDecl.text.trim()}\` in \`${headerDecl.filePath}\` — carries no \`volatile\`, ` +
        `\`_Atomic\`, or \`sig_atomic_t\`. Without it the compiler is entitled to keep the value ` +
        `in a register across the read, so the non-interrupt side can spin forever on a copy the ` +
        `handler already changed. VG-RTOS-002 catches this when the handler and the reader are in ` +
        `one file; this is the same defect spread over two translation units, which is where a ` +
        `generated driver normally puts it.`,
      severity,
      confidence,
      category: DESIGN_SMELL_CATEGORY,
      sourceEngine: 'core-rule',
      /**
       * `module`, not `line`. The fix is one word, but it has to be added to the
       * header declaration AND to the definition that must agree with it, in a
       * different file — so a `disable-next-line` pragma on either one is not a
       * coherent way to answer this finding, which is precisely what `scope`
       * exists to tell a suppression channel.
       */
      scope: 'module',
      filePath: headerDecl.filePath,
      startLine: headerDecl.line,
      startColumn: headerDecl.column,
      evidence: [
        `${headerDecl.filePath}:${headerDecl.line} ${headerDecl.text.trim()}`,
        `${isr.filePath}:${isr.startLine} written inside an interrupt handler`,
        `${readers[0]!.filePath}:${readers[0]!.startLine} read outside interrupt context`,
      ],
      primaryLocation: {
        filePath: headerDecl.filePath,
        startLine: headerDecl.line,
        startColumn: headerDecl.column,
        evidence: `declaration of ${name} without volatile`,
      },
      relatedLocations: [...isrLocations, ...readers],
      /**
       * `fanIn` of the DECLARING HEADER, taken from `metrics-calculator` rather
       * than written as a literal. It is the number of files the declaration is
       * visible to, which is the size of the population this defect can reach —
       * a reader deciding how urgent the finding is wants that number, and a
       * hardcoded one would assert a measurement nobody took.
       */
      metrics: fanMetrics(headerDecl.filePath, project.graph),
      /**
       * Explicitly false rather than omitted, and false rather than true.
       *
       * This is a CONCURRENCY defect, not a data-sensitivity one: the variable
       * is usually a tick counter or a ready flag, and claiming a sensitive data
       * flow because the finding is serious would put a fabricated signal into
       * the field consumers use to prioritise. VG-AISC-002 states the same thing
       * the same way — the flag is answered, not assumed.
       */
      securityContext: { containsSensitiveDataFlow: false },
      tags: ['embedded', 'rtos', 'isr', 'cross-file'],
      remediation: {
        why:
          'A variable shared between an interrupt handler and ordinary code must be volatile, or ' +
          'the reader can spin on a stale register-cached copy indefinitely. The bug survives ' +
          'testing because it depends on optimisation level: it appears when the build is ' +
          'switched to -O2 for release, which is the worst moment to find it.',
        how:
          `Add \`volatile\` to the declaration in \`${headerDecl.filePath}\` and to the matching ` +
          'definition, so the two agree. For values wider than one atomic access, also guard ' +
          'reads and writes (disable interrupts around them, or use a critical section) — ' +
          '`volatile` orders the access, it does not make it atomic.',
        exampleFix: fixed.trim(),
      },
    });
  }

  return findings;
}

export const isrVolatileCrossFile: CrossFileRule = {
  ruleId: 'VG-RTOS-003',
  name: 'Shared ISR variable missing volatile (cross-file)',
  description:
    'An interrupt handler writes a variable that another file reads, and the one header ' +
    'declaration both files share has no volatile / _Atomic qualifier. VG-RTOS-002 covers the ' +
    'same-file case; this covers the case where the handler and the reader are separate ' +
    'translation units.',
  category: DESIGN_SMELL_CATEGORY,
  severity: 'medium',
  defaultConfidence: 'medium',
  languages: ['c', 'cpp'],
  // Mirrors VG-RTOS-002 deliberately: the defect is the same one, and a reader
  // grepping a report by CWE should find both arms of it together.
  cwe: ['CWE-457', 'CWE-662'],
  remediation: {
    why: 'A non-volatile variable shared with an interrupt handler can be read from a stale register copy.',
    how: 'Add volatile to the header declaration and the matching definition; guard multi-byte access.',
  },
  analyze,
};
