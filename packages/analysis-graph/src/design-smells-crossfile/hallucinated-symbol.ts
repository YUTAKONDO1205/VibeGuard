// VG-AISC-002 (C/C++ arm) — Hallucinated API / Symbol.
//
// #20b's first deliverable. The failure it looks for is specific and real: a
// code generator asked for firmware produces a call to an SDK function that does
// not exist, spelled exactly the way the SDK's real functions are spelled. The
// generated file compiles in the model's head and fails at link time in yours —
// or worse, links against something else that happens to match.
//
// ★ WHY THE OBVIOUS FORMULATION IS UNSHIPPABLE
//
// "Report any call to a function declared in no reachable header" is the
// statement of the problem and a catastrophe as an implementation. C code calls
// `memcpy`, `printf`, and `malloc`, whose declarations live in system headers
// this analysis cannot see and must not pretend to. It calls macros that expand
// to other things. It calls compiler builtins with no declaration anywhere. Every
// one of those would be reported, on every correct file, and the rule would be
// switched off within a day of being switched on.
//
// The first attempt at a guard was `includeClosure(...).complete` — only speak
// when every include resolved. That is sound and it is also inert: a firmware
// file that includes `<stdio.h>` has an incomplete closure by construction, so
// the rule would stay silent on essentially the entire population it was written
// for. A rule that is safe because it never fires is not a safe rule, it is an
// absent one, and shipping it would have been a worse dishonesty than shipping a
// noisy one.
//
// ★ WHAT IS ASKED INSTEAD: KNOWN NAMESPACE, UNKNOWN MEMBER
//
// The observation that makes this tractable is that a hallucinated SDK call does
// not appear in a vacuum. It appears surrounded by REAL calls into the same SDK,
// because the model has seen that SDK and is imitating it. So the question
// becomes comparative rather than absolute:
//
//   this project's headers declare `cxd56_gpio_write` and `cxd56_gpio_read`,
//   the code calls `cxd56_gpio_toggle`, and nothing declares that anywhere
//
// A prefix that several declared symbols share is evidence that the prefix names
// a real API surface the project can see. An undeclared call INTO that surface is
// therefore not an unseen system header — the header for that surface is right
// there and was read. That is a far stronger signal than absence alone, and it
// structurally cannot fire on `memcpy`: no project header declares a family of
// `mem*` functions, so `mem` never becomes a known namespace.
//
// The cost is recall, deliberately. A hallucinated call to a one-off function
// whose namespace has no other members is invisible here. For a rule whose false
// positives land on correct firmware, that is the right trade, and it is the same
// trade every other design smell in this package makes.

import type { Confidence, Severity } from '@vibeguard/findings-schema';
import { DESIGN_SMELL_CATEGORY } from '@vibeguard/findings-schema';
import { includeClosure } from '../dependency-graph/index.js';
import type {
  CodeLocation,
  CrossFileFinding,
  CrossFileRule,
  CrossFileRuleContext,
  StructureIndex,
} from '../types.js';

const C_LANGUAGES = new Set(['c', 'cpp']);
const HEADER = /\.(?:h|hpp|hh|ipp)$/i;
const TEST_PATH =
  /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|mocks?|examples?|samples?|testdata)(?:\/|$)|_test\.[ch]\w{0,3}$/i;

/**
 * How many DECLARED symbols must share a prefix before it counts as a namespace
 * the project can see.
 *
 * Three, and the number is doing real work. At one, every declared function
 * makes its own prefix a namespace and the rule degenerates into "absence",
 * which is the formulation rejected above. At two, a coincidental pair
 * (`spi_init`/`spi_deinit`) is enough. Three declared members is a family, and a
 * family is what a real SDK header looks like.
 */
const MIN_NAMESPACE_MEMBERS = 3;

/** Minimum prefix length; short prefixes collide across unrelated APIs. */
const MIN_PREFIX_LENGTH = 3;

/**
 * Words that appear in call position but are not calls.
 *
 * Control-flow keywords are the obvious half. `sizeof`, `defined`, and the
 * `__builtin_*` family are the half that produces confident nonsense if omitted:
 * they are syntactically indistinguishable from a call and are declared nowhere
 * by design.
 */
const NOT_A_CALL = new Set([
  'if', 'for', 'while', 'switch', 'return', 'sizeof', 'defined', 'do', 'else',
  'catch', 'static_assert', '_Static_assert', 'alignof', '_Alignof', 'typeof',
  '__typeof__', 'offsetof', 'va_arg', 'va_start', 'va_end', 'assert',
]);

/** A call site: an identifier immediately followed by `(`. */
const CALL = /(?<![\w$.>])(?<name>[A-Za-z_]\w{2,79})[^\S\r\n]{0,4}\(/g;

/**
 * A function DECLARATION (prototype): a header-style `type name(args);`.
 *
 * The trailing `;` is what separates this from a definition, and it is why this
 * cannot reuse the structure indexer's `C_FUNC` — that pattern requires a `{`
 * precisely to exclude prototypes, and prototypes are exactly what is wanted
 * here. The two patterns are complements, not duplicates.
 *
 * ★ THE `(?!…)` GUARD IS THE REPAIR FOR A MEASURED FALSE-POSITIVE CLASS. Without
 * it, `return SSL_get_cipher_name(pSSL);` matches `PROTOTYPE` — `return` sits in
 * the type slot, the call's `)` is followed by `;`, and every character the
 * pattern wants is present. The rule then believes the PROJECT declares
 * `SSL_get_cipher_name`.
 *
 * That is not a cosmetic miscount, it inverts the rule's central safety
 * argument. The header above claims this "structurally cannot fire on `memcpy`:
 * no project header declares a family of `mem*` functions, so `mem` never
 * becomes a known namespace". True of headers — and irrelevant, because a
 * namespace could also be established by ORDINARY CALL SITES in `.c`/`.cpp`
 * files. Any project that returns the results of three functions from the same
 * system library made that library a "known namespace", and every other member
 * of it that the project called became a hallucination.
 *
 * MEASURED over `paper_data/corpus1k`, 1,000 repositories, before the fix:
 * 23 findings in 4 repositories, and the four populations name the mechanism —
 * OpenSSL `SSL_*` in eventmachine (10), Windows phlib `Ph*` and a vendored
 * libcxxabi in lucasg/Dependencies (10), Mach `thread_*` in go-delve's Darwin
 * backend (2), and the libtorch C++ API in detectron2 (1). Every one is a real
 * function in a real system library that the analysis is structurally unable to
 * see, which is precisely the case the rule promised never to report.
 *
 * ★ AND A SECOND, UNRELATED CAUSE THE SAME SWEEP EXPOSED — worth reading,
 * because it was not in this file at all.
 *
 * The repair above took 23 findings to 2. The survivors, `parse_number` and
 * `parse_substitution` in lucasg/Dependencies, were reported AT THE LINE OF
 * THEIR OWN DEFINITION. The cause was in the structure indexer: `C_FUNC`
 * required horizontal whitespace between the return type and the function name,
 * so the LLVM/libcxxabi house style
 *
 *     const char*
 *     parse_number(const char* first, const char* last)
 *
 * produced no symbol, the name was absent from `defined`, and a call to it
 * looked like a call to nothing. Fixed there, not here — see the note on
 * `C_FUNC` — which is the right place, because the missing symbols were also
 * invisible to every other rule that reads C.
 *
 * The general lesson is the one worth keeping: a missing symbol is SILENT, and
 * the only reason this was findable at all is that a rule built on top of it
 * was noisy. Absence does not announce itself; a false positive does.
 *
 * `\b` matters on each entry: it keeps `new_thing_t new_thing(void);` — where
 * `new` is a prefix of a real type name rather than the operator — matching.
 *
 * The guard is a lookahead immediately after the leading horizontal whitespace
 * rather than a post-filter on the match, because a post-filter would have to
 * re-derive which token landed in the type slot, and that is the same parse done
 * twice. The variable-length `[^\S\r\n]{0,20}` in front of it cannot be used to
 * slip past: backtracking to consume fewer spaces only moves the lookahead onto
 * whitespace, and everything that follows demands a word character, so the sole
 * position the pattern can proceed from is the one the lookahead inspects.
 */
const PROTOTYPE =
  /(?:^|\n|;|\})[^\S\r\n]{0,20}(?!(?:return|else|do|case|goto|sizeof|new|delete|throw|co_return|co_await|co_yield)\b)(?:[\w$]{1,40}[^\S\r\n]{1,8}){0,4}[\w$*]{1,60}[^\S\r\n]{1,8}\*{0,3}(?<name>[A-Za-z_]\w{1,79})[^\S\r\n]{0,4}\([^;{]{0,400}\)[^\S\r\n]{0,20};/g;

/** `#define NAME` / `#define NAME(args)`. */
const DEFINE = /(?:^|\n)[^\S\r\n]{0,20}#[^\S\r\n]{0,8}define[^\S\r\n]{1,8}(?<name>[A-Za-z_]\w{0,79})/g;

/** `typedef ... NAME;` — a type used in call position is a cast, not a call. */
const TYPEDEF = /(?:^|\n)[^\S\r\n]{0,20}typedef[^\S\r\n]{1,8}[^;\n]{0,200}?(?<name>[A-Za-z_]\w{0,79})[^\S\r\n]{0,4};/g;

function collectNames(text: string, pattern: RegExp, into: Set<string>): void {
  pattern.lastIndex = 0;
  for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
    const name = m.groups?.name;
    if (name) into.add(name);
    if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
  }
}

/**
 * Split an identifier into the prefixes that could name an API family.
 *
 * `cxd56_gpio_write` yields `cxd56` and `cxd56_gpio`. Underscore-delimited only:
 * camelCase splitting would make `getUser` and `getConfig` share the namespace
 * `get`, which is a naming convention rather than an API surface. Vendor SDKs in
 * C are underscore-namespaced essentially without exception, which is what makes
 * this cheap test work on the population the rule targets.
 */
function prefixesOf(name: string): string[] {
  const parts = name.split('_').filter((p) => p.length > 0);
  const out: string[] = [];
  for (let i = 1; i < parts.length; i += 1) {
    const prefix = parts.slice(0, i).join('_');
    if (prefix.length >= MIN_PREFIX_LENGTH) out.push(prefix);
  }
  return out;
}

function positionOf(content: string, offset: number): { line: number; column: number } {
  let line = 1;
  let lastBreak = -1;
  for (let i = 0; i < offset && i < content.length; i += 1) {
    if (content[i] === '\n') {
      line += 1;
      lastBreak = i;
    }
  }
  return { line, column: offset - lastBreak };
}

function analyze(ctx: CrossFileRuleContext): CrossFileFinding[] {
  const { project } = ctx;
  const cFiles = [...project.structures.keys()]
    .sort()
    .map((k) => project.structures.get(k)!)
    .filter((s) => C_LANGUAGES.has(s.language));

  if (cFiles.length === 0) return [];

  const findings: CrossFileFinding[] = [];

  for (const structure of cFiles) {
    if (TEST_PATH.test(structure.filePath)) continue;
    if (HEADER.test(structure.filePath)) continue;

    const closure = includeClosure(structure.filePath, project.structures);

    // Every QUOTED include must have resolved. Angled includes are allowed to
    // dangle — they are the system and toolchain headers the scan legitimately
    // cannot see, and requiring them would make the rule inert (see the module
    // comment). A dangling quoted include is different in kind: it means a
    // PROJECT header is missing from the scan, so the declarations this rule
    // reasons about are knowably incomplete and it must not accuse anyone.
    const quotedResolved = closure.files
      .map((f) => project.structures.get(f))
      .every((s) =>
        (s?.imports ?? []).every((e) => e.syntax !== 'quoted' || e.resolvedFile !== undefined),
      );
    if (!quotedResolved) continue;

    // Everything the translation unit can legitimately name.
    const declared = new Set<string>();
    const defined = new Set<string>();
    const macros = new Set<string>();
    const typedefs = new Set<string>();

    for (const file of closure.files) {
      const s = project.structures.get(file);
      if (!s) continue;
      collectNames(s.blanked, PROTOTYPE, declared);
      collectNames(s.blanked, DEFINE, macros);
      collectNames(s.blanked, TYPEDEF, typedefs);
      for (const sym of s.symbols) defined.add(sym.name);
    }
    // A symbol defined anywhere in the project is real regardless of which
    // translation unit it lives in — the linker will find it, and reporting it
    // as hallucinated because this file's includes do not declare it would be
    // reporting a missing prototype, which is a different (and compiler-caught)
    // problem.
    for (const s of cFiles) for (const sym of s.symbols) defined.add(sym.name);

    const known = new Set([...declared, ...defined, ...macros, ...typedefs]);

    // Namespaces the project can demonstrably see: prefixes shared by at least
    // MIN_NAMESPACE_MEMBERS DECLARED symbols. Declared, not defined — a family
    // the project defines itself is its own code, and a missing member there is
    // a typo the compiler reports, not a hallucinated third-party API.
    const prefixCounts = new Map<string, number>();
    for (const name of declared) {
      for (const prefix of prefixesOf(name)) {
        prefixCounts.set(prefix, (prefixCounts.get(prefix) ?? 0) + 1);
      }
    }
    const namespaces = new Set(
      [...prefixCounts.entries()]
        .filter(([, n]) => n >= MIN_NAMESPACE_MEMBERS)
        .map(([p]) => p),
    );
    if (namespaces.size === 0) continue;

    const source = project.files.find((f) => f.filePath === structure.filePath);
    if (!source) continue;

    const seen = new Set<string>();
    CALL.lastIndex = 0;
    for (let m = CALL.exec(structure.blanked); m; m = CALL.exec(structure.blanked)) {
      const name = m.groups?.name;
      if (!name) continue;
      if (CALL.lastIndex === m.index) CALL.lastIndex += 1;
      if (NOT_A_CALL.has(name) || known.has(name) || seen.has(name)) continue;

      // ★ The call's IMMEDIATE family must be the known one — not merely some
      // ancestor of it.
      //
      // `cxd56_gpio_toggle` has prefixes `cxd56` and `cxd56_gpio`. Requiring
      // only that SOME prefix is known was wrong, and demonstrably so: a project
      // that vendors `sdk/cxd56_gpio.h` (quoted, scanned) and includes
      // `<cxd56_pwm.h>` (angled, legitimately unscanned) made `cxd56` a known
      // namespace, and every real `cxd56_pwm_*` call was then accused of not
      // existing. Partially-vendored vendor SDKs are the normal case in embedded
      // work, so that reading turned the rule against exactly the projects it
      // was written for.
      //
      // The immediate family is the whole basis of the claim. The argument this
      // rule makes is "the header for THIS API surface was read and this member
      // was not in it" — and that is only true when the surface named by the
      // call's own last-but-one segment is one the project declares. When the
      // immediate family is unknown, its header simply was not seen, which is
      // the ordinary state of affairs and not evidence of anything.
      const prefixes = prefixesOf(name);
      const immediate = prefixes[prefixes.length - 1];
      if (!immediate || !namespaces.has(immediate)) continue;
      const claimed = immediate;

      seen.add(name);
      const offset = m.index + m[0].indexOf(name);
      const { line, column } = positionOf(source.content, offset);

      // The sibling calls that make the namespace real. Shown because the
      // finding's whole argument is comparative: without them the reader has
      // only "we could not find this", which is exactly the weak claim this
      // rule was designed not to make.
      const siblings = [...declared]
        .filter((d) => d.startsWith(`${claimed}_`))
        .sort()
        .slice(0, 5);

      const related: CodeLocation[] = [];
      for (const file of closure.files) {
        const s = project.structures.get(file);
        if (!s || !HEADER.test(file)) continue;
        for (const sib of siblings) {
          const idx = s.blanked.indexOf(sib);
          if (idx === -1) continue;
          related.push({
            filePath: file,
            startLine: s.blanked.slice(0, idx).split('\n').length,
            evidence: `${sib} — a real member of ${claimed}_*`,
          });
          break;
        }
      }

      const severity: Severity = 'high';
      /**
       * `medium`, and capped for the same reason VG-AISC-003 is: the evidence is
       * that a lexical scan of the resolved headers did not find a declaration.
       * A generated header, a symbol supplied by the linker, or a declaration
       * behind a preprocessor conditional this analysis does not evaluate would
       * all produce this shape with nothing wrong.
       */
      const confidence: Confidence = 'medium';

      findings.push({
        ruleId: 'VG-AISC-002',
        title: 'Hallucinated API / Symbol',
        description:
          `\`${name}\` is called here, and nothing in this translation unit's include ` +
          `closure declares it — no prototype, no macro, no typedef, and no definition ` +
          `anywhere in the project. It is spelled as a member of \`${claimed}_*\`, a family ` +
          `the project's own headers DO declare (${siblings.join(', ')}), so the header for ` +
          `this API surface was read and this member was not in it. That is the shape of a ` +
          `generated call to an SDK function that does not exist.`,
        severity,
        confidence,
        category: DESIGN_SMELL_CATEGORY,
        sourceEngine: 'core-rule',
        scope: 'symbol',
        filePath: structure.filePath,
        startLine: line,
        startColumn: column,
        evidence: [
          `${structure.filePath}:${line} call to ${name}`,
          `declared members of ${claimed}_*: ${siblings.join(', ')}`,
        ],
        primaryLocation: {
          filePath: structure.filePath,
          startLine: line,
          startColumn: column,
          evidence: `call to undeclared ${name}`,
        },
        relatedLocations: related,
        securityContext: { containsSensitiveDataFlow: false },
        tags: ['supply-chain', 'ai-prone', 'embedded', 'cross-file'],
        remediation: {
          why:
            'A call to a function the SDK does not export fails at link time at best. At ' +
            'worst it resolves to a different symbol with the same name and the firmware ' +
            'ships doing something nobody wrote.',
          how:
            `Check \`${name}\` against the SDK's actual header. Generated code imitating an ` +
            'API frequently invents plausible members of a real family; the fix is usually ' +
            'the neighbouring real function, not a missing include.',
        },
      });
    }
  }

  return findings;
}

export const hallucinatedSymbol: CrossFileRule = {
  ruleId: 'VG-AISC-002',
  name: 'Hallucinated API / Symbol',
  description:
    'A call names a member of an API family the project’s headers declare, but that member ' +
    'is declared nowhere — the shape of a generated call to a function that does not exist.',
  category: DESIGN_SMELL_CATEGORY,
  severity: 'high',
  defaultConfidence: 'medium',
  languages: ['c', 'cpp'],
  cwe: ['CWE-1104'],
  owasp: ['A08:2021'],
  remediation: {
    why: 'A call to a nonexistent SDK function fails at link time, or resolves to something else.',
    how: 'Check the symbol against the SDK header; the intended function is usually a sibling.',
  },
  analyze,
};
