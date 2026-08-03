// VG-AISC-003 (C/C++ arm) — Unintegrated Generated Security.
//
// #20b. A security initializer is defined, is declared in a project header so
// it is plainly meant to be called, and is mentioned nowhere else in the entire
// project. The generated code exists; nothing turns it on.
//
// WHY THIS IS A CROSS-FILE RULE AND CANNOT BE ANYTHING ELSE
//
// "This function is never called" is not a question a single file can answer.
// A file containing only `void crypto_init(void) { ... }` is indistinguishable
// between the library that exports it correctly and the firmware that forgot to
// call it; the difference lives in every OTHER file. That is the cleanest
// available demonstration of why `analysis-graph` exists as a separate package,
// and it is the reason this arm was held back from the single-file phase rather
// than approximated there.
//
// WHY IT IS NOT A REACHABILITY ANALYSIS
//
// The obvious implementation is "build a call graph, mark entry points, report
// what is unreachable", and it is wrong for embedded C specifically. Entry
// points there are not `main`: they are RTOS task registrations, interrupt
// vector tables, linker-placed constructors, weak symbols overridden at link
// time, and callback structs. Every one of those invokes a function without a
// syntactic call site, so a reachability analysis would report the entire
// firmware as dead code. Any fix requires enumerating the entry-point
// conventions of every RTOS, which is an open-ended list and therefore an
// open-ended source of false positives.
//
// The question is narrowed instead to one a lexical scan can answer soundly:
// does the identifier appear ANYWHERE in the project other than its own
// definition and declarations? A task registration mentions it
// (`xTaskCreate(crypto_init, ...)`). A callback table mentions it
// (`.init = crypto_init`). A macro mentions it. Taking the address mentions it.
// Every mechanism that could invoke it without calling it still has to NAME it,
// so "named nowhere else" is a conservative under-approximation of "never
// invoked" — it can miss a genuinely dead initializer, and it cannot invent one.
//
// That is the correct direction to be wrong in. This rule is aimed at
// AI-generated firmware, and the code it is looking for was written by something
// that will happily produce a perfect `secure_boot_init()` and then never wire
// it into `main`.

import type { Confidence, Severity } from '@vibeguard/findings-schema';
import { DESIGN_SMELL_CATEGORY } from '@vibeguard/findings-schema';
import { fanMetrics, mergeMetrics, symbolMetrics } from '../metrics/index.js';
import type {
  CodeLocation,
  CrossFileFinding,
  CrossFileRule,
  CrossFileRuleContext,
  IndexedSymbol,
  ProjectIndex,
  SourceFile,
  StructureIndex,
} from '../types.js';

/**
 * Initializer names this rule is willing to report on.
 *
 * An ALLOWLIST of security-relevant initializers, not a general `*_init`
 * pattern, and the restriction is what makes the rule shippable. A firmware
 * project contains dozens of `*_init` functions — `uart_init`, `led_init`,
 * `ringbuf_init` — many of which are legitimately unused in a given build
 * configuration, and reporting them would be a maintainability observation
 * dressed up as a security finding. VG-AISC-003 is "Unintegrated Generated
 * SECURITY", and the word doing the work is the last one.
 *
 * A named list also fails gracefully: a false positive is removed by editing one
 * entry, rather than by weakening a heuristic that everything else depends on.
 * Same discipline as the bundled package table in
 * `packages/rules/src/rules/ai-supply-chain-data.ts`.
 */
const SECURITY_INIT_PATTERNS: RegExp[] = [
  // TLS / crypto library setup
  /^mbedtls_\w{1,60}_init$/,
  /^wolfSSL_Init$/,
  /^wolfSSL_CTX_new$/,
  /^(?:SSL|TLS)_library_init$/,
  /^OPENSSL_init_(?:ssl|crypto)$/,
  /^psa_crypto_init$/,
  // Entropy and randomness
  /^\w{0,40}(?:rng|random|entropy|prng|drbg)_init$/i,
  /^\w{0,40}seed_random\w{0,20}$/i,
  // Generic crypto / secure-element setup
  /^(?:crypto|cipher|aes|hmac|sha\d{0,3}|ecc|rsa)_\w{0,40}init$/i,
  /^(?:se|ate?cc|tpm|hsm|keystore|keychain)_\w{0,40}init$/i,
  // Secure boot / attestation / firmware verification
  /^secure_boot_\w{1,40}$/i,
  /^(?:attest|verify_firmware|image_validate|signature_verify)\w{0,30}$/i,
  // Watchdog and tamper protection — safety mechanisms with the same failure
  // mode: present, correct, and never switched on.
  /^(?:wdt|watchdog|tamper|brownout)_\w{0,20}(?:init|enable|start|begin)$/i,
  // Access control / authentication subsystem bring-up
  /^(?:auth|authz|acl|permission|credential|session)_\w{0,30}(?:init|begin|setup)$/i,
  // Memory protection
  /^(?:mpu|mmu|stack_guard|canary)_\w{0,20}(?:init|enable)$/i,
];

function isSecurityInit(name: string): boolean {
  return SECURITY_INIT_PATTERNS.some((p) => p.test(name));
}

/** Languages this arm applies to. */
const C_LANGUAGES = new Set(['c', 'cpp']);

/** Header extensions, for deciding whether a mention is a declaration. */
const HEADER = /\.(?:h|hpp|hh|ipp)$/i;

/** Path segments whose contents are fixtures, not shipped firmware. */
const TEST_PATH =
  /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|mocks?|examples?|samples?|testdata)(?:\/|$)|_test\.[ch]\w{0,3}$/i;

/**
 * A definition carrying a weak linkage attribute.
 *
 * `__attribute__((weak))` and `__weak` mean "this is a placeholder another
 * translation unit is expected to override". A weak definition that nothing
 * calls is the DESIGNED state, not a defect — the vendor SDK ships weak stubs
 * precisely so that firmware which does not need them can leave them alone. The
 * check reads the text before the definition rather than the whole file, so an
 * unrelated weak symbol elsewhere does not exempt everything.
 */
const WEAK = /(?:__attribute__\s{0,4}\(\(\s{0,4}weak|__weak\b|\bWEAK\b)/;

function isWeakDefinition(structure: StructureIndex, bodyStart: number): boolean {
  const lookBack = structure.blanked.slice(Math.max(0, bodyStart - 300), bodyStart);
  return WEAK.test(lookBack);
}

/**
 * Count identifier occurrences of `name` across the project's blanked text.
 *
 * Blanked, so a mention inside a comment (`// remember to call crypto_init`) or
 * a string does not count as wiring the function up. That is the conservative
 * direction here: a comment is not a call, and treating it as one would
 * suppress a real finding.
 *
 * Word-boundary anchored on both sides so `crypto_init` is not matched inside
 * `crypto_init_helper` — a distinct symbol whose presence says nothing about
 * whether this one is used.
 */
function countMentions(name: string, structures: StructureIndex[]): {
  total: number;
  declarations: CodeLocation[];
  nonDefiningFiles: string[];
} {
  // The name comes from a matched identifier, so it contains no regex
  // metacharacters — but building a pattern from data without escaping is the
  // habit that eventually meets a name that does. Escape anyway.
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(String.raw`\b${escaped}\b`, 'g');
  let total = 0;
  const declarations: CodeLocation[] = [];
  const nonDefiningFiles: string[] = [];

  for (const structure of structures) {
    pattern.lastIndex = 0;
    let hits = 0;
    let firstIndex = -1;
    for (let m = pattern.exec(structure.blanked); m; m = pattern.exec(structure.blanked)) {
      hits += 1;
      if (firstIndex === -1) firstIndex = m.index;
      if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
    }
    if (hits === 0) continue;
    total += hits;
    const definesIt = structure.symbols.some((s) => s.name === name);
    if (!definesIt) nonDefiningFiles.push(structure.filePath);
    if (HEADER.test(structure.filePath) && !definesIt) {
      const line = structure.blanked.slice(0, firstIndex).split('\n').length;
      declarations.push({ filePath: structure.filePath, startLine: line, evidence: `declared here` });
    }
  }

  return { total, declarations, nonDefiningFiles };
}

function analyze(ctx: CrossFileRuleContext): CrossFileFinding[] {
  const { project } = ctx;
  const structures = [...project.structures.keys()]
    .sort()
    .map((k) => project.structures.get(k)!)
    .filter((s) => C_LANGUAGES.has(s.language));

  if (structures.length === 0) return [];

  const findings: CrossFileFinding[] = [];

  for (const structure of structures) {
    if (TEST_PATH.test(structure.filePath)) continue;
    // A definition in a header is usually a `static inline` helper; the "is it
    // wired up" question is about the implementation file.
    if (HEADER.test(structure.filePath)) continue;

    for (const symbol of structure.symbols) {
      const finding = findingForSymbol(symbol, structure, structures, project);
      if (finding) findings.push(finding);
    }
  }

  return findings;
}

/**
 * One indexed symbol, turned into a finding — or `null` when it is not one.
 *
 * ★ WHY THIS IS A SEPARATE FUNCTION. It was the body of `analyze`'s inner loop,
 * and `analyze` was long enough to trip this project's own VG-SMELL-003. The
 * same argument applies as in `cyclic-security-dependency.ts`: a detector that
 * exempts itself from its own advice is making an argument it does not believe.
 *
 * Every `continue` in the original body was a decision about THIS symbol alone
 * and becomes `return null`. The three numbered requirements below are the
 * rule's precision contract and are unchanged in order and in content — the
 * order matters because each is cheaper than the one after it.
 */
function findingForSymbol(
  symbol: IndexedSymbol,
  structure: StructureIndex,
  structures: StructureIndex[],
  project: ProjectIndex,
): CrossFileFinding | null {
      if (!isSecurityInit(symbol.name)) return null;
      if (isWeakDefinition(structure, symbol.bodyStart)) return null;
      // A `static` function is file-local by definition, so "declared in a
      // header for others to call" cannot apply and the intent is different.
      if (!symbol.exported) return null;

      const source: SourceFile | undefined = project.files.find(
        (f) => f.filePath === symbol.filePath,
      );
      const { total, declarations, nonDefiningFiles } = countMentions(symbol.name, structures);

      // Requirement 1: declared in a project header. Without a declaration there
      // is no evidence anyone was ever meant to call it from elsewhere, and a
      // file-local helper that happens to match the allowlist is not this
      // finding.
      if (declarations.length === 0) return null;

      // Requirement 2: mentioned nowhere outside its own file and its
      // declarations. `nonDefiningFiles` is every file naming it that does not
      // define it; subtract the headers that only declare it, and anything left
      // is a use.
      const declaringFiles = new Set(declarations.map((d) => d.filePath));
      const usingFiles = nonDefiningFiles.filter((f) => !declaringFiles.has(f));
      if (usingFiles.length > 0) return null;

      // Requirement 3: within its own file, the only occurrence is the
      // definition head itself. A local call, an address-of, or a designated
      // initialiser inside the same file all count as wiring.
      const ownFileHits = (() => {
        const escaped = symbol.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const p = new RegExp(String.raw`\b${escaped}\b`, 'g');
        let n = 0;
        for (let m = p.exec(structure.blanked); m; m = p.exec(structure.blanked)) {
          n += 1;
          if (p.lastIndex === m.index) p.lastIndex += 1;
        }
        return n;
      })();
      if (ownFileHits > 1) return null;
      // And nothing else in the project may mention it beyond the declarations.
      if (total > 1 + declarations.length) return null;

      const severity: Severity = 'high';
      /**
       * `medium`, capped, and it stays capped.
       *
       * The evidence is a lexical absence, which is the weakest kind of evidence
       * there is: it says the analysis looked in the files it was given and
       * found no mention. A build system that generates a call, a source file
       * outside the scanned tree, or a symbol invoked from assembly would all
       * produce this pattern with nothing wrong. `high` would claim a certainty
       * the method does not have, and this rule's whole safety argument is that
       * it under-claims.
       */
      const confidence: Confidence = 'medium';

      return {
        ruleId: 'VG-AISC-003',
        title: 'Unintegrated Generated Security',
        description:
          `\`${symbol.name}\` is defined and declared in a project header, but its name appears ` +
          `nowhere else in the scanned sources — not as a call, not as a function pointer, not in ` +
          `a task registration or callback table. The security mechanism it sets up is present in ` +
          `the code and never switched on. Generated firmware fails this way routinely: the ` +
          `initializer is written correctly and the one line that invokes it is never added.`,
        severity,
        confidence,
        category: DESIGN_SMELL_CATEGORY,
        sourceEngine: 'core-rule',
        scope: 'project',
        filePath: symbol.filePath,
        startLine: symbol.startLine,
        endLine: symbol.endLine,
        startColumn: symbol.startColumn,
        evidence: [
          `${symbol.filePath}:${symbol.startLine} definition of ${symbol.name}`,
          ...declarations.map((d) => `${d.filePath}:${d.startLine} declaration`),
        ],
        primaryLocation: {
          filePath: symbol.filePath,
          startLine: symbol.startLine,
          endLine: symbol.endLine,
          startColumn: symbol.startColumn,
          evidence: `definition of ${symbol.name}`,
        },
        relatedLocations: declarations,
        /**
         * `fanIn` comes from `metrics-calculator` rather than being written as
         * a literal `0`, and the difference is not cosmetic. A hard-coded zero
         * asserts a measurement that was never taken; routing through
         * `fanMetrics` makes it the graph's actual answer, so if a future change
         * causes this file to be imported somewhere the number stops saying
         * nothing-depends-on-this — which is precisely the claim this finding
         * leans on. `loc`/`branchCount`/`nestingDepth` for the initializer body
         * come from the same module, so a reader comparing this finding with any
         * other is reading one definition of each.
         */
        metrics: mergeMetrics(
          fanMetrics(symbol.filePath, project.graph),
          source ? symbolMetrics(symbol, source) : undefined,
        ),
        securityContext: { containsAuthLogic: true, containsCryptoLogic: true },
        tags: ['supply-chain', 'ai-prone', 'embedded', 'cross-file'],
        remediation: {
          why:
            'A security initializer that is never invoked leaves the mechanism inert while every ' +
            'review artefact — the code, the header, the commit — says it is present. That is ' +
            'worse than its absence, because it stops anyone from noticing it is missing.',
          how:
            `Call \`${symbol.name}\` from your start-up path before the subsystem it protects is ` +
            'used, and check its return value. If it is genuinely obsolete, delete it and its ' +
            'declaration so the code stops advertising protection it does not provide.',
          exampleFix: `int main(void) {\n  ${symbol.name}();  // must run before anything uses the subsystem\n  ...\n}`,
        },
      };
}

export const unintegratedSecurityInit: CrossFileRule = {
  ruleId: 'VG-AISC-003',
  name: 'Unintegrated Generated Security',
  description:
    'A security initializer is defined and declared but its name appears nowhere else in the ' +
    'project, so the mechanism it sets up is never activated.',
  category: DESIGN_SMELL_CATEGORY,
  severity: 'high',
  defaultConfidence: 'medium',
  languages: ['c', 'cpp'],
  cwe: ['CWE-1188', 'CWE-665'],
  owasp: ['A05:2021 Security Misconfiguration'],
  remediation: {
    why: 'Inert security code reads as protection that is not there.',
    how: 'Invoke the initializer from the start-up path, or delete it.',
  },
  analyze,
};
