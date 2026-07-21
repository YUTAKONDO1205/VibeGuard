// vibeguard:disable-file VG-SEC-001 VG-SEC-003
// Test fixtures contain intentional vulnerable code to exercise the rules.
//
// EXT_TO_LANGUAGE (./language-detect.ts) <-> LINE_COMMENT_SPECS
// (packages/rules/src/matcher-utils.ts) must stay in sync: every language this
// package's detector can hand to the rules engine needs a line-comment spec.
//
// TWO LAYERS KEEP THAT TRUE, AND THEY DO DIFFERENT JOBS. Neither replaces the
// other, so do not delete one because the other looks like it covers the case:
//
//   1. CI — this test. A language reachable from EXT_TO_LANGUAGE with no entry
//      in LINE_COMMENT_SPECS fails the build, naming the language and the fix.
//      This is what keeps FALSE POSITIVES from shipping: an unmapped language
//      gets the empty spec, so no line in it counts as a comment, so every
//      commented-out `eval(...)` in every file of that language reports a
//      finding. Noisy, but loud.
//
//   2. Runtime — `getLineCommentSpec`'s empty-spec fallback. If an unmapped
//      language ships anyway (an extension added in a hotfix, or a language name
//      that reaches the rules engine from somewhere other than EXT_TO_LANGUAGE),
//      the fallback keeps every match rather than dropping it. This is what
//      keeps SILENT FALSE NEGATIVES from shipping: `runRegex({ skipCommentLines
//      })` deletes matches *upstream* of the confidence chokepoint, so a match
//      wrongly classified as a comment is gone before any severity gate can
//      bound the mistake — nothing downstream can see it, let alone triage it.
//
// The fallback deliberately trades a silent miss for noise; this test is what
// keeps that noise from ever reaching a user. Losing the fallback turns a
// forgotten map entry into invisible missed findings; losing this test turns it
// into a false-positive flood nobody notices until a user reports it.
//
// WHY THE SOURCE TEXT IS PARSED: EXT_TO_LANGUAGE is a module-private const, so
// its value range cannot be imported. Probing `detectLanguageFromPath` with a
// hardcoded extension list would defeat the purpose — a newly added extension
// would not be in the list and the omission this test exists to catch would sail
// through. So the table is read out of the source and each parsed entry is then
// cross-checked against `detectLanguageFromPath`, which keeps the parse honest.
// The other in-package way a language reaches the rules engine —
// `detectLanguageFromContent`, for extensionless files — is parsed and checked
// too (its `return 'lang'` literals). A language reaching the engine from
// outside this package entirely is still invisible here (layer 2 covers it).
import { readFileSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { getLineCommentSpec, hasLineCommentSpec } from '@vibeguard/rules';
import { detectLanguageFromPath } from './language-detect.js';
import { scanPath } from './file-scanner.js';

const LANGUAGE_DETECT_SRC = fileURLToPath(new URL('./language-detect.ts', import.meta.url));

const TEMP_DIRS: string[] = [];

afterEach(async () => {
  while (TEMP_DIRS.length) {
    const dir = TEMP_DIRS.pop()!;
    await rm(dir, { recursive: true, force: true }).catch(() => {
      /* best-effort */
    });
  }
});

/**
 * Extensions any correct parse of the table must find. If one goes missing, the
 * parser has drifted from the table's shape and is under-reporting languages —
 * which would silently weaken the sync check below rather than fail it.
 */
const CANARY_EXTENSIONS = ['.py', '.php', '.html', '.ts', '.sql', '.ino'];

interface ExtEntry {
  readonly ext: string;
  readonly language: string;
}

/**
 * The `'.ext': 'language'` pairs of EXT_TO_LANGUAGE, read from the source text.
 * Throws rather than returning nothing when the table cannot be found: a parse
 * that quietly yields zero entries would make every assertion below vacuous.
 */
function parseExtToLanguage(): ExtEntry[] {
  const source = readFileSync(LANGUAGE_DETECT_SRC, 'utf8');
  const body = /const EXT_TO_LANGUAGE[^=]*=\s*\{([\s\S]*?)\n\};/.exec(source)?.[1];
  if (!body) {
    throw new Error(
      `Could not find the EXT_TO_LANGUAGE object literal in ${LANGUAGE_DETECT_SRC}. ` +
        `This test reads it out of the source because it is not exported. If the table was ` +
        `renamed, moved, or reshaped, update this parser (or export the table and import it) — ` +
        `do not delete the test: it is the only thing that catches a language added to the ` +
        `detector but not to LINE_COMMENT_SPECS in packages/rules/src/matcher-utils.ts.`,
    );
  }
  const entries: ExtEntry[] = [];
  const pair = /'([^']+)'\s*:\s*'([^']+)'/g;
  let m: RegExpExecArray | null;
  while ((m = pair.exec(body)) !== null) {
    entries.push({ ext: m[1]!, language: m[2]! });
  }
  return entries;
}

const ENTRIES = parseExtToLanguage();
const LANGUAGES = [...new Set(ENTRIES.map((e) => e.language))].sort();

/** Extensions per language, for a failure message that points at real files. */
const EXTENSIONS_BY_LANGUAGE = new Map<string, string[]>();
for (const { ext, language } of ENTRIES) {
  EXTENSIONS_BY_LANGUAGE.set(language, [...(EXTENSIONS_BY_LANGUAGE.get(language) ?? []), ext]);
}

/**
 * Languages `detectLanguageFromContent` can return, read from the source. This
 * detector is a SECOND way a language reaches the rules engine (extensionless
 * files whose content is sniffed), so its range needs a spec too — the
 * EXT_TO_LANGUAGE parse above does not see it. Canary-guarded like that parse so
 * a drifted regex fails loud instead of silently matching nothing.
 */
function parseContentDetectLanguages(): string[] {
  const source = readFileSync(LANGUAGE_DETECT_SRC, 'utf8');
  const body = /function detectLanguageFromContent[\s\S]*?\n\}/.exec(source)?.[0];
  if (!body) {
    throw new Error(
      `Could not find detectLanguageFromContent in ${LANGUAGE_DETECT_SRC}. This test reads its ` +
        `\`return 'lang'\` literals because the function is not exported. If it was renamed or ` +
        `reshaped, update this parser — do not delete the test: it is the only thing that catches ` +
        `a content-detected language added without a LINE_COMMENT_SPECS entry.`,
    );
  }
  const langs = new Set<string>();
  const ret = /return '([a-z]+)'/g;
  let m: RegExpExecArray | null;
  while ((m = ret.exec(body)) !== null) langs.add(m[1]!);
  return [...langs].sort();
}

const CONTENT_LANGUAGES = parseContentDetectLanguages();

function unmappedLanguagesMessage(unmapped: string[]): string {
  const listed = unmapped
    .map((lang) => `${lang} (${(EXTENSIONS_BY_LANGUAGE.get(lang) ?? []).join(', ')})`)
    .join('; ');
  return [
    `These languages are reachable from EXT_TO_LANGUAGE in`,
    `packages/analyzer-core/src/language-detect.ts but have no entry in LINE_COMMENT_SPECS in`,
    `packages/rules/src/matcher-utils.ts: ${listed}.`,
    ``,
    `FIX: add each one to LINE_COMMENT_SPECS, e.g.`,
    `  ${unmapped[0]}: { prefixes: ['#'], exclusions: [] },`,
    `where prefixes are the tokens that open a line comment and exclusions are executable`,
    `look-alikes that must NOT be treated as comments (PHP 8's '#[' attribute). A language`,
    `with no line-comment syntax gets { prefixes: [], exclusions: [] } — see html.`,
    ``,
    `UNTIL THEN: getLineCommentSpec returns the empty spec for it, so no line in that language`,
    `counts as a comment and commented-out code reports findings. That fallback is fail-safe`,
    `on purpose (noise beats a silent miss), but it is not the intended end state — this test`,
    `is here so the map gets fixed instead.`,
  ].join('\n');
}

describe('EXT_TO_LANGUAGE / LINE_COMMENT_SPECS sync', () => {
  it('parses the EXT_TO_LANGUAGE table out of language-detect.ts', () => {
    // Guards the parse itself: a regex that silently stops matching would make
    // the sync test below pass over an empty set and prove nothing.
    expect(ENTRIES.length).toBeGreaterThanOrEqual(10);
    expect(LANGUAGES.length).toBeGreaterThanOrEqual(5);
    for (const canary of CANARY_EXTENSIONS) {
      expect(
        ENTRIES.map((e) => e.ext),
        `Expected ${canary} in the parsed EXT_TO_LANGUAGE table. Either the extension was ` +
          `removed from language-detect.ts (then update CANARY_EXTENSIONS), or the parser in ` +
          `this file has drifted from the table's shape and is under-reporting languages.`,
      ).toContain(canary);
    }
  });

  it('parses the same mapping detectLanguageFromPath applies at runtime', () => {
    // Cross-check: the source text is only a stand-in for the real detector, so
    // every parsed pair must reproduce through the exported function.
    for (const { ext, language } of ENTRIES) {
      expect(detectLanguageFromPath(`sync-probe${ext}`), `for extension ${ext}`).toBe(language);
    }
  });

  it('gives every language EXT_TO_LANGUAGE can return a line-comment spec', () => {
    const unmapped = LANGUAGES.filter((lang) => !hasLineCommentSpec(lang));
    expect(unmapped, unmapped.length ? unmappedLanguagesMessage(unmapped) : undefined).toEqual([]);
  });

  it('distinguishes a mapped language from an unmapped one', () => {
    // Non-vacuity guard for the test above: a `hasLineCommentSpec` that always
    // returned true would make it pass no matter what the map contained.
    expect(hasLineCommentSpec('python')).toBe(true);
    expect(hasLineCommentSpec('cobol')).toBe(false);
  });

  it('treats html as mapped even though its spec is empty', () => {
    // html has an explicit entry that is *structurally* identical to the
    // unknown-language fallback ({ prefixes: [], exclusions: [] }) because its
    // only comment syntax, <!-- -->, is multi-line and out of scope for a
    // line-oriented predicate. `hasLineCommentSpec` compares by reference, which
    // is why it can tell "known to have no line comments" from "never heard of
    // it". Any future rewrite of this file that detects unmapped languages by
    // deep equality instead would wrongly report html as a gap.
    expect(hasLineCommentSpec('html')).toBe(true);
    expect(getLineCommentSpec('html').prefixes).toEqual([]);
  });
});

describe('unknown-language fail-safe', () => {
  it('returns an empty spec for an absent language', () => {
    expect(hasLineCommentSpec(undefined)).toBe(false);
    expect(getLineCommentSpec(undefined).prefixes).toEqual([]);
    expect(getLineCommentSpec(undefined).exclusions).toEqual([]);
  });

  it('returns an empty spec for an unrecognised language', () => {
    expect(hasLineCommentSpec('cobol')).toBe(false);
    expect(getLineCommentSpec('cobol').prefixes).toEqual([]);
    expect(getLineCommentSpec('cobol').exclusions).toEqual([]);
  });

  it('maps every language detectLanguageFromContent can return', () => {
    // The content sniffer is the other in-package path to the rules engine
    // (extensionless files), so its range must be mapped too. Guard the parse,
    // then require a spec for each returned language.
    expect(CONTENT_LANGUAGES.length).toBeGreaterThanOrEqual(5);
    const unmapped = CONTENT_LANGUAGES.filter((lang) => !hasLineCommentSpec(lang));
    expect(
      unmapped,
      unmapped.length
        ? `content-detected languages (detectLanguageFromContent) with no LINE_COMMENT_SPECS entry: ${unmapped.join(', ')}`
        : undefined,
    ).toEqual([]);
  });

  it('reaches that fail-safe for a file whose extension maps to nothing', () => {
    // The undefined-language path is not hypothetical: an unrecognised extension
    // yields `undefined`, which is what the analyzer passes to the rules engine
    // as `ctx.language`. With no spec, nothing is a comment and no match is
    // dropped — so a leading `#` in such a file can no longer erase a finding.
    expect(detectLanguageFromPath('deploy.hcl')).toBeUndefined();
    expect(hasLineCommentSpec(detectLanguageFromPath('deploy.hcl'))).toBe(false);
  });

  it('scans unknown-extension files by default, so that path is live', async () => {
    // Reachability precondition for the case above. The fail-safe only matters
    // because files with no detected language are actually scanned: skipping
    // them is opt-in (`knownLanguagesOnly`), and it is off by default here and
    // in the shipped CLI (apps/cli/src/args.ts sets `knownLanguagesOnly: false`
    // and apps/cli/src/index.ts forwards it). If this default ever flips to
    // true, unknown-extension files stop being scanned at all and the
    // undefined-language spec becomes dead code — which is a product decision,
    // not a cleanup. The opt-in `true` direction is covered in
    // file-scanner.test.ts; this pins the default that ships.
    const dir = await mkdtemp(join(tmpdir(), 'vibeguard-sync-'));
    TEMP_DIRS.push(dir);
    await writeFile(join(dir, 'note.txt'), 'API_KEY = "AKIAIOSFODNN7EXAMPLE"', 'utf8');
    expect(detectLanguageFromPath('note.txt')).toBeUndefined();
    const result = await scanPath(dir);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
