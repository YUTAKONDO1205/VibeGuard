import type { RuleMatch } from './rule-types.js';

export interface Position {
  line: number;
  column: number;
}

export function indexToPosition(content: string, index: number): Position {
  let line = 1;
  let column = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === '\n') {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }
  }
  return { line, column };
}

export function getLineText(lines: string[], lineNumber: number): string {
  return lines[lineNumber - 1] ?? '';
}

/**
 * Languages where a leading `#` is NOT a line comment (so we must not treat it
 * as one). In these languages `#` opens real, executed syntax: an ES2022 private
 * class field (`#count = 0`), a C/C++/C# preprocessor directive (`#define
 * DB_PASSWORD "…"`, `#include`), a Rust attribute (`#[derive(…)]`), a Swift
 * compiler directive (`#if DEBUG`). This set is the single source of truth for
 * that question: both comment-line predicates below and
 * `isInDocstringOrBlockComment` in confidence.ts consume it, so a language is
 * classified once, in one place.
 *
 * Deliberately absent are the languages where `#` genuinely does start a comment
 * — python, ruby, php, shell, yaml, toml, and sql (MySQL's `#`). Classifying one
 * of those as HASH_NOT_COMMENT would surface every commented-out line as a
 * finding.
 *
 * KNOWN LIMITATION — this is a blocklist, so its default for an unrecognised or
 * absent language is "`#` starts a comment", which drops the match (see
 * `isCommentLine` below). That default fails toward a silent false negative,
 * which is the unsafe direction for a security scanner. It is kept only because
 * inverting to an allowlist of `#`-comment languages would change behavior for
 * every language-undetected file at once, and that is a bigger change than this
 * fix. Keep this set in step with `EXT_TO_LANGUAGE` in
 * analyzer-core/src/language-detect.ts: a new language whose `#` is executable
 * MUST be added here, or its findings vanish before the analyzer ever sees them.
 */
export const HASH_NOT_COMMENT = new Set([
  'javascript',
  'typescript',
  'java',
  'go',
  'csharp',
  'c',
  'cpp',
  'rust',
  'swift',
  'kotlin',
]);

/**
 * True when a line is a whole-line comment, i.e. its first non-whitespace
 * characters are `//`, or `#` in a language where `#` starts a comment. This is
 * the single comment-line predicate used by both
 * `runRegex({ skipCommentLines })` (which drops such matches) and the
 * context-window confidence helper (which down-ranks them) — keeping one
 * definition so the two stay consistent.
 *
 * `language` is optional but should be passed wherever it is known. Omitted, we
 * fall back to treating a leading `#` as a comment, which is wrong for the
 * HASH_NOT_COMMENT languages: an ES2022 private class field whose initialiser
 * reaches a dangerous sink (`#run = (s) => dynamicEval(s);`) reads as a comment
 * line and its match is lost. That mistake is not a down-rank —
 * `runRegex({ skipCommentLines })` DROPS a match on a line this predicate
 * accepts, before the analyzer's confidence chokepoint ever sees it, so the
 * severity gate cannot bound it. A misclassification here is a silent false
 * negative, which is strictly worse than a wrong confidence.
 *
 * It does NOT detect trailing comments, block comments, or docstrings (see
 * confidence.ts for multi-line awareness).
 */
export function isCommentLine(lineText: string, language?: string): boolean {
  const hashIsComment = !(language != null && HASH_NOT_COMMENT.has(language));
  const trimmed = lineText.trimStart();
  return trimmed.startsWith('//') || (hashIsComment && trimmed.startsWith('#'));
}

/**
 * Run a global regex against the source and convert each match into a RuleMatch.
 * Pattern MUST have the global flag.
 */
export function runRegex(
  content: string,
  pattern: RegExp,
  options?: {
    /** When true, skip matches whose line is in a comment-only context (// or # at line start ignoring whitespace). */
    skipCommentLines?: boolean;
    /** Maximum matches to return. */
    limit?: number;
    /** Source language, so `#` is only treated as a comment where it is one. Pass `ctx.language`. */
    language?: string;
  },
): RuleMatch[] {
  if (!pattern.global) {
    throw new Error(`pattern must be global: ${pattern}`);
  }
  const matches: RuleMatch[] = [];
  const limit = options?.limit ?? 1000;
  let m: RegExpExecArray | null;
  pattern.lastIndex = 0;
  while ((m = pattern.exec(content)) !== null) {
    if (matches.length >= limit) break;
    const start = indexToPosition(content, m.index);
    const end = indexToPosition(content, m.index + m[0].length);
    if (options?.skipCommentLines) {
      const lineText = content.split('\n')[start.line - 1] ?? '';
      if (isCommentLine(lineText, options.language)) {
        if (m[0].length === 0) pattern.lastIndex += 1;
        continue;
      }
    }
    matches.push({
      startLine: start.line,
      endLine: end.line,
      startColumn: start.column,
      endColumn: end.column,
      evidence: m[0],
      variables: m.groups ? { ...m.groups } : undefined,
    });
    if (m[0].length === 0) pattern.lastIndex += 1;
  }
  return matches;
}

export function languageMatches(ruleLanguages: string[], inputLanguage?: string): boolean {
  if (ruleLanguages.includes('*')) return true;
  if (!inputLanguage) return false;
  return ruleLanguages.includes(inputLanguage);
}
